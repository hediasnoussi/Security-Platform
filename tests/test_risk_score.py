import json
import unittest
from pathlib import Path

from backend.correlation import CorrelationGroup, DeduplicatedEvent, deduplicate_alerts
from backend.models import NormalizedAlert
from backend.parser import parse_alert
from backend.risk_score import (
    MAX_SCORE,
    MIN_SCORE,
    RiskAssessment,
    assess_correlation_risk,
    assess_event_risk,
    assess_risk,
)


SAMPLE_ALERT_PATH = Path(__file__).resolve().parents[1] / "data" / "sample_alert_100101.json"


def _event(
    alert: NormalizedAlert,
    duplicate_count: int = 1,
    event_id: str = "event-test",
) -> DeduplicatedEvent:
    alerts = tuple(alert for _ in range(duplicate_count))
    return DeduplicatedEvent(
        event_id=event_id,
        representative_alert=alert,
        source_alert_ids=tuple(
            f"{alert.alert_id or event_id}-{index}"
            for index in range(duplicate_count)
        ),
        duplicate_count=duplicate_count,
        first_seen=alert.timestamp,
        last_seen=alert.timestamp,
        alerts=alerts,
    )


def _alert(
    rule_level: int | None,
    groups: tuple[str, ...],
    description: str,
    command: str | None = None,
    dstuser: str | None = None,
    alert_id: str = "alert-test",
) -> NormalizedAlert:
    return NormalizedAlert(
        timestamp="2026-08-26T10:15:30.000+0000",
        alert_id=alert_id,
        rule_id="test-rule",
        rule_level=rule_level,
        rule_description=description,
        rule_groups=groups,
        agent_id="001",
        agent_name="compute2-endpoint",
        source_user="hedia",
        destination_user=dstuser,
        command=command,
    )


class RiskScoreTestCase(unittest.TestCase):
    def test_low_event_score_and_level(self) -> None:
        assessment = assess_event_risk(
            _event(_alert(1, ("local",), "Generic system notice."))
        )

        self.assertGreaterEqual(assessment.score, 0)
        self.assertLessEqual(assessment.score, 24)
        self.assertEqual(assessment.level, "Low")

    def test_medium_event_score_and_level(self) -> None:
        assessment = assess_event_risk(
            _event(
                _alert(
                    7,
                    ("sshd", "authentication_failed"),
                    "sshd: authentication failed.",
                )
            )
        )

        self.assertGreaterEqual(assessment.score, 25)
        self.assertLessEqual(assessment.score, 49)
        self.assertEqual(assessment.level, "Medium")

    def test_high_event_score_and_level(self) -> None:
        assessment = assess_event_risk(
            _event(
                _alert(
                    10,
                    ("user_management",),
                    "User account was created.",
                    command="/usr/sbin/useradd analyst",
                )
            )
        )

        self.assertGreaterEqual(assessment.score, 50)
        self.assertLessEqual(assessment.score, 74)
        self.assertEqual(assessment.level, "High")

    def test_critical_event_score_and_level(self) -> None:
        assessment = assess_event_risk(
            _event(
                _alert(
                    12,
                    ("privilege_escalation", "sudo"),
                    "Suspicious privilege escalation: user added to sudo group",
                    command="/usr/sbin/usermod -aG sudo analyst",
                    dstuser="root",
                )
            )
        )

        self.assertGreaterEqual(assessment.score, 75)
        self.assertLessEqual(assessment.score, 100)
        self.assertEqual(assessment.level, "Critical")

    def test_real_rule_100101_produces_high_or_critical_risk(self) -> None:
        raw_alert = json.loads(SAMPLE_ALERT_PATH.read_text(encoding="utf-8"))
        alert = parse_alert(raw_alert)
        event = deduplicate_alerts([alert])[0]

        assessment = assess_event_risk(event)

        self.assertGreaterEqual(assessment.score, 50)
        self.assertIn(assessment.level, {"High", "Critical"})
        self.assertTrue(assessment.explanation)
        self.assertIn("Privilege Escalation", assessment.explanation)

    def test_higher_wazuh_level_increases_score(self) -> None:
        low_level = assess_event_risk(
            _event(_alert(3, ("sshd",), "sshd: authentication failed."))
        )
        high_level = assess_event_risk(
            _event(_alert(12, ("sshd",), "sshd: authentication failed."))
        )

        self.assertGreater(high_level.score, low_level.score)

    def test_more_critical_category_increases_score(self) -> None:
        compliance = assess_event_risk(
            _event(_alert(8, ("sca",), "CIS benchmark policy check failed."))
        )
        privilege = assess_event_risk(
            _event(
                _alert(
                    8,
                    ("privilege_escalation",),
                    "Privilege escalation detected.",
                )
            )
        )

        self.assertGreater(privilege.score, compliance.score)

    def test_repeated_similar_events_receive_repetition_bonus(self) -> None:
        alert = _alert(8, ("sshd",), "sshd: authentication failed.")

        single = assess_event_risk(_event(alert, duplicate_count=1))
        repeated = assess_event_risk(_event(alert, duplicate_count=3))

        self.assertGreater(repeated.score, single.score)
        self.assertGreater(repeated.factors["repetition"]["points"], 0)

    def test_correlated_group_scores_higher_than_same_event_alone(self) -> None:
        privilege_event = _event(
            _alert(
                12,
                ("privilege_escalation", "sudo"),
                "Suspicious privilege escalation: user added to sudo group",
                command="/usr/sbin/usermod -aG sudo analyst",
                dstuser="root",
                alert_id="priv-1",
            ),
            event_id="event-priv",
        )
        auth_event = _event(
            _alert(
                7,
                ("sshd", "authentication_failed"),
                "sshd: authentication failed.",
                alert_id="auth-1",
            ),
            event_id="event-auth",
        )
        group = CorrelationGroup(
            id="corr-test",
            events=(privilege_event, auth_event),
            first_seen=privilege_event.first_seen,
            last_seen=auth_event.last_seen,
            agent_id="001",
            categories=("Privilege Escalation", "Authentication"),
            correlation_type="same_agent_user_context",
            reason="Events share the same agent and user context.",
        )

        standalone = assess_event_risk(privilege_event)
        correlated = assess_correlation_risk(group)

        self.assertGreater(correlated.score, standalone.score)
        self.assertTrue(correlated.factors["correlation"]["correlated"])

    def test_sudo_sensitive_action_receives_bonus(self) -> None:
        base = assess_event_risk(
            _event(_alert(8, ("privilege_escalation",), "Privilege escalation detected."))
        )
        sudo = assess_event_risk(
            _event(
                _alert(
                    8,
                    ("privilege_escalation", "sudo"),
                    "Privilege escalation detected.",
                    command="/usr/sbin/usermod -aG sudo analyst",
                    dstuser="root",
                )
            )
        )

        self.assertGreater(sudo.score, base.score)
        self.assertIn(
            "sudo privilege modification",
            sudo.factors["sensitive_action"]["matched"],
        )

    def test_score_never_exceeds_100(self) -> None:
        noisy_event = _event(
            _alert(
                15,
                ("malware", "privilege_escalation", "sudo"),
                "Malware with privilege escalation and sudo modification.",
                command="/usr/sbin/usermod -aG sudo analyst",
                dstuser="root",
            ),
            duplicate_count=20,
        )
        group = CorrelationGroup(
            id="corr-max",
            events=(noisy_event, noisy_event, noisy_event, noisy_event),
            first_seen=noisy_event.first_seen,
            last_seen=noisy_event.last_seen,
            agent_id="001",
            categories=("Malware", "Privilege Escalation", "Authentication"),
            correlation_type="stress",
            reason="Stress test.",
        )

        assessment = assess_risk(group)

        self.assertLessEqual(assessment.score, MAX_SCORE)
        self.assertEqual(assessment.score, MAX_SCORE)

    def test_score_never_becomes_negative(self) -> None:
        assessment = assess_event_risk(
            _event(_alert(-10, ("local",), "Generic system notice."))
        )

        self.assertGreaterEqual(assessment.score, MIN_SCORE)

    def test_missing_fields_do_not_crash_risk_score(self) -> None:
        event = DeduplicatedEvent(
            event_id="missing-fields",
            representative_alert=NormalizedAlert(rule_groups=None, extra_data=None),
            source_alert_ids=(),
            duplicate_count=1,
            first_seen=None,
            last_seen=None,
        )

        assessment = assess_event_risk(event)

        self.assertIsInstance(assessment, RiskAssessment)
        self.assertGreaterEqual(assessment.score, MIN_SCORE)
        self.assertLessEqual(assessment.score, MAX_SCORE)

    def test_risk_assessment_contains_required_fields(self) -> None:
        assessment = assess_event_risk(
            _event(_alert(1, ("local",), "Generic system notice."))
        )

        self.assertEqual(
            set(assessment.to_dict()),
            {"score", "level", "factors", "explanation"},
        )
        self.assertEqual(
            set(assessment.factors),
            {
                "severity",
                "category",
                "repetition",
                "correlation",
                "sensitive_action",
            },
        )


if __name__ == "__main__":
    unittest.main()
