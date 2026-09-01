import json
import unittest
from pathlib import Path

from backend.classifier import (
    CATEGORY_ACCOUNT_MANAGEMENT,
    CATEGORY_AUTHENTICATION,
    CATEGORY_CONFIGURATION_COMPLIANCE,
    CATEGORY_FILE_INTEGRITY,
    CATEGORY_MALWARE,
    CATEGORY_NETWORK,
    CATEGORY_OTHER,
    CATEGORY_PRIVILEGE_ESCALATION,
)
from backend.correlation import CorrelationGroup, DeduplicatedEvent, deduplicate_alerts
from backend.models import NormalizedAlert
from backend.parser import parse_alert
from backend.recommendations import Recommendation, generate_recommendations
from backend.risk_score import RiskAssessment, assess_event_risk


SAMPLE_ALERT_PATH = Path(__file__).resolve().parents[1] / "data" / "sample_alert_100101.json"


def _alert(
    category_hint: str,
    rule_level: int = 7,
    description: str | None = None,
    groups: tuple[str, ...] | None = None,
    command: str | None = None,
    dstuser: str | None = None,
) -> NormalizedAlert:
    category_groups = {
        CATEGORY_AUTHENTICATION: ("sshd", "authentication_failed"),
        CATEGORY_PRIVILEGE_ESCALATION: ("privilege_escalation", "sudo"),
        CATEGORY_FILE_INTEGRITY: ("syscheck", "file_integrity"),
        CATEGORY_ACCOUNT_MANAGEMENT: ("user_management",),
        CATEGORY_NETWORK: ("network", "firewall"),
        CATEGORY_MALWARE: ("malware",),
        CATEGORY_CONFIGURATION_COMPLIANCE: ("sca", "cis", "compliance"),
        CATEGORY_OTHER: ("local",),
    }
    category_descriptions = {
        CATEGORY_AUTHENTICATION: "sshd: authentication failed.",
        CATEGORY_PRIVILEGE_ESCALATION: "Suspicious privilege escalation detected.",
        CATEGORY_FILE_INTEGRITY: "Integrity checksum changed.",
        CATEGORY_ACCOUNT_MANAGEMENT: "User account was created.",
        CATEGORY_NETWORK: "Firewall reported suspicious network activity.",
        CATEGORY_MALWARE: "Malware detected on endpoint.",
        CATEGORY_CONFIGURATION_COMPLIANCE: "CIS benchmark policy check failed.",
        CATEGORY_OTHER: "Generic system notice.",
    }

    return NormalizedAlert(
        timestamp="2026-08-26T10:15:30.000+0000",
        alert_id=f"alert-{category_hint}",
        rule_id="test-rule",
        rule_level=rule_level,
        rule_description=description or category_descriptions[category_hint],
        rule_groups=groups or category_groups[category_hint],
        agent_id="001",
        agent_name="compute2-endpoint",
        source_user="hedia",
        destination_user=dstuser,
        command=command,
        location="/var/log/auth.log",
    )


def _event(alert: NormalizedAlert, event_id: str = "event-test") -> DeduplicatedEvent:
    return DeduplicatedEvent(
        event_id=event_id,
        representative_alert=alert,
        source_alert_ids=(alert.alert_id,) if alert.alert_id else (),
        duplicate_count=1,
        first_seen=alert.timestamp,
        last_seen=alert.timestamp,
        alerts=(alert,),
    )


class RecommendationsTestCase(unittest.TestCase):
    def test_privilege_escalation_recommendations_are_relevant(self) -> None:
        recommendations = generate_recommendations(
            _event(
                _alert(
                    CATEGORY_PRIVILEGE_ESCALATION,
                    rule_level=12,
                    command="/usr/sbin/usermod -aG sudo analyst",
                    dstuser="root",
                )
            )
        )

        titles = _titles(recommendations)
        self.assertIn("Verify sudo privilege modification", titles)
        self.assertIn("Review subsequent privileged activity", titles)

    def test_authentication_recommendations_are_relevant(self) -> None:
        recommendations = generate_recommendations(_event(_alert(CATEGORY_AUTHENTICATION)))

        self.assertIn("Investigate authentication activity", _titles(recommendations))
        self.assertEqual(recommendations[0].category, CATEGORY_AUTHENTICATION)

    def test_file_integrity_recommendations_are_relevant(self) -> None:
        recommendations = generate_recommendations(_event(_alert(CATEGORY_FILE_INTEGRITY)))

        self.assertIn("Validate monitored file change", _titles(recommendations))

    def test_account_management_recommendations_are_relevant(self) -> None:
        recommendations = generate_recommendations(_event(_alert(CATEGORY_ACCOUNT_MANAGEMENT)))

        self.assertIn("Validate account or group change", _titles(recommendations))

    def test_network_recommendations_are_relevant(self) -> None:
        recommendations = generate_recommendations(_event(_alert(CATEGORY_NETWORK)))

        self.assertIn("Investigate suspicious network activity", _titles(recommendations))

    def test_malware_recommendations_are_relevant(self) -> None:
        recommendations = generate_recommendations(_event(_alert(CATEGORY_MALWARE)))

        self.assertIn("Investigate malware detection", _titles(recommendations))

    def test_configuration_compliance_recommendations_are_relevant(self) -> None:
        recommendations = generate_recommendations(
            _event(_alert(CATEGORY_CONFIGURATION_COMPLIANCE))
        )

        self.assertIn("Review failed compliance control", _titles(recommendations))

    def test_other_generates_generic_recommendation(self) -> None:
        recommendations = generate_recommendations(_event(_alert(CATEGORY_OTHER)))

        self.assertEqual(len(recommendations), 1)
        self.assertEqual(recommendations[0].category, CATEGORY_OTHER)
        self.assertIn("unclassified", recommendations[0].title.lower())

    def test_real_rule_100101_generates_multiple_critical_recommendations(self) -> None:
        raw_alert = json.loads(SAMPLE_ALERT_PATH.read_text(encoding="utf-8"))
        event = deduplicate_alerts([parse_alert(raw_alert)])[0]

        recommendations = generate_recommendations(event)

        titles = _titles(recommendations)
        self.assertGreaterEqual(len(recommendations), 3)
        self.assertIn("Verify sudo privilege modification", titles)
        self.assertIn("Investigate the initiating user", titles)
        self.assertTrue(all(item.priority == "Critical" for item in recommendations))

    def test_low_risk_keeps_low_priority(self) -> None:
        event = _event(_alert(CATEGORY_OTHER, rule_level=1))

        recommendations = generate_recommendations(event)

        self.assertTrue(all(item.priority == "Low" for item in recommendations))

    def test_critical_risk_keeps_critical_priority(self) -> None:
        event = _event(
            _alert(
                CATEGORY_PRIVILEGE_ESCALATION,
                rule_level=12,
                command="/usr/sbin/usermod -aG sudo analyst",
                dstuser="root",
            )
        )

        recommendations = generate_recommendations(event)

        self.assertTrue(all(item.priority == "Critical" for item in recommendations))

    def test_correlation_group_generates_correlation_recommendation(self) -> None:
        privilege_event = _event(
            _alert(
                CATEGORY_PRIVILEGE_ESCALATION,
                rule_level=12,
                command="/usr/sbin/usermod -aG sudo analyst",
                dstuser="root",
            ),
            event_id="privilege-event",
        )
        auth_event = _event(
            _alert(CATEGORY_AUTHENTICATION, rule_level=7),
            event_id="auth-event",
        )
        group = CorrelationGroup(
            id="corr-test",
            events=(privilege_event, auth_event),
            first_seen=privilege_event.first_seen,
            last_seen=auth_event.last_seen,
            agent_id="001",
            categories=(CATEGORY_PRIVILEGE_ESCALATION, CATEGORY_AUTHENTICATION),
            correlation_type="same_agent_user_context",
            reason="Events share the same agent and user context.",
        )

        recommendations = generate_recommendations(group)

        self.assertIn("Investigate correlated security activity", _titles(recommendations))
        self.assertIn(CATEGORY_PRIVILEGE_ESCALATION, _categories(recommendations))
        self.assertIn(CATEGORY_AUTHENTICATION, _categories(recommendations))

    def test_missing_fields_do_not_crash(self) -> None:
        recommendations = generate_recommendations(NormalizedAlert(rule_groups=None, extra_data=None))

        self.assertGreaterEqual(len(recommendations), 1)
        self.assertIsInstance(recommendations[0], Recommendation)

    def test_each_recommendation_contains_required_fields(self) -> None:
        recommendations = generate_recommendations(_event(_alert(CATEGORY_AUTHENTICATION)))

        for recommendation in recommendations:
            self.assertEqual(
                set(recommendation.to_dict()),
                {
                    "title",
                    "priority",
                    "description",
                    "rationale",
                    "actions",
                    "category",
                },
            )

    def test_recommendations_do_not_define_system_commands_to_execute(self) -> None:
        recommendations = generate_recommendations(
            _event(
                _alert(
                    CATEGORY_PRIVILEGE_ESCALATION,
                    rule_level=12,
                    command="/usr/sbin/usermod -aG sudo analyst",
                    dstuser="root",
                )
            )
        )

        for recommendation in recommendations:
            recommendation_dict = recommendation.to_dict()
            self.assertNotIn("command", recommendation_dict)
            self.assertNotIn("execute", recommendation_dict)
            for action in recommendation.actions:
                self.assertFalse(action.strip().lower().startswith(("sudo ", "rm ", "systemctl ")))

    def test_explicit_risk_assessment_can_override_priority_context(self) -> None:
        alert = _alert(CATEGORY_PRIVILEGE_ESCALATION, rule_level=12)
        event = _event(alert)
        risk_assessment = RiskAssessment(
            score=20,
            level="Low",
            factors={},
            explanation="Forced low risk for test.",
        )

        recommendations = generate_recommendations(event, risk_assessment=risk_assessment)

        self.assertTrue(all(item.priority == "Low" for item in recommendations))
        self.assertLess(assess_event_risk(event).score, 75)


def _titles(recommendations: list[Recommendation]) -> set[str]:
    return {recommendation.title for recommendation in recommendations}


def _categories(recommendations: list[Recommendation]) -> set[str]:
    return {recommendation.category for recommendation in recommendations}


if __name__ == "__main__":
    unittest.main()
