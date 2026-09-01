import unittest

from backend.classifier import (
    CATEGORY_AUTHENTICATION,
    CATEGORY_PRIVILEGE_ESCALATION,
    CATEGORY_PRIVILEGED_ACTIVITY,
    classify_alert,
)
from backend.correlation import correlate_events, deduplicate_alerts
from backend.incidents import create_incident
from backend.parser import parse_alert
from backend.recommendations import generate_recommendations
from backend.risk_score import assess_correlation_risk, assess_event_risk


def _alert(
    alert_id: str,
    timestamp: str,
    rule_id: str,
    level: int,
    description: str,
    groups: list[str],
    *,
    user: str = "hedia",
    destination_user: str | None = None,
    command: str | None = None,
    full_log: str | None = None,
) -> object:
    return parse_alert(
        {
            "timestamp": timestamp,
            "id": alert_id,
            "rule": {
                "id": rule_id,
                "level": level,
                "description": description,
                "groups": groups,
            },
            "agent": {"id": "001", "name": "compute2-endpoint"},
            "data": {
                "srcuser": user,
                "dstuser": destination_user,
                "command": command,
            },
            "full_log": full_log or description,
        }
    )


def _sudo_alert(alert_id: str, timestamp: str, level: int = 3) -> object:
    return _alert(
        alert_id,
        timestamp,
        "5402",
        level,
        "Successful sudo to ROOT executed.",
        ["syslog", "sudo"],
        destination_user="root",
        command="docker compose ps",
        full_log="sudo: hedia : COMMAND=/usr/bin/docker compose ps",
    )


def _privilege_modification_alert(alert_id: str, timestamp: str) -> object:
    return _alert(
        alert_id,
        timestamp,
        "100101",
        12,
        "Suspicious privilege escalation: user added to sudo group",
        ["privilege_escalation", "sudo"],
        destination_user="root",
        command="/usr/sbin/usermod -aG sudo suspicious-user",
    )


def _successful_login(alert_id: str, timestamp: str) -> object:
    return _alert(
        alert_id,
        timestamp,
        "5715",
        3,
        "sshd: Accepted password for hedia.",
        ["sshd", "authentication_success"],
        full_log="sshd: Accepted password for hedia",
    )


def _failed_login(alert_id: str, timestamp: str) -> object:
    return _alert(
        alert_id,
        timestamp,
        "5710",
        5,
        "sshd: authentication failed.",
        ["sshd", "authentication_failed"],
        full_log="sshd: Failed password for hedia",
    )


class PrivilegedActivityRegressionTestCase(unittest.TestCase):
    def test_rule_5402_is_privileged_activity_not_privilege_escalation(self) -> None:
        alert = _sudo_alert("sudo-1", "2026-09-01T10:00:00+00:00")
        event = deduplicate_alerts([alert])[0]

        classification = classify_alert(alert)
        assessment = assess_event_risk(event)
        recommendations = generate_recommendations(event, classification, assessment)

        self.assertEqual(classification.category, CATEGORY_PRIVILEGED_ACTIVITY)
        self.assertEqual(classification.subcategory, "Sudo Command")
        self.assertNotEqual(assessment.level, "Critical")
        self.assertNotIn(
            "Verify sudo privilege modification",
            [recommendation.title for recommendation in recommendations],
        )
        self.assertIn(
            "Review privileged command",
            [recommendation.title for recommendation in recommendations],
        )

    def test_privilege_modification_remains_high_or_critical(self) -> None:
        alert = _privilege_modification_alert("priv-1", "2026-09-01T10:00:00+00:00")
        event = deduplicate_alerts([alert])[0]

        classification = classify_alert(alert)
        assessment = assess_event_risk(event)

        self.assertEqual(classification.category, CATEGORY_PRIVILEGE_ESCALATION)
        self.assertEqual(classification.subcategory, "Sudo / Group Modification")
        self.assertIn(assessment.level, {"High", "Critical"})

    def test_systemd_event_does_not_join_sudo_activity(self) -> None:
        systemd_alert = _alert(
            "systemd-1",
            "2026-09-01T10:00:00+00:00",
            "40704",
            5,
            "Systemd: Service exited due to a failure.",
            ["syslog"],
        )
        events = deduplicate_alerts(
            [systemd_alert, _sudo_alert("sudo-1", "2026-09-01T10:00:30+00:00")]
        )

        self.assertEqual(correlate_events(events), [])

    def test_netstat_event_does_not_join_authentication(self) -> None:
        netstat_alert = _alert(
            "netstat-1",
            "2026-09-01T10:00:00+00:00",
            "533",
            3,
            "Listened ports status changed.",
            ["ossec"],
        )
        events = deduplicate_alerts(
            [netstat_alert, _successful_login("auth-1", "2026-09-01T10:00:30+00:00")]
        )

        self.assertEqual(correlate_events(events), [])

    def test_successful_login_and_sudo_do_not_become_critical(self) -> None:
        events = deduplicate_alerts(
            [
                _successful_login("auth-1", "2026-09-01T10:00:00+00:00"),
                _sudo_alert("sudo-1", "2026-09-01T10:00:30+00:00"),
            ]
        )

        groups = correlate_events(events)

        self.assertEqual(len(groups), 1)
        self.assertNotEqual(assess_correlation_risk(groups[0]).level, "Critical")

    def test_routine_sudo_session_title_does_not_repeat_activity(self) -> None:
        events = deduplicate_alerts(
            [
                _successful_login("auth-1", "2026-09-01T10:00:00+00:00"),
                _sudo_alert("sudo-1", "2026-09-01T10:00:30+00:00"),
            ]
        )

        incident = create_incident(correlate_events(events)[0])

        self.assertEqual(incident.title, "Correlated privileged activity")
        self.assertNotIn("activity activity", incident.title.lower())

    def test_multiple_routine_sudo_commands_do_not_become_critical(self) -> None:
        events = deduplicate_alerts(
            [
                _successful_login("auth-1", "2026-09-01T10:00:00+00:00"),
                _sudo_alert("sudo-1", "2026-09-01T10:00:20+00:00"),
                _sudo_alert("sudo-2", "2026-09-01T10:00:40+00:00"),
                _sudo_alert("sudo-3", "2026-09-01T10:01:00+00:00"),
            ]
        )

        assessment = assess_correlation_risk(correlate_events(events)[0])

        self.assertNotEqual(assessment.level, "Critical")
        self.assertLessEqual(assessment.score, 74)

    def test_routine_session_is_capped_at_high_even_with_high_wazuh_level(self) -> None:
        events = deduplicate_alerts(
            [
                _successful_login("auth-1", "2026-09-01T10:00:00+00:00"),
                _sudo_alert("sudo-1", "2026-09-01T10:00:30+00:00", level=15),
            ]
        )

        assessment = assess_correlation_risk(correlate_events(events)[0])

        self.assertEqual(assessment.level, "High")
        self.assertEqual(assessment.score, 74)

    def test_duplicate_pam_observations_do_not_inflate_routine_session_risk(self) -> None:
        events = deduplicate_alerts(
            [
                _successful_login("auth-1", "2026-09-01T10:00:00+00:00"),
                _successful_login("auth-2", "2026-09-01T10:00:01+00:00"),
                _sudo_alert("sudo-1", "2026-09-01T10:00:30+00:00"),
            ]
        )

        assessment = assess_correlation_risk(correlate_events(events)[0])

        self.assertEqual(assessment.factors["repetition"]["logical_event_count"], 2)
        self.assertEqual(assessment.factors["repetition"]["duplicate_observation_count"], 1)
        self.assertTrue(assessment.factors["repetition"]["duplicate_observations_suppressed"])
        self.assertNotEqual(assessment.level, "Critical")

    def test_authentication_and_privilege_modification_correlate(self) -> None:
        events = deduplicate_alerts(
            [
                _successful_login("auth-1", "2026-09-01T10:00:00+00:00"),
                _privilege_modification_alert("priv-1", "2026-09-01T10:00:30+00:00"),
            ]
        )

        groups = correlate_events(events)

        self.assertEqual(len(groups), 1)
        self.assertIn(
            assess_correlation_risk(groups[0]).level,
            {"High", "Critical"},
        )

    def test_authentication_and_rule_100101_can_be_critical(self) -> None:
        events = deduplicate_alerts(
            [
                _successful_login("auth-1", "2026-09-01T10:00:00+00:00"),
                _privilege_modification_alert("priv-1", "2026-09-01T10:00:30+00:00"),
            ]
        )

        self.assertEqual(
            assess_correlation_risk(correlate_events(events)[0]).level,
            "Critical",
        )

    def test_multistage_attack_sequence_is_critical(self) -> None:
        events = deduplicate_alerts(
            [
                _failed_login("failed-1", "2026-09-01T10:00:00+00:00"),
                _failed_login("failed-2", "2026-09-01T10:00:20+00:00"),
                _successful_login("auth-1", "2026-09-01T10:00:40+00:00"),
                _privilege_modification_alert("priv-1", "2026-09-01T10:01:00+00:00"),
                _sudo_alert("sudo-1", "2026-09-01T10:01:20+00:00"),
            ]
        )

        groups = correlate_events(events)

        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0].events), 5)
        self.assertEqual(assess_correlation_risk(groups[0]).level, "Critical")

    def test_incident_prefers_privilege_escalation_over_other_categories(self) -> None:
        events = deduplicate_alerts(
            [
                _successful_login("auth-1", "2026-09-01T10:00:00+00:00"),
                _privilege_modification_alert("priv-1", "2026-09-01T10:00:30+00:00"),
            ]
        )
        group = correlate_events(events)[0]

        incident = create_incident(group)

        self.assertEqual(incident.category, CATEGORY_PRIVILEGE_ESCALATION)
        self.assertIn("privilege escalation", incident.title.lower())
        self.assertNotEqual(incident.category, CATEGORY_AUTHENTICATION)


if __name__ == "__main__":
    unittest.main()
