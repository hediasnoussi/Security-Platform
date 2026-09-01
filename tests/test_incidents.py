import json
import re
import unittest
from pathlib import Path

from backend.classifier import (
    CATEGORY_AUTHENTICATION,
    CATEGORY_PRIVILEGE_ESCALATION,
    classify_alert,
)
from backend.correlation import CorrelationGroup, DeduplicatedEvent, deduplicate_alerts
from backend.incidents import (
    INCIDENT_STATUS_FALSE_POSITIVE,
    INCIDENT_STATUS_INVESTIGATING,
    INCIDENT_STATUS_OPEN,
    INCIDENT_STATUS_RESOLVED,
    Incident,
    IncidentStore,
    create_incident,
    update_incident_status,
)
from backend.models import NormalizedAlert
from backend.parser import parse_alert
from backend.recommendations import Recommendation, generate_recommendations
from backend.risk_score import RiskAssessment, assess_event_risk, assess_risk


SAMPLE_ALERT_PATH = Path(__file__).resolve().parents[1] / "data" / "sample_alert_100101.json"


def _alert(
    rule_id: str = "100101",
    rule_level: int = 12,
    description: str = "Suspicious privilege escalation: user added to sudo group",
    groups: tuple[str, ...] = ("privilege_escalation", "sudo"),
    timestamp: str = "2026-08-26T10:15:30.000+0000",
    agent_id: str = "001",
    agent_name: str = "compute2-endpoint",
    source_user: str | None = "hedia",
    destination_user: str | None = "root",
    command: str | None = "/usr/sbin/usermod -aG sudo analyst",
    alert_id: str = "alert-1",
) -> NormalizedAlert:
    return NormalizedAlert(
        timestamp=timestamp,
        alert_id=alert_id,
        rule_id=rule_id,
        rule_level=rule_level,
        rule_description=description,
        rule_groups=groups,
        agent_id=agent_id,
        agent_name=agent_name,
        source_user=source_user,
        destination_user=destination_user,
        command=command,
        location="/var/log/auth.log",
    )


def _event(
    alert: NormalizedAlert,
    *,
    event_id: str = "event-1",
    duplicate_count: int = 1,
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


def _correlation_group() -> CorrelationGroup:
    privilege_event = _event(
        _alert(alert_id="priv-1"),
        event_id="event-privilege",
    )
    auth_event = _event(
        _alert(
            rule_id="5710",
            rule_level=7,
            description="sshd: authentication failed.",
            groups=("sshd", "authentication_failed"),
            destination_user=None,
            command=None,
            alert_id="auth-1",
        ),
        event_id="event-authentication",
    )
    return CorrelationGroup(
        id="corr-incident-test",
        events=(privilege_event, auth_event),
        first_seen=privilege_event.first_seen,
        last_seen=auth_event.last_seen,
        agent_id="001",
        categories=(CATEGORY_PRIVILEGE_ESCALATION, CATEGORY_AUTHENTICATION),
        correlation_type="same_agent_user_context",
        reason="Events share the same agent and user context.",
    )


class IncidentCreationTestCase(unittest.TestCase):
    def test_creates_incident_from_logical_event(self) -> None:
        incident = create_incident(_event(_alert()))

        self.assertIsInstance(incident, Incident)
        self.assertEqual(incident.category, CATEGORY_PRIVILEGE_ESCALATION)

    def test_creates_incident_from_correlation_group(self) -> None:
        incident = create_incident(_correlation_group())

        self.assertEqual(incident.correlation_id, "corr-incident-test")
        self.assertEqual(
            incident.categories,
            (CATEGORY_PRIVILEGE_ESCALATION, CATEGORY_AUTHENTICATION),
        )

    def test_incident_id_is_unique_for_distinct_incidents(self) -> None:
        store = IncidentStore()

        first = store.get_or_create_incident(_event(_alert(alert_id="a1"), event_id="event-a1"))
        second = store.get_or_create_incident(
            _event(
                _alert(
                    alert_id="a2",
                    timestamp="2026-08-26T11:30:00.000+0000",
                    source_user="another-user",
                ),
                event_id="event-a2",
            )
        )

        self.assertNotEqual(first.incident_id, second.incident_id)
        self.assertRegex(first.incident_id, r"^INC-2026-\d{4}$")
        self.assertRegex(second.incident_id, r"^INC-2026-\d{4}$")

    def test_initial_status_is_open(self) -> None:
        incident = create_incident(_event(_alert()))

        self.assertEqual(incident.status, INCIDENT_STATUS_OPEN)

    def test_risk_score_is_reused(self) -> None:
        event = _event(_alert())
        risk_assessment = assess_event_risk(event)

        incident = create_incident(event, risk_assessment=risk_assessment)

        self.assertEqual(incident.risk_score, risk_assessment.score)

    def test_severity_is_reused(self) -> None:
        event = _event(_alert())
        risk_assessment = assess_event_risk(event)

        incident = create_incident(event, risk_assessment=risk_assessment)

        self.assertEqual(incident.severity, risk_assessment.level)

    def test_category_and_subcategory_are_preserved(self) -> None:
        event = _event(_alert())
        classification = classify_alert(event.representative_alert)

        incident = create_incident(event, classification=classification)

        self.assertEqual(incident.category, classification.category)
        self.assertEqual(incident.subcategory, classification.subcategory)

    def test_agent_is_preserved(self) -> None:
        incident = create_incident(_event(_alert(agent_id="007", agent_name="server-007")))

        self.assertEqual(incident.agent_id, "007")
        self.assertEqual(incident.agent_name, "server-007")

    def test_source_user_is_preserved(self) -> None:
        incident = create_incident(_event(_alert(source_user="alice")))

        self.assertEqual(incident.source_user, "alice")

    def test_event_ids_are_preserved(self) -> None:
        event = _event(_alert(), event_id="event-preserved")

        incident = create_incident(event)

        self.assertEqual(incident.event_ids, ("event-preserved",))

    def test_correlation_id_is_preserved_when_present(self) -> None:
        incident = create_incident(_correlation_group())

        self.assertEqual(incident.correlation_id, "corr-incident-test")

    def test_recommendations_are_preserved(self) -> None:
        event = _event(_alert())
        risk_assessment = assess_event_risk(event)
        recommendations = generate_recommendations(event, risk_assessment=risk_assessment)

        incident = create_incident(
            event,
            risk_assessment=risk_assessment,
            recommendations=recommendations,
        )

        self.assertEqual(len(incident.recommendations), len(recommendations))
        self.assertIsInstance(incident.recommendations[0], Recommendation)

    def test_first_seen_and_last_seen_are_preserved(self) -> None:
        event = _event(
            _alert(timestamp="2026-08-26T10:15:30.000+0000"),
            event_id="event-time",
        )

        incident = create_incident(event)

        self.assertEqual(incident.first_seen, "2026-08-26T10:15:30.000+0000")
        self.assertEqual(incident.last_seen, "2026-08-26T10:15:30.000+0000")


class IncidentStatusTestCase(unittest.TestCase):
    def test_status_can_move_from_open_to_investigating(self) -> None:
        incident = create_incident(_event(_alert()))

        updated = update_incident_status(
            incident,
            INCIDENT_STATUS_INVESTIGATING,
            updated_at="2026-08-26T10:20:00.000+0000",
        )

        self.assertEqual(updated.status, INCIDENT_STATUS_INVESTIGATING)
        self.assertEqual(updated.updated_at, "2026-08-26T10:20:00.000+0000")

    def test_status_can_move_from_investigating_to_resolved(self) -> None:
        incident = update_incident_status(
            create_incident(_event(_alert())),
            INCIDENT_STATUS_INVESTIGATING,
            updated_at="2026-08-26T10:20:00.000+0000",
        )

        updated = update_incident_status(
            incident,
            INCIDENT_STATUS_RESOLVED,
            updated_at="2026-08-26T10:25:00.000+0000",
        )

        self.assertEqual(updated.status, INCIDENT_STATUS_RESOLVED)

    def test_false_positive_status_is_supported(self) -> None:
        incident = create_incident(_event(_alert()))

        updated = update_incident_status(
            incident,
            INCIDENT_STATUS_FALSE_POSITIVE,
            updated_at="2026-08-26T10:22:00.000+0000",
        )

        self.assertEqual(updated.status, INCIDENT_STATUS_FALSE_POSITIVE)

    def test_invalid_status_is_rejected(self) -> None:
        incident = create_incident(_event(_alert()))

        with self.assertRaises(ValueError):
            update_incident_status(incident, "Closed")

    def test_invalid_status_transition_is_rejected(self) -> None:
        incident = update_incident_status(
            create_incident(_event(_alert())),
            INCIDENT_STATUS_RESOLVED,
            updated_at="2026-08-26T10:20:00.000+0000",
        )

        with self.assertRaises(ValueError):
            update_incident_status(incident, INCIDENT_STATUS_INVESTIGATING)


class IncidentRobustnessTestCase(unittest.TestCase):
    def test_missing_fields_do_not_crash(self) -> None:
        event = DeduplicatedEvent(
            event_id="missing-event",
            representative_alert=NormalizedAlert(rule_groups=None, extra_data=None),
            source_alert_ids=(),
            duplicate_count=1,
            first_seen=None,
            last_seen=None,
        )

        incident = create_incident(event)

        self.assertEqual(incident.status, INCIDENT_STATUS_OPEN)
        self.assertTrue(incident.title)

    def test_real_rule_100101_creates_critical_incident(self) -> None:
        raw_alert = json.loads(SAMPLE_ALERT_PATH.read_text(encoding="utf-8"))
        event = deduplicate_alerts([parse_alert(raw_alert)])[0]

        incident = create_incident(event)

        self.assertEqual(incident.severity, "Critical")
        self.assertEqual(incident.risk_score, 78)
        self.assertEqual(incident.category, CATEGORY_PRIVILEGE_ESCALATION)
        self.assertGreaterEqual(len(incident.recommendations), 3)

    def test_store_reuses_incident_for_same_logical_context(self) -> None:
        store = IncidentStore(reuse_window_seconds=300)
        first_event = _event(
            _alert(
                alert_id="ctx-1",
                timestamp="2026-08-26T10:15:30.000+0000",
            ),
            event_id="event-ctx-1",
        )
        second_event = _event(
            _alert(
                alert_id="ctx-2",
                timestamp="2026-08-26T10:16:00.000+0000",
            ),
            event_id="event-ctx-2",
        )

        first_incident = store.get_or_create_incident(first_event)
        second_incident = store.get_or_create_incident(second_event)

        self.assertEqual(first_incident.incident_id, second_incident.incident_id)
        self.assertEqual(
            second_incident.event_ids,
            ("event-ctx-1", "event-ctx-2"),
        )

    def test_store_does_not_merge_distant_contexts(self) -> None:
        store = IncidentStore(reuse_window_seconds=60)
        first_event = _event(
            _alert(
                alert_id="distant-1",
                timestamp="2026-08-26T10:15:30.000+0000",
            ),
            event_id="event-distant-1",
        )
        second_event = _event(
            _alert(
                alert_id="distant-2",
                timestamp="2026-08-26T11:30:00.000+0000",
            ),
            event_id="event-distant-2",
        )

        first_incident = store.get_or_create_incident(first_event)
        second_incident = store.get_or_create_incident(second_event)

        self.assertNotEqual(first_incident.incident_id, second_incident.incident_id)

    def test_incident_to_dict_contains_required_fields(self) -> None:
        incident = create_incident(_event(_alert()))

        self.assertEqual(
            set(incident.to_dict()),
            {
                "incident_id",
                "title",
                "description",
                "status",
                "severity",
                "risk_score",
                "category",
                "subcategory",
                "agent_id",
                "agent_name",
                "source_user",
                "destination_user",
                "first_seen",
                "last_seen",
                "event_ids",
                "correlation_id",
                "recommendations",
                "created_at",
                "updated_at",
                "categories",
                "source_alert_ids",
            },
        )

    def test_incident_title_is_human_readable(self) -> None:
        incident = create_incident(_event(_alert()))

        self.assertNotIn("100101", incident.title)
        self.assertTrue(re.search(r"sudo|privilege", incident.title, re.IGNORECASE))

    def test_risk_assessment_can_be_injected_without_recomputing_contract(self) -> None:
        event = _event(_alert())
        risk_assessment = RiskAssessment(
            score=20,
            level="Low",
            factors={},
            explanation="Forced low risk for incident test.",
        )

        incident = create_incident(event, risk_assessment=risk_assessment)

        self.assertEqual(incident.risk_score, 20)
        self.assertEqual(incident.severity, "Low")


if __name__ == "__main__":
    unittest.main()
