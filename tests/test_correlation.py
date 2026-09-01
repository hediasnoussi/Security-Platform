import json
import unittest
from pathlib import Path

from backend.classifier import (
    CATEGORY_AUTHENTICATION,
    CATEGORY_PRIVILEGE_ESCALATION,
)
from backend.correlation import (
    CorrelationGroup,
    DeduplicatedEvent,
    correlate_events,
    deduplicate_alerts,
)
from backend.models import NormalizedAlert
from backend.parser import parse_alert


SAMPLE_ALERT_PATH = Path(__file__).resolve().parents[1] / "data" / "sample_alert_100101.json"


def _rule_100101_alert(
    alert_id: str,
    timestamp: str,
    location: str = "/var/log/auth.log",
) -> NormalizedAlert:
    raw_alert = json.loads(SAMPLE_ALERT_PATH.read_text(encoding="utf-8"))
    raw_alert["id"] = alert_id
    raw_alert["timestamp"] = timestamp
    raw_alert["location"] = location
    return parse_alert(raw_alert)


def _authentication_alert(
    alert_id: str,
    timestamp: str,
    user: str = "hedia",
    agent_id: str = "001",
) -> NormalizedAlert:
    return parse_alert(
        {
            "timestamp": timestamp,
            "id": alert_id,
            "rule": {
                "id": "5710",
                "level": 5,
                "description": "sshd: authentication failed.",
                "groups": ["sshd", "authentication_failed"],
            },
            "agent": {"id": agent_id, "name": f"agent-{agent_id}"},
            "decoder": {"name": "sshd"},
            "location": "/var/log/auth.log",
            "data": {"srcuser": user, "srcip": "192.0.2.10"},
            "full_log": f"Failed password for invalid user {user}",
        }
    )


def _account_alert(
    alert_id: str,
    timestamp: str,
    user: str = "hedia",
    agent_id: str = "001",
) -> NormalizedAlert:
    return parse_alert(
        {
            "timestamp": timestamp,
            "id": alert_id,
            "rule": {
                "id": "5901",
                "level": 8,
                "description": "User account was created.",
                "groups": ["user_management"],
            },
            "agent": {"id": agent_id, "name": f"agent-{agent_id}"},
            "data": {
                "srcuser": user,
                "dstuser": "root",
                "command": "/usr/sbin/useradd analyst",
            },
            "full_log": "useradd analyst",
        }
    )


class DeduplicationTestCase(unittest.TestCase):
    def test_deduplicates_rule_100101_from_auth_log_and_journald(self) -> None:
        alerts = [
            _rule_100101_alert(
                "1756203330.100101",
                "2026-08-26T10:15:30.000+0000",
                "/var/log/auth.log",
            ),
            _rule_100101_alert(
                "1756203332.100101",
                "2026-08-26T10:15:32.000+0000",
                "journald",
            ),
        ]

        events = deduplicate_alerts(alerts, time_window_seconds=10)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].duplicate_count, 2)
        self.assertEqual(
            events[0].source_alert_ids,
            ("1756203330.100101", "1756203332.100101"),
        )

    def test_does_not_deduplicate_when_alerts_are_far_apart(self) -> None:
        alerts = [
            _rule_100101_alert("a1", "2026-08-26T10:15:30.000+0000"),
            _rule_100101_alert("a2", "2026-08-26T10:20:30.000+0000", "journald"),
        ]

        events = deduplicate_alerts(alerts, time_window_seconds=10)

        self.assertEqual(len(events), 2)

    def test_does_not_deduplicate_different_rule_ids_automatically(self) -> None:
        first_alert = _rule_100101_alert("a1", "2026-08-26T10:15:30.000+0000")
        raw_second = json.loads(SAMPLE_ALERT_PATH.read_text(encoding="utf-8"))
        raw_second["id"] = "a2"
        raw_second["timestamp"] = "2026-08-26T10:15:32.000+0000"
        raw_second["rule"]["id"] = "200001"
        second_alert = parse_alert(raw_second)

        events = deduplicate_alerts([first_alert, second_alert], time_window_seconds=10)

        self.assertEqual(len(events), 2)

    def test_does_not_deduplicate_alerts_from_different_agents(self) -> None:
        first_alert = _rule_100101_alert("a1", "2026-08-26T10:15:30.000+0000")
        raw_second = json.loads(SAMPLE_ALERT_PATH.read_text(encoding="utf-8"))
        raw_second["id"] = "a2"
        raw_second["timestamp"] = "2026-08-26T10:15:32.000+0000"
        raw_second["agent"]["id"] = "002"
        raw_second["agent"]["name"] = "other-endpoint"
        second_alert = parse_alert(raw_second)

        events = deduplicate_alerts([first_alert, second_alert], time_window_seconds=10)

        self.assertEqual(len(events), 2)

    def test_deduplicated_event_keeps_original_alert_traceability(self) -> None:
        alerts = [
            _rule_100101_alert("trace-1", "2026-08-26T10:15:30.000+0000"),
            _rule_100101_alert("trace-2", "2026-08-26T10:15:31.000+0000", "journald"),
        ]

        event = deduplicate_alerts(alerts, time_window_seconds=10)[0]
        event_dict = event.to_dict()

        self.assertEqual(event.source_alert_ids, ("trace-1", "trace-2"))
        self.assertEqual(len(event.alerts), 2)
        self.assertEqual(event_dict["source_alert_ids"], ["trace-1", "trace-2"])


class CorrelationTestCase(unittest.TestCase):
    def test_correlates_events_with_same_agent_and_user(self) -> None:
        events = deduplicate_alerts(
            [
                _rule_100101_alert("priv-1", "2026-08-26T10:15:30.000+0000"),
                _authentication_alert("auth-1", "2026-08-26T10:16:00.000+0000"),
            ],
            time_window_seconds=10,
        )

        groups = correlate_events(events, time_window_seconds=300)

        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0].events), 2)
        self.assertIn("same_agent_user_context", groups[0].correlation_type)

    def test_does_not_correlate_unrelated_events(self) -> None:
        events = deduplicate_alerts(
            [
                _rule_100101_alert("priv-1", "2026-08-26T10:15:30.000+0000"),
                _authentication_alert(
                    "auth-1",
                    "2026-08-26T10:16:00.000+0000",
                    user="another-user",
                    agent_id="002",
                ),
            ],
            time_window_seconds=10,
        )

        groups = correlate_events(events, time_window_seconds=300)

        self.assertEqual(groups, [])

    def test_does_not_correlate_events_outside_time_window(self) -> None:
        events = deduplicate_alerts(
            [
                _account_alert("acct-1", "2026-08-26T10:15:30.000+0000"),
                _authentication_alert("auth-1", "2026-08-26T10:25:30.000+0000"),
            ],
            time_window_seconds=10,
        )

        groups = correlate_events(events, time_window_seconds=60)

        self.assertEqual(groups, [])

    def test_correlation_group_preserves_multiple_categories(self) -> None:
        events = deduplicate_alerts(
            [
                _rule_100101_alert("priv-1", "2026-08-26T10:15:30.000+0000"),
                _authentication_alert("auth-1", "2026-08-26T10:16:00.000+0000"),
            ],
            time_window_seconds=10,
        )

        group = correlate_events(events, time_window_seconds=300)[0]

        self.assertIn(CATEGORY_PRIVILEGE_ESCALATION, group.categories)
        self.assertIn(CATEGORY_AUTHENTICATION, group.categories)

    def test_missing_fields_do_not_crash_deduplication_or_correlation(self) -> None:
        events = deduplicate_alerts(
            [
                NormalizedAlert(alert_id="missing-1"),
                NormalizedAlert(alert_id="missing-2", rule_groups=None, extra_data=None),
            ]
        )

        groups = correlate_events(events)

        self.assertEqual(len(events), 2)
        self.assertEqual(groups, [])

    def test_correlation_group_contains_required_fields(self) -> None:
        events = deduplicate_alerts(
            [
                _account_alert("acct-1", "2026-08-26T10:15:30.000+0000"),
                _authentication_alert("auth-1", "2026-08-26T10:16:00.000+0000"),
            ],
            time_window_seconds=10,
        )

        group = correlate_events(events, time_window_seconds=300)[0]

        self.assertIsInstance(group, CorrelationGroup)
        self.assertEqual(
            set(group.to_dict()),
            {
                "id",
                "events",
                "first_seen",
                "last_seen",
                "agent_id",
                "categories",
                "correlation_type",
                "reason",
            },
        )
        self.assertIsInstance(group.events[0], DeduplicatedEvent)


if __name__ == "__main__":
    unittest.main()
