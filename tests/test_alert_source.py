from contextlib import contextmanager
import json
import unittest
from pathlib import Path
import uuid

from backend.alert_source import DemoAlertSource, WazuhAlertSource
from backend.classifier import CATEGORY_PRIVILEGE_ESCALATION, classify_alert
from backend.parser import parse_alert


WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_ALERT_PATH = Path(__file__).resolve().parents[1] / "data" / "sample_alert_100101.json"


def _compact_json_line(path: Path) -> str:
    return json.dumps(json.loads(path.read_text(encoding="utf-8")))


@contextmanager
def _workspace_alerts_file() -> Path:
    alerts_path = WORKSPACE_ROOT / f"tmp_alerts_{uuid.uuid4().hex}.json"
    try:
        yield alerts_path
    finally:
        alerts_path.unlink(missing_ok=True)


class DemoAlertSourceTestCase(unittest.TestCase):
    def test_demo_alert_source_returns_reference_alert(self) -> None:
        source = DemoAlertSource()

        batch = source.get_alerts()
        alert = parse_alert(batch.alerts[0])

        self.assertEqual(len(batch.alerts), 1)
        self.assertEqual(alert.rule_id, "100101")

    def test_demo_alert_source_can_get_alert_by_id(self) -> None:
        source = DemoAlertSource()
        alert_id = parse_alert(source.get_alerts().alerts[0]).alert_id

        raw_alert = source.get_alert(alert_id or "")

        self.assertIsNotNone(raw_alert)
        self.assertEqual(parse_alert(raw_alert).alert_id, alert_id)


class WazuhAlertSourceTestCase(unittest.TestCase):
    def test_wazuh_alert_source_reads_one_json_alert(self) -> None:
        with _workspace_alerts_file() as alerts_path:
            alerts_path.write_text(_compact_json_line(SAMPLE_ALERT_PATH) + "\n", encoding="utf-8")

            source = WazuhAlertSource(alerts_path)
            batch = source.get_alerts()

            self.assertEqual(len(batch.alerts), 1)
            self.assertEqual(parse_alert(batch.alerts[0]).rule_id, "100101")

    def test_wazuh_alert_source_reads_multiple_lines(self) -> None:
        with _workspace_alerts_file() as alerts_path:
            raw_alert = json.loads(SAMPLE_ALERT_PATH.read_text(encoding="utf-8"))
            second_alert = dict(raw_alert)
            second_alert["id"] = "1756203331.100101"
            alerts_path.write_text(
                json.dumps(raw_alert) + "\n" + json.dumps(second_alert) + "\n",
                encoding="utf-8",
            )

            batch = WazuhAlertSource(alerts_path).get_alerts()

            self.assertEqual(len(batch.alerts), 2)

    def test_wazuh_alert_source_ignores_invalid_json_line(self) -> None:
        with _workspace_alerts_file() as alerts_path:
            alerts_path.write_text(
                json.dumps({"id": "valid-1", "rule": {"id": "100101"}}) + "\n"
                + "{invalid json}\n"
                + json.dumps({"id": "valid-2", "rule": {"id": "100102"}}) + "\n",
                encoding="utf-8",
            )

            batch = WazuhAlertSource(alerts_path).get_alerts()

            self.assertEqual(len(batch.alerts), 2)
            self.assertEqual(parse_alert(batch.alerts[0]).alert_id, "valid-1")
            self.assertEqual(parse_alert(batch.alerts[1]).alert_id, "valid-2")

    def test_wazuh_alert_source_returns_empty_batch_for_empty_file(self) -> None:
        with _workspace_alerts_file() as alerts_path:
            alerts_path.write_text("", encoding="utf-8")

            batch = WazuhAlertSource(alerts_path).get_alerts()

            self.assertEqual(batch.alerts, ())
            self.assertEqual(batch.next_offset, 0)

    def test_wazuh_alert_source_raises_clean_error_for_missing_file(self) -> None:
        source = WazuhAlertSource(Path("missing-directory") / "alerts.json")

        with self.assertRaises(FileNotFoundError):
            source.get_alerts()

    def test_wazuh_alert_source_get_alert_returns_expected_alert(self) -> None:
        with _workspace_alerts_file() as alerts_path:
            raw_alert = json.loads(SAMPLE_ALERT_PATH.read_text(encoding="utf-8"))
            raw_alert["id"] = "find-me"
            alerts_path.write_text(json.dumps(raw_alert) + "\n", encoding="utf-8")

            raw_result = WazuhAlertSource(alerts_path).get_alert("find-me")

            self.assertIsNotNone(raw_result)
            self.assertEqual(parse_alert(raw_result).alert_id, "find-me")

    def test_wazuh_alert_source_get_alert_returns_none_for_unknown_id(self) -> None:
        with _workspace_alerts_file() as alerts_path:
            alerts_path.write_text(_compact_json_line(SAMPLE_ALERT_PATH) + "\n", encoding="utf-8")

            raw_result = WazuhAlertSource(alerts_path).get_alert("does-not-exist")

            self.assertIsNone(raw_result)

    def test_parser_can_receive_data_from_wazuh_alert_source(self) -> None:
        with _workspace_alerts_file() as alerts_path:
            alerts_path.write_text(_compact_json_line(SAMPLE_ALERT_PATH) + "\n", encoding="utf-8")

            batch = WazuhAlertSource(alerts_path).get_alerts()
            alert = parse_alert(batch.alerts[0])

            self.assertEqual(alert.agent_name, "compute2-endpoint")
            self.assertEqual(alert.source_user, "hedia")

    def test_wazuh_alert_source_does_not_depend_on_windows_hardcoded_path(self) -> None:
        source = WazuhAlertSource("/var/ossec/logs/alerts/alerts.json")

        self.assertEqual(source.path.as_posix(), "/var/ossec/logs/alerts/alerts.json")

    def test_wazuh_alert_source_supports_offset_based_incremental_reading(self) -> None:
        with _workspace_alerts_file() as alerts_path:
            first_alert = json.loads(SAMPLE_ALERT_PATH.read_text(encoding="utf-8"))
            first_alert["id"] = "offset-1"
            second_alert = dict(first_alert)
            second_alert["id"] = "offset-2"
            alerts_path.write_text(
                json.dumps(first_alert) + "\n" + json.dumps(second_alert) + "\n",
                encoding="utf-8",
            )

            source = WazuhAlertSource(alerts_path)
            first_batch = source.get_alerts(limit=1)
            second_batch = source.get_alerts(offset=first_batch.next_offset)

            self.assertEqual(len(first_batch.alerts), 1)
            self.assertEqual(len(second_batch.alerts), 1)
            self.assertEqual(parse_alert(first_batch.alerts[0]).alert_id, "offset-1")
            self.assertEqual(parse_alert(second_batch.alerts[0]).alert_id, "offset-2")

    def test_real_rule_100101_round_trip_from_wazuh_source_to_classifier(self) -> None:
        with _workspace_alerts_file() as alerts_path:
            alerts_path.write_text(_compact_json_line(SAMPLE_ALERT_PATH) + "\n", encoding="utf-8")

            batch = WazuhAlertSource(alerts_path).get_alerts()
            alert = parse_alert(batch.alerts[0])
            classification = classify_alert(alert)

            self.assertEqual(alert.rule_id, "100101")
            self.assertEqual(classification.category, CATEGORY_PRIVILEGE_ESCALATION)
            self.assertEqual(alert.agent_name, "compute2-endpoint")
            self.assertEqual(alert.source_user, "hedia")
            self.assertEqual(alert.destination_user, "root")
            self.assertIn("usermod -aG sudo wazuh-suspicious", alert.command or "")


if __name__ == "__main__":
    unittest.main()
