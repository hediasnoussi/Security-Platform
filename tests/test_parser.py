import json
import unittest
from pathlib import Path

from backend.parser import iter_alerts_jsonl, parse_alert


SAMPLE_ALERT_PATH = Path(__file__).resolve().parents[1] / "data" / "sample_alert_100101.json"


class WazuhParserTestCase(unittest.TestCase):
    def test_parse_rule_100101_reference_alert(self) -> None:
        raw_alert = json.loads(SAMPLE_ALERT_PATH.read_text(encoding="utf-8"))

        alert = parse_alert(raw_alert)

        self.assertEqual(alert.rule_id, "100101")
        self.assertEqual(alert.rule_level, 12)
        self.assertEqual(
            alert.rule_description,
            "Suspicious privilege escalation: user added to sudo group",
        )
        self.assertEqual(alert.agent_id, "001")
        self.assertEqual(alert.agent_name, "compute2-endpoint")
        self.assertEqual(alert.location, "/var/log/auth.log")
        self.assertEqual(alert.source_user, "hedia")
        self.assertEqual(alert.destination_user, "root")
        self.assertEqual(
            alert.command,
            "/usr/sbin/usermod -aG sudo wazuh-suspicious",
        )
        self.assertIn("privilege_escalation", alert.rule_groups)
        self.assertEqual(alert.extra_data["data"]["srcip"], "127.0.0.1")

    def test_parse_alert_from_json_string(self) -> None:
        raw_alert = SAMPLE_ALERT_PATH.read_text(encoding="utf-8")

        alert = parse_alert(raw_alert)

        self.assertEqual(alert.rule_id, "100101")
        self.assertEqual(alert.agent_name, "compute2-endpoint")

    def test_missing_fields_are_handled_cleanly(self) -> None:
        alert = parse_alert({"rule": {"id": "5710"}, "agent": {"id": "001"}})

        self.assertEqual(alert.rule_id, "5710")
        self.assertIsNone(alert.rule_level)
        self.assertIsNone(alert.rule_description)
        self.assertEqual(alert.rule_groups, ())
        self.assertEqual(alert.agent_id, "001")
        self.assertIsNone(alert.command)
        self.assertEqual(alert.extra_data, {})

    def test_parser_does_not_classify_rule_100101(self) -> None:
        raw_alert = json.loads(SAMPLE_ALERT_PATH.read_text(encoding="utf-8"))

        alert_dict = parse_alert(raw_alert).to_dict()

        self.assertNotIn("category", alert_dict)
        self.assertNotIn("classification", alert_dict)

    def test_iter_alerts_jsonl_reads_wazuh_alert_file_format(self) -> None:
        raw_alert = SAMPLE_ALERT_PATH.read_text(encoding="utf-8")
        test_file = SAMPLE_ALERT_PATH.parent / "sample_alerts.jsonl"
        test_file.write_text(raw_alert.replace("\n", "") + "\n", encoding="utf-8")

        try:
            alerts = list(iter_alerts_jsonl(test_file))
        finally:
            test_file.unlink(missing_ok=True)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "100101")


if __name__ == "__main__":
    unittest.main()
