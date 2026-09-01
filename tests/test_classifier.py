import json
import unittest
from pathlib import Path

from backend.classifier import (
    CATEGORY_ACCOUNT_MANAGEMENT,
    CATEGORY_AUTHENTICATION,
    CATEGORY_CONFIGURATION_COMPLIANCE,
    CATEGORY_FILE_INTEGRITY,
    CATEGORY_OTHER,
    CATEGORY_PRIVILEGE_ESCALATION,
    classify_alert,
)
from backend.models import NormalizedAlert
from backend.parser import parse_alert


SAMPLE_ALERT_PATH = Path(__file__).resolve().parents[1] / "data" / "sample_alert_100101.json"


class WazuhClassifierTestCase(unittest.TestCase):
    def test_classifies_rule_100101_as_privilege_escalation(self) -> None:
        raw_alert = json.loads(SAMPLE_ALERT_PATH.read_text(encoding="utf-8"))
        alert = parse_alert(raw_alert)

        result = classify_alert(alert)

        self.assertEqual(result.category, CATEGORY_PRIVILEGE_ESCALATION)
        self.assertEqual(result.subcategory, "Sudo / Group Modification")
        self.assertGreaterEqual(result.confidence, 0.0)
        self.assertLessEqual(result.confidence, 1.0)
        self.assertIn("Wazuh group", result.reason)

    def test_classification_uses_groups_not_only_rule_100101(self) -> None:
        raw_alert = json.loads(SAMPLE_ALERT_PATH.read_text(encoding="utf-8"))
        raw_alert["rule"]["id"] = "999999"
        alert = parse_alert(raw_alert)

        result = classify_alert(alert)

        self.assertEqual(result.category, CATEGORY_PRIVILEGE_ESCALATION)
        self.assertEqual(result.subcategory, "Sudo / Group Modification")

    def test_classifies_ssh_authentication_alert(self) -> None:
        alert = parse_alert(
            {
                "rule": {
                    "id": "5710",
                    "level": 5,
                    "description": "sshd: authentication failed.",
                    "groups": ["syslog", "sshd", "authentication_failed"],
                },
                "agent": {"id": "001", "name": "compute2-endpoint"},
                "decoder": {"name": "sshd"},
                "location": "/var/log/auth.log",
                "data": {"srcuser": "unknown", "srcip": "192.0.2.10"},
                "full_log": "sshd[123]: Failed password for invalid user unknown",
            }
        )

        result = classify_alert(alert)

        self.assertEqual(result.category, CATEGORY_AUTHENTICATION)
        self.assertEqual(result.subcategory, "Failed Login")

    def test_classifies_fim_syscheck_alert(self) -> None:
        alert = parse_alert(
            {
                "rule": {
                    "id": "550",
                    "level": 7,
                    "description": "Integrity checksum changed.",
                    "groups": ["syscheck", "file_integrity"],
                },
                "agent": {"id": "001", "name": "compute2-endpoint"},
                "location": "syscheck",
                "full_log": "File '/etc/passwd' modified.",
            }
        )

        result = classify_alert(alert)

        self.assertEqual(result.category, CATEGORY_FILE_INTEGRITY)
        self.assertEqual(result.subcategory, "Syscheck / File Change")

    def test_classifies_account_management_alert(self) -> None:
        alert = parse_alert(
            {
                "rule": {
                    "id": "5901",
                    "level": 8,
                    "description": "User account was created.",
                    "groups": ["user_management"],
                },
                "agent": {"id": "001", "name": "compute2-endpoint"},
                "data": {"command": "/usr/sbin/useradd analyst"},
                "full_log": "useradd analyst",
            }
        )

        result = classify_alert(alert)

        self.assertEqual(result.category, CATEGORY_ACCOUNT_MANAGEMENT)
        self.assertEqual(result.subcategory, "User Creation")

    def test_classifies_sca_alert(self) -> None:
        alert = parse_alert(
            {
                "rule": {
                    "id": "19007",
                    "level": 7,
                    "description": "CIS benchmark policy check failed.",
                    "groups": ["sca", "cis", "compliance"],
                },
                "agent": {"id": "001", "name": "compute2-endpoint"},
                "location": "sca",
            }
        )

        result = classify_alert(alert)

        self.assertEqual(result.category, CATEGORY_CONFIGURATION_COMPLIANCE)
        self.assertEqual(result.subcategory, "SCA / CIS Benchmark")

    def test_classifies_unknown_alert_as_other(self) -> None:
        alert = NormalizedAlert(
            rule_id="999999",
            rule_level=3,
            rule_description="Generic system notice.",
            rule_groups=("local",),
            agent_name="compute2-endpoint",
        )

        result = classify_alert(alert)

        self.assertEqual(result.category, CATEGORY_OTHER)
        self.assertEqual(result.subcategory, "Unclassified")

    def test_missing_fields_do_not_crash_classifier(self) -> None:
        alert = NormalizedAlert(rule_groups=None, extra_data=None)

        result = classify_alert(alert)

        self.assertEqual(result.category, CATEGORY_OTHER)
        self.assertGreaterEqual(result.confidence, 0.0)
        self.assertLessEqual(result.confidence, 1.0)

    def test_classification_result_contains_required_fields(self) -> None:
        result = classify_alert(NormalizedAlert())

        self.assertEqual(
            set(result.to_dict()),
            {"category", "subcategory", "confidence", "reason"},
        )

    def test_classifies_alert_from_mitre_when_groups_are_not_specific(self) -> None:
        alert = parse_alert(
            {
                "rule": {
                    "id": "200001",
                    "level": 9,
                    "description": "Suspicious sudo technique detected.",
                    "groups": ["local"],
                    "mitre": {
                        "id": ["T1548.003"],
                        "tactic": ["Privilege Escalation"],
                        "technique": ["Sudo and Sudo Caching"],
                    },
                },
                "agent": {"id": "001", "name": "compute2-endpoint"},
            }
        )

        result = classify_alert(alert)

        self.assertEqual(result.category, CATEGORY_PRIVILEGE_ESCALATION)
        self.assertIn("MITRE", result.reason)


if __name__ == "__main__":
    unittest.main()
