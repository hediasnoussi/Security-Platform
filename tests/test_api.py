import unittest

from fastapi.testclient import TestClient

from backend.api import create_app


class ApiTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(create_app())

    def test_health_endpoint_returns_ok(self) -> None:
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_alerts_endpoint_returns_demo_alert(self) -> None:
        response = self.client.get("/alerts")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["rule_id"], "100101")
        self.assertEqual(payload[0]["category"], "Privilege Escalation")
        self.assertEqual(payload[0]["risk_score"], 78)
        self.assertEqual(payload[0]["risk_level"], "Critical")

    def test_alert_detail_endpoint_returns_alert(self) -> None:
        alert_id = self.client.get("/alerts").json()[0]["alert_id"]

        response = self.client.get(f"/alerts/{alert_id}")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["alert_id"], alert_id)
        self.assertEqual(payload["subcategory"], "Sudo / Group Modification")
        self.assertEqual(
            payload["command"],
            "/usr/sbin/usermod -aG sudo wazuh-suspicious",
        )
        self.assertGreaterEqual(len(payload["recommendations"]), 3)

    def test_alert_detail_endpoint_returns_404_for_missing_alert(self) -> None:
        response = self.client.get("/alerts/does-not-exist")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["error"], "not_found")

    def test_incidents_endpoint_returns_demo_incident(self) -> None:
        response = self.client.get("/incidents")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["title"], "Unauthorized sudo privilege modification")
        self.assertEqual(payload[0]["severity"], "Critical")
        self.assertEqual(payload[0]["risk_score"], 78)

    def test_incident_detail_endpoint_returns_incident(self) -> None:
        incident_id = self.client.get("/incidents").json()[0]["incident_id"]

        response = self.client.get(f"/incidents/{incident_id}")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["incident_id"], incident_id)
        self.assertEqual(payload["category"], "Privilege Escalation")
        self.assertEqual(payload["status"], "Open")
        self.assertIn("1756203330.100101", payload["source_alert_ids"])

    def test_incident_detail_endpoint_returns_404_for_missing_incident(self) -> None:
        response = self.client.get("/incidents/INC-2026-9999")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["error"], "not_found")

    def test_statistics_endpoint_returns_expected_counts(self) -> None:
        response = self.client.get("/statistics")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "total_incidents": 1,
                "critical": 1,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
        )


if __name__ == "__main__":
    unittest.main()
