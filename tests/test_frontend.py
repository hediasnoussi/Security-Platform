import unittest

from fastapi.testclient import TestClient

from backend.api import create_app


class FrontendDeliveryTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(create_app())

    def test_dashboard_root_returns_html(self) -> None:
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Security Monitoring Platform", response.text)
        self.assertIn("Security Posture", response.text)
        self.assertIn("Priority Threat", response.text)
        self.assertIn("Correlated Attack Path", response.text)

    def test_frontend_static_assets_are_reachable(self) -> None:
        for asset in ("/static/styles.css", "/static/app.js"):
            response = self.client.get(asset)

            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.text)

    def test_existing_api_routes_remain_reachable(self) -> None:
        for route in ("/health", "/alerts", "/incidents", "/statistics", "/docs"):
            response = self.client.get(route)

            self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
