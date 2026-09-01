from contextlib import contextmanager
import json
from pathlib import Path
import unittest
import uuid

from fastapi.testclient import TestClient

from backend.alert_source import WazuhAlertSource
from backend.api import SecurityAnalysisService, create_app


WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_ALERT_PATH = WORKSPACE_ROOT / "data" / "sample_alert_100101.json"


@contextmanager
def _alerts_file() -> Path:
    path = WORKSPACE_ROOT / f"tmp_refresh_alerts_{uuid.uuid4().hex}.json"
    try:
        yield path
    finally:
        path.unlink(missing_ok=True)


def _alert(alert_id: str, **overrides: object) -> dict[str, object]:
    alert = json.loads(SAMPLE_ALERT_PATH.read_text(encoding="utf-8"))
    alert["id"] = alert_id
    alert.update(overrides)
    return alert


def _write_alerts(path: Path, *alerts: dict[str, object]) -> None:
    path.write_text(
        "".join(f"{json.dumps(alert)}\n" for alert in alerts),
        encoding="utf-8",
    )


class WazuhRefreshSourceTestCase(unittest.TestCase):
    def test_truncation_restarts_from_the_start_of_the_current_file(self) -> None:
        with _alerts_file() as alerts_path:
            first_alert = _alert("before-truncation", full_log="x" * 4096)
            replacement_alert = _alert("after-truncation")
            _write_alerts(alerts_path, first_alert)
            source = WazuhAlertSource(alerts_path)
            first_batch = source.get_alerts()

            _write_alerts(alerts_path, replacement_alert)
            refreshed_batch = source.get_alerts(offset=first_batch.next_offset)

            self.assertTrue(refreshed_batch.reset_required)
            self.assertEqual(len(refreshed_batch.alerts), 1)
            self.assertIn("after-truncation", refreshed_batch.alerts[0])

    def test_replacement_restarts_even_when_the_new_file_is_larger(self) -> None:
        with _alerts_file() as alerts_path:
            original_alert = _alert("before-replacement")
            replacement_alert = _alert("after-replacement", full_log="x" * 4096)
            _write_alerts(alerts_path, original_alert)
            source = WazuhAlertSource(alerts_path)
            first_batch = source.get_alerts()

            replacement_path = alerts_path.with_name(f"{alerts_path.name}.replacement")
            try:
                _write_alerts(replacement_path, replacement_alert)
                replacement_path.replace(alerts_path)

                refreshed_batch = source.get_alerts(offset=first_batch.next_offset)
            finally:
                replacement_path.unlink(missing_ok=True)

            self.assertTrue(refreshed_batch.reset_required)
            self.assertEqual(len(refreshed_batch.alerts), 1)
            self.assertIn("after-replacement", refreshed_batch.alerts[0])


class SecurityAnalysisRefreshTestCase(unittest.TestCase):
    def test_refresh_adds_only_new_alerts(self) -> None:
        with _alerts_file() as alerts_path:
            _write_alerts(alerts_path, _alert("incremental-1"))
            service = SecurityAnalysisService(
                WazuhAlertSource(alerts_path),
                max_alerts=10,
                refresh_batch_size=10,
            )

            with alerts_path.open("a", encoding="utf-8") as alerts_file:
                alerts_file.write(f"{json.dumps(_alert('incremental-2'))}\n")

            self.assertTrue(service.refresh())
            self.assertFalse(service.refresh())
            self.assertEqual(
                [analysis.alert.alert_id for analysis in service.list_alerts()],
                ["incremental-1", "incremental-2"],
            )

    def test_refresh_retries_a_partial_json_line_after_it_is_completed(self) -> None:
        with _alerts_file() as alerts_path:
            _write_alerts(alerts_path, _alert("partial-1"))
            service = SecurityAnalysisService(WazuhAlertSource(alerts_path))
            partial_line = json.dumps(_alert("partial-2"))

            with alerts_path.open("a", encoding="utf-8") as alerts_file:
                alerts_file.write(partial_line[:-1])

            self.assertFalse(service.refresh())
            self.assertEqual(len(service.list_alerts()), 1)

            with alerts_path.open("a", encoding="utf-8") as alerts_file:
                alerts_file.write("}\n")

            self.assertTrue(service.refresh())
            self.assertEqual(
                [analysis.alert.alert_id for analysis in service.list_alerts()],
                ["partial-1", "partial-2"],
            )

    def test_memory_window_keeps_only_the_most_recent_alerts(self) -> None:
        with _alerts_file() as alerts_path:
            _write_alerts(
                alerts_path,
                _alert("window-1"),
                _alert("window-2"),
                _alert("window-3"),
            )
            service = SecurityAnalysisService(
                WazuhAlertSource(alerts_path),
                max_alerts=2,
                refresh_batch_size=1,
            )

            self.assertEqual(
                [analysis.alert.alert_id for analysis in service.list_alerts()],
                ["window-2", "window-3"],
            )

    def test_alert_endpoint_refreshes_before_returning_results(self) -> None:
        with _alerts_file() as alerts_path:
            _write_alerts(alerts_path, _alert("api-refresh-1"))
            service = SecurityAnalysisService(WazuhAlertSource(alerts_path))
            client = TestClient(create_app(service))

            self.assertEqual(len(client.get("/alerts").json()), 1)
            with alerts_path.open("a", encoding="utf-8") as alerts_file:
                alerts_file.write(f"{json.dumps(_alert('api-refresh-2'))}\n")

            response = client.get("/alerts")

            self.assertEqual(response.status_code, 200)
            self.assertEqual(
                [alert["alert_id"] for alert in response.json()],
                ["api-refresh-1", "api-refresh-2"],
            )


if __name__ == "__main__":
    unittest.main()
