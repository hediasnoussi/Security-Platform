"""Alert source abstractions for demo and Wazuh alert ingestion."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, TypeAlias


RawAlert: TypeAlias = str | Mapping[str, Any]


@dataclass(frozen=True)
class AlertBatch:
    """A batch of raw alerts plus an opaque source-specific offset."""

    alerts: tuple[RawAlert, ...]
    next_offset: int = 0
    reset_required: bool = False


class AlertSource(ABC):
    """Abstract source of raw Wazuh alerts."""

    @abstractmethod
    def get_alerts(
        self,
        offset: int = 0,
        limit: int | None = None,
    ) -> AlertBatch:
        """Return raw alerts from a source-specific offset."""

    @abstractmethod
    def get_alert(self, alert_id: str) -> RawAlert | None:
        """Return one raw alert by Wazuh alert id if it exists."""


class DemoAlertSource(AlertSource):
    """Static in-memory source used by tests and the default API mode."""

    def __init__(self, alerts: list[RawAlert] | None = None) -> None:
        self._alerts = tuple(alerts or _load_demo_alerts())

    def get_alerts(
        self,
        offset: int = 0,
        limit: int | None = None,
    ) -> AlertBatch:
        start = max(offset, 0)
        end = len(self._alerts) if limit is None else start + max(limit, 0)
        selected_alerts = self._alerts[start:end]
        next_offset = min(end, len(self._alerts))
        return AlertBatch(alerts=selected_alerts, next_offset=next_offset)

    def get_alert(self, alert_id: str) -> RawAlert | None:
        for raw_alert in self._alerts:
            if _extract_alert_id(raw_alert) == alert_id:
                return raw_alert
        return None


class WazuhAlertSource(AlertSource):
    """Local file reader for Wazuh ``alerts.json`` on Linux or future VM runs."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._last_file_identity: tuple[int, int] | None = None

    def get_alerts(
        self,
        offset: int = 0,
        limit: int | None = None,
    ) -> AlertBatch:
        alerts_path = self._ensure_exists()
        file_stat = alerts_path.stat()
        file_identity = (file_stat.st_dev, file_stat.st_ino)
        requested_offset = max(offset, 0)
        reset_required = (
            requested_offset > file_stat.st_size
            or (
                self._last_file_identity is not None
                and file_identity != self._last_file_identity
            )
        )
        start_offset = 0 if reset_required else requested_offset
        raw_alerts: list[str] = []
        next_offset = start_offset
        maximum_alerts = None if limit is None else max(limit, 0)

        if maximum_alerts == 0:
            self._last_file_identity = file_identity
            return AlertBatch(
                alerts=(),
                next_offset=next_offset,
                reset_required=reset_required,
            )

        with alerts_path.open("rb") as alerts_file:
            alerts_file.seek(next_offset)

            while True:
                line_start_offset = alerts_file.tell()
                line = alerts_file.readline()
                if not line:
                    next_offset = alerts_file.tell()
                    break

                next_offset = alerts_file.tell()
                stripped_line = line.strip()
                if not stripped_line:
                    continue

                decoded_line = _decode_json_line(stripped_line)
                if decoded_line is None or _load_json_line(decoded_line) is None:
                    # A writer can leave the final JSON object incomplete while it
                    # is appending. Keep its start offset so the next refresh retries it.
                    if not line.endswith((b"\n", b"\r")):
                        next_offset = line_start_offset
                        break
                    continue

                raw_alerts.append(decoded_line)
                if maximum_alerts is not None and len(raw_alerts) >= maximum_alerts:
                    break

        self._last_file_identity = file_identity
        return AlertBatch(
            alerts=tuple(raw_alerts),
            next_offset=next_offset,
            reset_required=reset_required,
        )

    def get_alert(self, alert_id: str) -> RawAlert | None:
        alerts_path = self._ensure_exists()

        with alerts_path.open("rb") as alerts_file:
            for line in alerts_file:
                stripped_line = line.strip()
                if not stripped_line:
                    continue

                decoded_line = _decode_json_line(stripped_line)
                if decoded_line is None:
                    continue
                loaded_line = _load_json_line(decoded_line)
                if loaded_line is None:
                    continue

                if str(loaded_line.get("id")) == alert_id:
                    return decoded_line

        return None

    def _ensure_exists(self) -> Path:
        if not self.path.exists():
            raise FileNotFoundError(f"Alert source file not found: {self.path}")
        return self.path


def _load_demo_alerts() -> list[str]:
    sample_alert_path = Path(__file__).resolve().parents[1] / "data" / "sample_alert_100101.json"
    return [sample_alert_path.read_text(encoding="utf-8")]


def _extract_alert_id(raw_alert: RawAlert) -> str | None:
    if isinstance(raw_alert, Mapping):
        value = raw_alert.get("id")
        return None if value is None else str(value)

    loaded_alert = _load_json_line(raw_alert)
    if loaded_alert is None:
        return None
    value = loaded_alert.get("id")
    return None if value is None else str(value)


def _load_json_line(raw_line: str) -> dict[str, Any] | None:
    try:
        loaded = json.loads(raw_line)
    except json.JSONDecodeError:
        return None

    if not isinstance(loaded, dict):
        return None

    return loaded


def _decode_json_line(raw_line: bytes) -> str | None:
    try:
        return raw_line.decode("utf-8")
    except UnicodeDecodeError:
        return None
