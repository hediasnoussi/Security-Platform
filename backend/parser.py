"""Parser for Wazuh JSON alerts."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

from backend.models import NormalizedAlert


CORE_TOP_LEVEL_FIELDS = {
    "timestamp",
    "id",
    "rule",
    "agent",
    "decoder",
    "location",
    "data",
    "full_log",
}

CORE_DATA_FIELDS = {
    "srcuser",
    "dstuser",
    "command",
}

CORE_RULE_FIELDS = {
    "id",
    "level",
    "description",
    "groups",
}

CORE_AGENT_FIELDS = {
    "id",
    "name",
    "ip",
}

CORE_DECODER_FIELDS = {
    "name",
}


def parse_alert(raw_alert: str | Mapping[str, Any]) -> NormalizedAlert:
    """Parse one Wazuh alert from a JSON string or dictionary.

    Missing optional fields are normalized to ``None`` or an empty tuple. The
    parser does not classify alerts; it only extracts stable Wazuh fields and
    preserves useful extra data for later analysis steps.
    """

    alert = _load_alert(raw_alert)

    rule = _mapping(alert.get("rule"))
    agent = _mapping(alert.get("agent"))
    decoder = _mapping(alert.get("decoder"))
    data = _mapping(alert.get("data"))

    return NormalizedAlert(
        timestamp=_optional_str(alert.get("timestamp")),
        alert_id=_optional_str(alert.get("id")),
        rule_id=_optional_str(rule.get("id")),
        rule_level=_optional_int(rule.get("level")),
        rule_description=_optional_str(rule.get("description")),
        rule_groups=_normalize_groups(rule.get("groups")),
        agent_id=_optional_str(agent.get("id")),
        agent_name=_optional_str(agent.get("name")),
        agent_ip=_optional_str(agent.get("ip")),
        decoder=_optional_str(decoder.get("name")),
        location=_optional_str(alert.get("location")),
        source_user=_optional_str(data.get("srcuser")),
        destination_user=_optional_str(data.get("dstuser")),
        command=_optional_str(data.get("command")),
        full_log=_optional_str(alert.get("full_log")),
        extra_data=_collect_extra_data(alert, rule, agent, decoder, data),
    )


def parse_alerts(raw_alerts: Iterable[str | Mapping[str, Any]]) -> list[NormalizedAlert]:
    """Parse an iterable of Wazuh alerts."""

    return [parse_alert(raw_alert) for raw_alert in raw_alerts]


def iter_alerts_jsonl(path: str | Path) -> Iterator[NormalizedAlert]:
    """Yield normalized alerts from a Wazuh JSONL alerts file.

    Wazuh ``alerts.json`` stores one JSON object per line, so this helper keeps
    file processing streaming-friendly for resource-limited environments.
    """

    alerts_path = Path(path)
    with alerts_path.open("r", encoding="utf-8") as alerts_file:
        for line_number, line in enumerate(alerts_file, start=1):
            stripped_line = line.strip()
            if not stripped_line:
                continue

            try:
                yield parse_alert(stripped_line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON alert at {alerts_path}:{line_number}"
                ) from exc


def _load_alert(raw_alert: str | Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(raw_alert, str):
        loaded = json.loads(raw_alert)
    else:
        loaded = raw_alert

    if not isinstance(loaded, Mapping):
        raise TypeError("A Wazuh alert must be a JSON object or a mapping.")

    return loaded


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_groups(value: Any) -> tuple[str, ...]:
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes)):
        return ()

    return tuple(str(group) for group in value if group is not None)


def _collect_extra_data(
    alert: Mapping[str, Any],
    rule: Mapping[str, Any],
    agent: Mapping[str, Any],
    decoder: Mapping[str, Any],
    data: Mapping[str, Any],
) -> dict[str, Any]:
    extra_data: dict[str, Any] = {}

    for key, value in alert.items():
        if key not in CORE_TOP_LEVEL_FIELDS:
            extra_data[key] = value

    rule_extra = {
        key: value for key, value in rule.items() if key not in CORE_RULE_FIELDS
    }
    if rule_extra:
        extra_data["rule"] = rule_extra

    agent_extra = {
        key: value for key, value in agent.items() if key not in CORE_AGENT_FIELDS
    }
    if agent_extra:
        extra_data["agent"] = agent_extra

    decoder_extra = {
        key: value for key, value in decoder.items() if key not in CORE_DECODER_FIELDS
    }
    if decoder_extra:
        extra_data["decoder"] = decoder_extra

    remaining_data = {
        key: value for key, value in data.items() if key not in CORE_DATA_FIELDS
    }
    if remaining_data:
        extra_data["data"] = remaining_data

    return extra_data
