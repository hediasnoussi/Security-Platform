"""Deduplication and correlation for normalized Wazuh alerts."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any

from backend.classifier import (
    CATEGORY_AUTHENTICATION,
    CATEGORY_OTHER,
    CATEGORY_PRIVILEGE_ESCALATION,
    classify_alert,
)
from backend.models import NormalizedAlert


DEFAULT_DEDUPLICATION_WINDOW_SECONDS = 10
DEFAULT_CORRELATION_WINDOW_SECONDS = 300


@dataclass(frozen=True)
class DeduplicatedEvent:
    """Logical event built from one or more original Wazuh alerts."""

    event_id: str
    representative_alert: NormalizedAlert
    source_alert_ids: tuple[str, ...]
    duplicate_count: int
    first_seen: str | None
    last_seen: str | None
    alerts: tuple[NormalizedAlert, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable event with original-alert traceability."""

        return {
            "event_id": self.event_id,
            "representative_alert": self.representative_alert.to_dict(),
            "source_alert_ids": list(self.source_alert_ids),
            "duplicate_count": self.duplicate_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "alerts": [alert.to_dict() for alert in self.alerts],
        }


@dataclass(frozen=True)
class CorrelationGroup:
    """Group of deduplicated events considered related."""

    id: str
    events: tuple[DeduplicatedEvent, ...]
    first_seen: str | None
    last_seen: str | None
    agent_id: str | None
    categories: tuple[str, ...]
    correlation_type: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable correlation group."""

        return {
            "id": self.id,
            "events": [event.to_dict() for event in self.events],
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "agent_id": self.agent_id,
            "categories": list(self.categories),
            "correlation_type": self.correlation_type,
            "reason": self.reason,
        }


@dataclass
class _EventBucket:
    fingerprint: tuple[str, ...]
    alerts: list[NormalizedAlert]


@dataclass(frozen=True)
class _CorrelationMatch:
    correlation_type: str
    reason: str


def deduplicate_alerts(
    alerts: Iterable[NormalizedAlert],
    time_window_seconds: int = DEFAULT_DEDUPLICATION_WINDOW_SECONDS,
) -> list[DeduplicatedEvent]:
    """Group alerts that probably represent the same logical event.

    The fingerprint intentionally ignores ``location`` so the same Wazuh event
    observed through ``/var/log/auth.log`` and ``journald`` can be merged.
    """

    buckets: list[_EventBucket] = []

    for alert in sorted(list(alerts), key=_alert_sort_key):
        fingerprint = _deduplication_fingerprint(alert)
        placed = False

        if _has_deduplication_context(alert):
            for bucket in buckets:
                if (
                    bucket.fingerprint == fingerprint
                    and _is_inside_alert_window(
                        alert,
                        bucket.alerts,
                        time_window_seconds,
                    )
                ):
                    bucket.alerts.append(alert)
                    placed = True
                    break

        if not placed:
            buckets.append(_EventBucket(fingerprint=fingerprint, alerts=[alert]))

    return [_build_deduplicated_event(bucket.alerts) for bucket in buckets]


def correlate_events(
    events: Iterable[DeduplicatedEvent],
    time_window_seconds: int = DEFAULT_CORRELATION_WINDOW_SECONDS,
) -> list[CorrelationGroup]:
    """Build groups of related deduplicated events.

    Correlation is intentionally separate from classification: it uses
    classification as one input signal, then answers which events are linked.
    """

    event_list = sorted(list(events), key=_event_sort_key)
    if len(event_list) < 2:
        return []

    event_categories = {
        event.event_id: classify_alert(event.representative_alert).category
        for event in event_list
    }
    adjacency: dict[str, set[str]] = {event.event_id: set() for event in event_list}
    match_reasons: dict[frozenset[str], _CorrelationMatch] = {}

    for index, left_event in enumerate(event_list):
        for right_event in event_list[index + 1 :]:
            match = _match_correlation_rules(
                left_event,
                right_event,
                event_categories[left_event.event_id],
                event_categories[right_event.event_id],
                time_window_seconds,
            )
            if match is None:
                continue

            adjacency[left_event.event_id].add(right_event.event_id)
            adjacency[right_event.event_id].add(left_event.event_id)
            match_reasons[frozenset((left_event.event_id, right_event.event_id))] = match

    return _build_correlation_groups(event_list, event_categories, adjacency, match_reasons)


def _build_deduplicated_event(alerts: list[NormalizedAlert]) -> DeduplicatedEvent:
    sorted_alerts = sorted(alerts, key=_alert_sort_key)
    representative_alert = sorted_alerts[0]
    source_alert_ids = tuple(
        alert_id
        for alert_id in (alert.alert_id for alert in sorted_alerts)
        if alert_id is not None
    )
    first_seen = _first_seen(sorted_alerts)
    last_seen = _last_seen(sorted_alerts)
    event_id = _stable_id(
        "event",
        {
            "fingerprint": _deduplication_fingerprint(representative_alert),
            "source_alert_ids": source_alert_ids,
            "first_seen": first_seen,
            "last_seen": last_seen,
        },
    )

    return DeduplicatedEvent(
        event_id=event_id,
        representative_alert=representative_alert,
        source_alert_ids=source_alert_ids,
        duplicate_count=len(sorted_alerts),
        first_seen=first_seen,
        last_seen=last_seen,
        alerts=tuple(sorted_alerts),
    )


def _build_correlation_groups(
    events: list[DeduplicatedEvent],
    event_categories: dict[str, str],
    adjacency: dict[str, set[str]],
    match_reasons: dict[frozenset[str], _CorrelationMatch],
) -> list[CorrelationGroup]:
    events_by_id = {event.event_id: event for event in events}
    visited: set[str] = set()
    groups: list[CorrelationGroup] = []

    for event in events:
        if event.event_id in visited or not adjacency[event.event_id]:
            continue

        component_ids = _connected_component(event.event_id, adjacency)
        visited.update(component_ids)
        component_events = sorted(
            (events_by_id[event_id] for event_id in component_ids),
            key=_event_sort_key,
        )
        component_reasons = _component_matches(component_ids, match_reasons)
        correlation_types = _unique_preserving_order(
            match.correlation_type for match in component_reasons
        )
        categories = _unique_preserving_order(
            event_categories[event.event_id] for event in component_events
        )
        first_seen = _first_event_seen(component_events)
        last_seen = _last_event_seen(component_events)
        agent_id = _shared_agent_id(component_events)

        groups.append(
            CorrelationGroup(
                id=_stable_id(
                    "corr",
                    {
                        "event_ids": [event.event_id for event in component_events],
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                    },
                ),
                events=tuple(component_events),
                first_seen=first_seen,
                last_seen=last_seen,
                agent_id=agent_id,
                categories=tuple(categories),
                correlation_type=" + ".join(correlation_types),
                reason=" ".join(match.reason for match in component_reasons),
            )
        )

    return groups


def _match_correlation_rules(
    left_event: DeduplicatedEvent,
    right_event: DeduplicatedEvent,
    left_category: str,
    right_category: str,
    time_window_seconds: int,
) -> _CorrelationMatch | None:
    if not _events_inside_window(left_event, right_event, time_window_seconds):
        return None

    for rule in (
        _same_agent_user_context_rule,
        _privilege_escalation_sudo_rule,
        _authentication_burst_rule,
    ):
        match = rule(left_event, right_event, left_category, right_category)
        if match is not None:
            return match

    return None


def _same_agent_user_context_rule(
    left_event: DeduplicatedEvent,
    right_event: DeduplicatedEvent,
    left_category: str,
    right_category: str,
) -> _CorrelationMatch | None:
    if CATEGORY_OTHER in (left_category, right_category):
        return None
    if _event_agent_id(left_event) != _event_agent_id(right_event):
        return None

    shared_users = _event_users(left_event) & _event_users(right_event)
    if not shared_users:
        return None

    return _CorrelationMatch(
        correlation_type="same_agent_user_context",
        reason=(
            "Events share the same agent and user context: "
            f"{', '.join(sorted(shared_users))}."
        ),
    )


def _privilege_escalation_sudo_rule(
    left_event: DeduplicatedEvent,
    right_event: DeduplicatedEvent,
    left_category: str,
    right_category: str,
) -> _CorrelationMatch | None:
    categories = {left_category, right_category}
    if CATEGORY_PRIVILEGE_ESCALATION not in categories:
        return None
    if _event_agent_id(left_event) != _event_agent_id(right_event):
        return None
    if not (_event_contains_text(left_event, "sudo") or _event_contains_text(right_event, "sudo")):
        return None

    return _CorrelationMatch(
        correlation_type="privilege_escalation_sudo_context",
        reason="Privilege escalation activity is close to sudo-related activity.",
    )


def _authentication_burst_rule(
    left_event: DeduplicatedEvent,
    right_event: DeduplicatedEvent,
    left_category: str,
    right_category: str,
) -> _CorrelationMatch | None:
    if left_category != CATEGORY_AUTHENTICATION or right_category != CATEGORY_AUTHENTICATION:
        return None
    if _event_agent_id(left_event) != _event_agent_id(right_event):
        return None

    shared_users = _event_users(left_event) & _event_users(right_event)
    shared_sources = _event_extra_values(left_event, "srcip") & _event_extra_values(
        right_event,
        "srcip",
    )
    if not shared_users and not shared_sources:
        return None

    return _CorrelationMatch(
        correlation_type="authentication_burst",
        reason="Authentication events share the same agent and source context.",
    )


def _connected_component(start_event_id: str, adjacency: dict[str, set[str]]) -> set[str]:
    stack = [start_event_id]
    component: set[str] = set()

    while stack:
        event_id = stack.pop()
        if event_id in component:
            continue
        component.add(event_id)
        stack.extend(adjacency[event_id] - component)

    return component


def _component_matches(
    component_ids: set[str],
    match_reasons: dict[frozenset[str], _CorrelationMatch],
) -> list[_CorrelationMatch]:
    matches = [
        match
        for event_pair, match in match_reasons.items()
        if event_pair.issubset(component_ids)
    ]
    return _unique_matches(matches)


def _unique_matches(matches: list[_CorrelationMatch]) -> list[_CorrelationMatch]:
    seen: set[tuple[str, str]] = set()
    unique: list[_CorrelationMatch] = []

    for match in matches:
        key = (match.correlation_type, match.reason)
        if key in seen:
            continue
        seen.add(key)
        unique.append(match)

    return unique


def _is_inside_alert_window(
    alert: NormalizedAlert,
    bucket_alerts: list[NormalizedAlert],
    time_window_seconds: int,
) -> bool:
    alert_time = _parse_timestamp(alert.timestamp)
    bucket_first = _first_alert_time(bucket_alerts)

    if alert_time is None or bucket_first is None:
        return False

    return abs((alert_time - bucket_first).total_seconds()) <= time_window_seconds


def _events_inside_window(
    left_event: DeduplicatedEvent,
    right_event: DeduplicatedEvent,
    time_window_seconds: int,
) -> bool:
    left_start, left_end = _event_time_range(left_event)
    right_start, right_end = _event_time_range(right_event)

    if None in (left_start, left_end, right_start, right_end):
        return False

    if left_start <= right_end and right_start <= left_end:
        return True

    distance = min(
        abs((right_start - left_end).total_seconds()),
        abs((left_start - right_end).total_seconds()),
    )
    return distance <= time_window_seconds


def _deduplication_fingerprint(alert: NormalizedAlert) -> tuple[str, ...]:
    return (
        _normalized_value(_event_alert_agent_id(alert)),
        _normalized_value(alert.rule_id),
        _normalized_value(alert.source_user),
        _normalized_value(alert.destination_user),
        _normalize_command(alert.command),
    )


def _has_deduplication_context(alert: NormalizedAlert) -> bool:
    has_identity = bool(_event_alert_agent_id(alert)) and bool(alert.rule_id)
    has_context = any((alert.source_user, alert.destination_user, alert.command))
    return has_identity and has_context


def _normalize_command(command: str | None) -> str:
    if command is None:
        return ""

    normalized = command.strip().lower()
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized


def _normalized_value(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _alert_sort_key(alert: NormalizedAlert) -> tuple[int, datetime, str]:
    alert_time = _parse_timestamp(alert.timestamp)
    if alert_time is None:
        return (1, datetime.max, alert.alert_id or "")
    return (0, alert_time, alert.alert_id or "")


def _event_sort_key(event: DeduplicatedEvent) -> tuple[int, datetime, str]:
    event_time = _parse_timestamp(event.first_seen)
    if event_time is None:
        return (1, datetime.max, event.event_id)
    return (0, event_time, event.event_id)


def _parse_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None

    timestamp = value.strip()
    if not timestamp:
        return None
    if timestamp.endswith("Z"):
        timestamp = f"{timestamp[:-1]}+00:00"

    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError:
        return None

    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)

    return parsed


def _first_alert_time(alerts: list[NormalizedAlert]) -> datetime | None:
    times = [
        alert_time
        for alert_time in (_parse_timestamp(alert.timestamp) for alert in alerts)
        if alert_time is not None
    ]
    return min(times) if times else None


def _first_seen(alerts: list[NormalizedAlert]) -> str | None:
    return _seen_value(alerts, use_min=True)


def _last_seen(alerts: list[NormalizedAlert]) -> str | None:
    return _seen_value(alerts, use_min=False)


def _seen_value(alerts: list[NormalizedAlert], use_min: bool) -> str | None:
    dated_alerts = [
        (alert_time, alert)
        for alert in alerts
        if (alert_time := _parse_timestamp(alert.timestamp)) is not None
    ]
    if not dated_alerts:
        return None

    selected = min(dated_alerts, key=lambda item: item[0])
    if not use_min:
        selected = max(dated_alerts, key=lambda item: item[0])
    return selected[1].timestamp


def _first_event_seen(events: list[DeduplicatedEvent]) -> str | None:
    return _event_seen_value(events, use_min=True)


def _last_event_seen(events: list[DeduplicatedEvent]) -> str | None:
    return _event_seen_value(events, use_min=False)


def _event_seen_value(events: list[DeduplicatedEvent], use_min: bool) -> str | None:
    dated_events = [
        (event_time, event)
        for event in events
        if (event_time := _parse_timestamp(event.first_seen if use_min else event.last_seen))
        is not None
    ]
    if not dated_events:
        return None

    selected = min(dated_events, key=lambda item: item[0])
    if not use_min:
        selected = max(dated_events, key=lambda item: item[0])
    return selected[1].first_seen if use_min else selected[1].last_seen


def _event_time_range(event: DeduplicatedEvent) -> tuple[datetime | None, datetime | None]:
    return _parse_timestamp(event.first_seen), _parse_timestamp(event.last_seen)


def _event_alert_agent_id(alert: NormalizedAlert) -> str | None:
    return alert.agent_id or alert.agent_name or alert.agent_ip


def _event_agent_id(event: DeduplicatedEvent) -> str | None:
    return _event_alert_agent_id(event.representative_alert)


def _shared_agent_id(events: list[DeduplicatedEvent]) -> str | None:
    agent_ids = {_event_agent_id(event) for event in events}
    agent_ids.discard(None)
    if len(agent_ids) == 1:
        return next(iter(agent_ids))
    return None


def _event_users(event: DeduplicatedEvent) -> set[str]:
    users: set[str] = set()
    for alert in event.alerts or (event.representative_alert,):
        for value in (alert.source_user, alert.destination_user):
            if value:
                users.add(value.strip().lower())
    return users


def _event_contains_text(event: DeduplicatedEvent, keyword: str) -> bool:
    needle = keyword.lower()
    return any(needle in _alert_text(alert) for alert in event.alerts or (event.representative_alert,))


def _alert_text(alert: NormalizedAlert) -> str:
    parts = [
        alert.rule_description,
        alert.decoder,
        alert.location,
        alert.source_user,
        alert.destination_user,
        alert.command,
        alert.full_log,
    ]
    extra_values = _flatten_extra_data(alert.extra_data)
    text = " ".join(str(part) for part in parts if part is not None)
    if extra_values:
        text = f"{text} {' '.join(extra_values)}"
    return text.lower()


def _event_extra_values(event: DeduplicatedEvent, wanted_key: str) -> set[str]:
    values: set[str] = set()
    for alert in event.alerts or (event.representative_alert,):
        values.update(_find_extra_values(alert.extra_data, wanted_key))
    return values


def _find_extra_values(value: Any, wanted_key: str) -> set[str]:
    if isinstance(value, dict):
        values: set[str] = set()
        for key, nested_value in value.items():
            if str(key).lower() == wanted_key.lower():
                values.update(_flatten_extra_data(nested_value))
            else:
                values.update(_find_extra_values(nested_value, wanted_key))
        return values

    if isinstance(value, list | tuple | set):
        values: set[str] = set()
        for item in value:
            values.update(_find_extra_values(item, wanted_key))
        return values

    return set()


def _flatten_extra_data(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        flattened: list[str] = []
        for key, nested_value in value.items():
            flattened.append(str(key).lower())
            flattened.extend(_flatten_extra_data(nested_value))
        return flattened
    if isinstance(value, list | tuple | set):
        flattened = []
        for item in value:
            flattened.extend(_flatten_extra_data(item))
        return flattened
    return [str(value).lower()]


def _unique_preserving_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []

    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)

    return unique


def _stable_id(prefix: str, payload: dict[str, Any]) -> str:
    serialized = json.dumps(payload, sort_keys=True, default=str)
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{digest}"
