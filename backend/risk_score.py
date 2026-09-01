"""Transparent risk scoring for deduplicated and correlated security events."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from backend.classifier import (
    CATEGORY_ACCOUNT_MANAGEMENT,
    CATEGORY_AUTHENTICATION,
    CATEGORY_CONFIGURATION_COMPLIANCE,
    CATEGORY_FILE_INTEGRITY,
    CATEGORY_MALWARE,
    CATEGORY_NETWORK,
    CATEGORY_OTHER,
    CATEGORY_PRIVILEGE_ESCALATION,
    classify_alert,
)
from backend.correlation import CorrelationGroup, DeduplicatedEvent
from backend.models import NormalizedAlert


MIN_SCORE = 0
MAX_SCORE = 100
MAX_WAZUH_LEVEL = 15

RISK_LEVEL_THRESHOLDS = (
    ("Low", 0, 24),
    ("Medium", 25, 49),
    ("High", 50, 74),
    ("Critical", 75, 100),
)

SEVERITY_MAX_POINTS = 40.0
CATEGORY_POINTS = {
    CATEGORY_PRIVILEGE_ESCALATION: 28.0,
    CATEGORY_MALWARE: 30.0,
    CATEGORY_NETWORK: 22.0,
    CATEGORY_ACCOUNT_MANAGEMENT: 18.0,
    CATEGORY_FILE_INTEGRITY: 16.0,
    CATEGORY_AUTHENTICATION: 14.0,
    CATEGORY_CONFIGURATION_COMPLIANCE: 10.0,
    CATEGORY_OTHER: 4.0,
}
REPETITION_DUPLICATE_POINTS = 4.0
REPETITION_EVENT_POINTS = 6.0
REPETITION_MAX_POINTS = 18.0
CORRELATION_BASE_POINTS = 12.0
CORRELATION_EXTRA_EVENT_POINTS = 2.0
CORRELATION_CATEGORY_DIVERSITY_POINTS = 4.0
CORRELATION_MAX_POINTS = 20.0
SENSITIVE_ACTION_MAX_POINTS = 18.0


@dataclass(frozen=True)
class RiskAssessment:
    """Risk score result for an event or a correlation group."""

    score: int
    level: str
    factors: dict[str, Any]
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable risk assessment."""

        return {
            "score": self.score,
            "level": self.level,
            "factors": self.factors,
            "explanation": self.explanation,
        }


def assess_event_risk(event: DeduplicatedEvent) -> RiskAssessment:
    """Assess the risk of one deduplicated logical event."""

    return _assess_risk(events=(event,), is_correlated=False)


def assess_correlation_risk(group: CorrelationGroup) -> RiskAssessment:
    """Assess the risk of a correlated group of events."""

    return _assess_risk(events=group.events, is_correlated=True)


def assess_risk(target: DeduplicatedEvent | CorrelationGroup) -> RiskAssessment:
    """Assess risk for a deduplicated event or a correlation group."""

    if isinstance(target, CorrelationGroup):
        return assess_correlation_risk(target)
    if isinstance(target, DeduplicatedEvent):
        return assess_event_risk(target)

    raise TypeError("Risk scoring expects a DeduplicatedEvent or CorrelationGroup.")


def _assess_risk(
    events: tuple[DeduplicatedEvent, ...],
    is_correlated: bool,
) -> RiskAssessment:
    alerts = _alerts_from_events(events)
    categories = _event_categories(events)

    severity = _severity_factor(alerts)
    category = _category_factor(categories)
    repetition = _repetition_factor(events)
    correlation = _correlation_factor(events, categories, is_correlated)
    sensitive_action = _sensitive_action_factor(alerts)

    raw_score = (
        severity["points"]
        + category["points"]
        + repetition["points"]
        + correlation["points"]
        + sensitive_action["points"]
    )
    score = _clamp_score(round(raw_score))
    level = _risk_level(score)
    factors = {
        "severity": severity,
        "category": category,
        "repetition": repetition,
        "correlation": correlation,
        "sensitive_action": sensitive_action,
    }

    return RiskAssessment(
        score=score,
        level=level,
        factors=factors,
        explanation=_build_explanation(level, factors),
    )


def _severity_factor(alerts: tuple[NormalizedAlert, ...]) -> dict[str, Any]:
    levels = [
        int(alert.rule_level)
        for alert in alerts
        if isinstance(alert.rule_level, int)
    ]
    wazuh_level = max(levels) if levels else 0
    normalized = _normalize_wazuh_level(wazuh_level)
    points = round((normalized / 100.0) * SEVERITY_MAX_POINTS, 2)

    return {
        "wazuh_level": wazuh_level,
        "normalized": round(normalized, 2),
        "points": points,
        "max_points": SEVERITY_MAX_POINTS,
    }


def _category_factor(categories: tuple[str, ...]) -> dict[str, Any]:
    category_points = {
        category: CATEGORY_POINTS.get(category, CATEGORY_POINTS[CATEGORY_OTHER])
        for category in categories
    }
    selected_category = max(
        category_points,
        key=lambda category: category_points[category],
        default=CATEGORY_OTHER,
    )

    return {
        "categories": list(categories) if categories else [CATEGORY_OTHER],
        "selected_category": selected_category,
        "points": category_points.get(selected_category, CATEGORY_POINTS[CATEGORY_OTHER]),
        "weights": dict(CATEGORY_POINTS),
    }


def _repetition_factor(events: tuple[DeduplicatedEvent, ...]) -> dict[str, Any]:
    logical_event_count = len(events)
    duplicate_observation_count = sum(max(event.duplicate_count - 1, 0) for event in events)
    points = min(
        duplicate_observation_count * REPETITION_DUPLICATE_POINTS
        + max(logical_event_count - 1, 0) * REPETITION_EVENT_POINTS,
        REPETITION_MAX_POINTS,
    )

    return {
        "logical_event_count": logical_event_count,
        "duplicate_observation_count": duplicate_observation_count,
        "points": round(points, 2),
        "max_points": REPETITION_MAX_POINTS,
    }


def _correlation_factor(
    events: tuple[DeduplicatedEvent, ...],
    categories: tuple[str, ...],
    is_correlated: bool,
) -> dict[str, Any]:
    if not is_correlated or len(events) < 2:
        return {
            "correlated": False,
            "event_count": len(events),
            "category_count": len(set(categories)),
            "points": 0.0,
            "max_points": CORRELATION_MAX_POINTS,
        }

    category_count = len({category for category in categories if category != CATEGORY_OTHER})
    points = CORRELATION_BASE_POINTS
    points += max(len(events) - 2, 0) * CORRELATION_EXTRA_EVENT_POINTS
    points += max(category_count - 1, 0) * CORRELATION_CATEGORY_DIVERSITY_POINTS
    points = min(points, CORRELATION_MAX_POINTS)

    return {
        "correlated": True,
        "event_count": len(events),
        "category_count": category_count,
        "points": round(points, 2),
        "max_points": CORRELATION_MAX_POINTS,
    }


def _sensitive_action_factor(alerts: tuple[NormalizedAlert, ...]) -> dict[str, Any]:
    points = 0.0
    reasons: list[str] = []

    for alert in alerts:
        text = _alert_text(alert)
        groups = _normalized_groups(alert.rule_groups)

        if _is_sudo_privilege_change(text, groups):
            points += 14.0
            reasons.append("sudo privilege modification")

        if _is_privileged_command(alert, text):
            points += 6.0
            reasons.append("privileged command context")

        if _contains_any(
            text,
            ("useradd", "userdel", "usermod", "groupadd", "groupdel", "passwd"),
        ):
            points += 6.0
            reasons.append("account or group modification command")

        if _contains_any(text, ("/etc/passwd", "/etc/shadow", "/etc/sudoers")):
            points += 8.0
            reasons.append("sensitive system file")

    unique_reasons = _unique_preserving_order(reasons)

    return {
        "matched": unique_reasons,
        "points": round(min(points, SENSITIVE_ACTION_MAX_POINTS), 2),
        "max_points": SENSITIVE_ACTION_MAX_POINTS,
    }


def _alerts_from_events(events: tuple[DeduplicatedEvent, ...]) -> tuple[NormalizedAlert, ...]:
    alerts: list[NormalizedAlert] = []
    for event in events:
        if event.alerts:
            alerts.extend(event.alerts)
        else:
            alerts.append(event.representative_alert)
    return tuple(alerts)


def _event_categories(events: tuple[DeduplicatedEvent, ...]) -> tuple[str, ...]:
    categories = [
        classify_alert(event.representative_alert).category
        for event in events
    ]
    return tuple(_unique_preserving_order(categories))


def _normalize_wazuh_level(level: int) -> float:
    clamped_level = min(max(level, 0), MAX_WAZUH_LEVEL)
    return (clamped_level / MAX_WAZUH_LEVEL) * 100.0


def _risk_level(score: int) -> str:
    for level, minimum, maximum in RISK_LEVEL_THRESHOLDS:
        if minimum <= score <= maximum:
            return level
    return "Critical" if score > MAX_SCORE else "Low"


def _clamp_score(score: int) -> int:
    return min(max(score, MIN_SCORE), MAX_SCORE)


def _build_explanation(level: str, factors: dict[str, Any]) -> str:
    selected_category = factors["category"]["selected_category"]
    wazuh_level = factors["severity"]["wazuh_level"]
    explanation_parts = [
        f"{level} risk because the event is classified as {selected_category}",
        f"with Wazuh severity level {wazuh_level}",
    ]

    sensitive_matches = factors["sensitive_action"]["matched"]
    if sensitive_matches:
        explanation_parts.append(
            "and involves " + ", ".join(sensitive_matches)
        )

    if factors["repetition"]["points"] > 0:
        explanation_parts.append("with repeated or duplicated observations")

    if factors["correlation"]["correlated"]:
        explanation_parts.append("inside a correlated event group")

    return " ".join(explanation_parts) + "."


def _is_sudo_privilege_change(text: str, groups: set[str]) -> bool:
    has_sudo_signal = "sudo" in groups or "sudo" in text
    has_change_signal = _contains_any(
        text,
        ("usermod", "groupmod", "added to sudo", "sudo group", "-ag sudo", "-aG sudo"),
    )
    return has_sudo_signal and has_change_signal


def _is_privileged_command(alert: NormalizedAlert, text: str) -> bool:
    destination_user = (alert.destination_user or "").strip().lower()
    return destination_user == "root" or _contains_any(text, ("sudo:", " user=root "))


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
    text = " ".join(str(part) for part in parts if part is not None)
    extra_values = _flatten_extra_data(alert.extra_data)
    if extra_values:
        text = f"{text} {' '.join(extra_values)}"
    return text.lower()


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


def _normalized_groups(groups: Any) -> set[str]:
    if groups is None:
        return set()
    if isinstance(groups, str):
        groups = (groups,)
    if not isinstance(groups, Iterable):
        return set()
    return {str(group).strip().lower() for group in groups if group is not None}


def _contains_any(text: str, keywords: tuple[str, ...]) -> bool:
    return any(keyword.lower() in text for keyword in keywords)


def _unique_preserving_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []

    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)

    return unique
