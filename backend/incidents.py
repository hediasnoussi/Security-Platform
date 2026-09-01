"""Incident management layer for analyzed security events."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import hashlib
import json
import re
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
    CATEGORY_PRIVILEGED_ACTIVITY,
    ClassificationResult,
    classify_alert,
)
from backend.correlation import CorrelationGroup, DeduplicatedEvent
from backend.models import NormalizedAlert
from backend.recommendations import Recommendation, generate_recommendations
from backend.risk_score import RiskAssessment, assess_risk


INCIDENT_STATUS_OPEN = "Open"
INCIDENT_STATUS_INVESTIGATING = "Investigating"
INCIDENT_STATUS_RESOLVED = "Resolved"
INCIDENT_STATUS_FALSE_POSITIVE = "False Positive"

INCIDENT_STATUSES = (
    INCIDENT_STATUS_OPEN,
    INCIDENT_STATUS_INVESTIGATING,
    INCIDENT_STATUS_RESOLVED,
    INCIDENT_STATUS_FALSE_POSITIVE,
)

ALLOWED_STATUS_TRANSITIONS = {
    INCIDENT_STATUS_OPEN: {
        INCIDENT_STATUS_INVESTIGATING,
        INCIDENT_STATUS_RESOLVED,
        INCIDENT_STATUS_FALSE_POSITIVE,
    },
    INCIDENT_STATUS_INVESTIGATING: {
        INCIDENT_STATUS_RESOLVED,
        INCIDENT_STATUS_FALSE_POSITIVE,
    },
    INCIDENT_STATUS_RESOLVED: set(),
    INCIDENT_STATUS_FALSE_POSITIVE: set(),
}

DEFAULT_INCIDENT_REUSE_WINDOW_SECONDS = 300


@dataclass(frozen=True)
class Incident:
    """Structured incident created from a logical event or a correlation group."""

    incident_id: str
    title: str
    description: str
    status: str
    severity: str
    risk_score: int
    category: str
    subcategory: str
    agent_id: str | None = None
    agent_name: str | None = None
    source_user: str | None = None
    destination_user: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    event_ids: tuple[str, ...] = field(default_factory=tuple)
    correlation_id: str | None = None
    recommendations: tuple[Recommendation, ...] = field(default_factory=tuple)
    created_at: str | None = None
    updated_at: str | None = None
    categories: tuple[str, ...] = field(default_factory=tuple)
    source_alert_ids: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable incident representation."""

        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "category": self.category,
            "subcategory": self.subcategory,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "source_user": self.source_user,
            "destination_user": self.destination_user,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_ids": list(self.event_ids),
            "correlation_id": self.correlation_id,
            "recommendations": [
                recommendation.to_dict()
                for recommendation in self.recommendations
            ],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "categories": list(self.categories),
            "source_alert_ids": list(self.source_alert_ids),
        }


class IncidentStore:
    """In-memory incident repository with simple incident reuse logic."""

    def __init__(
        self,
        reuse_window_seconds: int = DEFAULT_INCIDENT_REUSE_WINDOW_SECONDS,
    ) -> None:
        self._incidents: dict[str, Incident] = {}
        self._next_sequence = 1
        self._reuse_window_seconds = reuse_window_seconds

    def get_or_create_incident(
        self,
        target: DeduplicatedEvent | CorrelationGroup,
        *,
        classification: ClassificationResult | None = None,
        risk_assessment: RiskAssessment | None = None,
        recommendations: Sequence[Recommendation] | None = None,
        created_at: str | None = None,
    ) -> Incident:
        """Create a new incident or reuse a nearby matching incident."""

        classification = classification or classify_alert(_primary_alert(target))
        reusable_incident = self._find_reusable_incident(target, classification)
        if reusable_incident is not None:
            incident = _merge_incident(
                reusable_incident,
                target,
                classification=classification,
                risk_assessment=risk_assessment,
                recommendations=recommendations,
            )
            self._incidents[incident.incident_id] = incident
            return incident

        incident = create_incident(
            target,
            classification=classification,
            risk_assessment=risk_assessment,
            recommendations=recommendations,
            incident_id=self._next_incident_id(created_at or _target_created_at(target)),
            created_at=created_at,
        )
        self._incidents[incident.incident_id] = incident
        return incident

    def get(self, incident_id: str) -> Incident | None:
        """Return one incident by id if present."""

        return self._incidents.get(incident_id)

    def list_incidents(self) -> list[Incident]:
        """Return incidents in creation order."""

        return list(self._incidents.values())

    def retain_active_context(
        self,
        event_ids: set[str],
        alert_ids: set[str],
    ) -> None:
        """Discard in-memory incident context outside the active alert window."""

        retained_incidents: dict[str, Incident] = {}
        for incident_id, incident in self._incidents.items():
            retained_event_ids = tuple(
                event_id for event_id in incident.event_ids if event_id in event_ids
            )
            if not retained_event_ids:
                continue

            retained_incidents[incident_id] = replace(
                incident,
                event_ids=retained_event_ids,
                source_alert_ids=tuple(
                    alert_id
                    for alert_id in incident.source_alert_ids
                    if alert_id in alert_ids
                ),
            )

        self._incidents = retained_incidents

    def update_status(
        self,
        incident_id: str,
        new_status: str,
        *,
        updated_at: str | None = None,
    ) -> Incident:
        """Update the status of a stored incident."""

        incident = self._incidents[incident_id]
        updated_incident = update_incident_status(
            incident,
            new_status,
            updated_at=updated_at,
        )
        self._incidents[incident_id] = updated_incident
        return updated_incident

    def _find_reusable_incident(
        self,
        target: DeduplicatedEvent | CorrelationGroup,
        classification: ClassificationResult,
    ) -> Incident | None:
        target_event_ids = set(_event_ids(target))
        target_correlation_id = _correlation_id(target)
        target_key = _incident_reuse_key(target, classification)

        for incident in sorted(self._incidents.values(), key=lambda item: item.incident_id):
            if target_correlation_id and incident.correlation_id == target_correlation_id:
                return incident

            if target_event_ids and target_event_ids.intersection(incident.event_ids):
                return incident

            if (
                target_correlation_id
                and incident.correlation_id
                and target_correlation_id != incident.correlation_id
            ):
                continue

            if not _has_reuse_context(target_key):
                continue

            if _incident_reuse_key_from_incident(incident) != target_key:
                continue

            if _time_ranges_close(
                incident.first_seen,
                incident.last_seen,
                _first_seen(target),
                _last_seen(target),
                self._reuse_window_seconds,
            ):
                return incident

        return None

    def _next_incident_id(self, created_at: str | None) -> str:
        year = _incident_year(created_at)
        incident_id = f"INC-{year}-{self._next_sequence:04d}"
        self._next_sequence += 1
        return incident_id


def create_incident(
    target: DeduplicatedEvent | CorrelationGroup,
    *,
    classification: ClassificationResult | None = None,
    risk_assessment: RiskAssessment | None = None,
    recommendations: Sequence[Recommendation] | None = None,
    incident_id: str | None = None,
    created_at: str | None = None,
) -> Incident:
    """Create a deterministic incident from a logical event or correlation group."""

    primary_alert = _primary_alert(target)
    classification = classification or classify_alert(primary_alert)
    risk_assessment = risk_assessment or assess_risk(target)
    normalized_recommendations = _recommendations_for_target(
        target,
        classification,
        risk_assessment,
        recommendations,
    )
    categories = _categories_for_target(target, classification)
    created_at = created_at or _target_created_at(target)
    incident_id = incident_id or _stable_incident_id(
        target,
        classification,
        created_at,
    )

    return Incident(
        incident_id=incident_id,
        title=_incident_title(target, classification),
        description=_incident_description(target, classification),
        status=INCIDENT_STATUS_OPEN,
        severity=risk_assessment.level,
        risk_score=risk_assessment.score,
        category=classification.category,
        subcategory=classification.subcategory,
        agent_id=primary_alert.agent_id,
        agent_name=primary_alert.agent_name,
        source_user=primary_alert.source_user,
        destination_user=primary_alert.destination_user,
        first_seen=_first_seen(target),
        last_seen=_last_seen(target),
        event_ids=_event_ids(target),
        correlation_id=_correlation_id(target),
        recommendations=normalized_recommendations,
        created_at=created_at,
        updated_at=created_at,
        categories=categories,
        source_alert_ids=_source_alert_ids(target),
    )


def update_incident_status(
    incident: Incident,
    new_status: str,
    *,
    updated_at: str | None = None,
) -> Incident:
    """Return a copy of the incident with a controlled status transition."""

    _validate_incident_status(new_status)

    if new_status != incident.status:
        allowed_statuses = ALLOWED_STATUS_TRANSITIONS[incident.status]
        if new_status not in allowed_statuses:
            raise ValueError(
                f"Invalid incident status transition: {incident.status} -> {new_status}"
            )

    effective_updated_at = (
        updated_at or incident.updated_at or incident.created_at or _utc_now_iso()
    )
    return replace(
        incident,
        status=new_status,
        updated_at=effective_updated_at,
    )


def _merge_incident(
    incident: Incident,
    target: DeduplicatedEvent | CorrelationGroup,
    *,
    classification: ClassificationResult | None = None,
    risk_assessment: RiskAssessment | None = None,
    recommendations: Sequence[Recommendation] | None = None,
) -> Incident:
    classification = classification or classify_alert(_primary_alert(target))
    risk_assessment = risk_assessment or assess_risk(target)
    normalized_recommendations = _recommendations_for_target(
        target,
        classification,
        risk_assessment,
        recommendations,
    )

    updated_at = _last_seen(target) or incident.updated_at or incident.created_at
    merged_risk_score, merged_severity = _higher_risk(
        incident.risk_score,
        incident.severity,
        risk_assessment.score,
        risk_assessment.level,
    )

    return replace(
        incident,
        risk_score=merged_risk_score,
        severity=merged_severity,
        first_seen=_earliest_timestamp(incident.first_seen, _first_seen(target)),
        last_seen=_latest_timestamp(incident.last_seen, _last_seen(target)),
        event_ids=_unique_preserving_order(
            (*incident.event_ids, *_event_ids(target))
        ),
        correlation_id=incident.correlation_id or _correlation_id(target),
        recommendations=_merge_recommendations(
            incident.recommendations,
            normalized_recommendations,
        ),
        updated_at=updated_at,
        categories=_unique_preserving_order(
            (*incident.categories, *_categories_for_target(target, classification))
        ),
        source_alert_ids=_unique_preserving_order(
            (*incident.source_alert_ids, *_source_alert_ids(target))
        ),
    )


def _recommendations_for_target(
    target: DeduplicatedEvent | CorrelationGroup,
    classification: ClassificationResult,
    risk_assessment: RiskAssessment,
    recommendations: Sequence[Recommendation] | None,
) -> tuple[Recommendation, ...]:
    if recommendations is not None:
        return tuple(recommendations)

    return tuple(
        generate_recommendations(
            target,
            classification=classification,
            risk_assessment=risk_assessment,
        )
    )


def _incident_title(
    target: DeduplicatedEvent | CorrelationGroup,
    classification: ClassificationResult,
) -> str:
    if isinstance(target, CorrelationGroup):
        primary_category = classification.category.lower()
        if len(target.categories) > 1:
            return f"Correlated {primary_category} activity"
        return f"Correlated {primary_category} incident"

    if classification.category == CATEGORY_PRIVILEGE_ESCALATION:
        if classification.subcategory == "Sudo / Group Modification" or _contains_any(
            _alert_text(_primary_alert(target)),
            ("sudo", "usermod"),
        ):
            return "Unauthorized sudo privilege modification"
        return "Suspicious privilege escalation"

    if classification.category == CATEGORY_AUTHENTICATION:
        if classification.subcategory == "Failed Login":
            return "Suspicious failed authentication"
        if classification.subcategory == "Successful Login":
            return "Unusual successful authentication"
        return "Authentication activity requires investigation"

    if classification.category == CATEGORY_FILE_INTEGRITY:
        return "Unexpected monitored file change"

    if classification.category == CATEGORY_ACCOUNT_MANAGEMENT:
        if classification.subcategory == "User Creation":
            return "Suspicious user account creation"
        if classification.subcategory == "User Deletion":
            return "Suspicious user account deletion"
        return "Suspicious account or group modification"

    if classification.category == CATEGORY_NETWORK:
        return "Suspicious network activity"

    if classification.category == CATEGORY_MALWARE:
        return "Malware detection incident"

    if classification.category == CATEGORY_CONFIGURATION_COMPLIANCE:
        return "Failed configuration compliance control"

    return "Security incident requires triage"


def _incident_description(
    target: DeduplicatedEvent | CorrelationGroup,
    classification: ClassificationResult,
) -> str:
    primary_alert = _primary_alert(target)
    endpoint = primary_alert.agent_name or primary_alert.agent_id or "the endpoint"

    if isinstance(target, CorrelationGroup):
        categories = ", ".join(target.categories) if target.categories else classification.category
        return (
            f"Correlated security activity involving {categories} was detected on "
            f"{endpoint}."
        )

    if classification.category == CATEGORY_PRIVILEGE_ESCALATION:
        if classification.subcategory == "Sudo / Group Modification":
            return (
                f"A privilege escalation event was detected on {endpoint} involving "
                "modification of sudo group membership."
            )
        return f"A privilege escalation event was detected on {endpoint}."

    if classification.category == CATEGORY_AUTHENTICATION:
        return f"An authentication-related security event was detected on {endpoint}."

    if classification.category == CATEGORY_FILE_INTEGRITY:
        return f"A monitored file integrity change was detected on {endpoint}."

    if classification.category == CATEGORY_ACCOUNT_MANAGEMENT:
        return f"An account-management event was detected on {endpoint}."

    if classification.category == CATEGORY_NETWORK:
        return f"Suspicious network activity was detected on {endpoint}."

    if classification.category == CATEGORY_MALWARE:
        return f"A potential malware-related event was detected on {endpoint}."

    if classification.category == CATEGORY_CONFIGURATION_COMPLIANCE:
        return f"A configuration or compliance control failed on {endpoint}."

    if primary_alert.rule_description:
        return f"Security activity was detected on {endpoint}: {primary_alert.rule_description}."

    return f"A security event was detected on {endpoint}."


def _categories_for_target(
    target: DeduplicatedEvent | CorrelationGroup,
    classification: ClassificationResult,
) -> tuple[str, ...]:
    if isinstance(target, CorrelationGroup):
        categories = tuple(
            category
            for category in target.categories
            if category
        )
        return categories or (classification.category,)

    return (classification.category,)


def _primary_alert(target: DeduplicatedEvent | CorrelationGroup) -> NormalizedAlert:
    if isinstance(target, DeduplicatedEvent):
        return target.representative_alert
    if target.events:
        return max(
            target.events,
            key=lambda event: _category_priority(
                classify_alert(event.representative_alert).category
            ),
        ).representative_alert
    return NormalizedAlert()


def _category_priority(category: str) -> int:
    return {
        CATEGORY_MALWARE: 7,
        CATEGORY_PRIVILEGE_ESCALATION: 6,
        CATEGORY_ACCOUNT_MANAGEMENT: 5,
        CATEGORY_NETWORK: 4,
        CATEGORY_PRIVILEGED_ACTIVITY: 3,
        CATEGORY_AUTHENTICATION: 2,
        CATEGORY_FILE_INTEGRITY: 2,
        CATEGORY_CONFIGURATION_COMPLIANCE: 1,
        CATEGORY_OTHER: 0,
    }.get(category, 0)


def _event_ids(target: DeduplicatedEvent | CorrelationGroup) -> tuple[str, ...]:
    if isinstance(target, DeduplicatedEvent):
        return (target.event_id,)

    return tuple(event.event_id for event in target.events)


def _source_alert_ids(target: DeduplicatedEvent | CorrelationGroup) -> tuple[str, ...]:
    if isinstance(target, DeduplicatedEvent):
        return target.source_alert_ids

    return _unique_preserving_order(
        alert_id
        for event in target.events
        for alert_id in event.source_alert_ids
    )


def _correlation_id(target: DeduplicatedEvent | CorrelationGroup) -> str | None:
    if isinstance(target, CorrelationGroup):
        return target.id
    return None


def _first_seen(target: DeduplicatedEvent | CorrelationGroup) -> str | None:
    if isinstance(target, DeduplicatedEvent):
        return target.first_seen
    return target.first_seen


def _last_seen(target: DeduplicatedEvent | CorrelationGroup) -> str | None:
    if isinstance(target, DeduplicatedEvent):
        return target.last_seen
    return target.last_seen


def _validate_incident_status(status: str) -> None:
    if status not in INCIDENT_STATUSES:
        raise ValueError(f"Invalid incident status: {status}")


def _higher_risk(
    current_score: int,
    current_severity: str,
    incoming_score: int,
    incoming_severity: str,
) -> tuple[int, str]:
    if incoming_score > current_score:
        return incoming_score, incoming_severity
    return current_score, current_severity


def _incident_reuse_key(
    target: DeduplicatedEvent | CorrelationGroup,
    classification: ClassificationResult,
) -> tuple[str, ...]:
    primary_alert = _primary_alert(target)
    return (
        _normalized_value(primary_alert.agent_id or primary_alert.agent_name or primary_alert.agent_ip),
        _normalized_value(classification.category),
        _normalized_value(classification.subcategory),
        _normalized_value(primary_alert.source_user),
        _normalized_value(primary_alert.destination_user),
        _normalize_command(primary_alert.command),
    )


def _incident_reuse_key_from_incident(incident: Incident) -> tuple[str, ...]:
    return (
        _normalized_value(incident.agent_id or incident.agent_name),
        _normalized_value(incident.category),
        _normalized_value(incident.subcategory),
        _normalized_value(incident.source_user),
        _normalized_value(incident.destination_user),
        _normalize_command(_command_from_recommendations(incident.recommendations)),
    )


def _command_from_recommendations(
    recommendations: Sequence[Recommendation],
) -> str | None:
    for recommendation in recommendations:
        match = re.search(r"command=([^,.]+)", recommendation.description)
        if match:
            return match.group(1)
    return None


def _has_reuse_context(reuse_key: tuple[str, ...]) -> bool:
    agent, category, subcategory, source_user, destination_user, command = reuse_key
    return bool(agent and category and (source_user or destination_user or command or subcategory))


def _stable_incident_id(
    target: DeduplicatedEvent | CorrelationGroup,
    classification: ClassificationResult,
    created_at: str | None,
) -> str:
    payload = {
        "event_ids": list(_event_ids(target)),
        "correlation_id": _correlation_id(target),
        "category": classification.category,
        "subcategory": classification.subcategory,
        "agent_id": _primary_alert(target).agent_id,
        "agent_name": _primary_alert(target).agent_name,
        "source_user": _primary_alert(target).source_user,
        "destination_user": _primary_alert(target).destination_user,
        "first_seen": _first_seen(target),
        "last_seen": _last_seen(target),
    }
    serialized = json.dumps(payload, sort_keys=True, default=str)
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:8].upper()
    return f"INC-{_incident_year(created_at)}-{digest}"


def _incident_year(timestamp: str | None) -> int:
    parsed = _parse_timestamp(timestamp)
    if parsed is not None:
        return parsed.year
    return datetime.now(timezone.utc).year


def _target_created_at(target: DeduplicatedEvent | CorrelationGroup) -> str | None:
    return _last_seen(target) or _first_seen(target) or _utc_now_iso()


def _merge_recommendations(
    existing: Sequence[Recommendation],
    incoming: Sequence[Recommendation],
) -> tuple[Recommendation, ...]:
    unique: list[Recommendation] = []
    seen: set[tuple[str, str]] = set()

    for recommendation in (*existing, *incoming):
        key = (recommendation.title, recommendation.category)
        if key in seen:
            continue
        seen.add(key)
        unique.append(recommendation)

    return tuple(unique)


def _unique_preserving_order(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    unique: list[str] = []

    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)

    return tuple(unique)


def _normalize_command(command: str | None) -> str:
    if command is None:
        return ""

    normalized = command.strip().lower()
    return re.sub(r"\s+", " ", normalized)


def _normalized_value(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _alert_text(alert: NormalizedAlert) -> str:
    parts = [
        alert.rule_description,
        alert.location,
        alert.source_user,
        alert.destination_user,
        alert.command,
        alert.full_log,
    ]
    return " ".join(str(part) for part in parts if part is not None).lower()


def _contains_any(text: str, keywords: tuple[str, ...]) -> bool:
    return any(keyword.lower() in text for keyword in keywords)


def _earliest_timestamp(left: str | None, right: str | None) -> str | None:
    left_dt = _parse_timestamp(left)
    right_dt = _parse_timestamp(right)

    if left_dt is None:
        return right
    if right_dt is None:
        return left
    return left if left_dt <= right_dt else right


def _latest_timestamp(left: str | None, right: str | None) -> str | None:
    left_dt = _parse_timestamp(left)
    right_dt = _parse_timestamp(right)

    if left_dt is None:
        return right
    if right_dt is None:
        return left
    return left if left_dt >= right_dt else right


def _time_ranges_close(
    left_first_seen: str | None,
    left_last_seen: str | None,
    right_first_seen: str | None,
    right_last_seen: str | None,
    window_seconds: int,
) -> bool:
    left_start = _parse_timestamp(left_first_seen)
    left_end = _parse_timestamp(left_last_seen)
    right_start = _parse_timestamp(right_first_seen)
    right_end = _parse_timestamp(right_last_seen)

    if None in (left_start, left_end, right_start, right_end):
        return False

    if left_start <= right_end and right_start <= left_end:
        return True

    distance = min(
        abs((right_start - left_end).total_seconds()),
        abs((left_start - right_end).total_seconds()),
    )
    return distance <= window_seconds


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


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
