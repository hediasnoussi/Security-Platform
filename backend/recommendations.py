"""Rule-based security recommendation engine."""

from __future__ import annotations

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
    ClassificationResult,
    classify_alert,
)
from backend.correlation import CorrelationGroup, DeduplicatedEvent
from backend.models import NormalizedAlert
from backend.risk_score import RiskAssessment, assess_event_risk, assess_risk


PRIORITIES = ("Low", "Medium", "High", "Critical")


@dataclass(frozen=True)
class Recommendation:
    """A deterministic action proposal for a security analyst."""

    title: str
    priority: str
    description: str
    rationale: str
    actions: tuple[str, ...]
    category: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable recommendation."""

        return {
            "title": self.title,
            "priority": self.priority,
            "description": self.description,
            "rationale": self.rationale,
            "actions": list(self.actions),
            "category": self.category,
        }


@dataclass(frozen=True)
class RecommendationRule:
    """Static recommendation rule for one security category."""

    category: str
    title: str
    description: str
    rationale: str
    actions: tuple[str, ...]


CATEGORY_RULES = {
    CATEGORY_AUTHENTICATION: (
        RecommendationRule(
            category=CATEGORY_AUTHENTICATION,
            title="Investigate authentication activity",
            description="Review whether the authentication activity is expected for the user and endpoint.",
            rationale="Authentication alerts can indicate brute-force attempts, stolen credentials, or unusual login behavior.",
            actions=(
                "Verify the source user, source IP, target endpoint, and login time.",
                "Review nearby authentication events for the same user and endpoint.",
                "Confirm whether the login attempt matches normal user activity.",
                "Strengthen authentication controls if suspicious activity is confirmed.",
            ),
        ),
    ),
    CATEGORY_PRIVILEGE_ESCALATION: (
        RecommendationRule(
            category=CATEGORY_PRIVILEGE_ESCALATION,
            title="Verify sudo privilege modification",
            description="Check whether the observed privilege change was authorized and expected.",
            rationale="Adding a user to a privileged group can grant administrative control over the endpoint.",
            actions=(
                "Confirm whether the sudo or privileged group change was approved.",
                "Identify the initiating user and validate the business justification.",
                "Review the exact command and the affected account or group.",
                "Remove unauthorized privileges if the change is confirmed as malicious or accidental.",
            ),
        ),
        RecommendationRule(
            category=CATEGORY_PRIVILEGE_ESCALATION,
            title="Review subsequent privileged activity",
            description="Look for privileged commands executed after the privilege escalation event.",
            rationale="A privilege change followed by administrative activity can indicate active compromise.",
            actions=(
                "Review related sudo, shell, and account-management events on the same endpoint.",
                "Check whether the affected account performed sensitive actions after the change.",
                "Preserve relevant logs before remediation decisions are made.",
            ),
        ),
        RecommendationRule(
            category=CATEGORY_PRIVILEGE_ESCALATION,
            title="Investigate the initiating user",
            description="Assess whether the source user account may have been misused.",
            rationale="Privilege escalation often starts from a compromised or misused user account.",
            actions=(
                "Verify recent login history for the initiating user.",
                "Check whether the user's activity matches expected administrative behavior.",
                "Consider credential rotation if the activity is not legitimate.",
            ),
        ),
    ),
    CATEGORY_FILE_INTEGRITY: (
        RecommendationRule(
            category=CATEGORY_FILE_INTEGRITY,
            title="Validate monitored file change",
            description="Review the modified file and decide whether the change is expected.",
            rationale="Unexpected changes to monitored files can indicate tampering, persistence, or configuration drift.",
            actions=(
                "Identify the file path, timestamp, and endpoint involved.",
                "Compare the change with the approved system baseline.",
                "Identify the responsible user or process where possible.",
                "Restore the legitimate version if the change is unauthorized.",
            ),
        ),
    ),
    CATEGORY_ACCOUNT_MANAGEMENT: (
        RecommendationRule(
            category=CATEGORY_ACCOUNT_MANAGEMENT,
            title="Validate account or group change",
            description="Check whether the user or group management action was legitimate.",
            rationale="Unexpected account changes can create persistence or broaden access.",
            actions=(
                "Review the created, deleted, or modified account.",
                "Verify group memberships and privilege assignments.",
                "Check activity performed by the account after the change.",
                "Disable or correct the account if the change is unauthorized.",
            ),
        ),
    ),
    CATEGORY_NETWORK: (
        RecommendationRule(
            category=CATEGORY_NETWORK,
            title="Investigate suspicious network activity",
            description="Review the network event and determine whether the traffic is expected.",
            rationale="Network alerts can indicate scanning, lateral movement, command-and-control, or policy violations.",
            actions=(
                "Identify the source, destination, ports, protocol, and endpoint involved.",
                "Review firewall, IDS, and endpoint logs around the same time window.",
                "Check whether the traffic pattern matches approved services.",
                "Contain or block the suspicious source if malicious activity is confirmed.",
            ),
        ),
    ),
    CATEGORY_MALWARE: (
        RecommendationRule(
            category=CATEGORY_MALWARE,
            title="Investigate malware detection",
            description="Validate the malware alert and assess the affected endpoint.",
            rationale="Malware detections may require rapid containment to prevent spread or persistence.",
            actions=(
                "Identify the detected file, process, signature, and affected endpoint.",
                "Check whether the detection was quarantined or only reported.",
                "Run an approved endpoint scan using existing security tooling.",
                "Isolate the endpoint if active compromise is suspected.",
            ),
        ),
    ),
    CATEGORY_CONFIGURATION_COMPLIANCE: (
        RecommendationRule(
            category=CATEGORY_CONFIGURATION_COMPLIANCE,
            title="Review failed compliance control",
            description="Inspect the failed SCA or compliance control and compare it with the expected baseline.",
            rationale="Compliance failures can expose insecure configuration or drift from hardening standards.",
            actions=(
                "Identify the failed policy, check, and affected endpoint.",
                "Compare the finding with the organization's accepted baseline.",
                "Validate whether an exception already exists.",
                "Apply an approved configuration correction if the finding is valid.",
            ),
        ),
    ),
    CATEGORY_OTHER: (
        RecommendationRule(
            category=CATEGORY_OTHER,
            title="Review unclassified security alert",
            description="Collect more context because the alert did not match a more specific category.",
            rationale="Unclassified alerts still need triage before they can be closed or escalated.",
            actions=(
                "Review the raw Wazuh alert and normalized fields.",
                "Check related alerts from the same endpoint and time window.",
                "Decide whether a new classification rule should be added.",
            ),
        ),
    ),
}


def generate_recommendations(
    target: NormalizedAlert | DeduplicatedEvent | CorrelationGroup,
    classification: ClassificationResult | None = None,
    risk_assessment: RiskAssessment | None = None,
) -> list[Recommendation]:
    """Generate deterministic recommendations from available analysis context."""

    event_or_group = _ensure_event_or_group(target)
    primary_alert = _primary_alert(target)
    classification = classification or classify_alert(primary_alert)
    risk_assessment = risk_assessment or _assess_target_risk(event_or_group)
    priority = _priority_from_risk(risk_assessment)
    categories = _categories_for_target(event_or_group, classification)

    recommendations: list[Recommendation] = []
    if isinstance(event_or_group, CorrelationGroup):
        recommendations.append(
            _correlation_recommendation(event_or_group, risk_assessment, priority)
        )

    for category in categories:
        rules = CATEGORY_RULES.get(category, CATEGORY_RULES[CATEGORY_OTHER])
        recommendations.extend(
            _build_recommendation(rule, priority, primary_alert, risk_assessment)
            for rule in rules
        )

    return _deduplicate_recommendations(recommendations)


def _build_recommendation(
    rule: RecommendationRule,
    priority: str,
    alert: NormalizedAlert,
    risk_assessment: RiskAssessment,
) -> Recommendation:
    context = _alert_context(alert)
    description = rule.description
    if context:
        description = f"{description} Context: {context}."

    rationale = (
        f"{rule.rationale} Current risk level is {risk_assessment.level} "
        f"with score {risk_assessment.score}."
    )

    return Recommendation(
        title=rule.title,
        priority=priority,
        description=description,
        rationale=rationale,
        actions=rule.actions,
        category=rule.category,
    )


def _correlation_recommendation(
    group: CorrelationGroup,
    risk_assessment: RiskAssessment,
    priority: str,
) -> Recommendation:
    categories = ", ".join(group.categories) if group.categories else CATEGORY_OTHER
    return Recommendation(
        title="Investigate correlated security activity",
        priority=priority,
        description=(
            "Multiple related security events were observed on the same endpoint "
            "and should be investigated together."
        ),
        rationale=(
            f"Correlation type: {group.correlation_type}. Categories involved: "
            f"{categories}. Current risk level is {risk_assessment.level} "
            f"with score {risk_assessment.score}."
        ),
        actions=(
            "Review the correlated events as one investigation timeline.",
            "Identify the shared endpoint, users, commands, and time window.",
            "Look for escalation from authentication activity to privileged actions.",
            "Preserve the linked alert identifiers for analyst traceability.",
        ),
        category="Correlation",
    )


def _ensure_event_or_group(
    target: NormalizedAlert | DeduplicatedEvent | CorrelationGroup,
) -> DeduplicatedEvent | CorrelationGroup:
    if isinstance(target, CorrelationGroup | DeduplicatedEvent):
        return target
    if isinstance(target, NormalizedAlert):
        return DeduplicatedEvent(
            event_id=target.alert_id or "single-alert",
            representative_alert=target,
            source_alert_ids=(target.alert_id,) if target.alert_id else (),
            duplicate_count=1,
            first_seen=target.timestamp,
            last_seen=target.timestamp,
            alerts=(target,),
        )

    raise TypeError(
        "Recommendations expect a NormalizedAlert, DeduplicatedEvent, or CorrelationGroup."
    )


def _primary_alert(
    target: NormalizedAlert | DeduplicatedEvent | CorrelationGroup,
) -> NormalizedAlert:
    if isinstance(target, NormalizedAlert):
        return target
    if isinstance(target, DeduplicatedEvent):
        return target.representative_alert
    if target.events:
        return target.events[0].representative_alert
    return NormalizedAlert()


def _assess_target_risk(
    target: DeduplicatedEvent | CorrelationGroup,
) -> RiskAssessment:
    if isinstance(target, CorrelationGroup):
        return assess_risk(target)
    return assess_event_risk(target)


def _priority_from_risk(risk_assessment: RiskAssessment) -> str:
    if risk_assessment.level in PRIORITIES:
        return risk_assessment.level
    if risk_assessment.score >= 75:
        return "Critical"
    if risk_assessment.score >= 50:
        return "High"
    if risk_assessment.score >= 25:
        return "Medium"
    return "Low"


def _categories_for_target(
    target: DeduplicatedEvent | CorrelationGroup,
    fallback_classification: ClassificationResult,
) -> tuple[str, ...]:
    if isinstance(target, CorrelationGroup):
        categories = tuple(
            category
            for category in target.categories
            if category and category != CATEGORY_OTHER
        )
        return categories or (fallback_classification.category,)

    return (fallback_classification.category,)


def _alert_context(alert: NormalizedAlert) -> str:
    parts: list[str] = []
    if alert.agent_name or alert.agent_id:
        parts.append(f"agent={alert.agent_name or alert.agent_id}")
    if alert.source_user:
        parts.append(f"source_user={alert.source_user}")
    if alert.destination_user:
        parts.append(f"destination_user={alert.destination_user}")
    if alert.command:
        parts.append(f"command={alert.command}")
    if alert.location:
        parts.append(f"location={alert.location}")
    return ", ".join(parts)


def _deduplicate_recommendations(
    recommendations: list[Recommendation],
) -> list[Recommendation]:
    seen_titles: set[tuple[str, str]] = set()
    unique: list[Recommendation] = []

    for recommendation in recommendations:
        key = (recommendation.title, recommendation.category)
        if key in seen_titles:
            continue
        seen_titles.add(key)
        unique.append(recommendation)

    return unique
