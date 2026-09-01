"""Security category classifier for normalized Wazuh alerts."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
import re

from backend.models import NormalizedAlert


CATEGORY_AUTHENTICATION = "Authentication"
CATEGORY_PRIVILEGE_ESCALATION = "Privilege Escalation"
CATEGORY_FILE_INTEGRITY = "File Integrity"
CATEGORY_ACCOUNT_MANAGEMENT = "Account Management"
CATEGORY_NETWORK = "Network"
CATEGORY_MALWARE = "Malware"
CATEGORY_CONFIGURATION_COMPLIANCE = "Configuration / Compliance"
CATEGORY_OTHER = "Other"


@dataclass(frozen=True)
class ClassificationResult:
    """Result produced by the alert classifier."""

    category: str
    subcategory: str
    confidence: float
    reason: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable classification result."""

        return {
            "category": self.category,
            "subcategory": self.subcategory,
            "confidence": self.confidence,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ClassificationRule:
    """A generic classification rule based on reusable Wazuh signals."""

    category: str
    group_keywords: tuple[str, ...] = ()
    mitre_keywords: tuple[str, ...] = ()
    text_keywords: tuple[str, ...] = ()
    group_confidence: float = 0.88
    mitre_confidence: float = 0.82
    text_confidence: float = 0.64


GROUP_RULES = (
    ClassificationRule(
        category=CATEGORY_PRIVILEGE_ESCALATION,
        group_keywords=("privilege_escalation", "sudo", "privilege"),
    ),
    ClassificationRule(
        category=CATEGORY_FILE_INTEGRITY,
        group_keywords=("file_integrity", "syscheck", "fim"),
    ),
    ClassificationRule(
        category=CATEGORY_MALWARE,
        group_keywords=("malware", "virus", "antivirus", "clamav", "yara", "rootkit"),
    ),
    ClassificationRule(
        category=CATEGORY_CONFIGURATION_COMPLIANCE,
        group_keywords=("sca", "cis", "compliance", "policy_monitoring"),
    ),
    ClassificationRule(
        category=CATEGORY_ACCOUNT_MANAGEMENT,
        group_keywords=("account_management", "user_management", "account_changed"),
    ),
    ClassificationRule(
        category=CATEGORY_AUTHENTICATION,
        group_keywords=("authentication", "auth", "pam", "sshd", "login"),
    ),
    ClassificationRule(
        category=CATEGORY_NETWORK,
        group_keywords=("network", "firewall", "iptables", "ids", "suricata"),
    ),
)

MITRE_RULES = (
    ClassificationRule(
        category=CATEGORY_PRIVILEGE_ESCALATION,
        mitre_keywords=("privilege escalation", "ta0004", "t1548", "t1068"),
    ),
    ClassificationRule(
        category=CATEGORY_ACCOUNT_MANAGEMENT,
        mitre_keywords=("create account", "account manipulation", "t1136", "t1098"),
    ),
    ClassificationRule(
        category=CATEGORY_AUTHENTICATION,
        mitre_keywords=("valid accounts", "brute force", "t1078", "t1110"),
    ),
    ClassificationRule(
        category=CATEGORY_NETWORK,
        mitre_keywords=(
            "command and control",
            "exfiltration",
            "lateral movement",
            "ta0011",
            "ta0010",
            "ta0008",
        ),
    ),
    ClassificationRule(
        category=CATEGORY_MALWARE,
        mitre_keywords=("malware", "trojan", "ransomware"),
    ),
)

TEXT_RULES = (
    ClassificationRule(
        category=CATEGORY_PRIVILEGE_ESCALATION,
        text_keywords=(
            "usermod -ag sudo",
            "usermod -ag wheel",
            "usermod -a -g sudo",
            "usermod -ag",
            "sudo group",
            "added to sudo",
            "privilege escalation",
        ),
    ),
    ClassificationRule(
        category=CATEGORY_ACCOUNT_MANAGEMENT,
        text_keywords=(
            "useradd",
            "adduser",
            "userdel",
            "deluser",
            "usermod",
            "groupadd",
            "groupdel",
            "passwd",
            "account created",
            "account deleted",
            "account modified",
            "user account",
        ),
    ),
    ClassificationRule(
        category=CATEGORY_FILE_INTEGRITY,
        text_keywords=(
            "syscheck",
            "file integrity",
            "integrity checksum",
            "file added",
            "file deleted",
            "file modified",
        ),
    ),
    ClassificationRule(
        category=CATEGORY_AUTHENTICATION,
        text_keywords=(
            "failed password",
            "authentication failed",
            "invalid user",
            "accepted password",
            "accepted publickey",
            "session opened",
            "login failed",
        ),
    ),
    ClassificationRule(
        category=CATEGORY_CONFIGURATION_COMPLIANCE,
        text_keywords=("sca", "cis", "benchmark", "compliance", "policy check"),
    ),
    ClassificationRule(
        category=CATEGORY_MALWARE,
        text_keywords=("malware", "virus", "trojan", "ransomware", "yara", "clamav"),
    ),
    ClassificationRule(
        category=CATEGORY_NETWORK,
        text_keywords=(
            "port scan",
            "iptables",
            "firewall",
            "network connection",
            "suricata",
        ),
    ),
)


def classify_alert(alert: NormalizedAlert) -> ClassificationResult:
    """Classify one normalized Wazuh alert into a security category."""

    groups = _normalized_groups(getattr(alert, "rule_groups", ()))
    text = _alert_text(alert)
    mitre_text = _mitre_text(alert)

    group_result = _classify_from_groups(alert, groups)
    if group_result:
        return group_result

    mitre_result = _classify_from_mitre(alert, mitre_text)
    if mitre_result:
        return mitre_result

    rule_id_result = _classify_from_rule_id(alert)
    if rule_id_result:
        return rule_id_result

    text_result = _classify_from_text(alert, text)
    if text_result:
        return text_result

    return ClassificationResult(
        category=CATEGORY_OTHER,
        subcategory="Unclassified",
        confidence=0.2,
        reason="No reliable Wazuh group, MITRE, rule id, or text signal matched.",
    )


def _classify_from_groups(
    alert: NormalizedAlert,
    groups: set[str],
) -> ClassificationResult | None:
    for rule in GROUP_RULES:
        matched = _matching_keywords(groups, rule.group_keywords)
        if matched:
            return ClassificationResult(
                category=rule.category,
                subcategory=_subcategory_for(rule.category, alert),
                confidence=rule.group_confidence,
                reason=f"Matched Wazuh group signal: {', '.join(matched)}.",
            )
    return None


def _classify_from_mitre(
    alert: NormalizedAlert,
    mitre_text: str,
) -> ClassificationResult | None:
    for rule in MITRE_RULES:
        matched = _matching_text_keywords(mitre_text, rule.mitre_keywords)
        if matched:
            return ClassificationResult(
                category=rule.category,
                subcategory=_subcategory_for(rule.category, alert),
                confidence=rule.mitre_confidence,
                reason=f"Matched MITRE ATT&CK signal: {', '.join(matched)}.",
            )
    return None


def _classify_from_rule_id(alert: NormalizedAlert) -> ClassificationResult | None:
    # Keep this as an extension point for specific Wazuh or local rules that
    # cannot be classified reliably from groups, MITRE data, or text.
    rule_id_overrides: dict[str, tuple[str, str, float, str]] = {}
    rule_id = _safe_lower(getattr(alert, "rule_id", None))

    if rule_id not in rule_id_overrides:
        return None

    category, subcategory, confidence, reason = rule_id_overrides[rule_id]
    return ClassificationResult(
        category=category,
        subcategory=subcategory,
        confidence=confidence,
        reason=reason,
    )


def _classify_from_text(
    alert: NormalizedAlert,
    text: str,
) -> ClassificationResult | None:
    for rule in TEXT_RULES:
        matched = _matching_text_keywords(text, rule.text_keywords)
        if matched:
            return ClassificationResult(
                category=rule.category,
                subcategory=_subcategory_for(rule.category, alert),
                confidence=rule.text_confidence,
                reason=f"Matched normalized alert text signal: {', '.join(matched)}.",
            )
    return None


def _subcategory_for(category: str, alert: NormalizedAlert) -> str:
    groups = _normalized_groups(getattr(alert, "rule_groups", ()))
    text = _alert_text(alert)

    if category == CATEGORY_PRIVILEGE_ESCALATION:
        if "sudo" in groups or _contains_any(text, ("sudo", "wheel")):
            return "Sudo / Group Modification"
        return "Privilege Escalation"

    if category == CATEGORY_AUTHENTICATION:
        if _contains_any(text, ("failed", "invalid", "failure", "authentication failed")):
            return "Failed Login"
        if _contains_any(text, ("accepted", "success", "session opened")):
            return "Successful Login"
        if "sshd" in groups or "sshd" in text:
            return "SSH Authentication"
        return "Authentication Event"

    if category == CATEGORY_FILE_INTEGRITY:
        if _contains_any(text, ("deleted", "removed")):
            return "File Deleted"
        if _contains_any(text, ("added", "created")):
            return "File Added"
        return "Syscheck / File Change"

    if category == CATEGORY_ACCOUNT_MANAGEMENT:
        if _contains_any(text, ("useradd", "adduser", "account created")):
            return "User Creation"
        if _contains_any(text, ("userdel", "deluser", "account deleted")):
            return "User Deletion"
        return "User / Group Modification"

    if category == CATEGORY_NETWORK:
        if _contains_any(text, ("port scan", "scan")):
            return "Port Scan"
        if _contains_any(text, ("firewall", "iptables")):
            return "Firewall"
        return "Network Activity"

    if category == CATEGORY_MALWARE:
        if _contains_any(text, ("yara", "clamav", "antivirus")):
            return "Antivirus / YARA"
        return "Malware Detection"

    if category == CATEGORY_CONFIGURATION_COMPLIANCE:
        if "sca" in groups or _contains_any(text, ("sca", "cis", "benchmark")):
            return "SCA / CIS Benchmark"
        return "Configuration / Compliance"

    return "Unclassified"


def _normalized_groups(raw_groups: Any) -> set[str]:
    if raw_groups is None:
        return set()
    if isinstance(raw_groups, str):
        raw_groups = (raw_groups,)
    if not isinstance(raw_groups, Iterable):
        return set()

    return {_normalize_token(group) for group in raw_groups if group is not None}


def _normalize_token(value: Any) -> str:
    lowered = str(value).strip().lower()
    return re.sub(r"[\s./-]+", "_", lowered)


def _safe_lower(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _alert_text(alert: NormalizedAlert) -> str:
    parts: list[str] = []
    for value in (
        getattr(alert, "rule_description", None),
        getattr(alert, "decoder", None),
        getattr(alert, "location", None),
        getattr(alert, "source_user", None),
        getattr(alert, "destination_user", None),
        getattr(alert, "command", None),
        getattr(alert, "full_log", None),
    ):
        if value is not None:
            parts.append(str(value))

    extra_data = getattr(alert, "extra_data", None)
    if extra_data:
        parts.extend(_flatten_values(extra_data))

    normalized_text = " ".join(parts).lower()
    return re.sub(r"\s+", " ", normalized_text)


def _mitre_text(alert: NormalizedAlert) -> str:
    extra_data = getattr(alert, "extra_data", None)
    if not extra_data:
        return ""

    values = list(_find_values_for_key(extra_data, "mitre"))
    normalized_text = " ".join(values).lower()
    return re.sub(r"\s+", " ", normalized_text)


def _find_values_for_key(value: Any, wanted_key: str) -> Iterable[str]:
    if isinstance(value, Mapping):
        for key, nested_value in value.items():
            if str(key).lower() == wanted_key:
                yield from _flatten_values(nested_value)
            else:
                yield from _find_values_for_key(nested_value, wanted_key)
    elif isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
        for item in value:
            yield from _find_values_for_key(item, wanted_key)


def _flatten_values(value: Any) -> Iterable[str]:
    if isinstance(value, Mapping):
        for key, nested_value in value.items():
            yield str(key)
            yield from _flatten_values(nested_value)
    elif isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
        for item in value:
            yield from _flatten_values(item)
    elif value is not None:
        yield str(value)


def _matching_keywords(groups: set[str], keywords: tuple[str, ...]) -> list[str]:
    matched: list[str] = []
    for keyword in keywords:
        normalized_keyword = _normalize_token(keyword)
        if any(
            normalized_keyword == group or normalized_keyword in group
            for group in groups
        ):
            matched.append(keyword)
    return matched


def _matching_text_keywords(text: str, keywords: tuple[str, ...]) -> list[str]:
    return [keyword for keyword in keywords if keyword.lower() in text]


def _contains_any(text: str, keywords: tuple[str, ...]) -> bool:
    return any(keyword.lower() in text for keyword in keywords)
