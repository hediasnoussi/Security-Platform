"""Normalized data models used by the security analysis platform."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class NormalizedAlert:
    """Normalized representation of one Wazuh alert.

    The parser fills the fields that are present in the raw alert and keeps
    missing values as ``None`` or empty collections. Classification and risk
    scoring are intentionally handled outside this model.
    """

    timestamp: str | None = None
    alert_id: str | None = None
    rule_id: str | None = None
    rule_level: int | None = None
    rule_description: str | None = None
    rule_groups: tuple[str, ...] = field(default_factory=tuple)
    agent_id: str | None = None
    agent_name: str | None = None
    agent_ip: str | None = None
    decoder: str | None = None
    location: str | None = None
    source_user: str | None = None
    destination_user: str | None = None
    command: str | None = None
    full_log: str | None = None
    extra_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary for APIs, tests, and storage."""

        return {
            "timestamp": self.timestamp,
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_level": self.rule_level,
            "rule_description": self.rule_description,
            "rule_groups": list(self.rule_groups),
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "agent_ip": self.agent_ip,
            "decoder": self.decoder,
            "location": self.location,
            "source_user": self.source_user,
            "destination_user": self.destination_user,
            "command": self.command,
            "full_log": self.full_log,
            "extra_data": self.extra_data,
        }
