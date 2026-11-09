from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class EventType(str, Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    PRIVILEGE_CHANGE = "privilege_change"
    ENDPOINT_ALERT = "endpoint_alert"
    NETWORK_CONNECTION = "network_connection"
    LARGE_DATA_TRANSFER = "large_data_transfer"


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: datetime

    source: str
    event_type: EventType

    username: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None

    message: str

    details: dict[str, Any] = Field(default_factory=dict)


class SecurityAlert(BaseModel):
    alert_id: str
    alert_type: str

    severity: Literal[
        "low",
        "medium",
        "high",
        "critical",
    ]

    username: str | None = None

    summary: str

    evidence_event_ids: list[str]

    details: dict[str, Any] = Field(default_factory=dict)


class TriageResult(BaseModel):
    severity: Literal[
        "low",
        "medium",
        "high",
        "critical",
    ]

    summary: str

    possible_tactic: Literal[
        "Credential Access",
        "Privilege Escalation",
        "Exfiltration",
        "Unknown",
    ]

    evidence_ids: list[str]

    recommended_actions: list[str]

    confidence: Literal[
        "low",
        "medium",
        "high",
    ]

    requires_human_review: bool