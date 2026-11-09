import pytest
from pydantic import ValidationError

from app.models import SecurityEvent


def test_valid_security_event():
    event = SecurityEvent(
        event_id="evt-001",
        timestamp="2026-11-07T10:00:00Z",
        source="identity",
        event_type="login_failure",
        username="alice",
        source_ip="203.0.113.10",
        message="Authentication failed",
    )

    assert event.username == "alice"
    assert event.event_type.value == "login_failure"


def test_invalid_event_type_is_rejected():
    with pytest.raises(ValidationError):
        SecurityEvent(
            event_id="evt-002",
            timestamp="2026-11-07T10:00:00Z",
            source="identity",
            event_type="banana",
            message="Invalid event",
        )