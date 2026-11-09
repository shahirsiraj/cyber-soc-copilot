from app.models import (
    SecurityAlert,
)
from app.rag import (
    build_alert_query,
)


def test_build_alert_query_contains_context():

    alert = SecurityAlert(
        alert_id="alert-1",
        alert_type=(
            "repeated_authentication_failure"
        ),
        severity="high",
        username="alice",
        summary=(
            "Repeated login failures."
        ),
        evidence_event_ids=[
            "event-1"
        ],
        details={
            "source_ip": "1.2.3.4",
            "successful_login_afterward":
                True,
        },
    )

    query = build_alert_query(
        alert
    )

    assert (
        "repeated_authentication_failure"
        in query
    )

    assert "high" in query

    assert (
        "successful_login_afterward"
        in query
    )