from datetime import (
    datetime,
    timedelta,
    timezone,
)

from app.detections import (
    detect_login_burst,
    detect_unusual_privilege_changes,
    detect_suspicious_transfer
)

from app.models import (
    EventType,
    SecurityEvent,
)


def test_login_burst_detected():

    start = datetime(
        2026,
        11,
        7,
        10,
        0,
        tzinfo=timezone.utc,
    )

    events = []

    for index in range(10):

        events.append(
            SecurityEvent(
                event_id=(
                    f"event-{index}"
                ),
                timestamp=(
                    start
                    + timedelta(
                        seconds=index * 10
                    )
                ),
                source="test",
                event_type=(
                    EventType.LOGIN_FAILURE
                ),
                username="alice",
                source_ip="1.2.3.4",
                message=(
                    "Authentication failed"
                ),
            )
        )

    alerts = detect_login_burst(
        events
    )

    assert len(alerts) == 1

    assert (
        alerts[0].alert_type
        == "repeated_authentication_failure"
    )

    assert alerts[0].severity == "medium"

    start = datetime(
        2026,
        11,
        7,
        10,
        0,
        tzinfo=timezone.utc,
    )

    events = []

    for index in range(10):

        events.append(
            SecurityEvent(
                event_id=(
                    f"event-{index}"
                ),
                timestamp=(
                    start
                    + timedelta(
                        seconds=index * 10
                    )
                ),
                source="test",
                event_type=(
                    EventType.LOGIN_FAILURE
                ),
                username="alice",
                source_ip="1.2.3.4",
                message=(
                    "Authentication failed"
                ),
            )
        )

    alerts = detect_login_burst(
        events
    )

    assert len(alerts) == 1

    assert (
        alerts[0].alert_type
        == "repeated_authentication_failure"
    )


def test_login_burst_with_success_is_high_severity():

    start = datetime(
        2026,
        11,
        7,
        10,
        0,
        tzinfo=timezone.utc,
    )

    events = []

    for index in range(10):

        events.append(
            SecurityEvent(
                event_id=(
                    f"failure-{index}"
                ),
                timestamp=(
                    start
                    + timedelta(
                        seconds=index * 10
                    )
                ),
                source="test",
                event_type=(
                    EventType.LOGIN_FAILURE
                ),
                username="alice",
                source_ip="1.2.3.4",
                message=(
                    "Authentication failed"
                ),
            )
        )

    events.append(
        SecurityEvent(
            event_id="success-1",
            timestamp=(
                start
                + timedelta(
                    minutes=3
                )
            ),
            source="test",
            event_type=(
                EventType.LOGIN_SUCCESS
            ),
            username="alice",
            source_ip="1.2.3.4",
            message=(
                "Authentication successful"
            ),
        )
    )

    alerts = detect_login_burst(
        events
    )

    assert len(alerts) == 1

    assert alerts[0].severity == "high"

    assert (
        alerts[0]
        .details[
            "successful_login_afterward"
        ]
        is True
    )
def test_unusual_privilege_change_detected():

    event = SecurityEvent(
        event_id="privilege-1",
        timestamp=datetime(
            2026,
            11,
            7,
            2,
            30,
            tzinfo=timezone.utc,
        ),
        source="test",
        event_type=(
            EventType.PRIVILEGE_CHANGE
        ),
        username="charlie",
        message=(
            "Role changed to administrator"
        ),
        details={
            "previous_role": "user",
            "new_role": "administrator",
        },
    )

    alerts = (
        detect_unusual_privilege_changes(
            [event]
        )
    )

    assert len(alerts) == 1

    assert (
        alerts[0].alert_type
        == "unusual_privilege_change"
    )

    assert alerts[0].severity == "high"

    assert alerts[0].username == "charlie" 
def test_privilege_change_during_normal_hours_is_not_alerted():

    event = SecurityEvent(
        event_id="privilege-2",
        timestamp=datetime(
            2026,
            11,
            7,
            10,
            0,
            tzinfo=timezone.utc,
        ),
        source="test",
        event_type=(
            EventType.PRIVILEGE_CHANGE
        ),
        username="charlie",
        message=(
            "Role changed to administrator"
        ),
        details={
            "previous_role": "user",
            "new_role": "administrator",
        },
    )

    alerts = (
        detect_unusual_privilege_changes(
            [event]
        )
    )

    assert alerts == []

def test_suspicious_outbound_transfer_detected():

    event = SecurityEvent(
        event_id="transfer-1",
        timestamp=datetime(
            2026,
            11,
            7,
            14,
            0,
            tzinfo=timezone.utc,
        ),
        source="test",
        event_type=(
            EventType.LARGE_DATA_TRANSFER
        ),
        username="diana",
        source_ip="10.0.0.20",
        destination_ip="198.51.100.99",
        message=(
            "Large outbound data transfer"
        ),
        details={
            "bytes": 8_000_000_000,
            "destination_known": False,
        },
    )

    alerts = detect_suspicious_transfer(
        [event]
    )

    assert len(alerts) == 1

    assert (
        alerts[0].alert_type
        == "suspicious_outbound_transfer"
    )

    assert alerts[0].severity == "high"

def test_large_transfer_to_known_destination_is_not_alerted():

    event = SecurityEvent(
        event_id="transfer-2",
        timestamp=datetime(
            2026,
            11,
            7,
            14,
            0,
            tzinfo=timezone.utc,
        ),
        source="test",
        event_type=(
            EventType.LARGE_DATA_TRANSFER
        ),
        username="backup-service",
        source_ip="10.0.0.50",
        destination_ip="10.10.10.20",
        message=(
            "Scheduled backup transfer"
        ),
        details={
            "bytes": 15_000_000_000,
            "destination_known": True,
        },
    )

    alerts = detect_suspicious_transfer(
        [event]
    )

    assert alerts == []