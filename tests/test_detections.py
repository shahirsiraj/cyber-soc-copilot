from datetime import (
    datetime,
    timedelta,
    timezone,
)

from app.detections import (
    detect_login_burst,
    detect_unusual_privilege_changes,
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