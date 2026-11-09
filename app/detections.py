from collections import defaultdict
from datetime import timedelta

from app.models import (
    EventType,
    SecurityAlert,
    SecurityEvent,
)


def detect_login_burst(
    events: list[SecurityEvent],
) -> list[SecurityAlert]:

    # Group failed login events by:
    # (username, source_ip)
    failures = defaultdict(list)

    # Store successful logins separately
    successful_logins = []

    # STEP 1:
    # Separate failures and successful logins
    for event in events:

        if (
            event.event_type
            == EventType.LOGIN_FAILURE
        ):

            key = (
                event.username,
                event.source_ip,
            )

            failures[key].append(
                event
            )

        elif (
            event.event_type
            == EventType.LOGIN_SUCCESS
        ):

            successful_logins.append(
                event
            )

   
    # STEP 2:
    # Analyse grouped failures

    alerts = []

    for (
        username,
        source_ip,
    ), user_failures in failures.items():

        # Make sure failures are in
        # chronological order
        user_failures.sort(
            key=lambda event:
                event.timestamp
        )

        # Look at groups of 10 failures
        for index in range(
            len(user_failures) - 9
        ):

            window = (
                user_failures[
                    index:
                    index + 10
                ]
            )

            duration = (
                window[-1].timestamp
                - window[0].timestamp
            )

            # If these 10 failures took
            # longer than 5 minutes,
            # this window doesn't match
            if duration > timedelta(
                minutes=5
            ):
                continue

            # Check whether a successful
            # login occurred shortly after
            # the failures
            successful_afterward = any(

                login.username
                == username

                and login.source_ip
                == source_ip

                and login.timestamp
                >= window[-1].timestamp

                and login.timestamp
                <= (
                    window[-1].timestamp
                    + timedelta(
                        minutes=10
                    )
                )

                for login
                in successful_logins
            )

            severity = (
                "high"
                if successful_afterward
                else "medium"
            )

            alerts.append(
                SecurityAlert(
                    alert_id=(
                        f"login-burst-"
                        f"{username}-"
                        f"{int(window[0].timestamp.timestamp())}"
                    ),
                    alert_type=(
                        "repeated_authentication_failure"
                    ),
                    severity=severity,
                    username=username,
                    summary=(
                        "At least 10 failed login "
                        "attempts occurred "
                        f"for {username} "
                        f"from {source_ip} "
                        "within five minutes."
                    ),
                    evidence_event_ids=[
                        event.event_id
                        for event in window
                    ],
                    details={
                        "source_ip":
                            source_ip,

                        "successful_login_afterward":
                            successful_afterward,
                    },
                )
            )

            # We found a matching suspicious
            # window for this user/IP.
            # Stop checking additional windows.
            break

    return alerts

def detect_unusual_privilege_changes(
    events: list[SecurityEvent],
) -> list[SecurityAlert]:

    alerts: list[SecurityAlert] = []

    for event in events:

        if (
            event.event_type
            != EventType.PRIVILEGE_CHANGE
        ):
            continue

        new_role = event.details.get(
            "new_role"
        )

        outside_change_window = not (
            8
            <= event.timestamp.hour
            < 18
        )

        if (
            new_role == "administrator"
            and outside_change_window
        ):

            alerts.append(
                SecurityAlert(
                    alert_id=(
                        f"privilege-"
                        f"{event.event_id}"
                    ),
                    alert_type=(
                        "unusual_privilege_change"
                    ),
                    severity="high",
                    username=event.username,
                    summary=(
                        "Administrator privileges "
                        "were assigned outside "
                        "the expected change window."
                    ),
                    evidence_event_ids=[
                        event.event_id
                    ],
                    details={
                        "new_role": new_role,
                        "event_hour":
                            event.timestamp.hour,
                    },
                )
            )

    return alerts

def detect_suspicious_transfer(
    events: list[SecurityEvent],
) -> list[SecurityAlert]:

    alerts: list[SecurityAlert] = []

    for event in events:

        if (
            event.event_type
            != EventType.LARGE_DATA_TRANSFER
        ):
            continue

        transferred_bytes = (
            event.details.get(
                "bytes",
                0,
            )
        )

        destination_known = (
            event.details.get(
                "destination_known",
                True,
            )
        )

        if (
            transferred_bytes
            >= 1_000_000_000
            and not destination_known
        ):

            alerts.append(
                SecurityAlert(
                    alert_id=(
                        f"transfer-"
                        f"{event.event_id}"
                    ),
                    alert_type=(
                        "suspicious_outbound_transfer"
                    ),
                    severity="high",
                    username=event.username,
                    summary=(
                        "Large outbound data "
                        "transfer to an "
                        "unknown destination."
                    ),
                    evidence_event_ids=[
                        event.event_id
                    ],
                    details={
                        "bytes":
                            transferred_bytes,

                        "destination_ip":
                            event.destination_ip,

                        "destination_known":
                            destination_known,
                    },
                )
            )

    return alerts