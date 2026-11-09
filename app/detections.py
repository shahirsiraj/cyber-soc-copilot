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