import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from app.models import EventType, SecurityEvent


OUTPUT_FILE = Path(
    "data/raw/security_events.jsonl"
)

RANDOM_SEED = 42

BASE_TIME = datetime(
    2026,
    11,
    7,
    8,
    0,
    tzinfo=timezone.utc,
)

def create_event(
    timestamp: datetime,
    event_type: EventType,
    username: str | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    message: str = "",
    details: dict | None = None,
) -> SecurityEvent:

    return SecurityEvent(
        event_id=str(uuid4()),
        timestamp=timestamp,
        source="synthetic-lab",
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        destination_ip=destination_ip,
        message=message,
        details=details or {},
    )

def generate_events() -> list[SecurityEvent]:

    rng = random.Random(
        RANDOM_SEED
    )

    events: list[SecurityEvent] = []

    users = [
        "alice",
        "bob",
        "charlie",
        "diana",
        "eric",
    ]

    internal_ips = [
        "10.0.0.10",
        "10.0.0.11",
        "10.0.0.12",
        "10.0.0.13",
    ]

    for _ in range(300):

        timestamp = (
            BASE_TIME
            + timedelta(
                minutes=rng.randint(
                    0,
                    600,
                )
            )
        )

        events.append(
            create_event(
                timestamp=timestamp,
                event_type=EventType.LOGIN_SUCCESS,
                username=rng.choice(users),
                source_ip=rng.choice(
                    internal_ips
                ),
                message=(
                    "Successful authentication"
                ),
            )
        )

    for _ in range(40):

        timestamp = (
            BASE_TIME
            + timedelta(
                minutes=rng.randint(
                    0,
                    600,
                )
            )
        )

        events.append(
            create_event(
                timestamp=timestamp,
                event_type=(
                    EventType.LOGIN_FAILURE
                ),
                username=rng.choice(users),
                source_ip=rng.choice(
                    internal_ips
                ),
                message=(
                    "Authentication failed"
                ),
            )
        )

        attack_start = (
        BASE_TIME
        + timedelta(hours=2)
    )

    for index in range(20):

        events.append(
            create_event(
                timestamp=(
                    attack_start
                    + timedelta(
                        seconds=index * 10
                    )
                ),
                event_type=(
                    EventType.LOGIN_FAILURE
                ),
                username="alice",
                source_ip="203.0.113.50",
                message=(
                    "Authentication failed"
                ),
            )
        )

        events.append(
            create_event(
                timestamp=(
                    attack_start
                    + timedelta(
                        minutes=4
                    )
                ),
                event_type=(
                    EventType.LOGIN_SUCCESS
                ),
                username="alice",
                source_ip="203.0.113.50",
                message=(
                    "Successful authentication"
                ),
            )
        )
        events.append(
            create_event(
                timestamp=(
                    BASE_TIME
                    + timedelta(
                        hours=18
                    )
                ),
                event_type=(
                    EventType.PRIVILEGE_CHANGE
                ),
                username="charlie",
                message=(
                    "User role changed "
                    "to administrator"
                ),
                details={
                    "previous_role":
                        "user",
    
                    "new_role":
                        "administrator",
                },
            )
        )
        events.append(
            create_event(
                timestamp=(
                    BASE_TIME
                    + timedelta(hours=6)
                ),
                event_type=(
                    EventType.LARGE_DATA_TRANSFER
                ),
                username="diana",
                source_ip="10.0.0.20",
                destination_ip=(
                    "198.51.100.99"
                ),
                message=(
                    "Large outbound "
                    "data transfer"
                ),
                details={
                    "bytes":
                        8_000_000_000,
    
                    "destination_known":
                        False,
                },
            )
        )
        events.sort(
            key=lambda event:
                event.timestamp
        )
    
        return events
    
def write_events(
        events: list[SecurityEvent],
    ) -> None:
    
        OUTPUT_FILE.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
    
        with OUTPUT_FILE.open(
            "w",
            encoding="utf-8",
        ) as file:
    
            for event in events:
    
                file.write(
                    event.model_dump_json()
                    + "\n"
                )
if __name__ == "__main__":

    generated_events = (
        generate_events()
    )

    write_events(
        generated_events
    )

    print(
        f"Generated "
        f"{len(generated_events)} "
        f"events at {OUTPUT_FILE}"
    )