from pathlib import Path

from app.models import SecurityEvent


def load_events(
    path: Path,
) -> list[SecurityEvent]:

    events: list[SecurityEvent] = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:

        for line_number, line in enumerate(
            file,
            start=1,
        ):

            if not line.strip():
                continue

            try:

                event = (
                    SecurityEvent
                    .model_validate_json(
                        line
                    )
                )

                events.append(event)

            except Exception as exc:

                raise ValueError(
                    "Invalid security event "
                    f"on line {line_number}: "
                    f"{exc}"
                ) from exc

    return events