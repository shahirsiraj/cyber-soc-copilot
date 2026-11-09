import json
from pathlib import Path

from app.detections import (
    run_all_detections,
)
from app.ingest import load_events


RAW_PATH = Path(
    "data/raw/security_events.jsonl"
)

OUTPUT_PATH = Path(
    "data/processed/alerts.json"
)


def main() -> None:

    events = load_events(
        RAW_PATH
    )

    print(
        f"Loaded {len(events)} events"
    )

    alerts = run_all_detections(
        events
    )

    print(
        f"Detected {len(alerts)} alerts"
    )

    for alert in alerts:

        print(
            alert.model_dump_json(
                indent=2
            )
        )

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    alert_data = [
        alert.model_dump(
            mode="json"
        )
        for alert in alerts
    ]

    OUTPUT_PATH.write_text(
        json.dumps(
            alert_data,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(
        f"Alerts written to "
        f"{OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()