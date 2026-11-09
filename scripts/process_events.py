from pathlib import Path

from app.ingest import load_events
from app.storage import (
    create_duckdb_database,
    events_to_dataframe,
    write_parquet,
)


RAW_PATH = Path(
    "data/raw/security_events.jsonl"
)

PARQUET_PATH = Path(
    "data/processed/security_events.parquet"
)

DATABASE_PATH = Path(
    "data/processed/security.duckdb"
)


def main() -> None:

    events = load_events(
        RAW_PATH
    )

    print(
        f"Loaded {len(events)} events"
    )

    dataframe = (
        events_to_dataframe(
            events
        )
    )

    write_parquet(
        dataframe,
        PARQUET_PATH,
    )

    create_duckdb_database(
        dataframe,
        DATABASE_PATH,
    )

    print(
        "Telemetry processing complete."
    )


if __name__ == "__main__":
    main()