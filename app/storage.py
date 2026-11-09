import json
from pathlib import Path

import duckdb
import pandas as pd

from app.models import SecurityEvent


def events_to_dataframe(
    events: list[SecurityEvent],
) -> pd.DataFrame:

    rows = []

    for event in events:

        row = event.model_dump(
            mode="json"
        )

        row["details"] = json.dumps(
            row["details"],
            sort_keys=True,
        )

        rows.append(row)

    return pd.DataFrame(rows)

def write_parquet(
    dataframe: pd.DataFrame,
    output_path: Path,
) -> None:

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    dataframe.to_parquet(
        output_path,
        index=False,
    )

def create_duckdb_database(
    dataframe: pd.DataFrame,
    database_path: Path,
) -> None:

    database_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = duckdb.connect(
        str(database_path)
    )

    connection.register(
        "events_dataframe",
        dataframe,
    )

    connection.execute(
        """
        CREATE OR REPLACE TABLE
        security_events AS

        SELECT *
        FROM events_dataframe
        """
    )

    connection.close()

    connection.register(
        "events_dataframe",
        dataframe,
    )