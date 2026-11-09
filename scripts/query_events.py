import duckdb


def main() -> None:

    connection = duckdb.connect(
        "data/processed/security.duckdb"
    )

    results = connection.execute(
        """
        SELECT
            username,
            COUNT(*) AS failed_attempts

        FROM security_events

        WHERE
            event_type = 'login_failure'

        GROUP BY
            username

        ORDER BY
            failed_attempts DESC
        """
    ).fetchall()

    for username, count in results:

        print(
            username,
            count,
        )

    connection.close()


if __name__ == "__main__":
    main()