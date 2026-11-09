from pathlib import Path

from app.ingest import load_events


def test_load_valid_events(
    tmp_path: Path,
):

    test_file = (
        tmp_path
        / "events.jsonl"
    )

    test_file.write_text(
        (
            '{"event_id":"1",'
            '"timestamp":"2026-11-07T10:00:00Z",'
            '"source":"test",'
            '"event_type":"login_failure",'
            '"username":"alice",'
            '"message":"Failed"}'
            "\n"
        ),
        encoding="utf-8",
    )

    events = load_events(
        test_file
    )

    assert len(events) == 1
    assert events[0].username == "alice"