from pathlib import Path

from app.knowledge import (
    chunk_markdown_file,
)


def test_chunk_markdown_preserves_paragraphs(
    tmp_path: Path,
):

    runbook_directory = (
        tmp_path
        / "runbooks"
    )

    runbook_directory.mkdir()

    document = (
        runbook_directory
        / "login.md"
    )

    document.write_text(
        (
            "# Login\n\n"
            "Repeated failed logins "
            "require review.\n\n"
            "Check the source IP and "
            "subsequent user activity."
        ),
        encoding="utf-8",
    )

    chunks = chunk_markdown_file(
        document,
        max_characters=60,
    )

    assert len(chunks) == 2

    assert (
        chunks[0].source
        == "login.md"
    )

    assert (
        chunks[0].category
        == "runbooks"
    )

    assert (
        chunks[0].chunk_id
        == "login-000"
    )