import json
from pathlib import Path

from app.embeddings import (
    SentenceTransformerEmbedder,
)
from app.knowledge import (
    load_knowledge_chunks,
)
from app.models import SecurityAlert
from app.rag import build_alert_query
from app.retrieval import (
    InMemoryRetriever,
)


ALERT_PATH = Path(
    "data/processed/alerts.json"
)


def main() -> None:

    raw_alerts = json.loads(
        ALERT_PATH.read_text(
            encoding="utf-8"
        )
    )

    alerts = [
        SecurityAlert.model_validate(
            raw_alert
        )
        for raw_alert in raw_alerts
    ]

    chunks = load_knowledge_chunks(
        Path("knowledge")
    )

    retriever = InMemoryRetriever(
        chunks=chunks,
        embedder=(
            SentenceTransformerEmbedder()
        ),
    )

    for alert in alerts:

        query = build_alert_query(
            alert
        )

        results = retriever.search(
            query,
            top_k=3,
        )

        print(
            "\n"
            + "=" * 70
        )

        print(
            f"ALERT: "
            f"{alert.alert_type}"
        )

        print(
            f"USER: "
            f"{alert.username}"
        )

        print(
            f"SEVERITY: "
            f"{alert.severity}"
        )

        print(
            "\nRETRIEVED CONTEXT:"
        )

        for result in results:

            print(
                f"\n"
                f"[{result.score:.4f}] "
                f"{result.chunk.source} "
                f"({result.chunk.chunk_id})"
            )


if __name__ == "__main__":
    main()