import asyncio
import json
from pathlib import Path

from app.embeddings import (
    SentenceTransformerEmbedder,
)
from app.knowledge import (
    load_knowledge_chunks,
)
from app.llm import (
    OllamaClient,
)
from app.models import (
    SecurityAlert,
)
from app.retrieval import (
    InMemoryRetriever,
)
from app.triage import (
    TriageService,
)


ALERT_PATH = Path(
    "data/processed/alerts.json"
)

OUTPUT_PATH = Path(
    "data/processed/triage_results.json"
)


async def main() -> None:

    if not ALERT_PATH.exists():

        raise FileNotFoundError(
            "Alert file not found. "
            "Run these first:\n"
            "python -m scripts.generate_events\n"
            "python -m scripts.process_events\n"
            "python -m scripts.detect_alerts"
        )

    raw_alerts = json.loads(
        ALERT_PATH.read_text(
            encoding="utf-8"
        )
    )

    alerts = [
        SecurityAlert.model_validate(
            item
        )
        for item in raw_alerts
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

    llm_client = OllamaClient(
        model="qwen3:4b-instruct"
    )

    triage_service = TriageService(
        retriever=retriever,
        llm_client=llm_client,
        top_k=3,
    )

    output_records = []

    for alert in alerts:

        print(
            "\n"
            + "=" * 70
        )

        print(
            f"TRIAGING: "
            f"{alert.alert_type}"
        )

        try:

            result, response, evidence = (
                await triage_service.triage(
                    alert
                )
            )

        except Exception as exc:

            print(
                f"Failed to triage "
                f"{alert.alert_id}: "
                f"{exc}"
            )

            continue

        print(
            "\nRETRIEVED EVIDENCE:"
        )

        for item in evidence:

            print(
                f"- "
                f"{item.chunk.chunk_id} "
                f"({item.score:.4f})"
            )

        print(
            "\nAI TRIAGE RESULT:"
        )

        print(
            result.model_dump_json(
                indent=2
            )
        )

        print(
            "\nMODEL METADATA:"
        )

        print(
            f"Model: "
            f"{response.model}"
        )

        if (
            response.total_duration_ns
            is not None
        ):

            seconds = (
                response.total_duration_ns
                / 1_000_000_000
            )

            print(
                f"Model duration: "
                f"{seconds:.2f}s"
            )

        print(
            f"Prompt tokens: "
            f"{response.prompt_tokens}"
        )

        print(
            f"Output tokens: "
            f"{response.output_tokens}"
        )

        output_records.append(
            {
                "alert":
                    alert.model_dump(
                        mode="json"
                    ),

                "triage":
                    result.model_dump(
                        mode="json"
                    ),

                "model":
                    response.model,

                "total_duration_ns":
                    response.total_duration_ns,

                "prompt_tokens":
                    response.prompt_tokens,

                "output_tokens":
                    response.output_tokens,

                "retrieval": [
                    {
                        "chunk_id":
                            item.chunk.chunk_id,

                        "source":
                            item.chunk.source,

                        "score":
                            item.score,
                    }
                    for item
                    in evidence
                ],
            }
        )

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT_PATH.write_text(
        json.dumps(
            output_records,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(
        f"\nSaved triage results "
        f"to {OUTPUT_PATH}"
    )


if __name__ == "__main__":
    asyncio.run(
        main()
    )
