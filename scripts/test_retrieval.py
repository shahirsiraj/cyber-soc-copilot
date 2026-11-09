from pathlib import Path

from app.embeddings import (
    SentenceTransformerEmbedder,
)
from app.knowledge import (
    load_knowledge_chunks,
)
from app.retrieval import (
    InMemoryRetriever,
)


def main() -> None:

    chunks = load_knowledge_chunks(
        Path("knowledge")
    )

    print(
        f"Loaded {len(chunks)} "
        "knowledge chunks."
    )

    embedder = (
        SentenceTransformerEmbedder()
    )

    retriever = InMemoryRetriever(
        chunks=chunks,
        embedder=embedder,
    )

    query = (
        "A user had many failed "
        "authentication attempts "
        "from the same IP address "
        "followed by a successful login."
    )

    results = retriever.search(
        query,
        top_k=3,
    )

    print(
        f"\nQUERY:\n{query}"
    )

    print(
        "\nTOP RESULTS:"
    )

    for position, result in enumerate(
        results,
        start=1,
    ):

        print(
            "\n"
            + "=" * 60
        )

        print(
            f"RANK: {position}"
        )

        print(
            f"SCORE: "
            f"{result.score:.4f}"
        )

        print(
            f"SOURCE: "
            f"{result.chunk.source}"
        )

        print(
            f"CATEGORY: "
            f"{result.chunk.category}"
        )

        print(
            f"CHUNK ID: "
            f"{result.chunk.chunk_id}"
        )

        print()

        print(
            result.chunk.text
        )


if __name__ == "__main__":
    main()