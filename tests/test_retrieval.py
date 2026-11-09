import numpy as np

from app.knowledge import (
    KnowledgeChunk,
)
from app.retrieval import (
    InMemoryRetriever,
)


class FakeEmbedder:

    def __init__(self):

        self.vectors = {
            "Repeated login guidance":
                np.array(
                    [1.0, 0.0, 0.0]
                ),

            "Privilege guidance":
                np.array(
                    [0.0, 1.0, 0.0]
                ),

            "Transfer guidance":
                np.array(
                    [0.0, 0.0, 1.0]
                ),

            "failed login query":
                np.array(
                    [1.0, 0.0, 0.0]
                ),
        }

    def embed_documents(
        self,
        texts,
    ):

        return np.stack(
            [
                self.vectors[text]
                for text in texts
            ]
        )

    def embed_query(
        self,
        text,
    ):

        return self.vectors[
            text
        ]

def test_retriever_ranks_most_similar_chunk_first():

    chunks = [
        KnowledgeChunk(
            chunk_id="login-000",
            source="login.md",
            category="runbooks",
            text=(
                "Repeated login guidance"
            ),
        ),

        KnowledgeChunk(
            chunk_id="privilege-000",
            source="privilege.md",
            category="runbooks",
            text=(
                "Privilege guidance"
            ),
        ),

        KnowledgeChunk(
            chunk_id="transfer-000",
            source="transfer.md",
            category="runbooks",
            text=(
                "Transfer guidance"
            ),
        ),
    ]

    retriever = InMemoryRetriever(
        chunks=chunks,
        embedder=FakeEmbedder(),
    )

    results = retriever.search(
        "failed login query",
        top_k=2,
    )

    assert len(results) == 2

    assert (
        results[0].chunk.chunk_id
        == "login-000"
    )

    assert results[0].score == 1.0