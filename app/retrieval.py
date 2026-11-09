from dataclasses import dataclass

import numpy as np

from app.embeddings import Embedder
from app.knowledge import KnowledgeChunk


@dataclass(frozen=True)
class RetrievalResult:
    chunk: KnowledgeChunk
    score: float

class InMemoryRetriever:

    def __init__(
        self,
        chunks: list[KnowledgeChunk],
        embedder: Embedder,
    ) -> None:

        if not chunks:
            raise ValueError(
                "Retriever requires "
                "at least one knowledge chunk."
            )

        self.chunks = chunks

        self.embedder = embedder

        document_texts = [
            chunk.text
            for chunk in chunks
        ]

        self.document_embeddings = (
            self.embedder
            .embed_documents(
                document_texts
            )
        )
    def search(
        self,
        query: str,
        top_k: int = 3,
    ) -> list[RetrievalResult]:

        if top_k <= 0:
            raise ValueError(
                "top_k must be greater "
                "than zero."
            )

        query_embedding = (
            self.embedder
            .embed_query(
                query
            )
        )

        scores = (
            self.document_embeddings
            @ query_embedding
        )

        best_indices = (
            np.argsort(scores)
            [::-1]
            [:top_k]
        )

        results: list[
            RetrievalResult
        ] = []

        for index in best_indices:

            results.append(
                RetrievalResult(
                    chunk=self.chunks[
                        int(index)
                    ],
                    score=float(
                        scores[index]
                    ),
                )
            )

        return results