from typing import Protocol, Sequence

import numpy as np
from sentence_transformers import (
    SentenceTransformer,
)

class Embedder(Protocol):

    def embed_documents(
        self,
        texts: Sequence[str],
    ) -> np.ndarray:
        ...

    def embed_query(
        self,
        text: str,
    ) -> np.ndarray:
        ...


class SentenceTransformerEmbedder:

    def __init__(
        self,
        model_name: str = (
            "sentence-transformers/"
            "all-MiniLM-L6-v2"
        ),
    ) -> None:

        self.model = (
            SentenceTransformer(
                model_name
            )
        )

    def embed_documents(
        self,
        texts: Sequence[str],
    ) -> np.ndarray:

        return np.asarray(
            self.model.encode_document(
                list(texts),
                normalize_embeddings=True,
            )
        )

    def embed_query(
        self,
        text: str,
    ) -> np.ndarray:

        return np.asarray(
            self.model.encode_query(
                text,
                normalize_embeddings=True,
            )
        )