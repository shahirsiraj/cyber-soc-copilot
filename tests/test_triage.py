import asyncio
import json

import numpy as np
import pytest
from pydantic import ValidationError

from app.knowledge import (
    KnowledgeChunk,
)
from app.llm import (
    LLMResponse,
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


class FakeEmbedder:

    def embed_documents(
        self,
        texts,
    ):

        vectors = []

        for text in texts:

            if "login" in text.lower():
                vectors.append(
                    [1.0, 0.0]
                )
            else:
                vectors.append(
                    [0.0, 1.0]
                )

        return np.array(
            vectors
        )

    def embed_query(
        self,
        text,
    ):

        return np.array(
            [1.0, 0.0]
        )


class FakeLLMClient:

    async def generate_structured(
        self,
        messages,
        schema,
    ) -> LLMResponse:

        content = json.dumps(
            {
                "severity": "high",
                "summary": (
                    "Repeated authentication "
                    "failures require review."
                ),
                "possible_tactic":
                    "Credential Access",
                "evidence_ids": [
                    "login-000"
                ],
                "recommended_actions": [
                    "Review the source IP.",
                    "Check subsequent "
                    "account activity.",
                ],
                "confidence": "high",
                "requires_human_review":
                    True,
            }
        )

        return LLMResponse(
            content=content,
            model="fake-model",
        )


class HallucinatingLLMClient:

    async def generate_structured(
        self,
        messages,
        schema,
    ) -> LLMResponse:

        content = json.dumps(
            {
                "severity": "high",
                "summary":
                    "Suspicious activity.",
                "possible_tactic":
                    "Credential Access",
                "evidence_ids": [
                    "imaginary-secret-report"
                ],
                "recommended_actions": [
                    "Investigate."
                ],
                "confidence": "high",
                "requires_human_review":
                    True,
            }
        )

        return LLMResponse(
            content=content,
            model="hallucinating-model",
        )


class InvalidSchemaLLMClient:

    async def generate_structured(
        self,
        messages,
        schema,
    ) -> LLMResponse:

        content = json.dumps(
            {
                "severity": "urgent",
                "summary":
                    "Invalid severity value.",
                "possible_tactic":
                    "Credential Access",
                "evidence_ids": [
                    "login-000"
                ],
                "recommended_actions": [
                    "Investigate."
                ],
                "confidence": "high",
                "requires_human_review":
                    True,
            }
        )

        return LLMResponse(
            content=content,
            model="invalid-schema-model",
        )


def build_retriever():

    chunks = [
        KnowledgeChunk(
            chunk_id="login-000",
            source="login.md",
            category="runbooks",
            text=(
                "Repeated login failures "
                "should be investigated."
            ),
        ),
        KnowledgeChunk(
            chunk_id="transfer-000",
            source="transfer.md",
            category="runbooks",
            text=(
                "Large outbound transfers "
                "require context."
            ),
        ),
    ]

    return InMemoryRetriever(
        chunks=chunks,
        embedder=FakeEmbedder(),
    )


def build_alert():

    return SecurityAlert(
        alert_id="alert-001",
        alert_type=(
            "repeated_authentication_failure"
        ),
        severity="high",
        username="alice",
        summary=(
            "Ten failed login attempts."
        ),
        evidence_event_ids=[
            "event-1"
        ],
        details={
            "source_ip": "1.2.3.4",
            "successful_login_afterward":
                True,
        },
    )


def test_triage_returns_grounded_result():

    service = TriageService(
        retriever=build_retriever(),
        llm_client=FakeLLMClient(),
    )

    result, response, evidence = (
        asyncio.run(
            service.triage(
                build_alert()
            )
        )
    )

    assert (
        result.possible_tactic
        == "Credential Access"
    )

    assert result.evidence_ids == [
        "login-000"
    ]

    assert response.model == "fake-model"

    assert (
        evidence[0].chunk.chunk_id
        == "login-000"
    )


def test_triage_rejects_unretrieved_evidence():

    service = TriageService(
        retriever=build_retriever(),
        llm_client=(
            HallucinatingLLMClient()
        ),
    )

    with pytest.raises(
        ValueError,
        match="unretrieved evidence",
    ):

        asyncio.run(
            service.triage(
                build_alert()
            )
        )


def test_triage_rejects_invalid_schema():

    service = TriageService(
        retriever=build_retriever(),
        llm_client=(
            InvalidSchemaLLMClient()
        ),
    )

    with pytest.raises(
        ValidationError
    ):

        asyncio.run(
            service.triage(
                build_alert()
            )
        )
