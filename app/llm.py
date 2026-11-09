from dataclasses import dataclass
from typing import Any, Protocol

import httpx


@dataclass(frozen=True)
class LLMResponse:
    content: str
    model: str
    total_duration_ns: int | None = None
    prompt_tokens: int | None = None
    output_tokens: int | None = None


class LLMClient(Protocol):

    async def generate_structured(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
    ) -> LLMResponse:
        ...


class OllamaClient:

    def __init__(
        self,
        model: str = "qwen3:4b-instruct",
        base_url: str = "http://localhost:11434",
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")

    async def generate_structured(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
    ) -> LLMResponse:

        url = f"{self.base_url}/api/chat"

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "format": schema,
            "options": {
                "temperature": 0,
            },
        }

        async with httpx.AsyncClient(
            timeout=120.0,
        ) as client:

            response = await client.post(
                url,
                json=payload,
            )

            response.raise_for_status()

            data = response.json()

        message = data.get(
            "message",
            {},
        )

        return LLMResponse(
            content=message.get(
                "content",
                "",
            ),
            model=data.get(
                "model",
                self.model,
            ),
            total_duration_ns=data.get(
                "total_duration"
            ),
            prompt_tokens=data.get(
                "prompt_eval_count"
            ),
            output_tokens=data.get(
                "eval_count"
            ),
        )
