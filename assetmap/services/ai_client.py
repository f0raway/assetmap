from __future__ import annotations

from typing import Any

import httpx

from assetmap.config import AiConfig


def ai_headers(config: AiConfig) -> dict[str, str]:
    header_name = config.api_key_header.strip()
    if header_name.lower() in {"authorization", "bearer"}:
        return {"Authorization": f"Bearer {config.api_key}", "Content-Type": "application/json"}
    return {header_name: config.api_key, "Content-Type": "application/json"}


def completion_finish_reason(response: dict[str, Any]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0]
    if not isinstance(first, dict):
        return ""
    return str(first.get("finish_reason") or "")


def chat_completion(
    config: AiConfig,
    messages: list[dict[str, Any]],
    *,
    temperature: float = 0.1,
    tools: list[dict[str, Any]] | None = None,
    max_completion_tokens: int | None = None,
    extra_body: dict[str, Any] | None = None,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": config.model,
        "messages": messages,
        "temperature": temperature,
        "stream": False,
    }
    if tools:
        body["tools"] = tools
    token_budget = max_completion_tokens or config.max_completion_tokens
    if token_budget:
        body["max_completion_tokens"] = token_budget
    if extra_body:
        body.update(extra_body)
    with httpx.Client(timeout=timeout_seconds or config.timeout_seconds, trust_env=False) as client:
        response = client.post(
            f"{config.base_url.rstrip('/')}/chat/completions",
            headers=ai_headers(config),
            json=body,
        )
        response.raise_for_status()
        return response.json()
