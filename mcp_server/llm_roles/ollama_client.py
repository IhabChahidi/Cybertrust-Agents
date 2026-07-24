"""Thin client for a local Ollama server, used to back the "llama" LLM mode.

Ollama's /api/chat accepts a JSON Schema in `format` and constrains the model's
output to match it (structured output), which is what lets each role return a
schema-shaped dict instead of free text we'd have to parse ourselves.

Timeouts surface as a plain TimeoutError so mcp_server.orchestrator._invoke_role
retries them and, on exhaustion, raises MCPTechnicalFailure(LLM_TIMEOUT, ...) —
never treated as a security block.

NOTE: Ollama's structured-output grammar (llama.cpp GBNF) does not support
`maxLength` on string properties — including it makes /api/chat return HTTP 400
("failed to parse grammar"). Keep string properties in json_schema unconstrained
and truncate the returned values in Python instead (see llama_generator.py,
llama_verifier.py, llama_validator.py).
"""

import json

import requests

from mcp_server.errors import EventCode, MCPTechnicalFailure


def call_ollama(*, host: str, model: str, system_prompt: str, user_prompt: str,
                 json_schema: dict, timeout_seconds: float) -> dict:
    """Call Ollama's chat endpoint and return the parsed, schema-shaped JSON body."""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "format": json_schema,
        "stream": False,
        "options": {"temperature": 0},
    }

    try:
        response = requests.post(f"{host}/api/chat", json=payload, timeout=timeout_seconds)
    except requests.exceptions.Timeout as exc:
        raise TimeoutError(str(exc)) from exc
    except requests.exceptions.RequestException as exc:
        raise MCPTechnicalFailure(EventCode.LLM_PROVIDER_ERROR, f"Ollama request failed: {exc}") from exc

    if response.status_code != 200:
        raise MCPTechnicalFailure(
            EventCode.LLM_PROVIDER_ERROR, f"Ollama returned HTTP {response.status_code}: {response.text[:300]}",
        )

    body = response.json()
    content = body.get("message", {}).get("content", "")
    if not content:
        raise MCPTechnicalFailure(EventCode.LLM_EMPTY_RESPONSE, "Ollama returned an empty message content")

    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        raise MCPTechnicalFailure(
            EventCode.LLM_PROVIDER_ERROR, f"Ollama response was not valid JSON: {exc}. Raw: {content[:300]}",
        ) from exc
