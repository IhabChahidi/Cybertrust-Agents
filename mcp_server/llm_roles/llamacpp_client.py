"""Async client for a llama.cpp server's OpenAI-compatible /v1/chat/completions
endpoint (spec: Foundation-Sec-8B-Instruct.Q4_K_M.gguf served by `llama-server`).

Deliberately NOT the same client as mcp_server/llm_roles/ollama_client.py: that
one talks Ollama's native /api/chat with grammar-constrained structured output;
this one talks the OpenAI chat-completions wire format, which llama.cpp's server
also implements. Both Generators can coexist -- selecting one over the other is
a matter of which config/client the caller wires up (see
mcp_server/generator_service.py), not a replacement of the Ollama-backed
LlamaGenerator used by the existing mcp_server pipeline.

Uses response_format={"type": "json_object"} (widely supported across
llama.cpp server versions) rather than assuming a specific build's JSON-Schema
grammar support -- this guarantees syntactically valid JSON but not the exact
shape, so callers still validate the parsed object against a Pydantic model
afterwards (see mcp_server/generator_claims.py) and may request one deterministic
repair pass on shape mismatch.
"""

import json
import logging

import httpx

from mcp_server.errors import EventCode, MCPTechnicalFailure
from mcp_server.generator_prompts import GENERATED_CLAIM_JSON_SCHEMA
from mcp_server.llamacpp_config import LlamaCppConfig

_logger = logging.getLogger("mcp_server.llamacpp")

# Per-base_url cache for the "auto" mode's one-time capability probe (spec:
# structured-output capability detection should not re-probe on every single
# generation request). Deliberately process-local, in-memory -- same
# non-durability tradeoff as mcp_server/rag/jobs.py, acceptable for a pilot.
_capability_cache: dict[str, str] = {}


class LlamaCppUnavailable(RuntimeError):
    """Raised by the readiness check (health_check()) when the llama.cpp server
    is not reachable. NOT raised by chat_completion() itself, which raises
    MCPTechnicalFailure like the rest of this codebase's LLM clients, for
    consistent error handling by callers already built around that type."""


async def health_check(config: LlamaCppConfig, *, timeout_seconds: float = 5.0) -> bool:
    """GET {base_url}/models -- the standard OpenAI-compatible model-list
    endpoint, which llama.cpp's server also exposes. Used by /health/ready
    (see web/generator_api.py) to confirm the model server is reachable BEFORE
    the Generator API accepts generation requests (spec section 2)."""
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.get(f"{config.base_url}/models")
            return response.status_code == 200
    except httpx.HTTPError:
        return False


async def tokenize(config: LlamaCppConfig, text: str, *, timeout_seconds: float = 5.0) -> list[int] | None:
    """Calls llama.cpp server's native `/tokenize` endpoint (present on
    llama.cpp's server, distinct from the OpenAI-compatible `/v1/...` surface
    used by chat_completion/health_check) for an EXACT token count of `text`.

    Returns None -- never raises -- on any failure: server unreachable,
    non-200, unexpected body shape. This is deliberately best-effort (spec:
    "prefer the llama.cpp tokenize endpoint when available, provide a
    conservative local fallback for tests and failure cases"). Callers
    (mcp_server/rag/token_budget.py) must fall back to
    mcp_server.rag.context_builder.approximate_token_count when this returns
    None, and must record which path was used rather than silently treating
    an approximation as exact.
    """
    base = config.base_url
    root = base[:-3] if base.endswith("/v1") else base  # /tokenize lives at server root, not under /v1
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.post(f"{root}/tokenize", json={"content": text})
        if response.status_code != 200:
            return None
        body = response.json()
        tokens = body.get("tokens") if isinstance(body, dict) else None
        if not isinstance(tokens, list):
            return None
        return tokens
    except (httpx.HTTPError, json.JSONDecodeError, ValueError, AttributeError, TypeError):
        return None


async def probe_structured_output_capability(config: LlamaCppConfig, *, timeout_seconds: float = 5.0) -> bool:
    """Best-effort, never-raising probe: sends one minimal chat-completion
    request with `response_format={"type": "json_schema", ...}` and reports
    whether the server accepted it. Do NOT assume support from documentation
    for a different llama.cpp build (spec) -- this is a live check against
    the ACTUAL configured server. Any failure (unreachable, timeout, non-200,
    malformed response) is treated as "not supported", never as an error --
    callers fall back to json_object mode.
    """
    payload = {
        "model": config.model_name,
        "messages": [{"role": "user", "content": "Respond with {\"ok\": true} and nothing else."}],
        "max_tokens": 16,
        "temperature": 0.0,
        "response_format": {"type": "json_schema", "json_schema": {
            "name": "probe", "schema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        }},
        "stream": False,
    }
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.post(f"{config.base_url}/chat/completions", json=payload)
        return response.status_code == 200
    except Exception:  # noqa: BLE001 -- a probe must never raise, only report False
        return False


async def resolve_structured_output_mode(config: LlamaCppConfig) -> str:
    """Resolves `config.structured_output_mode` to one of "json_schema",
    "json_object", "disabled" -- "auto" is replaced by a live capability
    probe (cached per base_url so repeated generation requests do not
    re-probe every time). Logs the resolved capability (never prompts or
    evidence content, per spec: "log the selected capability without logging
    prompts").
    """
    mode = config.structured_output_mode
    if mode != "auto":
        return mode

    cached = _capability_cache.get(config.base_url)
    if cached is not None:
        return cached

    supported = await probe_structured_output_capability(config)
    resolved = "json_schema" if supported else "json_object"
    _capability_cache[config.base_url] = resolved
    _logger.info("structured_output_mode=auto resolved to %r for base_url=%r", resolved, config.base_url)
    return resolved


def _response_format_for_mode(mode: str) -> dict | None:
    if mode == "json_schema":
        return {"type": "json_schema", "json_schema": GENERATED_CLAIM_JSON_SCHEMA}
    if mode == "json_object":
        return {"type": "json_object"}
    if mode == "disabled":
        return None
    raise ValueError(f"unresolved structured output mode: {mode!r}")  # pragma: no cover -- resolve_* always normalizes first


async def chat_completion(*, config: LlamaCppConfig, system_prompt: str, user_prompt: str) -> str:
    """Returns the raw string content of the model's reply (the caller parses
    and validates it as JSON -- see mcp_server/generator_service.py). Raises
    MCPTechnicalFailure (never a bare exception) on any provider-level failure,
    consistent with mcp_server/llm_roles/ollama_client.py's contract, so the
    same orchestrator-style retry/fail-closed handling applies uniformly.

    Pydantic validation (mcp_server/generator_claims.py) remains authoritative
    regardless of structured-output mode -- even a schema-constrained response
    is re-validated, never trusted blindly (spec: "Keep Pydantic and
    deterministic validators authoritative in every mode").
    """
    resolved_mode = await resolve_structured_output_mode(config)
    response_format = _response_format_for_mode(resolved_mode)

    payload = {
        "model": config.model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": config.temperature,
        "top_p": config.top_p,
        "seed": config.seed,
        "max_tokens": config.max_output_tokens,
        "stream": False,
    }
    if response_format is not None:
        payload["response_format"] = response_format

    try:
        async with httpx.AsyncClient(timeout=config.request_timeout_seconds) as client:
            response = await client.post(f"{config.base_url}/chat/completions", json=payload)
    except httpx.TimeoutException as exc:
        raise TimeoutError(str(exc)) from exc
    except httpx.HTTPError as exc:
        raise MCPTechnicalFailure(EventCode.LLM_PROVIDER_ERROR, f"llama.cpp request failed: {exc}") from exc

    if response.status_code != 200:
        raise MCPTechnicalFailure(
            EventCode.LLM_PROVIDER_ERROR, f"llama.cpp returned HTTP {response.status_code}: {response.text[:300]}",
        )

    try:
        body = response.json()
    except json.JSONDecodeError as exc:
        raise MCPTechnicalFailure(EventCode.LLM_PROVIDER_ERROR, f"llama.cpp response was not JSON: {exc}") from exc

    choices = body.get("choices") or []
    if not choices:
        raise MCPTechnicalFailure(EventCode.LLM_EMPTY_RESPONSE, "llama.cpp returned no choices")

    content = (choices[0].get("message") or {}).get("content", "")
    if not content:
        raise MCPTechnicalFailure(EventCode.LLM_EMPTY_RESPONSE, "llama.cpp returned an empty message content")

    return content
