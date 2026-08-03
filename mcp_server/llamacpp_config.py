"""Typed configuration for the llama.cpp-backed Generator (Foundation-Sec Q4 GGUF).

Separate from mcp_server/config.py (the Ollama-backed MCP pipeline's config) and
mcp_server/rag/config.py (Chroma/embedding/RAG tuning): this module is specific to
the OpenAI-compatible llama.cpp server and the new /api/v1/generator/claims,
/api/v1/ingestion/*, and /api/v1/retrieval/search endpoints. Ollama-backed
LlamaGenerator/LlamaVerifier (mcp_server/llm_roles/) are untouched by this file --
this is an additional, independently-configured Generator backend, not a
replacement.
"""

import os
from dataclasses import dataclass, field

# Allowed values for GENERATOR_STRUCTURED_OUTPUT_MODE (spec: "Investigate
# constrained JSON support"). "auto" probes the configured llama.cpp server
# once (mcp_server.llm_roles.llamacpp_client.resolve_structured_output_mode)
# and falls back to "json_object" if json_schema is not supported;
# "json_schema"/"json_object"/"disabled" pin the behavior explicitly.
STRUCTURED_OUTPUT_MODES = frozenset({"auto", "json_schema", "json_object", "disabled"})


class InvalidStructuredOutputMode(ValueError):
    pass


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class LlamaCppConfig:
    """Points at an OpenAI-chat-completions-compatible llama.cpp server
    (`llama-server`) hosting Foundation-Sec-8B-Instruct.Q4_K_M.gguf, or any
    other GGUF model swapped in via GENERATOR_MODEL_PATH."""

    base_url: str = field(default_factory=lambda: os.environ.get("GENERATOR_BASE_URL", "http://llama-generator:8080/v1"))
    model_name: str = field(default_factory=lambda: os.environ.get("GENERATOR_MODEL_NAME", "foundation-sec-generator"))
    model_path: str = field(default_factory=lambda: os.environ.get(
        "GENERATOR_MODEL_PATH", "/models/Foundation-Sec-8B-Instruct.Q4_K_M.gguf",
    ))
    context_size: int = field(default_factory=lambda: _env_int("GENERATOR_CONTEXT_SIZE", 8192))
    max_output_tokens: int = field(default_factory=lambda: _env_int("GENERATOR_MAX_OUTPUT_TOKENS", 1200))
    temperature: float = field(default_factory=lambda: _env_float("GENERATOR_TEMPERATURE", 0.1))
    top_p: float = field(default_factory=lambda: _env_float("GENERATOR_TOP_P", 0.9))
    seed: int = field(default_factory=lambda: _env_int("GENERATOR_SEED", 42))
    request_timeout_seconds: float = field(default_factory=lambda: _env_float("GENERATOR_TIMEOUT_SECONDS", 300.0))

    # CPU/GPU knobs surfaced here for documentation/health-check purposes; the
    # actual values are consumed by docker-compose.yml's llama-generator service
    # command, not by this Python client (the client only talks HTTP to it).
    llama_threads: int = field(default_factory=lambda: _env_int("LLAMA_THREADS", 8))
    llama_gpu_layers: int = field(default_factory=lambda: _env_int("LLAMA_GPU_LAYERS", 0))

    structured_output_mode: str = field(
        default_factory=lambda: os.environ.get("GENERATOR_STRUCTURED_OUTPUT_MODE", "auto")
    )

    def __post_init__(self) -> None:
        if self.structured_output_mode not in STRUCTURED_OUTPUT_MODES:
            raise InvalidStructuredOutputMode(
                f"GENERATOR_STRUCTURED_OUTPUT_MODE={self.structured_output_mode!r} is not one of "
                f"{sorted(STRUCTURED_OUTPUT_MODES)}"
            )


@dataclass(frozen=True)
class ApiSecuritySettings:
    """API-key auth for the new machine-to-machine endpoints (ingestion,
    retrieval, generator claims) -- distinct from the CISO dashboard's
    session-cookie auth (web/auth.py), which remains unchanged and is for the
    human-facing dashboard only."""

    api_key_header: str = field(default_factory=lambda: os.environ.get("API_KEY_HEADER", "X-API-Key"))
    api_key: str = field(default_factory=lambda: os.environ.get("API_KEY", "change-me"))


DEFAULT_LLAMACPP_CONFIG = LlamaCppConfig()
DEFAULT_API_SECURITY = ApiSecuritySettings()
