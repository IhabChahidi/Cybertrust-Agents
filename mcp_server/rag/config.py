"""RAG configuration, read from environment variables. Separate from
mcp_server.config.MCPConfig (which only gets a single `rag_enabled` flag) so the
much larger RAG-specific surface doesn't bloat the core pipeline config that
every test in the repo already constructs.
"""

import os
from dataclasses import dataclass, field

# The only four collections this system will ever create or query. Never
# accept an arbitrary collection name from an API client or from LLM output
# (spec section 2) -- every call site in this package validates against this
# set instead of taking a free-form string.
CORPORATE_EVIDENCE = "corporate_evidence"
MITRE_ATTACK = "mitre_attack"
VULNERABILITIES = "vulnerabilities"
RUNBOOKS = "runbooks"
ALL_COLLECTIONS = frozenset({CORPORATE_EVIDENCE, MITRE_ATTACK, VULNERABILITIES, RUNBOOKS})
REFERENCE_COLLECTIONS = frozenset({MITRE_ATTACK, VULNERABILITIES, RUNBOOKS})


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
class RagConfig:
    embedding_model: str = field(default_factory=lambda: os.environ.get("EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5"))
    embedding_device: str = field(default_factory=lambda: os.environ.get("EMBEDDING_DEVICE", "cpu"))
    embedding_batch_size: int = field(default_factory=lambda: _env_int("EMBEDDING_BATCH_SIZE", 32))

    # No Chroma server exists in this environment (no Docker), so the default
    # is a local on-disk PersistentClient. Set CHROMA_HOST to switch to
    # chromadb's HttpClient against a real server (e.g. in Docker Compose)
    # without any code change.
    chroma_host: str | None = field(default_factory=lambda: os.environ.get("CHROMA_HOST") or None)
    chroma_port: int = field(default_factory=lambda: _env_int("CHROMA_PORT", 8000))
    chroma_tenant: str = field(default_factory=lambda: os.environ.get("CHROMA_TENANT", "default_tenant"))
    chroma_database: str = field(default_factory=lambda: os.environ.get("CHROMA_DATABASE", "cybertrust"))
    chroma_persist_dir: str = field(default_factory=lambda: os.environ.get("CHROMA_PERSIST_DIR", "mcp_server/rag_store"))

    vector_top_k: int = field(default_factory=lambda: _env_int("RAG_VECTOR_TOP_K", 12))
    final_top_k: int = field(default_factory=lambda: _env_int("RAG_FINAL_TOP_K", 8))
    max_context_tokens: int = field(default_factory=lambda: _env_int("RAG_MAX_CONTEXT_TOKENS", 5000))
    min_score: float = field(default_factory=lambda: _env_float("RAG_MIN_SCORE", 0.35))

    # The existing Generator model's stated context window (spec section 4).
    # Kept here for documentation/validation; the actual reservation math lives
    # in context_builder.py.
    generator_max_context_tokens: int = 8192


DEFAULT_RAG_CONFIG = RagConfig()
