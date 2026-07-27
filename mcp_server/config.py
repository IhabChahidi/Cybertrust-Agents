"""MCP server configuration: endpoint whitelist, LLM mode switch, retry policy.

No secrets live here. Real API keys/endpoints are read from environment variables
only, at the point of use in llm_roles/real_stub.py, once access is available.
"""

import os
from dataclasses import dataclass, field

# Only these logical endpoints may be called by the MCP server (TC-12).
ENDPOINT_WHITELIST = {
    "GENERATOR_COPILOT_STUDIO",
    "VERIFIER_EXTERNAL_LLM",
    "VALIDATOR_EXTERNAL_LLM",
}

SUPPORTED_LLM_MODES = ("mock", "llama", "real")


@dataclass(frozen=True)
class MCPConfig:
    """Runtime configuration for one MCP session."""

    # "mock"  -> deterministic keyword-based stand-ins (no model at all).
    # "llama" -> local llama3.1 via Ollama, used as a real-LLM substitute
    #            while there is no Copilot Studio / external LLM access yet.
    # "real"  -> the eventual Copilot Studio + external LLM production wiring
    #            (mcp_server/llm_roles/real_stub.py), still to be implemented.
    llm_mode: str = field(default_factory=lambda: os.environ.get("MCP_LLM_MODE", "mock"))
    llm_timeout_seconds: float = 30.0
    llm_max_retries: int = 2
    catalogue_valid_dir: str = "catalogue/valid"
    journal_path: str = "mcp_server/journal.jsonl"

    ollama_host: str = field(default_factory=lambda: os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    # Fallback shared model, used by any role whose own env var isn't set.
    ollama_model: str = field(default_factory=lambda: os.environ.get("OLLAMA_MODEL", "llama3.1"))

    # Per-role model overrides for the two roles that are still genuinely
    # LLM-backed. There is no validator_model / VALIDATOR_OLLAMA_MODEL: the
    # Validator (mcp_server/llm_roles/policy_validator.py) is a deterministic
    # policy engine with no LLM call at all, so a model knob for it would be
    # dead configuration. It was removed rather than kept-but-unused.
    generator_model: str = field(default_factory=lambda: os.environ.get("GENERATOR_OLLAMA_MODEL", "qwen2.5:7b-instruct"))
    verifier_model: str = field(default_factory=lambda: os.environ.get("VERIFIER_OLLAMA_MODEL", "llama3.1"))

    def __post_init__(self):
        if self.llm_mode not in SUPPORTED_LLM_MODES:
            raise ValueError(f"Unsupported MCP_LLM_MODE: {self.llm_mode!r}")


DEFAULT_CONFIG = MCPConfig()
