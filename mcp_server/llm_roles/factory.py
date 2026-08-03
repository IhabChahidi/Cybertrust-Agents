"""Selects LLM role implementations per MCPConfig.llm_mode.

The Ollama-backed classic pipeline (LlamaGenerator, LlamaVerifier, the "real"
provider stubs, and the FoundationSecRagGenerator bridge that let the classic
/api/process endpoint opt into the RAG generator via GENERATOR_BACKENDs) was
archived to legacy/mcp_server/llm_roles/ -- none of it is deployed anywhere in
docker-compose.yml (there is no Ollama service in this stack), and the live
/api/v1/generator/verified-claims path never calls build_generator() at all
(it calls mcp_server.generator_service.generate_claim() directly). Restore
from legacy/ (see legacy/README.md) if Ollama support is needed again.

PolicyValidator is NOT part of that archive: despite living under the old
llm_mode == "llama" branch, it calls no LLM and has no Ollama dependency --
it is (and was always) a pure deterministic policy engine identical to
MockValidator (both just call mcp_server.policy.decide()). It stays wired
under llm_mode == "llama" here so no external caller's llm_mode string
changes meaning.
"""

from mcp_server.config import MCPConfig
from mcp_server.llm_roles.base import Generator, Validator, Verifier
from mcp_server.llm_roles.mock_generator import MockGenerator
from mcp_server.llm_roles.mock_validator import MockValidator
from mcp_server.llm_roles.mock_verifier import MockVerifier
from mcp_server.llm_roles.policy_validator import PolicyValidator


def build_generator(config: MCPConfig) -> Generator:
    if config.llm_mode == "mock":
        return MockGenerator()
    raise NotImplementedError(
        f"llm_mode={config.llm_mode!r} has no generator available: the Ollama-backed "
        "and 'real' generator implementations were archived to legacy/mcp_server/llm_roles/ "
        "(not deployed in this stack). Only 'mock' is supported here -- the live "
        "/api/v1/generator/verified-claims path does not use this factory function at all."
    )


def build_verifier(config: MCPConfig) -> Verifier:
    if config.llm_mode == "mock":
        return MockVerifier()
    raise NotImplementedError(
        f"llm_mode={config.llm_mode!r} has no verifier available: the Ollama-backed "
        "verifier was archived to legacy/mcp_server/llm_roles/ (not deployed in this "
        "stack). Only 'mock' is supported."
    )


def build_validator(config: MCPConfig) -> Validator:
    if config.llm_mode == "mock":
        return MockValidator()
    if config.llm_mode == "llama":
        return PolicyValidator(config)
    raise NotImplementedError(f"llm_mode={config.llm_mode!r} has no validator available.")
