"""Selects LLM role implementations per MCPConfig.llm_mode.

The Generator stays factory-free: the live /api/v1/generator/verified-claims
path never calls build_generator() at all (it calls
mcp_server.generator_service.generate_claim() directly, which always runs
Foundation-Sec-8B via llama.cpp). The classic Ollama-backed LlamaGenerator,
the "real" provider stubs, and the FoundationSecRagGenerator bridge for the
old /api/process endpoint remain archived in legacy/mcp_server/llm_roles/
(see legacy/README.md) -- build_generator() below still only supports "mock".

The Verifier is restored for llm_mode == "llama": LlamaVerifier
(mcp_server/llm_roles/llama_verifier.py, calling Ollama via ollama_client.py)
runs a real LLM judgment (config.verifier_model, Qwen 2.5:7b-instruct by
default -- see mcp_server/config.py) against the Claim produced by the
Foundation-Sec Generator. Chosen over Llama 3.1 for this role based on the
comparative benchmark in reports/CyberTrust_Agents_Baseline_Attendu_vs_Resultat.docx:
Qwen 2.5 tied Foundation-Sec-8B at 3/3 on the ground-truth Verifier cases and
showed the best resistance to prompt injection in Evidence content, while
Llama 3.1 scored 2/3 and was the weakest against injection -- it is kept
available only as a Generator/benchmark model, never wired as the production
Verifier.

PolicyValidator is NOT part of the legacy archive: despite living under the
old llm_mode == "llama" branch, it calls no LLM and has no Ollama dependency
-- it is (and was always) a pure deterministic policy engine identical to
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
        "and 'real' generator implementations remain archived in legacy/mcp_server/llm_roles/ "
        "(not deployed in this stack). Only 'mock' is supported here -- the live "
        "/api/v1/generator/verified-claims path does not use this factory function at all "
        "(it always runs Foundation-Sec-8B via mcp_server.generator_service)."
    )


def build_verifier(config: MCPConfig) -> Verifier:
    if config.llm_mode == "mock":
        return MockVerifier()
    if config.llm_mode == "llama":
        from mcp_server.llm_roles.llama_verifier import LlamaVerifier
        return LlamaVerifier(config)
    raise NotImplementedError(f"llm_mode={config.llm_mode!r} has no verifier available.")


def build_validator(config: MCPConfig) -> Validator:
    if config.llm_mode == "mock":
        return MockValidator()
    if config.llm_mode == "llama":
        return PolicyValidator(config)
    raise NotImplementedError(f"llm_mode={config.llm_mode!r} has no validator available.")
