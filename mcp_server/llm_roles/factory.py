"""Selects mock, llama (local Ollama), or real LLM role implementations per MCPConfig.llm_mode."""

from mcp_server.config import MCPConfig
from mcp_server.llm_roles.base import Generator, Validator, Verifier
from mcp_server.llm_roles.llama_generator import LlamaGenerator
from mcp_server.llm_roles.llama_validator import LlamaValidator
from mcp_server.llm_roles.llama_verifier import LlamaVerifier
from mcp_server.llm_roles.mock_generator import MockGenerator
from mcp_server.llm_roles.mock_validator import MockValidator
from mcp_server.llm_roles.mock_verifier import MockVerifier
from mcp_server.llm_roles.real_stub import RealGenerator, RealValidator, RealVerifier


def build_generator(config: MCPConfig) -> Generator:
    if config.llm_mode == "mock":
        return MockGenerator()
    if config.llm_mode == "llama":
        return LlamaGenerator(config)
    return RealGenerator(config)


def build_verifier(config: MCPConfig) -> Verifier:
    if config.llm_mode == "mock":
        return MockVerifier()
    if config.llm_mode == "llama":
        return LlamaVerifier(config)
    return RealVerifier(config)


def build_validator(config: MCPConfig) -> Validator:
    if config.llm_mode == "mock":
        return MockValidator()
    if config.llm_mode == "llama":
        return LlamaValidator(config)
    return RealValidator(config)
