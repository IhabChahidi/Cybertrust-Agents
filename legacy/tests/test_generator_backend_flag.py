"""GENERATOR_BACKEND feature flag and the FoundationSecRagGenerator bridge
(spec: "Prepare Verifier integration without enabling it by default").
Covers mcp_server/config.py's generator_backend field,
mcp_server/llm_roles/factory.py::build_generator, and
mcp_server/llm_roles/foundation_sec_generator.py.
"""

from datetime import datetime, timezone

import jsonschema
import pytest

from mcp_server.config import MCPConfig
from mcp_server.errors import LLMOutputContractViolation, MCPTechnicalFailure
from mcp_server.generator_claims import GeneratedClaim
from mcp_server.llm_roles.factory import build_generator
from mcp_server.llm_roles.foundation_sec_generator import FoundationSecRagGenerator
from mcp_server.llm_roles.llama_generator import LlamaGenerator
from mcp_server.llm_roles.mock_generator import MockGenerator
from mcp_server.llm_roles.real_stub import RealGenerator
from mcp_server.rag.retrieval import RagUnavailable
from mcp_server.schemas import CLAIM_SCHEMA

pytestmark = pytest.mark.unit


def test_ollama_backend_is_the_default():
    config = MCPConfig()
    assert config.generator_backend == "ollama"


def test_default_backend_selects_the_existing_llm_mode_dispatch():
    assert isinstance(build_generator(MCPConfig(llm_mode="mock")), MockGenerator)
    assert isinstance(build_generator(MCPConfig(llm_mode="llama")), LlamaGenerator)
    assert isinstance(build_generator(MCPConfig(llm_mode="real")), RealGenerator)


def test_foundation_sec_rag_backend_can_be_selected_regardless_of_llm_mode():
    for llm_mode in ("mock", "llama", "real"):
        config = MCPConfig(llm_mode=llm_mode, generator_backend="foundation_sec_rag")
        assert isinstance(build_generator(config), FoundationSecRagGenerator)


def test_unknown_generator_backend_fails_at_config_construction():
    with pytest.raises(ValueError, match="GENERATOR_BACKEND"):
        MCPConfig(generator_backend="something_else")


def test_foundation_sec_generator_never_falls_back_silently(monkeypatch, tmp_path):
    """A retrieval failure must propagate as an explicit, audited exception --
    never be swallowed into a silent switch to a different Generator."""
    config = MCPConfig(generator_backend="foundation_sec_rag", journal_path=str(tmp_path / "journal.jsonl"))
    generator = FoundationSecRagGenerator(config)

    async def _raise_rag_unavailable(req, *, chroma, embeddings, rag_config, llamacpp_config):
        raise RagUnavailable("ChromaDB is unavailable for this test")

    monkeypatch.setattr("mcp_server.llm_roles.foundation_sec_generator.generate_claim", _raise_rag_unavailable)

    with pytest.raises(MCPTechnicalFailure):
        generator.generate(
            request_statement="Is EVD-0001 remediated?", evidence=[], claim_id="CLM-0001",
            session_id="SES-TEST0001", correlation_id="COR-TEST0001",
        )


def test_foundation_sec_generator_rejects_insufficient_evidence_rather_than_fabricating_a_claim(monkeypatch, tmp_path):
    config = MCPConfig(generator_backend="foundation_sec_rag", journal_path=str(tmp_path / "journal.jsonl"))
    generator = FoundationSecRagGenerator(config)

    insufficient = GeneratedClaim(
        claim_id="GCLM-TEST0001", request_id="REQ-TEST0001", status="INSUFFICIENT_EVIDENCE", claim=None,
        evidence_ids=[], reference_ids=[], reasoning_summary="no evidence found", confidence=0.1,
        limitations=[], generated_at=datetime.now(timezone.utc), model_name="test-model",
        retrieval_trace_id="RAGTRC-TEST0001",
    )

    async def _fake_generate_claim(req, *, chroma, embeddings, rag_config, llamacpp_config):
        return insufficient

    monkeypatch.setattr("mcp_server.llm_roles.foundation_sec_generator.generate_claim", _fake_generate_claim)

    with pytest.raises(LLMOutputContractViolation):
        generator.generate(
            request_statement="Is EVD-0001 remediated?", evidence=[], claim_id="CLM-0001",
            session_id="SES-TEST0001", correlation_id="COR-TEST0001",
        )


def test_foundation_sec_generator_returns_a_claim_schema_conformant_dict(monkeypatch, tmp_path):
    """Both backends must return compatible Claim objects: whatever
    FoundationSecRagGenerator.generate() returns must validate against the
    exact same CLAIM_SCHEMA the existing Generators (Mock/Llama/Real) do."""
    config = MCPConfig(generator_backend="foundation_sec_rag", journal_path=str(tmp_path / "journal.jsonl"))
    generator = FoundationSecRagGenerator(config)

    generated = GeneratedClaim(
        claim_id="GCLM-TEST0002", request_id="REQ-TEST0002", status="CLAIM_GENERATED",
        claim="The ticket is closed and a rescan confirms remediation.",
        evidence_ids=["EVD-0001"], reference_ids=["CVE-2026-12345"],
        reasoning_summary="Based on EVD-0001.", confidence=0.8, limitations=[],
        generated_at=datetime.now(timezone.utc), model_name="test-model", retrieval_trace_id="RAGTRC-TEST0002",
    )

    async def _fake_generate_claim(req, *, chroma, embeddings, rag_config, llamacpp_config):
        return generated

    monkeypatch.setattr("mcp_server.llm_roles.foundation_sec_generator.generate_claim", _fake_generate_claim)

    claim = generator.generate(
        request_statement="Is EVD-0001 remediated?", evidence=[], claim_id="CLM-0042",
        session_id="SES-TEST0002", correlation_id="COR-TEST0002",
    )
    jsonschema.Draft7Validator(CLAIM_SCHEMA).validate(claim)
    assert claim["id"] == "CLM-0042"
    assert claim["evidence_ids"] == ["EVD-0001"]
    assert claim["reference_ids"] == ["CVE-2026-12345"]
    assert claim["retrieval_trace_id"] == "RAGTRC-TEST0002"


def test_foundation_sec_generator_audit_preserves_fields_the_claim_schema_cannot_carry(monkeypatch, tmp_path):
    journal_path = tmp_path / "journal.jsonl"
    config = MCPConfig(generator_backend="foundation_sec_rag", journal_path=str(journal_path))
    generator = FoundationSecRagGenerator(config)

    generated = GeneratedClaim(
        claim_id="GCLM-UNIQUEMARKER", request_id="REQ-UNIQUEMARKER", status="CLAIM_GENERATED",
        claim="The ticket is closed and a rescan confirms remediation.",
        evidence_ids=["EVD-0001"], reference_ids=[], reasoning_summary="Based on EVD-0001.",
        confidence=0.7, limitations=[], generated_at=datetime.now(timezone.utc),
        model_name="unique-model-marker", retrieval_trace_id="RAGTRC-TEST0003",
    )

    async def _fake_generate_claim(req, *, chroma, embeddings, rag_config, llamacpp_config):
        return generated

    monkeypatch.setattr("mcp_server.llm_roles.foundation_sec_generator.generate_claim", _fake_generate_claim)

    generator.generate(
        request_statement="Is EVD-0001 remediated?", evidence=[], claim_id="CLM-0043",
        session_id="SES-TEST0003", correlation_id="COR-TEST0003",
    )
    journal_content = journal_path.read_text(encoding="utf-8")
    assert "GCLM-UNIQUEMARKER" in journal_content
    assert "REQ-UNIQUEMARKER" in journal_content
    assert "unique-model-marker" in journal_content
