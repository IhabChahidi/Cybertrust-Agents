"""End-to-end Generator + RAG integration (spec section 8/9/12), with call_ollama
mocked (no live model needed) — covers the citation-validation and
INSUFFICIENT_EVIDENCE-signaling requirements specifically.
"""

import pytest

from mcp_server.config import MCPConfig
from mcp_server.errors import LLMOutputContractViolation
from mcp_server.llm_roles.llama_generator import LlamaGenerator
from mcp_server.rag.generator_integration import RagAugmentation

pytestmark = pytest.mark.integration

_EVIDENCE = [{
    "id": "EVD-0001", "type": "ticket", "severity": "HIGH",
    "content": {"summary": "s", "raw_data": "status=Closed", "affected_assets": [], "indicators": []},
}]


def _rag_config(rag_enabled=True):
    return MCPConfig(llm_mode="llama", rag_enabled=rag_enabled)


def _patch_ollama(monkeypatch, statement, confidence=0.7, context="ctx"):
    def fake_call_ollama(**kwargs):
        # The AUTHORITATIVE_CORPORATE_EVIDENCE / REFERENCE_KNOWLEDGE delimiters
        # must actually reach the model's user_prompt when RAG is enabled and
        # found something.
        return {"statement": statement, "confidence": confidence, "context": context}
    monkeypatch.setattr("mcp_server.llm_roles.llama_generator.call_ollama", fake_call_ollama)


def _patch_rag(monkeypatch, augmentation: RagAugmentation):
    monkeypatch.setattr(
        "mcp_server.rag.generator_integration.augment_with_rag",
        lambda **kwargs: augmentation,
    )


def test_rag_context_is_delimited_and_reaches_the_prompt(monkeypatch):
    captured = {}

    def fake_call_ollama(**kwargs):
        captured["user_prompt"] = kwargs["user_prompt"]
        return {"statement": "CVE-2026-12345 est corrige sur SRV-ERP-01.", "confidence": 0.8, "context": "c"}
    monkeypatch.setattr("mcp_server.llm_roles.llama_generator.call_ollama", fake_call_ollama)
    _patch_rag(monkeypatch, RagAugmentation(
        available=True, context_text="<AUTHORITATIVE_CORPORATE_EVIDENCE>\n[record_id=EVD-0001 ...]\n"
                                      "</AUTHORITATIVE_CORPORATE_EVIDENCE>\n\n<REFERENCE_KNOWLEDGE>\n"
                                      "[record_id=CVE-2026-12345 ...]\n</REFERENCE_KNOWLEDGE>",
        reference_ids=["CVE-2026-12345"], authoritative_ids=["EVD-0001"], limitations=[], trace_id="RAGTRC-TEST",
    ))

    gen = LlamaGenerator(_rag_config())
    claim = gen.generate(
        request_statement="Is CVE-2026-12345 remediated on SRV-ERP-01?", evidence=_EVIDENCE,
        claim_id="CLM-0001", session_id="SES-TEST0000", correlation_id="COR-TEST0000",
    )

    assert "<AUTHORITATIVE_CORPORATE_EVIDENCE>" in captured["user_prompt"]
    assert "<REFERENCE_KNOWLEDGE>" in captured["user_prompt"]
    assert claim["reference_ids"] == ["CVE-2026-12345"]
    assert claim["retrieval_trace_id"] == "RAGTRC-TEST"
    assert claim["limitations"] == []


def test_hallucinated_cve_citation_is_rejected(monkeypatch):
    """The model cites a CVE id that was never retrieved -- must be treated as a
    fabricated citation, the same way an unknown EVD- id already was."""
    _patch_ollama(monkeypatch, "CVE-9999-99999 est corrige sur SRV-ERP-01.")
    _patch_rag(monkeypatch, RagAugmentation(
        available=True, context_text="<AUTHORITATIVE_CORPORATE_EVIDENCE>\n</AUTHORITATIVE_CORPORATE_EVIDENCE>\n\n<REFERENCE_KNOWLEDGE>\n</REFERENCE_KNOWLEDGE>",
        reference_ids=[],  # nothing was actually retrieved
        authoritative_ids=[], limitations=["RAG_NO_AUTHORITATIVE_EVIDENCE"], trace_id="RAGTRC-TEST",
    ))
    gen = LlamaGenerator(_rag_config())
    with pytest.raises(LLMOutputContractViolation):
        gen.generate(
            request_statement="q", evidence=_EVIDENCE, claim_id="CLM-0001",
            session_id="SES-TEST0000", correlation_id="COR-TEST0000",
        )


def test_citing_a_genuinely_retrieved_reference_id_is_accepted(monkeypatch):
    _patch_ollama(monkeypatch, "CVE-2026-12345 est corrige sur SRV-ERP-01.")
    _patch_rag(monkeypatch, RagAugmentation(
        available=True, context_text="ctx", reference_ids=["CVE-2026-12345"],
        authoritative_ids=["EVD-0001"], limitations=[], trace_id="RAGTRC-TEST",
    ))
    gen = LlamaGenerator(_rag_config())
    claim = gen.generate(
        request_statement="q", evidence=_EVIDENCE, claim_id="CLM-0001",
        session_id="SES-TEST0000", correlation_id="COR-TEST0000",
    )
    assert "CVE-2026-12345" in claim["statement"]


def test_no_authoritative_evidence_found_sets_limitation_flag(monkeypatch):
    _patch_ollama(monkeypatch, "Le ticket SEC-1452 est correctement remedie.")
    _patch_rag(monkeypatch, RagAugmentation(
        available=True, context_text="ctx", reference_ids=[], authoritative_ids=[],
        limitations=["RAG_NO_AUTHORITATIVE_EVIDENCE"], trace_id="RAGTRC-TEST",
    ))
    gen = LlamaGenerator(_rag_config())
    claim = gen.generate(
        request_statement="q", evidence=_EVIDENCE, claim_id="CLM-0001",
        session_id="SES-TEST0000", correlation_id="COR-TEST0000",
    )
    assert claim["limitations"] == ["RAG_NO_AUTHORITATIVE_EVIDENCE"]


def test_rag_unavailable_falls_back_to_evidence_only_generation_silently(monkeypatch):
    """RAG reporting unavailable must not add reference_ids/limitations/
    retrieval_trace_id to the Claim at all -- the Claim looks exactly like the
    pre-RAG shape."""
    _patch_ollama(monkeypatch, "Le ticket SEC-1452 est correctement remedie.")
    _patch_rag(monkeypatch, RagAugmentation(available=False, unavailable_reason="ChromaDB down"))
    gen = LlamaGenerator(_rag_config())
    claim = gen.generate(
        request_statement="q", evidence=_EVIDENCE, claim_id="CLM-0001",
        session_id="SES-TEST0000", correlation_id="COR-TEST0000",
    )
    assert "reference_ids" not in claim
    assert "limitations" not in claim
    assert "retrieval_trace_id" not in claim


def test_rag_disabled_by_default_produces_the_exact_same_shape_as_before(monkeypatch):
    _patch_ollama(monkeypatch, "Le ticket SEC-1452 est correctement remedie.")
    gen = LlamaGenerator(_rag_config(rag_enabled=False))
    claim = gen.generate(
        request_statement="q", evidence=_EVIDENCE, claim_id="CLM-0001",
        session_id="SES-TEST0000", correlation_id="COR-TEST0000",
    )
    assert set(claim.keys()) == {
        "schema_version", "session_id", "correlation_id", "id", "evidence_ids",
        "statement", "confidence", "context", "generated_at", "generator_role",
    }
