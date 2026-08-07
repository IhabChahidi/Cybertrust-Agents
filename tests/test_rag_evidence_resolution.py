"""Regression coverage for MCPServer._select_evidence_for_claim() and
_lookup_cve_severity() (mcp_server/orchestrator.py) -- the RAG-aware evidence
resolution path added for process_claim() (the Foundation-Sec/RAG bridge).

Before this fix, process_claim() resolved every cited evidence_id exclusively
against the static catalogue (catalogue/valid/*.json), which caused two real
production defects:
  1. An id ingested only via the RAG API (never mirrored into the static
     catalogue) failed closed with INVALID_EVIDENCE_ID even though it was
     real, retrievable evidence (observed on the ML1/ML3 scenarios).
  2. An id that happened to exist in BOTH stores under unrelated content
     silently substituted the stale static-catalogue record instead of the
     real RAG-ingested one (observed on Scenario A: EVD-0002 exists in
     catalogue/valid/EVD-0002.json with content unrelated to whatever a RAG
     caller actually ingested under that same id).

Uses the deterministic fake embedding backend (no model download, no torch
dependency, no network) -- ChromaCollections.get_by_ids() is a direct id
lookup that never needs to embed a query, so retrieval correctness here does
not depend on embedding quality at all.
"""

import uuid
from datetime import datetime, timezone

import pytest

from mcp_server.config import MCPConfig
from mcp_server.errors import MCPBlockedError
from mcp_server.logging_utils import AuditLogger
from mcp_server.orchestrator import MCPServer
from mcp_server.rag.chroma_client import ChromaCollections
from mcp_server.rag.config import RagConfig
from mcp_server.rag.embeddings import get_embedding_backend
from mcp_server.rag.ingestion import ingest_cve, ingest_evidence

pytestmark = pytest.mark.integration


@pytest.fixture()
def rag_env(tmp_path):
    config = RagConfig(chroma_persist_dir=str(tmp_path / "chroma"), min_score=0.0)
    chroma = ChromaCollections(config)
    embeddings = get_embedding_backend(config, force_fake=True)
    audit = AuditLogger(journal_path=str(tmp_path / "ingest_journal.jsonl"))
    return config, chroma, embeddings, audit


def _ingest_evidence(rag_env, records):
    config, chroma, embeddings, audit = rag_env
    return ingest_evidence(records, chroma=chroma, embeddings=embeddings, config=config, audit=audit,
                            session_id="SES-TESTINGEST01", correlation_id="COR-TESTINGEST01")


def _ingest_cve(rag_env, records):
    config, chroma, embeddings, audit = rag_env
    return ingest_cve(records, chroma=chroma, embeddings=embeddings, config=config, audit=audit,
                       session_id="SES-TESTINGEST01", correlation_id="COR-TESTINGEST01")


def _mcp_server(rag_env, tmp_path, *, with_chroma=True):
    _, chroma, _, _ = rag_env
    config = MCPConfig(llm_mode="mock", journal_path=str(tmp_path / "mcp_journal.jsonl"))
    return MCPServer(config, chroma=chroma if with_chroma else None)


def _claim(evidence_ids, statement="Test statement.", reference_ids=None):
    return {
        "schema_version": "1.0",
        "session_id": f"SES-{uuid.uuid4().hex[:12].upper()}",
        "correlation_id": f"COR-{uuid.uuid4().hex[:12].upper()}",
        "id": "CLM-0001",
        "evidence_ids": evidence_ids,
        "statement": statement,
        "confidence": 0.9,
        "context": "test",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator_role": "GENERATOR",
        "reference_ids": reference_ids or [],
        "limitations": [],
        "retrieval_trace_id": "RAGTRC-TEST0001",
    }


# --- Fix 1: RAG-only evidence, never in the static catalogue -----------------

def test_rag_only_evidence_id_resolves_without_static_catalogue_entry(rag_env, tmp_path):
    """EVD-9001 does not exist under catalogue/valid/ at all -- before the fix
    this failed closed with INVALID_EVIDENCE_ID even though it is real,
    RAG-ingested evidence (the ML1/ML3 production defect)."""
    _ingest_evidence(rag_env, [
        {"id": "EVD-9001", "case_id": "VUL-900", "source": "TEST", "observed_at": "2026-07-31T00:00:00Z",
         "evidence_type": "remediation_ticket", "classification": "INTERNAL",
         "content": "Ticket closed, vendor patch applied."},
    ])
    server = _mcp_server(rag_env, tmp_path)
    result = server.process_claim(_claim(["EVD-9001"]))
    assert result["mcp_state"] == "COMPLETED"
    assert result["verification_result"]["supporting_evidence"] == ["EVD-9001"]


# --- Fix 2: id collision between RAG and the static catalogue ---------------

def test_rag_record_takes_priority_over_colliding_static_catalogue_entry(rag_env, tmp_path):
    """EVD-0002 exists in BOTH stores: catalogue/valid/EVD-0002.json (stale,
    unrelated content with explicit 'patch_report=absent' / 'rescan_result=absent'
    markers) and this test's own fresh RAG ingestion (clean prose, no absence
    markers). Before the fix, the static catalogue always won -- the Verifier
    would see the wrong record and flag EXPLICIT_ABSENCE_MARKER_DETECTED even
    though the real (RAG) evidence contains no such marker."""
    _ingest_evidence(rag_env, [
        {"id": "EVD-0002", "case_id": "VUL-018", "source": "TEST", "observed_at": "2026-07-31T00:00:00Z",
         "evidence_type": "vulnerability_scan", "classification": "INTERNAL",
         "content": "Rescan confirms the vulnerability is no longer present."},
    ])
    server = _mcp_server(rag_env, tmp_path)
    result = server.process_claim(_claim(["EVD-0002"]))
    assert result["mcp_state"] == "COMPLETED"
    diag_codes = [d["code"] for d in result["validation_decision"]["diagnostic_details"]]
    assert "EXPLICIT_ABSENCE_MARKER_DETECTED" not in diag_codes, (
        "resolved the stale static-catalogue EVD-0002 instead of the real RAG-ingested record"
    )


# --- Fallback: id absent from RAG, present in the static catalogue ----------

def test_falls_back_to_static_catalogue_for_ids_not_in_rag(rag_env, tmp_path):
    """EVD-0001 is never RAG-ingested in this test -- only present in
    catalogue/valid/EVD-0001.json. Confirms the classic-pipeline fallback
    still works when self.chroma is set but a specific id isn't in it."""
    server = _mcp_server(rag_env, tmp_path)
    result = server.process_claim(_claim(["EVD-0001"]))
    assert result["mcp_state"] == "COMPLETED"
    assert result["verification_result"]["supporting_evidence"] == ["EVD-0001"]


# --- Fail-closed: absent from both stores ------------------------------------

def test_blocks_with_invalid_evidence_id_when_absent_from_both_stores(rag_env, tmp_path):
    server = _mcp_server(rag_env, tmp_path)
    result = server.process_claim(_claim(["EVD-9999"]))
    assert result["mcp_state"] == "BLOCKED"
    assert result["blocked_reason"] == "INVALID_EVIDENCE_ID"
    assert "EVD-9999" in result["detail"]
    assert "RAG store or static catalogue" in result["detail"]


# --- Classic pipeline (chroma=None) behaves exactly as before ---------------

def test_classic_pipeline_without_chroma_only_uses_static_catalogue(rag_env, tmp_path):
    """process_claim() with self.chroma=None (the classic pipeline's own
    MCPServer instances never pass chroma) must resolve purely from the
    static catalogue, matching pre-fix behavior exactly -- no regression for
    callers that never wire a chroma client in."""
    _ingest_evidence(rag_env, [
        {"id": "EVD-9002", "case_id": "VUL-901", "source": "TEST", "observed_at": "2026-07-31T00:00:00Z",
         "evidence_type": "remediation_ticket", "classification": "INTERNAL",
         "content": "Ticket closed, vendor patch applied."},
    ])
    server = _mcp_server(rag_env, tmp_path, with_chroma=False)
    # EVD-9002 was RAG-ingested but chroma is None here -- must fail closed,
    # never silently reach into a store this MCPServer was never given.
    result = server.process_claim(_claim(["EVD-9002"]))
    assert result["mcp_state"] == "BLOCKED"
    assert result["blocked_reason"] == "INVALID_EVIDENCE_ID"

    # EVD-0001 (static-only) still resolves normally.
    result = server.process_claim(_claim(["EVD-0001"]))
    assert result["mcp_state"] == "COMPLETED"


# --- _lookup_cve_severity() -------------------------------------------------

def test_lookup_cve_severity_returns_none_without_chroma(rag_env, tmp_path):
    server = _mcp_server(rag_env, tmp_path, with_chroma=False)
    assert server._lookup_cve_severity("CVE-2026-00001") is None


def test_lookup_cve_severity_returns_none_for_unknown_cve(rag_env, tmp_path):
    server = _mcp_server(rag_env, tmp_path)
    assert server._lookup_cve_severity("CVE-9999-99999") is None


def test_lookup_cve_severity_returns_ingested_severity(rag_env, tmp_path):
    _ingest_cve(rag_env, [
        {"cve_id": "CVE-2026-00001", "description": "Test CVE.", "severity": "CRITICAL", "cvss_score": 9.8},
    ])
    server = _mcp_server(rag_env, tmp_path)
    assert server._lookup_cve_severity("CVE-2026-00001") == "CRITICAL"


def test_rag_evidence_severity_derived_from_linked_cve(rag_env, tmp_path):
    """An adapted RAG Evidence with cve_ids set must inherit that CVE's real
    severity (not the MEDIUM default) -- confirms the derivation wiring
    inside _select_evidence_for_claim(), not just _lookup_cve_severity() in
    isolation."""
    _ingest_cve(rag_env, [
        {"cve_id": "CVE-2026-00002", "description": "Test CVE.", "severity": "CRITICAL", "cvss_score": 9.8},
    ])
    _ingest_evidence(rag_env, [
        {"id": "EVD-9003", "case_id": "VUL-902", "cve_ids": ["CVE-2026-00002"], "source": "TEST",
         "observed_at": "2026-07-31T00:00:00Z", "evidence_type": "remediation_ticket",
         "classification": "INTERNAL", "content": "Ticket closed, vendor patch applied."},
    ])
    server = _mcp_server(rag_env, tmp_path)
    resolved = server._select_evidence_for_claim(_fake_session(), _claim(["EVD-9003"]), ["EVD-9003"])
    assert resolved[0]["severity"] == "CRITICAL"


def test_rag_evidence_severity_defaults_to_medium_without_linked_cve(rag_env, tmp_path):
    _ingest_evidence(rag_env, [
        {"id": "EVD-9004", "case_id": "VUL-903", "source": "TEST", "observed_at": "2026-07-31T00:00:00Z",
         "evidence_type": "remediation_ticket", "classification": "INTERNAL", "content": "Ticket closed."},
    ])
    server = _mcp_server(rag_env, tmp_path)
    resolved = server._select_evidence_for_claim(_fake_session(), _claim(["EVD-9004"]), ["EVD-9004"])
    assert resolved[0]["severity"] == "MEDIUM"


def _fake_session():
    from mcp_server.orchestrator import MCPSession
    return MCPSession(session_id="SES-FAKESESSION01", correlation_id="COR-FAKESESSION01", state="SELECTION_EVIDENCE")


# --- Defensive fallback when the RAG store raises mid-request ---------------

class _RaisingChroma:
    """Stands in for a ChromaCollections whose get_by_ids() raises (RAG store
    unreachable mid-request) -- both _lookup_cve_severity() and
    _select_evidence_for_claim() must degrade gracefully rather than let the
    exception propagate and take down the whole request."""

    def get_by_ids(self, *, collection, ids):
        raise RuntimeError("simulated ChromaDB outage")


def test_lookup_cve_severity_returns_none_when_chroma_raises(tmp_path):
    config = MCPConfig(llm_mode="mock", journal_path=str(tmp_path / "mcp_journal.jsonl"))
    server = MCPServer(config, chroma=_RaisingChroma())
    assert server._lookup_cve_severity("CVE-2026-00001") is None


def test_select_evidence_for_claim_falls_back_to_static_catalogue_when_chroma_raises(tmp_path):
    """EVD-0001 exists only in the static catalogue. With a chroma client that
    raises on every call, resolution must still fall back to the static
    catalogue rather than blocking or propagating the exception -- the same
    degrade-gracefully contract ChromaUnavailable already has elsewhere in
    the RAG layer."""
    config = MCPConfig(llm_mode="mock", journal_path=str(tmp_path / "mcp_journal.jsonl"))
    server = MCPServer(config, chroma=_RaisingChroma())
    result = server.process_claim(_claim(["EVD-0001"]))
    assert result["mcp_state"] == "COMPLETED"
    assert result["verification_result"]["supporting_evidence"] == ["EVD-0001"]
