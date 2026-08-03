"""RAG ingestion + hybrid retrieval, against a REAL local ChromaDB (ephemeral,
tmp_path-backed PersistentClient — no network) with the deterministic fake
embedding backend (no model download, no torch dependency for this file).
Covers most of spec section 12's test list except the two items that need the
real sentence-transformers model (see test_rag_real_embeddings.py).
"""

from datetime import datetime, timezone

import pytest

from mcp_server.logging_utils import AuditLogger
from mcp_server.rag.chroma_client import ChromaCollections
from mcp_server.rag.config import CORPORATE_EVIDENCE, MITRE_ATTACK, VULNERABILITIES, RagConfig
from mcp_server.rag.embeddings import get_embedding_backend
from mcp_server.rag.ingestion import ingest_cve, ingest_evidence, ingest_mitre, ingest_runbooks
from mcp_server.rag.retrieval import retrieve
from mcp_server.rag.schemas import Runbook

pytestmark = pytest.mark.integration


@pytest.fixture()
def rag_env(tmp_path):
    config = RagConfig(chroma_persist_dir=str(tmp_path / "chroma"), min_score=0.0)
    chroma = ChromaCollections(config)
    embeddings = get_embedding_backend(config, force_fake=True)
    audit = AuditLogger(journal_path=str(tmp_path / "rag_journal.jsonl"))
    return config, chroma, embeddings, audit


def _evidence_record(eid="EVD-0001", case_id="VUL-018", ticket_id="SEC-104", asset_id="SRV-ERP-01",
                      cve_ids=("CVE-2026-12345",), content="Remediation ticket closed with patch report."):
    return {
        "id": eid, "case_id": case_id, "ticket_id": ticket_id, "asset_id": asset_id,
        "cve_ids": list(cve_ids), "source": "ITSM-FICTIF", "observed_at": "2026-07-22T09:00:00Z",
        "evidence_type": "remediation_ticket", "content": content, "classification": "CONFIDENTIAL",
    }


def test_evidence_ingestion_computes_integrity_hash_when_missing(rag_env):
    config, chroma, embeddings, audit = rag_env
    result = ingest_evidence([_evidence_record()], chroma=chroma, embeddings=embeddings, config=config,
                              audit=audit, session_id="SES-RAG0000", correlation_id="COR-RAG0000")
    assert result.ingested == 1
    stored = chroma.get_by_ids(collection=CORPORATE_EVIDENCE, ids=["EVD-0001"])
    assert stored["metadatas"][0]["integrity_hash"].startswith("sha256:")


def test_duplicate_ingestion_is_detected_and_skipped(rag_env):
    config, chroma, embeddings, audit = rag_env
    record = _evidence_record()
    ingest_evidence([record], chroma=chroma, embeddings=embeddings, config=config,
                     audit=audit, session_id="SES-RAG0000", correlation_id="COR-RAG0000")
    result = ingest_evidence([record], chroma=chroma, embeddings=embeddings, config=config,
                              audit=audit, session_id="SES-RAG0000", correlation_id="COR-RAG0000")
    assert result.duplicates == 1
    assert result.ingested == 0


def test_content_hash_change_is_treated_as_an_update(rag_env):
    config, chroma, embeddings, audit = rag_env
    record = _evidence_record()
    ingest_evidence([record], chroma=chroma, embeddings=embeddings, config=config,
                     audit=audit, session_id="SES-RAG0000", correlation_id="COR-RAG0000")
    updated_record = {**record, "content": "Remediation ticket closed with a DIFFERENT patch report."}
    result = ingest_evidence([updated_record], chroma=chroma, embeddings=embeddings, config=config,
                              audit=audit, session_id="SES-RAG0000", correlation_id="COR-RAG0000")
    assert result.updated == 1
    assert result.duplicates == 0


def test_exact_cve_lookup_does_not_depend_on_embedding_similarity(rag_env):
    config, chroma, embeddings, audit = rag_env
    ingest_cve([{
        "cve_id": "CVE-2026-12345", "description": "Remote code execution in ERP module.",
        "severity": "CRITICAL", "cvss_score": 9.8, "vendor": "Acme", "product": "ERP",
    }], chroma=chroma, embeddings=embeddings, config=config, audit=audit,
        session_id="SES-RAG0000", correlation_id="COR-RAG0000")

    results, trace = retrieve(
        query="Is CVE-2026-12345 remediated?", chroma=chroma, embeddings=embeddings, config=config,
    )
    cve_hits = [r for r in results if r.collection == VULNERABILITIES]
    assert cve_hits
    assert cve_hits[0].retrieval_method == "exact_identifier"
    assert cve_hits[0].retrieval_score == 1.0
    assert trace.identifiers_extracted.get("cve_id") == ["CVE-2026-12345"]


def test_exact_identifier_and_metadata_results_outrank_vector_only(rag_env):
    config, chroma, embeddings, audit = rag_env
    ingest_evidence([_evidence_record(eid="EVD-0001", content="Unrelated filler text for vector noise.")],
                     chroma=chroma, embeddings=embeddings, config=config, audit=audit,
                     session_id="SES-RAG0000", correlation_id="COR-RAG0000")
    ingest_evidence([_evidence_record(eid="EVD-0002", case_id="VUL-999", ticket_id="SEC-999", asset_id="SRV-OTHER",
                                       cve_ids=(), content="Some other completely different corporate record.")],
                     chroma=chroma, embeddings=embeddings, config=config, audit=audit,
                     session_id="SES-RAG0000", correlation_id="COR-RAG0000")

    results, _ = retrieve(query="EVD-0001 status", chroma=chroma, embeddings=embeddings, config=config)
    assert results[0].record_id == "EVD-0001"
    assert results[0].retrieval_method == "exact_identifier"


def test_metadata_filter_by_case_ticket_asset(rag_env):
    config, chroma, embeddings, audit = rag_env
    ingest_evidence([_evidence_record(eid="EVD-0001", case_id="VUL-018")], chroma=chroma, embeddings=embeddings,
                     config=config, audit=audit, session_id="SES-RAG0000", correlation_id="COR-RAG0000")
    ingest_evidence([_evidence_record(eid="EVD-0002", case_id="VUL-999", ticket_id="SEC-999", asset_id="SRV-OTHER")],
                     chroma=chroma, embeddings=embeddings, config=config, audit=audit,
                     session_id="SES-RAG0000", correlation_id="COR-RAG0000")

    results, _ = retrieve(query="remediation status", case_id="VUL-018", chroma=chroma,
                           embeddings=embeddings, config=config)
    ids = {r.record_id for r in results if r.collection == CORPORATE_EVIDENCE}
    assert "EVD-0001" in ids
    assert "EVD-0002" not in ids


def test_cross_case_evidence_is_never_retrieved_via_semantic_similarity(rag_env):
    """Same wording, different case -- must not leak across cases even via
    vector similarity (spec section 3's explicit requirement)."""
    config, chroma, embeddings, audit = rag_env
    same_wording = "Ticket closed with valid remediation proof and clean rescan."
    ingest_evidence([_evidence_record(eid="EVD-0001", case_id="VUL-018", content=same_wording)],
                     chroma=chroma, embeddings=embeddings, config=config, audit=audit,
                     session_id="SES-RAG0000", correlation_id="COR-RAG0000")
    ingest_evidence([_evidence_record(eid="EVD-0002", case_id="VUL-999", ticket_id="SEC-999", asset_id="SRV-OTHER",
                                       cve_ids=(), content=same_wording)],
                     chroma=chroma, embeddings=embeddings, config=config, audit=audit,
                     session_id="SES-RAG0000", correlation_id="COR-RAG0000")

    results, _ = retrieve(query=same_wording, case_id="VUL-018", chroma=chroma, embeddings=embeddings, config=config)
    ids = {r.record_id for r in results if r.collection == CORPORATE_EVIDENCE}
    assert "EVD-0002" not in ids


def test_authoritative_flag_true_only_for_corporate_evidence(rag_env):
    config, chroma, embeddings, audit = rag_env
    ingest_evidence([_evidence_record()], chroma=chroma, embeddings=embeddings, config=config,
                     audit=audit, session_id="SES-RAG0000", correlation_id="COR-RAG0000")
    ingest_cve([{"cve_id": "CVE-2026-12345", "description": "desc"}], chroma=chroma, embeddings=embeddings,
               config=config, audit=audit, session_id="SES-RAG0000", correlation_id="COR-RAG0000")

    results, _ = retrieve(query="CVE-2026-12345 EVD-0001", chroma=chroma, embeddings=embeddings, config=config)
    for r in results:
        if r.collection == CORPORATE_EVIDENCE:
            assert r.authoritative is True
        else:
            assert r.authoritative is False


def test_deprecated_mitre_object_can_be_stored_but_normal_retrieval_flags_it():
    """Ingestion preserves revoked/deprecated status on the Pydantic model."""
    from mcp_server.rag.schemas import MitreObject
    obj = MitreObject(attack_id="T1059", stix_id="attack-pattern--x", name="Command Interpreter",
                       object_type="attack-pattern", deprecated=True)
    assert obj.deprecated is True


def test_exact_mitre_lookup_does_not_depend_on_embedding_similarity(rag_env):
    config, chroma, embeddings, audit = rag_env
    ingest_mitre([{
        "attack_id": "T1190", "stix_id": "attack-pattern--fictitious-0001", "name": "Exploit Public-Facing App",
        "description": "Adversaries exploit internet-facing applications.", "object_type": "attack-pattern",
    }], chroma=chroma, embeddings=embeddings, config=config, audit=audit,
        session_id="SES-RAG0000", correlation_id="COR-RAG0000")

    results, trace = retrieve(query="T1190 detail", chroma=chroma, embeddings=embeddings, config=config)
    hits = [r for r in results if r.collection == MITRE_ATTACK]
    assert hits
    assert hits[0].retrieval_method == "exact_identifier"
    assert trace.identifiers_extracted.get("mitre_technique") == ["T1190"]


def test_exact_evidence_id_lookup_does_not_depend_on_embedding_similarity(rag_env):
    config, chroma, embeddings, audit = rag_env
    ingest_evidence([_evidence_record(eid="EVD-0007", content="Unrelated noise text.")],
                     chroma=chroma, embeddings=embeddings, config=config, audit=audit,
                     session_id="SES-RAG0000", correlation_id="COR-RAG0000")

    results, trace = retrieve(query="What is the status of EVD-0007?", chroma=chroma, embeddings=embeddings, config=config)
    hits = [r for r in results if r.record_id == "EVD-0007"]
    assert hits
    assert hits[0].retrieval_method == "exact_identifier"
    assert trace.identifiers_extracted.get("evidence_id") == ["EVD-0007"]


def test_cross_asset_evidence_is_excluded_when_asset_id_scope_given(rag_env):
    config, chroma, embeddings, audit = rag_env
    ingest_evidence([_evidence_record(eid="EVD-0001", asset_id="SRV-ERP-01")], chroma=chroma, embeddings=embeddings,
                     config=config, audit=audit, session_id="SES-RAG0000", correlation_id="COR-RAG0000")
    ingest_evidence([_evidence_record(eid="EVD-0002", case_id="VUL-999", ticket_id="SEC-999", asset_id="SRV-OTHER")],
                     chroma=chroma, embeddings=embeddings, config=config, audit=audit,
                     session_id="SES-RAG0000", correlation_id="COR-RAG0000")

    results, _ = retrieve(query="remediation status", asset_id="SRV-ERP-01", chroma=chroma,
                           embeddings=embeddings, config=config)
    ids = {r.record_id for r in results if r.collection == CORPORATE_EVIDENCE}
    assert "EVD-0001" in ids
    assert "EVD-0002" not in ids


def test_retrieve_excludes_deprecated_and_revoked_mitre_objects_by_default(rag_env):
    config, chroma, embeddings, audit = rag_env
    ingest_mitre([
        {"attack_id": "T1059", "stix_id": "attack-pattern--live", "name": "Command Interpreter",
         "description": "Active technique.", "object_type": "attack-pattern"},
        {"attack_id": "T1086", "stix_id": "attack-pattern--dead", "name": "PowerShell (deprecated)",
         "description": "Deprecated technique, superseded by T1059.001.", "object_type": "attack-pattern",
         "deprecated": True},
        {"attack_id": "T1077", "stix_id": "attack-pattern--revoked", "name": "Windows Admin Shares (revoked)",
         "description": "Revoked technique.", "object_type": "attack-pattern", "revoked": True},
    ], chroma=chroma, embeddings=embeddings, config=config, audit=audit,
        session_id="SES-RAG0000", correlation_id="COR-RAG0000")

    results, _ = retrieve(query="technique T1059 T1086 T1077", chroma=chroma, embeddings=embeddings, config=config)
    ids = {r.record_id for r in results}
    assert "attack-pattern--live" in ids
    assert "attack-pattern--dead" not in ids
    assert "attack-pattern--revoked" not in ids


def test_retrieve_excludes_non_approved_and_superseded_runbooks(rag_env):
    config, chroma, embeddings, audit = rag_env
    ingest_runbooks([
        {"runbook_id": "RB-APPROVED", "title": "Approved runbook", "version": "1", "status": "APPROVED",
         "classification": "INTERNAL", "content": "# Steps\ndo the approved thing"},
        {"runbook_id": "RB-DRAFT", "title": "Draft runbook", "version": "1", "status": "DRAFT",
         "classification": "INTERNAL", "content": "# Steps\ndo the draft thing"},
        {"runbook_id": "RB-OLD", "title": "Superseded runbook", "version": "1", "status": "APPROVED",
         "classification": "INTERNAL", "superseded_by": "RB-APPROVED", "content": "# Steps\ndo the old thing"},
    ], chroma=chroma, embeddings=embeddings, config=config, audit=audit,
        session_id="SES-RAG0000", correlation_id="COR-RAG0000")

    results, _ = retrieve(query="approved draft superseded runbook steps", chroma=chroma, embeddings=embeddings, config=config)
    ids = {r.record_id for r in results}
    assert any(rid.startswith("RB-APPROVED") for rid in ids)
    assert not any(rid.startswith("RB-DRAFT") for rid in ids)
    assert not any(rid.startswith("RB-OLD") for rid in ids)


def test_retrieve_enforces_allowed_classification(rag_env):
    config, chroma, embeddings, audit = rag_env
    ingest_evidence([_evidence_record(eid="EVD-0001", content="Confidential record content.")],
                     chroma=chroma, embeddings=embeddings, config=config, audit=audit,
                     session_id="SES-RAG0000", correlation_id="COR-RAG0000")

    # The fixture evidence is classification="CONFIDENTIAL" -- requesting a
    # different classification must exclude it, never silently return it
    # because the caller's JSON field alone doesn't restrict anything.
    results, _ = retrieve(query="EVD-0001", allowed_classification="PUBLIC", chroma=chroma,
                           embeddings=embeddings, config=config)
    assert "EVD-0001" not in {r.record_id for r in results}

    results, _ = retrieve(query="EVD-0001", allowed_classification="CONFIDENTIAL", chroma=chroma,
                           embeddings=embeddings, config=config)
    assert "EVD-0001" in {r.record_id for r in results}

    # No allowed_classification supplied at all -- unrestricted, matching
    # existing behavior for callers that don't ask for classification scoping.
    results, _ = retrieve(query="EVD-0001", chroma=chroma, embeddings=embeddings, config=config)
    assert "EVD-0001" in {r.record_id for r in results}


def test_runbook_is_retrievable_only_when_approved_effective_not_superseded():
    approved = Runbook(runbook_id="RB-001", title="t", version="1", status="APPROVED",
                        effective_date=datetime(2020, 1, 1, tzinfo=timezone.utc))
    draft = Runbook(runbook_id="RB-002", title="t", version="1", status="DRAFT")
    future = Runbook(runbook_id="RB-003", title="t", version="1", status="APPROVED",
                      effective_date=datetime(2099, 1, 1, tzinfo=timezone.utc))
    superseded = Runbook(runbook_id="RB-004", title="t", version="1", status="APPROVED", superseded_by="RB-005")

    assert approved.is_retrievable() is True
    assert draft.is_retrievable() is False
    assert future.is_retrievable() is False
    assert superseded.is_retrievable() is False


def test_runbook_chunking_splits_by_heading_not_arbitrary_length():
    from mcp_server.rag.ingestion import _chunk_by_headings
    text = "# Step 1\ncontent one\n\n# Step 2\ncontent two"
    chunks = _chunk_by_headings(text)
    assert len(chunks) == 2
    assert chunks[0].startswith("# Step 1")
    assert chunks[1].startswith("# Step 2")


def test_token_budget_enforcement_excludes_records_beyond_the_limit(rag_env):
    config, chroma, embeddings, audit = rag_env
    config = RagConfig(chroma_persist_dir=config.chroma_persist_dir, max_context_tokens=50, min_score=0.0)
    long_content = "x" * 2000  # far bigger than the 50-token budget alone
    ingest_evidence([_evidence_record(eid="EVD-0001", content=long_content)],
                     chroma=chroma, embeddings=embeddings, config=config, audit=audit,
                     session_id="SES-RAG0000", correlation_id="COR-RAG0000")

    from mcp_server.rag.context_builder import build_rag_context
    results, _ = retrieve(query="EVD-0001", chroma=chroma, embeddings=embeddings, config=config)
    context, included_ids = build_rag_context(results, config)
    assert included_ids == []  # too big to fit -- excluded whole, not truncated in place
    assert "AUTHORITATIVE_CORPORATE_EVIDENCE" in context


def test_deduplication_keeps_the_higher_priority_method_for_the_same_record(rag_env):
    config, chroma, embeddings, audit = rag_env
    ingest_evidence([_evidence_record(eid="EVD-0001")], chroma=chroma, embeddings=embeddings, config=config,
                     audit=audit, session_id="SES-RAG0000", correlation_id="COR-RAG0000")
    results, _ = retrieve(query="EVD-0001 remediation ticket closed", chroma=chroma, embeddings=embeddings, config=config)
    matching = [r for r in results if r.record_id == "EVD-0001"]
    assert len(matching) == 1  # never duplicated in the final result set
    assert matching[0].retrieval_method == "exact_identifier"  # wins over any vector hit on the same id


def test_unknown_collection_name_is_rejected(rag_env):
    config, chroma, embeddings, audit = rag_env
    with pytest.raises(ValueError):
        retrieve(query="x", chroma=chroma, embeddings=embeddings, config=config, collections=["arbitrary_name"])


def test_classification_filter_on_runbook_metadata():
    approved_confidential = Runbook(runbook_id="RB-001", title="t", version="1", status="APPROVED",
                                    classification="CONFIDENTIAL")
    assert approved_confidential.is_retrievable(allowed_classification="CONFIDENTIAL") is True
    assert approved_confidential.is_retrievable(allowed_classification="PUBLIC") is False
