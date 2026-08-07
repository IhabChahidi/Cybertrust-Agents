"""Tests for the new Generator/RAG FastAPI surface (web/generator_api.py):
API-key auth, health endpoints, ingestion job tracking, retrieval search, and
the /api/v1/generator/claims endpoint against a MOCKED llama.cpp server (no
real network call, no GGUF model required -- see
mcp_server.llm_roles.llamacpp_client.chat_completion, monkeypatched below).

Uses a real, ephemeral ChromaDB (tmp_path-backed PersistentClient) with the
deterministic fake embedding backend, same pattern as tests/test_rag_retrieval.py.
"""

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mcp_server.llamacpp_config import ApiSecuritySettings, LlamaCppConfig
from mcp_server.logging_utils import AuditLogger
from mcp_server.rag.chroma_client import ChromaCollections
from mcp_server.rag.config import RagConfig
from mcp_server.rag.embeddings import get_embedding_backend
from mcp_server.rag.jobs import JobService
from web import generator_api
from web.backend import app

pytestmark = pytest.mark.integration

API_KEY = "test-api-key"


async def _no_real_tokenizer(config, text, *, timeout_seconds=5.0):
    """Test-only stand-in for the real llama.cpp /tokenize endpoint: always
    returns None (no live llama.cpp server exists in these tests), forcing
    mcp_server.rag.token_budget to fall back to the conservative character
    approximation -- deterministic and instant, no network/DNS round-trip."""
    return None


@pytest.fixture()
def client(tmp_path, monkeypatch):
    config = RagConfig(chroma_persist_dir=str(tmp_path / "chroma"), min_score=0.0)
    chroma = ChromaCollections(config)
    embeddings = get_embedding_backend(config, force_fake=True)
    audit = AuditLogger(journal_path=str(tmp_path / "journal.jsonl"))
    jobs = JobService()
    llamacpp_config = LlamaCppConfig(base_url="http://mock-llama:8080/v1")
    security = ApiSecuritySettings(api_key=API_KEY)

    monkeypatch.setattr("mcp_server.llm_roles.llamacpp_client.tokenize", _no_real_tokenizer)

    app.dependency_overrides[generator_api.get_chroma] = lambda: chroma
    app.dependency_overrides[generator_api.get_embeddings] = lambda: embeddings
    app.dependency_overrides[generator_api.get_rag_config] = lambda: config
    app.dependency_overrides[generator_api.get_audit] = lambda: audit
    app.dependency_overrides[generator_api.get_job_service] = lambda: jobs
    app.dependency_overrides[generator_api.get_llamacpp_config] = lambda: llamacpp_config
    app.dependency_overrides[generator_api.get_api_security] = lambda: security

    yield TestClient(app)

    app.dependency_overrides.clear()


def _headers():
    return {"X-API-Key": API_KEY}


def _wait_for_job(client, job_id, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = client.get(f"/api/v1/ingestion/jobs/{job_id}", headers=_headers())
        assert resp.status_code == 200
        body = resp.json()
        if body["status"] in ("SUCCEEDED", "FAILED"):
            return body
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish within {timeout}s")


def test_health_live_requires_no_auth(client):
    resp = client.get("/health/live")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_protected_endpoint_rejects_missing_api_key(client):
    resp = client.post("/api/v1/retrieval/search", json={"query": "x"})
    assert resp.status_code == 401


def test_protected_endpoint_rejects_wrong_api_key(client):
    resp = client.post("/api/v1/retrieval/search", json={"query": "x"}, headers={"X-API-Key": "wrong"})
    assert resp.status_code == 401


def test_ingestion_job_not_found_returns_404(client):
    resp = client.get("/api/v1/ingestion/jobs/JOB-DOESNOTEXIST", headers=_headers())
    assert resp.status_code == 404


def _evidence_record(eid="EVD-0001"):
    return {
        "id": eid, "case_id": "VUL-018", "ticket_id": "SEC-104", "asset_id": "SRV-ERP-01",
        "cve_ids": ["CVE-2026-12345"], "source": "ITSM-FICTIF", "observed_at": "2026-07-22T09:00:00Z",
        "evidence_type": "remediation_ticket", "content": "Remediation ticket closed with patch report.",
        "classification": "CONFIDENTIAL",
    }


def _verification_scan_record(eid="EVD-0002"):
    # A distinct evidence_type from _evidence_record() -- enforce_source_authority()
    # (mcp_server/generator_claims.py) requires at least one verification-type
    # citation alongside a ticket when the claim asserts a remediation outcome
    # (spec: "a ticket status alone cannot prove technical remediation").
    return {
        "id": eid, "case_id": "VUL-018", "ticket_id": "SEC-104", "asset_id": "SRV-ERP-01",
        "cve_ids": ["CVE-2026-12345"], "source": "SCANNER-FICTIF", "observed_at": "2026-07-23T09:00:00Z",
        "evidence_type": "vulnerability_scan", "content": "Rescan confirms the vulnerability is no longer present.",
        "classification": "CONFIDENTIAL",
    }


def test_evidence_ingestion_end_to_end_via_job(client):
    resp = client.post("/api/v1/ingestion/evidence", json=[_evidence_record()], headers=_headers())
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]
    job = _wait_for_job(client, job_id)
    assert job["status"] == "SUCCEEDED"
    assert job["result"]["ingested"] == 1
    assert job["result"]["record_ids"] == ["EVD-0001"]


def test_kev_enrichment_skips_unknown_cve(client):
    resp = client.post(
        "/api/v1/ingestion/kev",
        json=[{"cve_id": "CVE-2099-99999", "known_ransomware_campaign_use": True}],
        headers=_headers(),
    )
    job = _wait_for_job(client, resp.json()["job_id"])
    assert job["status"] == "SUCCEEDED"
    assert job["result"]["updated"] == 0
    # ingest_kev() reuses the IngestionResult.skipped_suspicious slot to count
    # "skipped: no matching CVE record to enrich" -- not an injection signal
    # here, just the same dataclass field repurposed for this ingestion kind.
    assert job["result"]["skipped_suspicious"] == 1


def test_retrieval_search_finds_ingested_evidence(client):
    resp = client.post("/api/v1/ingestion/evidence", json=[_evidence_record()], headers=_headers())
    _wait_for_job(client, resp.json()["job_id"])

    resp = client.post(
        "/api/v1/retrieval/search", json={"query": "EVD-0001"}, headers=_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()
    ids = [r["record_id"] for r in body["results"]]
    assert "EVD-0001" in ids


def test_retrieval_search_rejects_empty_query(client):
    resp = client.post("/api/v1/retrieval/search", json={"query": "   "}, headers=_headers())
    assert resp.status_code == 400


def _mock_chat_completion(valid_json: str):
    async def _fake(*, config, system_prompt, user_prompt):
        return valid_json
    return _fake


def test_generator_claims_happy_path(client, monkeypatch):
    resp = client.post(
        "/api/v1/ingestion/evidence", json=[_evidence_record(), _verification_scan_record()], headers=_headers(),
    )
    _wait_for_job(client, resp.json()["job_id"])

    valid = (
        '{"status": "CLAIM_GENERATED", "claim": "The remediation ticket for the affected asset is closed and a '
        'rescan confirms the vulnerability is no longer present.", '
        '"evidence_ids": ["EVD-0001", "EVD-0002"], "reference_ids": [], '
        '"reasoning_summary": "Based on EVD-0001 (ticket closed) and EVD-0002 (rescan clean).", '
        '"confidence": 0.8, "limitations": []}'
    )
    monkeypatch.setattr("mcp_server.generator_service.chat_completion", _mock_chat_completion(valid))

    resp = client.post(
        "/api/v1/generator/claims",
        json={"request_id": "REQ-0001", "question": "Is EVD-0001 remediated?"},
        headers=_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "CLAIM_GENERATED"
    assert set(body["evidence_ids"]) == {"EVD-0001", "EVD-0002"}


def test_generator_claims_rejects_ticket_only_remediation_claim(client, monkeypatch):
    """enforce_source_authority() (mcp_server/generator_claims.py): a ticket
    record alone can never prove technical remediation -- a verification-type
    citation (scan/rescan/pentest/audit) is required whenever the claim text
    asserts a remediation/closure/compliance outcome (spec section 4)."""
    resp = client.post("/api/v1/ingestion/evidence", json=[_evidence_record()], headers=_headers())
    _wait_for_job(client, resp.json()["job_id"])

    ticket_only = (
        '{"status": "CLAIM_GENERATED", "claim": "The remediation ticket for the affected asset is closed.", '
        '"evidence_ids": ["EVD-0001"], "reference_ids": [], '
        '"reasoning_summary": "Based on EVD-0001, the ticket is closed.", '
        '"confidence": 0.8, "limitations": []}'
    )
    monkeypatch.setattr("mcp_server.generator_service.chat_completion", _mock_chat_completion(ticket_only))

    resp = client.post(
        "/api/v1/generator/claims",
        json={"request_id": "REQ-0001B", "question": "Is EVD-0001 remediated?"},
        headers=_headers(),
    )
    assert resp.status_code == 502


def test_generator_claims_repairs_once_then_succeeds(client, monkeypatch):
    resp = client.post(
        "/api/v1/ingestion/evidence", json=[_evidence_record(), _verification_scan_record()], headers=_headers(),
    )
    _wait_for_job(client, resp.json()["job_id"])

    calls = {"n": 0}
    valid = (
        '{"status": "CLAIM_GENERATED", "claim": "The remediation ticket for the affected asset is closed and a '
        'rescan confirms the vulnerability is no longer present.", '
        '"evidence_ids": ["EVD-0001", "EVD-0002"], "reference_ids": [], '
        '"reasoning_summary": "Based on EVD-0001 (ticket closed) and EVD-0002 (rescan clean).", '
        '"confidence": 0.8, "limitations": []}'
    )

    async def _fake(*, config, system_prompt, user_prompt):
        calls["n"] += 1
        if calls["n"] == 1:
            return "not json at all"
        return valid

    monkeypatch.setattr("mcp_server.generator_service.chat_completion", _fake)

    resp = client.post(
        "/api/v1/generator/claims",
        json={"request_id": "REQ-0002", "question": "Is EVD-0001 remediated?"},
        headers=_headers(),
    )
    assert resp.status_code == 200
    assert calls["n"] == 2


def test_generator_claims_rejects_hallucinated_citation_even_after_repair(client, monkeypatch):
    resp = client.post("/api/v1/ingestion/evidence", json=[_evidence_record()], headers=_headers())
    _wait_for_job(client, resp.json()["job_id"])

    hallucinated = (
        '{"status": "CLAIM_GENERATED", "claim": "EVD-9999 proves remediation.", '
        '"evidence_ids": ["EVD-9999"], "reference_ids": [], '
        '"reasoning_summary": "Based on EVD-9999.", "confidence": 0.9, "limitations": []}'
    )
    monkeypatch.setattr("mcp_server.generator_service.chat_completion", _mock_chat_completion(hallucinated))

    resp = client.post(
        "/api/v1/generator/claims",
        json={"request_id": "REQ-0003", "question": "Is EVD-0001 remediated?"},
        headers=_headers(),
    )
    assert resp.status_code == 502


def test_health_ready_reports_ready_when_everything_is_available(client, monkeypatch):
    async def _reachable(config, *, timeout_seconds=5.0):
        return True

    monkeypatch.setattr(generator_api, "health_check", _reachable)
    resp = client.get("/health/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert body["components"]["chromadb"] == "ready"
    assert body["components"]["embedding_backend"] == "ready"
    assert body["components"]["llama_cpp"] == "ready"


def test_health_ready_reports_not_ready_when_llama_cpp_unreachable(client, monkeypatch):
    async def _unreachable(config, *, timeout_seconds=5.0):
        return False

    monkeypatch.setattr(generator_api, "health_check", _unreachable)
    resp = client.get("/health/ready")
    assert resp.status_code == 503
    body = resp.json()["detail"]
    assert body["status"] == "not_ready"
    assert body["components"]["llama_cpp"] == "unavailable"


def test_health_ready_reports_not_ready_when_chromadb_unavailable(client, monkeypatch):
    async def _reachable(config, *, timeout_seconds=5.0):
        return True

    monkeypatch.setattr(generator_api, "health_check", _reachable)
    monkeypatch.setattr(type(generator_api.get_chroma()), "is_available", lambda self: False)
    resp = client.get("/health/ready")
    assert resp.status_code == 503
    assert resp.json()["detail"]["components"]["chromadb"] == "unavailable"


def test_health_ready_reports_not_ready_when_embedding_backend_unavailable(client, monkeypatch):
    from mcp_server.rag.embeddings import DeterministicHashEmbeddingBackend

    async def _reachable(config, *, timeout_seconds=5.0):
        return True

    monkeypatch.setattr(generator_api, "health_check", _reachable)
    monkeypatch.setattr(DeterministicHashEmbeddingBackend, "is_available", lambda self: False)
    resp = client.get("/health/ready")
    assert resp.status_code == 503
    assert resp.json()["detail"]["components"]["embedding_backend"] == "unavailable"


def test_health_ready_never_exposes_model_path_or_api_key(client, monkeypatch):
    async def _unreachable(config, *, timeout_seconds=5.0):
        return False

    monkeypatch.setattr(generator_api, "health_check", _unreachable)
    resp = client.get("/health/ready")
    body_text = resp.text
    assert generator_api.DEFAULT_LLAMACPP_CONFIG.model_path not in body_text
    assert API_KEY not in body_text


def test_health_ready_fails_when_json_schema_mode_is_required_but_unsupported(client, monkeypatch):
    async def _reachable(config, *, timeout_seconds=5.0):
        return True

    async def _unsupported(config, *, timeout_seconds=5.0):
        return False

    monkeypatch.setattr(generator_api, "health_check", _reachable)
    monkeypatch.setattr(generator_api, "probe_structured_output_capability", _unsupported)
    strict_config = generator_api.LlamaCppConfig(
        base_url="http://mock-llama:8080/v1", structured_output_mode="json_schema",
    )
    app.dependency_overrides[generator_api.get_llamacpp_config] = lambda: strict_config

    resp = client.get("/health/ready")
    assert resp.status_code == 503
    assert resp.json()["detail"]["components"]["structured_output"] == "unsupported"


# --- classification / collection authorization (spec section 6) -----------

def test_retrieval_search_enforces_allowed_classification(client):
    resp = client.post(
        "/api/v1/ingestion/evidence",
        json=[{**_evidence_record(), "classification": "CONFIDENTIAL"}],
        headers=_headers(),
    )
    _wait_for_job(client, resp.json()["job_id"])

    resp = client.post(
        "/api/v1/retrieval/search",
        json={"query": "EVD-0001", "allowed_classification": "PUBLIC"},
        headers=_headers(),
    )
    assert "EVD-0001" not in {r["record_id"] for r in resp.json()["results"]}


def test_retrieval_search_rejects_classification_escalation_attempt(client):
    """A CONFIDENTIAL record must not be returned just because the caller's
    JSON body claims a matching (or higher) classification -- the field is
    never trusted as authorization by itself, only used as a filter that can
    exclude, never as a credential that unlocks (spec section 6: "classification
    authorization is not trusted solely from a caller-provided JSON field")."""
    resp = client.post(
        "/api/v1/ingestion/evidence",
        json=[{**_evidence_record(), "id": "EVD-0005", "classification": "CONFIDENTIAL"}],
        headers=_headers(),
    )
    _wait_for_job(client, resp.json()["job_id"])

    # Caller asserts a DIFFERENT classification than the stored record's --
    # this must exclude the record rather than being treated as a valid grant.
    resp = client.post(
        "/api/v1/retrieval/search",
        json={"query": "EVD-0005", "allowed_classification": "SECRET"},
        headers=_headers(),
    )
    assert "EVD-0005" not in {r["record_id"] for r in resp.json()["results"]}


def test_retrieval_search_request_cannot_specify_arbitrary_collections(client):
    """The request schema (RetrievalSearchRequest) has no `collections` field
    at all -- there is no way for a caller (or, downstream, the LLM) to name
    an arbitrary collection through this endpoint; extra JSON fields are
    silently ignored by Pydantic's default config, never wired to retrieve()."""
    resp = client.post(
        "/api/v1/retrieval/search",
        json={"query": "x", "collections": ["some_other_database", "arbitrary_name"]},
        headers=_headers(),
    )
    assert resp.status_code == 200  # the extra field is ignored, not rejected and not honored
    assert "collections" not in generator_api.RetrievalSearchRequest.model_fields


def test_auth_failure_never_logs_the_submitted_or_configured_api_key(client, tmp_path):
    wrong_key_value = "SUPER-SECRET-WRONG-KEY-VALUE-12345"
    resp = client.post("/api/v1/retrieval/search", json={"query": "x"}, headers={"X-API-Key": wrong_key_value})
    assert resp.status_code == 401
    assert wrong_key_value not in resp.text

    # Nothing about the attempted key (or the real one) should ever reach the
    # audit journal -- require_api_key() never calls audit.log() at all, so
    # this also guards against a future change accidentally adding that call
    # without redacting it.
    from web.generator_api import _JOURNAL_PATH
    journal_file = Path(_JOURNAL_PATH)
    if journal_file.exists():
        content = journal_file.read_text(encoding="utf-8")
        assert wrong_key_value not in content
        assert API_KEY not in content


def test_require_api_key_uses_constant_time_comparison():
    """secrets.compare_digest, not `==`/`!=`, must back the comparison --
    guards against a future regression reintroducing a variable-time compare
    on a shared static secret."""
    import inspect

    source = inspect.getsource(generator_api.require_api_key)
    assert "compare_digest" in source
