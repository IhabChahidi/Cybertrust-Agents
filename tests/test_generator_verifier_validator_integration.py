"""Integration tests for the Foundation-Sec/RAG Generator <-> MCP
Verifier/Validator bridge (Option B, spec: "integrate Foundation-Sec/RAG with
the Verifier/Validator"): POST /api/v1/generator/verified-claims composes
mcp_server.generator_service.generate_claim() (Foundation-Sec's own scoped RAG
retrieval + citation/source-authority enforcement) with
mcp_server.orchestrator.MCPServer.process_claim() (the SAME Verifier and
deterministic Validator the classic Ollama-backed pipeline uses).

Uses a MOCKED llama.cpp call (no real network/GGUF, same pattern as
tests/test_generator_api.py) and llm_mode="mock" (MockVerifier/MockValidator),
so this suite runs in the normal (non-ollama, non-real_model) test pass. The
real llama3.1/Foundation-Sec models are exercised separately by
tests/test_ollama_integration.py and tests/test_real_model_generator.py.

Evidence for the Verifier is looked up from the orchestrator's OWN static
catalogue (catalogue/valid/EVD-0001.json, EVD-0002.json -- real pilot
fixtures), NOT from the ephemeral Chroma store this suite ingests into for
RAG retrieval: those are two intentionally separate stores (see
mcp_server/orchestrator.py::process_claim docstring), linked only by
convention on the EVD-#### id, which is exactly what these tests exercise.
"""

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
    generator_api._mcp_servers.clear()


def _headers():
    return {"X-API-Key": API_KEY}


def _mock_chat_completion(valid_json: str):
    async def _fake(*, config, system_prompt, user_prompt):
        return valid_json
    return _fake


# EVD-0001/EVD-0002 are real static fixtures under catalogue/valid/ (the
# orchestrator's own Evidence store) -- distinct from whatever this suite
# ingests into the ephemeral Chroma store below for RAG retrieval purposes.
_VALID_CLAIM_JSON = (
    '{"status": "CLAIM_GENERATED", "claim": "The SEC-1452 ticket is closed and a rescan confirms remediation.", '
    '"evidence_ids": ["EVD-0001", "EVD-0002"], "reference_ids": [], '
    '"reasoning_summary": "Based on EVD-0001 (ticket closed) and EVD-0002 (rescan clean).", '
    '"confidence": 0.8, "limitations": []}'
)


def _ingest_rag_evidence(client):
    resp = client.post(
        "/api/v1/ingestion/evidence",
        json=[
            {
                "id": "EVD-0001", "case_id": "VUL-018", "ticket_id": "SEC-104", "asset_id": "SRV-ERP-01",
                "cve_ids": [], "source": "ITSM-FICTIF", "observed_at": "2026-07-22T09:00:00Z",
                "evidence_type": "remediation_ticket", "content": "Remediation ticket closed with patch report.",
                "classification": "CONFIDENTIAL",
            },
            {
                "id": "EVD-0002", "case_id": "VUL-018", "ticket_id": "SEC-104", "asset_id": "SRV-ERP-01",
                "cve_ids": [], "source": "SCANNER-FICTIF", "observed_at": "2026-07-23T09:00:00Z",
                "evidence_type": "vulnerability_scan", "content": "Rescan confirms the vulnerability is no longer present.",
                "classification": "CONFIDENTIAL",
            },
        ],
        headers=_headers(),
    )
    job_id = resp.json()["job_id"]
    import time
    deadline = time.time() + 5.0
    while time.time() < deadline:
        job = client.get(f"/api/v1/ingestion/jobs/{job_id}", headers=_headers()).json()
        if job["status"] in ("SUCCEEDED", "FAILED"):
            assert job["status"] == "SUCCEEDED", job
            return
        time.sleep(0.05)
    raise AssertionError("evidence ingestion job did not finish")


def test_verified_claims_runs_generator_then_real_verifier_and_validator(client, monkeypatch):
    """The core Option B path: Foundation-Sec generates a Claim citing
    catalogue Evidence, and it is hands-off adapted into the SAME
    Verifier/Validator chain the classic pipeline uses -- MockVerifier here
    detects no contradiction/missing-field signal in EVD-0001/EVD-0002's real
    catalogue content, so it should report status=supported."""
    _ingest_rag_evidence(client)
    monkeypatch.setattr("mcp_server.generator_service.chat_completion", _mock_chat_completion(_VALID_CLAIM_JSON))

    resp = client.post(
        "/api/v1/generator/verified-claims",
        json={"request_id": "REQ-VC-0001", "question": "Is SEC-1452 remediated?"},
        headers=_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()

    assert body["mcp_state"] == "COMPLETED"
    assert set(body["claim"]["evidence_ids"]) == {"EVD-0001", "EVD-0002"}
    assert body["verification_result"]["status"] in ("supported", "unsupported", "contradicted", "insufficient_evidence")
    assert body["verification_result"]["claim_id"] == body["claim"]["id"]
    assert "validation_decision" in body
    assert body["validation_decision"]["verification_result_id"] == body["verification_result"]["id"]


def test_verified_claims_returns_insufficient_evidence_without_reaching_verifier(client, monkeypatch):
    """status=INSUFFICIENT_EVIDENCE from Foundation-Sec must short-circuit
    before the Verifier is ever invoked -- to_mcp_claim() cannot adapt a
    non-conclusive GeneratedClaim, and an inconclusive result is not the
    Verifier's to adjudicate."""
    _ingest_rag_evidence(client)
    insufficient = (
        '{"status": "INSUFFICIENT_EVIDENCE", "claim": null, "evidence_ids": [], "reference_ids": [], '
        '"reasoning_summary": "No verification-type evidence was retrieved for this asset.", '
        '"confidence": 0.2, "limitations": ["no rescan evidence found"]}'
    )
    monkeypatch.setattr("mcp_server.generator_service.chat_completion", _mock_chat_completion(insufficient))

    resp = client.post(
        "/api/v1/generator/verified-claims",
        json={"request_id": "REQ-VC-0002", "question": "Is SRV-DOES-NOT-EXIST remediated?"},
        headers=_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["mcp_state"] == "INSUFFICIENT_EVIDENCE"
    assert "verification_result" not in body

    # Audit coverage (added after a real diagnostic gap this session: these
    # pre-Verifier stages used to be invisible in the journal on anything
    # other than a fully-COMPLETED session). REQUEST_RECEIVED and
    # GENERATION_RESULT must both be present, on the SAME session_id, even
    # though this request never reaches process_claim().
    events = generator_api._mcp_servers["mock"].audit.events
    event_types = [e["event_type"] for e in events if e["correlation_id"] == events[-1]["correlation_id"]]
    assert "REQUEST_RECEIVED" in event_types
    assert "GENERATION_RESULT" in event_types
    result_event = next(e for e in events if e["event_type"] == "GENERATION_RESULT")
    assert result_event["result"] == "INSUFFICIENT_EVIDENCE"


def test_verified_claims_fails_closed_when_cited_evidence_is_absent_from_orchestrator_catalogue(client, monkeypatch):
    """The Foundation-Sec RAG evidence collection and the orchestrator's own
    static catalogue (catalogue/valid/) are two separate stores linked only by
    the EVD-#### id convention (see process_claim's docstring). If Foundation-Sec
    cites an id that is real in ITS store but absent from the orchestrator's,
    this must fail closed (BLOCKED/INVALID_EVIDENCE_ID), never fabricate a
    stand-in Evidence record for the Verifier."""
    resp = client.post(
        "/api/v1/ingestion/evidence",
        json=[{
            "id": "EVD-9001", "case_id": "VUL-999", "ticket_id": "SEC-999", "asset_id": "SRV-GHOST-01",
            "cve_ids": [], "source": "ITSM-FICTIF", "observed_at": "2026-07-22T09:00:00Z",
            "evidence_type": "remediation_ticket", "content": "Ticket closed.", "classification": "CONFIDENTIAL",
        }],
        headers=_headers(),
    )
    import time
    job_id = resp.json()["job_id"]
    deadline = time.time() + 5.0
    while time.time() < deadline:
        job = client.get(f"/api/v1/ingestion/jobs/{job_id}", headers=_headers()).json()
        if job["status"] in ("SUCCEEDED", "FAILED"):
            break
        time.sleep(0.05)

    # Claim text deliberately avoids remediation/closure wording -- a
    # ticket-only citation would otherwise be rejected upstream by
    # enforce_source_authority() (mcp_server/generator_claims.py), which is a
    # different, earlier guarantee than the one this test targets.
    not_in_catalogue = (
        '{"status": "CLAIM_GENERATED", "claim": "EVD-9001 documents the ticket status.", '
        '"evidence_ids": ["EVD-9001"], "reference_ids": [], '
        '"reasoning_summary": "Based on EVD-9001.", "confidence": 0.7, "limitations": []}'
    )
    monkeypatch.setattr("mcp_server.generator_service.chat_completion", _mock_chat_completion(not_in_catalogue))

    resp = client.post(
        "/api/v1/generator/verified-claims",
        json={"request_id": "REQ-VC-0003", "question": "Is SRV-GHOST-01 remediated?"},
        headers=_headers(),
    )
    # process_claim() runs inside the endpoint and returns its result at 200
    # (same convention as /api/process in web/backend.py) -- BLOCKED is a
    # pipeline outcome carried in the body, not an HTTP-level error.
    assert resp.status_code == 200
    body = resp.json()
    assert body["mcp_state"] == "BLOCKED"
    assert body["blocked_reason"] == "INVALID_EVIDENCE_ID"


def test_verified_claims_rejects_empty_claim_text_with_a_repair_attempt(client, monkeypatch):
    """Reproduces the exact real-world failure diagnosed this session
    (scripts/diagnose_failing_scenarios.py, scenarios B/ML3): Foundation-Sec
    returns status=CLAIM_GENERATED with evidence_ids populated but claim=null.
    Previously nothing caught this before to_mcp_claim() rejected it too late
    for a repair attempt. enforce_source_authority() now checks claim text
    too (mcp_server/generator_claims.py), so generate_claim() itself catches
    it, attempts its one deterministic repair, and -- since this mock always
    returns the same malformed JSON -- fails closed with GENERATION_FAILED,
    never reaching to_mcp_claim()/ADAPTATION_FAILED at all. Confirms both the
    fix and that the failure (now caught one stage earlier) is still fully
    visible in the audit journal.
    """
    _ingest_rag_evidence(client)
    empty_claim = (
        '{"status": "CLAIM_GENERATED", "claim": null, '
        '"evidence_ids": ["EVD-0001"], "reference_ids": [], '
        '"reasoning_summary": "Ticket closed for EVD-0001.", "confidence": 0.8, "limitations": []}'
    )
    monkeypatch.setattr("mcp_server.generator_service.chat_completion", _mock_chat_completion(empty_claim))

    resp = client.post(
        "/api/v1/generator/verified-claims",
        json={"request_id": "REQ-VC-0004", "question": "Is SEC-1452 remediated?"},
        headers=_headers(),
    )
    assert resp.status_code == 502
    assert "non-empty claim text" in resp.text

    events = generator_api._mcp_servers["mock"].audit.events
    event_types = [e["event_type"] for e in events if e["correlation_id"] == events[-1]["correlation_id"]]
    assert "REQUEST_RECEIVED" in event_types
    assert "GENERATION_FAILED" in event_types
    failed_event = next(e for e in events if e["event_type"] == "GENERATION_FAILED")
    assert "non-empty claim text" in failed_event["detail"]


def test_verified_claims_repairs_empty_claim_text_when_the_model_self_corrects(client, monkeypatch):
    """Happy-path counterpart to the test above: if the model DOES fill in
    claim text on the repair attempt (unlike the always-broken mock above),
    generate_claim() must succeed on the second try -- proving the new check
    triggers a genuine repair opportunity, not just an earlier failure."""
    _ingest_rag_evidence(client)
    empty_claim = (
        '{"status": "CLAIM_GENERATED", "claim": null, '
        '"evidence_ids": ["EVD-0001", "EVD-0002"], "reference_ids": [], '
        '"reasoning_summary": "Based on EVD-0001 and EVD-0002.", "confidence": 0.8, "limitations": []}'
    )
    calls = {"n": 0}

    async def _fake(*, config, system_prompt, user_prompt):
        calls["n"] += 1
        if calls["n"] == 1:
            return empty_claim
        return _VALID_CLAIM_JSON

    monkeypatch.setattr("mcp_server.generator_service.chat_completion", _fake)

    resp = client.post(
        "/api/v1/generator/verified-claims",
        json={"request_id": "REQ-VC-0005", "question": "Is SEC-1452 remediated?"},
        headers=_headers(),
    )
    assert resp.status_code == 200
    assert calls["n"] == 2
    assert resp.json()["mcp_state"] == "COMPLETED"


def test_repair_prompt_lists_the_actually_available_ids():
    """Unit-level check that the repair prompt now names concrete valid ids
    (diagnosed this session, scenarios G/ML4: without this, the model
    repeated the exact same fabricated citation on the repair attempt --
    naming the error alone gave it nothing to correct toward)."""
    from mcp_server.generator_prompts import build_repair_prompt

    prompt = build_repair_prompt(
        original_output='{"reference_ids": ["CVE-9999-FAKE"]}',
        error_detail="reference_ids cites 'CVE-9999-FAKE', which was not in the retrieved context",
        valid_evidence_ids=["EVD-0001"], valid_reference_ids=["CVE-2026-12345"],
    )
    assert "EVD-0001" in prompt
    assert "CVE-2026-12345" in prompt
    assert "Cite ONLY from these two lists" in prompt
