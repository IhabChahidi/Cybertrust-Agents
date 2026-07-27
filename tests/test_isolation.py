"""TC-14 — Isolation between Verifier and Validator contexts, even under a shared model."""

import inspect

from mcp_server.llm_roles.base import Validator, Verifier
from mcp_server.llm_roles.mock_validator import MockValidator
from mcp_server.llm_roles.mock_verifier import MockVerifier


def test_verifier_signature_excludes_generator_context():
    """The Verifier interface cannot receive the Generator's prompt/history/session context."""
    params = set(inspect.signature(Verifier.verify).parameters)
    assert params == {"self", "claim", "evidence", "verification_id", "session_id", "correlation_id"}
    assert "generator_context" not in params
    assert "prompt_history" not in params


def test_validator_signature_excludes_evidence_and_claim():
    """The Validator interface cannot receive the Evidence catalogue, the Claim, or the
    Verifier's context. diagnostic_warnings (string codes only, mcp_server.diagnostics)
    is permitted — it is not raw Evidence content."""
    params = set(inspect.signature(Validator.validate).parameters)
    assert params == {
        "self", "verification_result", "mcp_score", "diagnostic_warnings",
        "decision_id", "session_id", "correlation_id",
    }
    assert "evidence" not in params
    assert "claim" not in params


def test_shared_model_two_sessions_do_not_leak_context():
    """Same underlying mock 'model' used for both roles across two sessions: no shared mutable state."""
    verifier = MockVerifier()
    validator = MockValidator()

    claim_a = {"id": "CLM-0001", "evidence_ids": ["EVD-0001"]}
    evidence_a = [{
        "id": "EVD-0001", "severity": "CRITICAL",
        "content": {"summary": "s", "raw_data": "status=Closed", "affected_assets": ["A"], "indicators": ["I"]},
    }]
    verification_a = verifier.verify(
        claim=claim_a, evidence=evidence_a, verification_id="VER-0001",
        session_id="SES-AAAAAAAA", correlation_id="COR-AAAAAAAA",
    )

    # The Validator call for a second, unrelated session must not be able to see
    # session A's VerificationResult unless explicitly passed as its argument.
    verification_b = {
        "id": "VER-0002", "status": "supported", "supporting_evidence": ["EVD-0002"],
        "missing_evidence": [], "reasoning_summary": "unrelated",
    }
    score_b = {"id": "MCP-SCORE-0002", "value": 40, "risk_level": "MEDIUM"}
    decision_b = validator.validate(
        verification_result=verification_b, mcp_score=score_b, diagnostic_warnings=[],
        decision_id="VAL-0002", session_id="SES-BBBBBBBB", correlation_id="COR-BBBBBBBB",
    )

    assert decision_b["verification_result_id"] == "VER-0002"
    assert "EVD-0001" not in decision_b["justification"]
    assert verification_a["id"] != decision_b["verification_result_id"]
