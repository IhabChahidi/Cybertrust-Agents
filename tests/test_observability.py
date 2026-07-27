"""Section 10: audit journal must expose enough to reconstruct a decision
(request id, evidence ids, Verifier status, diagnostic codes, risk level,
policy version/rule, final decision) without leaking raw secrets."""

from tests.conftest import make_request


def test_journal_exposes_full_decision_trail_without_secrets(mcp):
    result = mcp.process_request(make_request(["EVD-0001", "EVD-0002"]))
    assert result["mcp_state"] == "COMPLETED"

    events_by_type = {e["event_type"]: e for e in mcp.audit.events}

    assert "SELECTION_EVIDENCE" in events_by_type
    assert "2 evidence selected" in events_by_type["SELECTION_EVIDENCE"]["detail"]

    assert "VERIFICATION" in events_by_type
    assert result["verification_result"]["status"] in events_by_type["VERIFICATION"]["detail"]

    assert "DIAGNOSTICS" in events_by_type  # always logged, even with zero warnings

    assert "SCORING" in events_by_type
    assert result["mcp_score"]["risk_level"] in events_by_type["SCORING"]["detail"]

    assert "VALIDATION" in events_by_type
    validation_detail = events_by_type["VALIDATION"]["detail"]
    assert result["validation_decision"]["decision"] in validation_detail
    assert "policy_rule=" in validation_detail
    assert "policy_version=" in validation_detail

    # Every event carries session/correlation id (request-level traceability).
    for event in mcp.audit.events:
        assert event["session_id"] == result["session_id"]
        assert event["correlation_id"] == result["correlation_id"]


def test_journal_never_contains_a_secret_shaped_value_from_evidence_or_request(mcp):
    secret_statement = "Contexte api_key=LEAKED-SECRET-VALUE a verifier."
    mcp.process_request(make_request(["EVD-0001"], statement=secret_statement))
    for event in mcp.audit.events:
        assert "LEAKED-SECRET-VALUE" not in str(event)


def test_schema_validation_failure_is_logged_with_its_event_code(mcp):
    from mcp_server.errors import EventCode
    from mcp_server.llm_roles.base import Generator

    class BadGenerator(Generator):
        def generate(self, **kwargs):
            return {"schema_version": "1.0", "id": "CLM-0001"}  # missing required fields

    mcp.generator = BadGenerator()
    result = mcp.process_request(make_request(["EVD-0001"]))
    assert result["mcp_state"] == "BLOCKED"
    assert result["blocked_reason"] == EventCode.SCHEMA_ERROR.value
    logged_codes = [e["event_type"] for e in mcp.audit.events]
    assert EventCode.SCHEMA_ERROR.value in logged_codes
