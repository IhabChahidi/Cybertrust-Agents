"""Reference-integrity and score-approval guards not covered by test_negative.py.

These target the orchestrator's defense-in-depth checks against a *misbehaving*
role output — schema-valid but semantically wrong — which is exactly the shape
of failure a real LLM can produce (see docs/s3_llama_test_results.md: a real
Validator run, back when the Validator was still LLM-backed, returned
requires_ciso_approval=false on a HIGH-risk dossier, which is the live incident
test_ciso_approval_required_blocks_high_risk below reproduces deterministically).
The Validator has since been replaced by a fully deterministic policy engine
(mcp_server/policy.py) precisely because of this incident.
"""

from datetime import datetime, timezone

from mcp_server.errors import EventCode
from mcp_server.llm_roles.base import Validator, Verifier
from tests.conftest import make_request


def test_ciso_approval_required_blocks_high_risk_without_flag(mcp):
    """A Validator that never grants requires_ciso_approval must not let a
    HIGH/CRITICAL dossier through — this is the exact failure mode observed
    when the Validator was still LLM-backed (docs/s3_llama_test_results.md)."""

    class RogueValidator(Validator):
        def validate(self, *, verification_result, mcp_score, diagnostic_warnings, decision_id, session_id, correlation_id):
            return {
                "schema_version": "1.0", "session_id": session_id, "correlation_id": correlation_id,
                "id": decision_id, "verification_result_id": verification_result["id"],
                "mcp_score_reference": mcp_score["id"], "decision": "READY_FOR_CISO_INFORMATION",
                "diagnostic_warnings": list(diagnostic_warnings or []),
                "justification": "j", "risk_level": mcp_score["risk_level"],
                "requires_ciso_approval": False,  # wrong on purpose: HIGH/CRITICAL always requires this
                "decided_at": datetime.now(timezone.utc).isoformat(), "validator_role": "VALIDATOR",
            }

    mcp.validator = RogueValidator()
    # EVD-0001 is CRITICAL severity and, alone, verifies as "supported" in mock
    # mode, so scoring lands in HIGH/CRITICAL — the case that must be blocked.
    result = mcp.process_request(make_request(["EVD-0001"]))

    assert result["mcp_state"] == "BLOCKED"
    assert result["blocked_reason"] == EventCode.CISO_APPROVAL_REQUIRED.value
    assert "VALIDATION" not in result["transitions"]  # blocked before Validation could be logged as done

    # The frontend needs this partial data to explain *why* the block
    # happened (docs/s3_llama_test_results.md incident): which stage it was
    # in, and whatever was already computed at that point.
    assert result["last_stage"] == "VALIDATION"
    assert result["partial"]["mcp_score"]["risk_level"] in ("HIGH", "CRITICAL")
    assert result["partial"]["verification_result"]["status"] == "supported"
    assert result["partial"]["claim"] is not None
    assert result["partial"]["validation_decision"] is None  # rejected before being bound


def test_ready_for_ciso_decision_without_approval_flag_blocks(mcp):
    """Governance invariant: READY_FOR_CISO_DECISION always means mandatory CISO
    sign-off. A Validator returning that decision with requires_ciso_approval=False
    must be blocked, independent of the HIGH/CRITICAL risk-level floor check."""

    class RogueValidator(Validator):
        def validate(self, *, verification_result, mcp_score, diagnostic_warnings, decision_id, session_id, correlation_id):
            return {
                "schema_version": "1.0", "session_id": session_id, "correlation_id": correlation_id,
                "id": decision_id, "verification_result_id": verification_result["id"],
                "mcp_score_reference": mcp_score["id"], "decision": "READY_FOR_CISO_DECISION",
                "diagnostic_warnings": list(diagnostic_warnings or []),
                "justification": "j", "risk_level": mcp_score["risk_level"],
                "requires_ciso_approval": False,  # wrong on purpose
                "decided_at": datetime.now(timezone.utc).isoformat(), "validator_role": "VALIDATOR",
            }

    mcp.validator = RogueValidator()
    # EVD-0007 alone is LOW risk in mock mode, so the HIGH/CRITICAL floor check
    # would not itself catch this -- only the READY_FOR_CISO_DECISION-specific
    # invariant does.
    result = mcp.process_request(make_request(["EVD-0007"]))

    assert result["mcp_state"] == "BLOCKED"
    assert result["blocked_reason"] == EventCode.CISO_APPROVAL_REQUIRED.value


def test_invalid_claim_reference_blocks(mcp):
    """A Verifier that returns a VerificationResult tied to the wrong Claim must be rejected."""

    class RogueVerifier(Verifier):
        def verify(self, *, claim, evidence, verification_id, session_id, correlation_id):
            return {
                "schema_version": "1.0", "session_id": session_id, "correlation_id": correlation_id,
                "id": verification_id, "claim_id": "CLM-9999",  # does not match the real Claim.id
                "status": "supported", "reasoning_summary": "r",
                "supporting_evidence": [e["id"] for e in evidence],
                "contradicting_evidence": [], "missing_evidence": [],
                "verified_at": datetime.now(timezone.utc).isoformat(), "verifier_role": "VERIFIER",
            }

    mcp.verifier = RogueVerifier()
    result = mcp.process_request(make_request(["EVD-0001"]))

    assert result["mcp_state"] == "BLOCKED"
    assert result["blocked_reason"] == EventCode.INVALID_CLAIM_REFERENCE.value


def test_invalid_verification_reference_in_decision_blocks(mcp):
    """A Validator whose ValidationDecision points at the wrong VerificationResult must be rejected."""

    class RogueValidator(Validator):
        def validate(self, *, verification_result, mcp_score, diagnostic_warnings, decision_id, session_id, correlation_id):
            return {
                "schema_version": "1.0", "session_id": session_id, "correlation_id": correlation_id,
                "id": decision_id, "verification_result_id": "VER-9999",  # wrong on purpose
                "mcp_score_reference": mcp_score["id"], "decision": "READY_FOR_CISO_DECISION",
                "diagnostic_warnings": list(diagnostic_warnings or []),
                "justification": "j", "risk_level": mcp_score["risk_level"], "requires_ciso_approval": True,
                "decided_at": datetime.now(timezone.utc).isoformat(), "validator_role": "VALIDATOR",
            }

    mcp.validator = RogueValidator()
    result = mcp.process_request(make_request(["EVD-0001"]))

    assert result["mcp_state"] == "BLOCKED"
    assert result["blocked_reason"] == EventCode.INVALID_VERIFICATION_REFERENCE.value


def test_invalid_score_reference_in_decision_blocks(mcp):
    """A Validator whose ValidationDecision points at the wrong MCPScore must be rejected."""

    class RogueValidator(Validator):
        def validate(self, *, verification_result, mcp_score, diagnostic_warnings, decision_id, session_id, correlation_id):
            return {
                "schema_version": "1.0", "session_id": session_id, "correlation_id": correlation_id,
                "id": decision_id, "verification_result_id": verification_result["id"],
                "mcp_score_reference": "MCP-SCORE-9999",  # wrong on purpose
                "decision": "READY_FOR_CISO_DECISION", "diagnostic_warnings": list(diagnostic_warnings or []),
                "justification": "j", "risk_level": mcp_score["risk_level"], "requires_ciso_approval": True,
                "decided_at": datetime.now(timezone.utc).isoformat(), "validator_role": "VALIDATOR",
            }

    mcp.validator = RogueValidator()
    result = mcp.process_request(make_request(["EVD-0001"]))

    assert result["mcp_state"] == "BLOCKED"
    assert result["blocked_reason"] == EventCode.INVALID_SCORE_REFERENCE.value


def test_generic_provider_exception_yields_technical_failure_not_block(mcp):
    """A non-timeout provider error (e.g. HTTP 5xx) must surface as LLM_PROVIDER_ERROR /
    TECHNICAL_FAILURE — never treated as a security block."""

    class FlakyGenerator:
        role_name = "GENERATOR"

        def generate(self, **kwargs):
            raise RuntimeError("upstream returned HTTP 503")

    mcp.generator = FlakyGenerator()
    result = mcp.process_request(make_request(["EVD-0001"]))

    assert result["mcp_state"] == "TECHNICAL_FAILURE"
    assert result["failure_reason"] == EventCode.LLM_PROVIDER_ERROR.value


def test_role_recovers_within_retry_budget(mcp):
    """A role failing on its first two attempts but succeeding on the third
    (within config.llm_max_retries=2, i.e. 3 total attempts) must still
    complete the pipeline — retries are supposed to recover, not just delay
    the same failure."""

    from mcp_server.llm_roles.mock_generator import MockGenerator

    class FlakyThenOkGenerator:
        role_name = "GENERATOR"

        def __init__(self):
            self.calls = 0
            self._delegate = MockGenerator()

        def generate(self, **kwargs):
            self.calls += 1
            if self.calls < 3:
                raise RuntimeError("transient upstream error")
            return self._delegate.generate(**kwargs)

    flaky = FlakyThenOkGenerator()
    mcp.generator = flaky
    result = mcp.process_request(make_request(["EVD-0001"]))

    assert result["mcp_state"] == "COMPLETED"
    assert flaky.calls == 3
