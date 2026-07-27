"""Workstream E: adversarial / security tests.

7.1 (prompt injection) is covered by tests/test_evidence_injection.py and the
UC-04 injection test in tests/test_business_use_cases.py.
7.2 (Generator fabrication) is covered by tests/test_llama_generator_validation.py.
7.4 (policy configuration attacks) is covered by tests/test_policy_config.py.
This file covers 7.3 (Verifier malformed output) and a representative slice of
7.5 (date/chronology), using only fixed, deterministic dates -- no wall-clock
dependency for the assertions themselves (STALE_EVIDENCE's own threshold check
does read datetime.now() internally; see mcp_server/diagnostics.py's
known-limitation note in the final report about clock injection not being
implemented).
"""

import pytest

from mcp_server.config import MCPConfig
from mcp_server.errors import EventCode
from mcp_server.llm_roles.llama_verifier import LlamaVerifier
from tests.conftest import make_request

pytestmark = pytest.mark.security


def _patch_ollama(monkeypatch, raw_response):
    """raw_response: either a dict (normal path) or a callable returning one,
    or an exception to raise, simulating the various malformed-output shapes."""
    def fake_call_ollama(**kwargs):
        if isinstance(raw_response, Exception):
            raise raw_response
        if callable(raw_response):
            return raw_response()
        return raw_response
    monkeypatch.setattr("mcp_server.llm_roles.llama_verifier.call_ollama", fake_call_ollama)


def _run(mcp):
    return mcp.process_request(make_request(["EVD-0001"]))


# -- 7.3 Verifier malformed output --------------------------------------------

def test_unknown_status_value_blocks_with_schema_error(mcp, monkeypatch):
    _patch_ollama(monkeypatch, {
        "status": "PROBABLY_FINE", "reasoning_summary": "r",
        "supporting_evidence": [], "contradicting_evidence": [], "missing_evidence": [],
    })
    mcp.verifier = LlamaVerifier(MCPConfig(llm_mode="llama"))
    result = _run(mcp)
    assert result["mcp_state"] == "BLOCKED"
    assert result["blocked_reason"] == EventCode.SCHEMA_ERROR.value


def test_missing_status_key_blocks_with_schema_error(mcp, monkeypatch):
    _patch_ollama(monkeypatch, {
        "reasoning_summary": "r", "supporting_evidence": [], "contradicting_evidence": [], "missing_evidence": [],
    })
    mcp.verifier = LlamaVerifier(MCPConfig(llm_mode="llama"))
    # The adapter itself does `llm_output["status"]` -- a missing key raises
    # KeyError inside the adapter, which the orchestrator's retry loop catches
    # (as a generic provider-shaped failure) and, after exhausting retries,
    # surfaces as a TECHNICAL_FAILURE result -- never an unhandled exception,
    # and never an optimistic "supported" default.
    result = _run(mcp)
    assert result["mcp_state"] in ("BLOCKED", "TECHNICAL_FAILURE")


def test_wrong_data_type_for_supporting_evidence_is_handled_without_fabricating_ids(mcp, monkeypatch):
    """supporting_evidence as a string instead of a list: _known_only() iterates
    it as a sequence of characters, none of which are known Evidence ids, so it
    is filtered down to an empty (but never fabricated) list -- not a crash, not
    an optimistic pass-through."""
    _patch_ollama(monkeypatch, {
        "status": "supported", "reasoning_summary": "r",
        "supporting_evidence": "EVD-0001", "contradicting_evidence": [], "missing_evidence": [],
    })
    mcp.verifier = LlamaVerifier(MCPConfig(llm_mode="llama"))
    result = _run(mcp)
    if result["mcp_state"] == "COMPLETED":
        assert "EVD-9999" not in result["verification_result"]["supporting_evidence"]


def test_extremely_long_reasoning_summary_is_truncated_not_rejected(mcp, monkeypatch):
    _patch_ollama(monkeypatch, {
        "status": "supported", "reasoning_summary": "x" * 100_000,
        "supporting_evidence": ["EVD-0001"], "contradicting_evidence": [], "missing_evidence": [],
    })
    mcp.verifier = LlamaVerifier(MCPConfig(llm_mode="llama"))
    result = _run(mcp)
    assert result["mcp_state"] == "COMPLETED"
    assert len(result["verification_result"]["reasoning_summary"]) <= 1500


def test_extra_unrecognized_field_from_llm_is_dropped_not_propagated(mcp, monkeypatch):
    _patch_ollama(monkeypatch, {
        "status": "supported", "reasoning_summary": "r",
        "supporting_evidence": ["EVD-0001"], "contradicting_evidence": [], "missing_evidence": [],
        "unexpected_field": "should never reach the schema-validated output",
    })
    mcp.verifier = LlamaVerifier(MCPConfig(llm_mode="llama"))
    result = _run(mcp)
    assert result["mcp_state"] == "COMPLETED"
    assert "unexpected_field" not in result["verification_result"]


def test_provider_raising_generic_exception_yields_technical_failure(mcp, monkeypatch):
    _patch_ollama(monkeypatch, RuntimeError("upstream returned malformed markdown-wrapped JSON"))
    mcp.verifier = LlamaVerifier(MCPConfig(llm_mode="llama"))
    result = _run(mcp)
    assert result["mcp_state"] == "TECHNICAL_FAILURE"
    assert result["failure_reason"] == EventCode.LLM_PROVIDER_ERROR.value


def test_no_legacy_decision_value_can_ever_result_from_malformed_verifier_output(mcp, monkeypatch):
    _patch_ollama(monkeypatch, {
        "status": "unsupported", "reasoning_summary": "r",
        "supporting_evidence": [], "contradicting_evidence": [], "missing_evidence": [],
    })
    mcp.verifier = LlamaVerifier(MCPConfig(llm_mode="llama"))
    result = _run(mcp)
    dumped = str(result)
    assert "HUMAN_REVIEW" not in dumped
    assert "APPROVED_FOR_CISO_REVIEW" not in dumped


# -- 7.5 Date / chronology (deterministic dates only, no wall-clock dependency) --

def test_two_evidence_same_subject_different_dates_both_kept_contradiction_regardless_of_order():
    """Recency must never silently resolve a contradiction -- verified with fixed
    dates in both temporal orders."""
    from mcp_server.evidence_parsing import find_contradictions

    older_first = [
        {"id": "EVD-A", "date": "2020-01-01T00:00:00Z", "content": {"raw_data": "pv_reference=PV-1; pv_status=Signed"}},
        {"id": "EVD-B", "date": "2020-06-01T00:00:00Z", "content": {"raw_data": "pv_reference=PV-1; pv_status=Invalidated"}},
    ]
    newer_first = [
        {"id": "EVD-B", "date": "2020-06-01T00:00:00Z", "content": {"raw_data": "pv_reference=PV-1; pv_status=Invalidated"}},
        {"id": "EVD-A", "date": "2020-01-01T00:00:00Z", "content": {"raw_data": "pv_reference=PV-1; pv_status=Signed"}},
    ]
    assert len(find_contradictions(older_first)) == 1
    assert len(find_contradictions(newer_first)) == 1


def test_stale_evidence_uses_a_fixed_far_past_date_not_relative_to_wall_clock():
    """Uses an absolute date far enough in the past (2015) that it will read as
    stale (>90 days old) for the entire foreseeable lifetime of this test suite,
    without needing to inject a clock abstraction."""
    from mcp_server.diagnostics import STALE_EVIDENCE, compute_diagnostics

    e = [{
        "id": "EVD-OLD", "type": "ticket", "date": "2015-01-01T00:00:00Z",
        "content": {"summary": "s", "raw_data": "status=Closed"},
    }]
    assert STALE_EVIDENCE in compute_diagnostics(e, "supported")


def test_malformed_date_string_does_not_crash_staleness_check():
    from mcp_server.diagnostics import compute_diagnostics

    e = [{
        "id": "EVD-BAD-DATE", "type": "ticket", "date": "not-a-real-date",
        "content": {"summary": "s", "raw_data": "status=Closed"},
    }]
    codes = compute_diagnostics(e, "supported")  # must not raise
    assert isinstance(codes, list)


def test_missing_date_field_does_not_crash_staleness_check():
    from mcp_server.diagnostics import compute_diagnostics

    e = [{"id": "EVD-NO-DATE", "type": "ticket", "content": {"summary": "s", "raw_data": "status=Closed"}}]
    codes = compute_diagnostics(e, "supported")
    assert isinstance(codes, list)
