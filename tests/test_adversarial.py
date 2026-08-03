"""Workstream E: adversarial / security tests.

7.1 (prompt injection) is covered by tests/test_evidence_injection.py and the
UC-04 injection test in tests/test_business_use_cases.py.
7.3 (Verifier malformed output, against the legacy Ollama-backed LlamaVerifier)
moved to legacy/tests/test_adversarial_llama_verifier.py alongside the rest of
the archived Ollama pipeline -- MockVerifier (the Verifier actually used in the
deployed stack) never goes through LlamaVerifier's raw-LLM-output-parsing
adapter, so those tests no longer exercise anything reachable here.
7.4 (policy configuration attacks) is covered by tests/test_policy_config.py.
This file covers a representative slice of 7.5 (date/chronology), using only
fixed, deterministic dates -- no wall-clock dependency for the assertions
themselves (STALE_EVIDENCE's own threshold check does read datetime.now()
internally; see mcp_server/diagnostics.py's known-limitation note in the final
report about clock injection not being implemented).
"""

import pytest

pytestmark = pytest.mark.security


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
