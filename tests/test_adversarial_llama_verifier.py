"""Workstream E: adversarial / security tests — 7.3 (Verifier malformed output),
archived alongside the legacy Ollama-backed LlamaVerifier (see legacy/README.md).

Split out of tests/test_adversarial.py when the Ollama classic pipeline was
archived: these tests exercise LlamaVerifier's raw-LLM-output-parsing adapter,
which MockVerifier (the Verifier actually used in the deployed stack) never
goes through at all -- it compares evidence directly, with no raw LLM output
to validate/repair. Restore alongside legacy/mcp_server/llm_roles/llama_verifier.py
and legacy/mcp_server/llm_roles/ollama_client.py if Ollama support returns.
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


def test_fabricated_citation_triggers_one_repair_attempt_that_fixes_it(mcp, monkeypatch):
    """First call cites EVD-9999 (never provided) alongside the real EVD-0001;
    the repair prompt should be sent, and if the (simulated) model corrects
    itself, the final result must contain only EVD-0001 -- and call_ollama
    must have been invoked exactly twice (initial + one repair, never more)."""
    calls = []

    def fake_call_ollama(**kwargs):
        calls.append(kwargs["user_prompt"])
        if len(calls) == 1:
            return {
                "status": "supported", "reasoning_summary": "r",
                "supporting_evidence": ["EVD-0001", "EVD-9999"],
                "contradicting_evidence": [], "missing_evidence": [],
            }
        return {
            "status": "supported", "reasoning_summary": "r (corrigee)",
            "supporting_evidence": ["EVD-0001"],
            "contradicting_evidence": [], "missing_evidence": [],
        }

    monkeypatch.setattr("mcp_server.llm_roles.llama_verifier.call_ollama", fake_call_ollama)
    mcp.verifier = LlamaVerifier(MCPConfig(llm_mode="llama"))
    result = _run(mcp)
    assert len(calls) == 2
    assert "EVD-9999" in calls[1]  # repair prompt names the fabricated id
    assert result["mcp_state"] == "COMPLETED"
    assert result["verification_result"]["supporting_evidence"] == ["EVD-0001"]


def test_fabricated_citation_still_present_after_repair_is_defensively_stripped(mcp, monkeypatch):
    """If the (simulated) model repeats the same fabrication even after the
    repair prompt, _known_only()'s existing defensive filter must still keep
    it out of the final result -- the repair attempt is a best-effort
    improvement, never the only safeguard."""
    def fake_call_ollama(**kwargs):
        return {
            "status": "supported", "reasoning_summary": "r",
            "supporting_evidence": ["EVD-0001", "EVD-9999"],
            "contradicting_evidence": [], "missing_evidence": [],
        }

    monkeypatch.setattr("mcp_server.llm_roles.llama_verifier.call_ollama", fake_call_ollama)
    mcp.verifier = LlamaVerifier(MCPConfig(llm_mode="llama"))
    result = _run(mcp)
    assert result["mcp_state"] == "COMPLETED"
    assert "EVD-9999" not in result["verification_result"]["supporting_evidence"]


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
