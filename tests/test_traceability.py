"""TC-13 — Traceability: every object of a session shares session_id/correlation_id."""

from tests.conftest import CORRELATION_ID, SESSION_ID, make_request


def test_tc13_all_objects_share_session_and_correlation_id(mcp):
    result = mcp.process_request(make_request(["EVD-0001", "EVD-0002"]))

    assert result["mcp_state"] == "COMPLETED"
    for obj in (result["claim"], result["verification_result"], result["mcp_score"], result["validation_decision"]):
        assert obj["session_id"] == SESSION_ID
        assert obj["correlation_id"] == CORRELATION_ID

    assert result["transitions"][0] == "INIT"
    assert result["transitions"][-1] == "COMPLETED"
    assert len(result["transitions"]) == len(set(result["transitions"]))  # no repeated/looping state


def test_tc13_journal_records_full_transition_order(mcp):
    mcp.process_request(make_request(["EVD-0003"]))
    states = [e["state"] for e in mcp.audit.events]

    canonical_order = [
        "INIT", "VALIDATION_ENTREE", "SELECTION_EVIDENCE", "GENERATION_CLAIM",
        "VERIFICATION", "DIAGNOSTICS", "SCORING", "VALIDATION", "DECISION_CISO", "COMPLETED",
    ]
    seen_indices = [canonical_order.index(s) for s in states]
    assert seen_indices == sorted(seen_indices), "MCP states must not appear out of order"
    assert all(e["session_id"] == SESSION_ID and e["correlation_id"] == CORRELATION_ID for e in mcp.audit.events)
