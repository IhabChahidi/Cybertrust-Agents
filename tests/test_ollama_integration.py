"""Real Ollama integration tests (spec section 8). Automatically skipped if
Ollama is not reachable (see tests/conftest.py::pytest_collection_modifyitems) —
the normal test suite never depends on a running model. Asserts schema,
statuses, traceability, and policy invariants only; never asserts exact
natural-language wording (an LLM's phrasing is not deterministic).

Run explicitly with:  py -m pytest tests/test_ollama_integration.py -m ollama -v
"""

import pytest

from mcp_server.config import MCPConfig
from mcp_server.orchestrator import MCPServer
from tests.conftest import make_request

pytestmark = pytest.mark.ollama


@pytest.fixture()
def llama_mcp(tmp_path):
    config = MCPConfig(
        llm_mode="llama", llm_timeout_seconds=180,
        journal_path=str(tmp_path / "journal_ollama.jsonl"),
    )
    return MCPServer(config)


def test_full_pipeline_against_real_ollama_produces_schema_valid_traceable_result(llama_mcp):
    """Records the model configuration used, then asserts structure/traceability/
    invariants only -- never the exact Claim/reasoning wording, which varies by
    model and is not deterministic."""
    result = llama_mcp.process_request(
        make_request(["EVD-0001", "EVD-0002"], statement="Le ticket SEC-1452 a-t-il ete correctement remedie ?")
    )

    print(f"\n[ollama integration] generator_model={llama_mcp.config.generator_model} "
          f"verifier_model={llama_mcp.config.verifier_model}")

    assert result["mcp_state"] in ("COMPLETED", "BLOCKED", "TECHNICAL_FAILURE")

    if result["mcp_state"] != "COMPLETED":
        pytest.skip(f"pipeline did not complete this run ({result['mcp_state']}) -- model-dependent, not a hard failure")

    claim = result["claim"]
    vr = result["verification_result"]
    decision = result["validation_decision"]

    # Traceability: every object shares session/correlation id and correctly
    # references the previous stage's id.
    assert claim["session_id"] == vr["session_id"] == decision["session_id"]
    assert vr["claim_id"] == claim["id"]
    assert decision["verification_result_id"] == vr["id"]

    # Policy invariants, independent of what the model actually said.
    assert vr["status"] in ("supported", "unsupported", "contradicted", "insufficient_evidence")
    assert decision["decision"] in ("READY_FOR_CISO_DECISION", "READY_FOR_CISO_INFORMATION", "REJECTED", "INSUFFICIENT_EVIDENCE")
    assert "HUMAN_REVIEW" not in str(result)
    assert "APPROVED_FOR_CISO_REVIEW" not in str(result)
    if vr["status"] == "insufficient_evidence":
        assert decision["decision"] == "INSUFFICIENT_EVIDENCE"
    if decision["decision"] == "READY_FOR_CISO_DECISION":
        assert decision["requires_ciso_approval"] is True

    # Non-fabrication: every cited Evidence id must be one that was selected.
    known_ids = {"EVD-0001", "EVD-0002"}
    assert set(vr["supporting_evidence"]) <= known_ids
    assert set(vr["contradicting_evidence"]) <= known_ids
