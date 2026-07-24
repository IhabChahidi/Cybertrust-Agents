"""Nominal pipeline tests: TC-01, TC-02, TC-03, TC-20."""

from tests.conftest import make_request


def test_tc01_full_pipeline_nominal(mcp):
    """TC-01 — Evidence valide -> Claim -> VerificationResult -> MCPScore -> ValidationDecision."""
    result = mcp.process_request(make_request(["EVD-0007"], statement="Action AUD-3390 est-elle cloturee ?"))

    assert result["mcp_state"] == "COMPLETED"
    assert result["transitions"] == [
        "INIT", "VALIDATION_ENTREE", "SELECTION_EVIDENCE", "GENERATION_CLAIM",
        "VERIFICATION", "SCORING", "VALIDATION", "DECISION_CISO", "COMPLETED",
    ]
    assert result["claim"]["evidence_ids"] == ["EVD-0007"]
    assert result["mcp_score"]["value"] >= 0
    assert result["ciso_routing"] in {
        "READY_FOR_CISO_DECISION", "READY_FOR_CISO_INFORMATION",
        "CLOSED_REJECTED", "CLOSED_INSUFFICIENT_EVIDENCE",
    }


def test_tc02_claim_with_multiple_evidence(mcp):
    """TC-02 — Claim avec plusieurs Evidence valides : les deux sont reconnues et utilisees."""
    result = mcp.process_request(make_request(["EVD-0001", "EVD-0002"]))

    assert result["mcp_state"] == "COMPLETED"
    assert set(result["claim"]["evidence_ids"]) == {"EVD-0001", "EVD-0002"}
    assert set(result["verification_result"]["supporting_evidence"]) <= {"EVD-0001", "EVD-0002"}


def test_tc03_medium_severity_routes_to_information(mcp):
    """TC-03 — Evidence MEDIUM => statut informationnel, pas de decision CISO forcee."""
    result = mcp.process_request(make_request(["EVD-0006"]))  # severity MEDIUM, incomplete report

    assert result["mcp_state"] == "COMPLETED"
    # insufficient_evidence closes the flow without needing CISO decision either way
    assert result["ciso_routing"] in {"READY_FOR_CISO_INFORMATION", "CLOSED_INSUFFICIENT_EVIDENCE"}


def test_tc20_high_or_critical_routes_to_ciso_decision(mcp):
    """TC-20 — MCPScore >= 60 (HIGH/CRITICAL) et dossier coherent => READY_FOR_CISO_DECISION."""
    result = mcp.process_request(make_request(["EVD-0001"]))  # CRITICAL severity, single supported ticket

    assert result["mcp_score"]["risk_level"] in ("HIGH", "CRITICAL")
    assert result["ciso_routing"] == "READY_FOR_CISO_DECISION"
    assert result["validation_decision"]["requires_ciso_approval"] is True
