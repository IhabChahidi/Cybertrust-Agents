"""Unit tests for the deterministic MCPScore engine (L5)."""

from mcp_server.scoring import compute_mcp_score

_EVIDENCE = [{
    "id": "EVD-0001", "severity": "CRITICAL",
    "content": {"summary": "s", "raw_data": "status=Closed", "affected_assets": ["A"], "indicators": ["I"]},
}]


def _score(status, contradicting=None, missing=None):
    verification_result = {
        "id": "VER-0001", "status": status,
        "supporting_evidence": ["EVD-0001"],
        "contradicting_evidence": contradicting or [],
        "missing_evidence": missing or [],
    }
    return compute_mcp_score(
        evidence=_EVIDENCE, verification_result=verification_result, score_id="MCP-SCORE-0001",
        session_id="SES-20260722-PILOT", correlation_id="COR-20260722-PILOT",
    )


def test_score_is_deterministic_for_same_inputs():
    a = _score("supported")
    b = _score("supported")
    a.pop("calculated_at")
    b.pop("calculated_at")
    assert a == b


def test_score_bounded_between_0_and_100():
    for status in ("supported", "unsupported", "insufficient_evidence", "contradicted"):
        result = _score(status)
        assert 0 <= result["value"] <= 100


def test_contradicted_status_applies_penalty_and_lower_verification_factor():
    supported = _score("supported")
    contradicted = _score("contradicted", contradicting=["EVD-0002"])
    assert contradicted["factors"]["contradiction_penalty"] < 0
    assert contradicted["value"] < supported["value"]


def test_risk_level_thresholds_match_l5_ranges():
    result = _score("supported")
    value = result["value"]
    risk = result["risk_level"]
    if value >= 80:
        assert risk == "CRITICAL"
    elif value >= 60:
        assert risk == "HIGH"
    elif value >= 30:
        assert risk == "MEDIUM"
    else:
        assert risk == "LOW"
