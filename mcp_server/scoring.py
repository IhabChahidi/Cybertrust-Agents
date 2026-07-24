"""Deterministic MCPScore engine (L5).

The MCP server — never an LLM — computes this score. Claim.confidence is never
read here. Given the same Evidence + VerificationResult and the same
calculation_version, the output is always identical.

Evidence does not carry explicit "exposure" or "impact" fields (see the S1
Evidence contract), so this mock-mode engine derives them from severity as a
documented heuristic. When real Evidence sources are wired in S3+, replace
`_exposure_factor` / `_impact_factor` with fields sourced from the actual
ticket/scan/audit metadata, bump `CALCULATION_VERSION`, and keep the old
version's logic available for reproducibility (L5 section 10).
"""

from datetime import datetime, timezone

CALCULATION_VERSION = "1.0"

_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

_CRITICALITY_POINTS = {"LOW": 5, "MEDIUM": 10, "HIGH": 18, "CRITICAL": 25}
_EXPOSURE_POINTS = {"LOW": 3, "MEDIUM": 8, "HIGH": 15, "CRITICAL": 15}
_IMPACT_POINTS = {"LOW": 5, "MEDIUM": 10, "HIGH": 15, "CRITICAL": 20}

_VERIFICATION_POINTS = {
    "supported": 20,
    "unsupported": 0,
    "insufficient_evidence": -5,
    "contradicted": -10,
}


def _principal_severity(evidence: list[dict]) -> str:
    return max((e["severity"] for e in evidence), key=lambda s: _SEVERITY_RANK[s])


def _evidence_quality(evidence: list[dict]) -> float:
    quality = 3.0
    if any(e["content"].get("affected_assets") for e in evidence):
        quality += 3.0
    if any(e["content"].get("indicators") for e in evidence):
        quality += 3.0
    raw_all = " ".join(e["content"]["raw_data"].lower() for e in evidence)
    absent_hits = raw_all.count("absent")
    quality -= min(6.0, absent_hits * 3.0)
    if len(evidence) > 1:
        quality += 3.0  # correlation bonus: multiple independent Evidence (L5 "Corrélation")
    return max(0.0, min(15.0, quality))


def _contradiction_penalty(verification_result: dict) -> float:
    if verification_result["status"] != "contradicted":
        return 0.0
    # The mock Verifier only flags "contradicted" when it found a clear,
    # direct opposition between two Evidence items => treated as "majeure".
    return -30.0


def compute_mcp_score(*, evidence: list[dict], verification_result: dict, score_id: str,
                       session_id: str, correlation_id: str) -> dict:
    """Compute a MCPScore dict conforming to MCP_SCORE_SCHEMA."""
    severity = _principal_severity(evidence)

    factors = {
        "severity": float(_CRITICALITY_POINTS[severity]),
        "exposure": float(_EXPOSURE_POINTS[severity]),
        "impact": float(_IMPACT_POINTS[severity]),
        "evidence_quality": _evidence_quality(evidence),
        "verification": float(_VERIFICATION_POINTS[verification_result["status"]]),
        "contradiction_penalty": _contradiction_penalty(verification_result),
    }

    raw_value = sum(factors.values())
    value = max(0.0, min(100.0, raw_value))

    if value >= 80:
        risk_level = "CRITICAL"
    elif value >= 60:
        risk_level = "HIGH"
    elif value >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "schema_version": "1.0",
        "session_id": session_id,
        "correlation_id": correlation_id,
        "id": score_id,
        "verification_result_id": verification_result["id"],
        "value": round(value, 1),
        "risk_level": risk_level,
        "factors": {k: round(v, 1) for k, v in factors.items()},
        "calculation_version": CALCULATION_VERSION,
        "calculated_at": datetime.now(timezone.utc).isoformat(),
    }
