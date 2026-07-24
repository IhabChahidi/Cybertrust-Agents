"""Deterministic stand-in for the external Validator role.

Receives only `verification_result` and `mcp_score` — never the Evidence
catalogue, the Claim, or the Verifier's context (isolation rule, TC-14). Cannot
modify the score; only reads verification_result.status and mcp_score.risk_level
to produce a ValidationDecision (L5 section 7).
"""

from datetime import datetime, timezone

from mcp_server.llm_roles.base import Validator


class MockValidator(Validator):

    def validate(self, *, verification_result: dict, mcp_score: dict, decision_id: str,
                 session_id: str, correlation_id: str) -> dict:
        status = verification_result["status"]
        risk_level = mcp_score["risk_level"]
        high_risk = risk_level in ("HIGH", "CRITICAL")

        if status == "unsupported":
            decision = "REJECTED"
            requires_approval = False
            justification = "Le Claim n'est confirme par aucune Evidence disponible."
        elif status == "insufficient_evidence":
            decision = "INSUFFICIENT_EVIDENCE"
            requires_approval = False
            justification = (
                "Preuves insuffisantes pour conclure : "
                f"{'; '.join(verification_result['missing_evidence']) or 'elements manquants non precises'}."
            )
        elif status == "contradicted":
            decision = "HUMAN_REVIEW"
            requires_approval = True
            justification = (
                "Evidence contradictoires detectees "
                f"({verification_result['reasoning_summary']}). Arbitrage du CISO requis."
            )
        else:  # supported
            decision = "APPROVED_FOR_CISO_REVIEW"
            requires_approval = high_risk
            justification = (
                f"Claim supporte par les Evidence {verification_result['supporting_evidence']}, "
                f"score MCP {mcp_score['value']}/100 ({risk_level})."
            )

        # Risk-level floor: HIGH/CRITICAL always requires explicit CISO approval,
        # regardless of what the Validator concluded (L4 blocking rule).
        if high_risk:
            requires_approval = True

        return {
            "schema_version": "1.0",
            "session_id": session_id,
            "correlation_id": correlation_id,
            "id": decision_id,
            "verification_result_id": verification_result["id"],
            "mcp_score_reference": mcp_score["id"],
            "decision": decision,
            "justification": justification[:2000],
            "risk_level": risk_level,
            "requires_ciso_approval": requires_approval,
            "decided_at": datetime.now(timezone.utc).isoformat(),
            "validator_role": "VALIDATOR",
        }
