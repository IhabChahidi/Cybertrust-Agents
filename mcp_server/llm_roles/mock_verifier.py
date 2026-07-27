"""Deterministic stand-in for the external Verifier role.

Receives only `claim` and the `evidence` it references — never the Generator's
prompt or session history (isolation rule, TC-14). Contradiction and
incompleteness signals are derived from exact, parsed raw_data fields via
mcp_server.evidence_parsing — never a substring search across free text (see
that module's docstring: a naive substring match is an injection surface a
comment, a quoted example, or attacker-controlled text could trigger just by
containing the right word).
"""

from datetime import datetime, timezone

from mcp_server.evidence_parsing import fields_marked_absent, find_contradictions
from mcp_server.llm_roles.base import Verifier


class MockVerifier(Verifier):

    def verify(self, *, claim: dict, evidence: list[dict], verification_id: str,
               session_id: str, correlation_id: str) -> dict:
        contradictions = find_contradictions(evidence)

        if contradictions:
            status = "contradicted"
            supporting = sorted({h["baseline_id"] for h in contradictions})
            contradicting = sorted({h["anomaly_id"] for h in contradictions})
            missing: list[str] = []
            reasoning = (
                f"Les Evidence {supporting} et {contradicting} se contredisent sur le meme "
                "indicateur ou actif."
            )
        else:
            absent = [(e["id"], fields_marked_absent(e)) for e in evidence]
            absent = [(eid, fields) for eid, fields in absent if fields]
            if absent:
                status = "insufficient_evidence"
                absent_ids = sorted(eid for eid, _ in absent)
                supporting = sorted(eid for eid in {e["id"] for e in evidence} if eid not in absent_ids)
                contradicting = []
                missing = [f"{eid}: champ(s) marque(s) absent dans raw_data" for eid in absent_ids]
                reasoning = (
                    f"Les Evidence {absent_ids} indiquent des champs manquants empechant de "
                    "conclure."
                )
            else:
                status = "supported"
                supporting = sorted(e["id"] for e in evidence)
                contradicting = []
                missing = []
                reasoning = (
                    f"Les Evidence {supporting} sont coherentes entre elles et confirment "
                    "l'affirmation du Claim."
                )

        return {
            "schema_version": "1.0",
            "session_id": session_id,
            "correlation_id": correlation_id,
            "id": verification_id,
            "claim_id": claim["id"],
            "status": status,
            "reasoning_summary": reasoning[:1500],
            "supporting_evidence": sorted(set(supporting)),
            "contradicting_evidence": sorted(set(contradicting)),
            "missing_evidence": missing,
            "verified_at": datetime.now(timezone.utc).isoformat(),
            "verifier_role": "VERIFIER",
        }
