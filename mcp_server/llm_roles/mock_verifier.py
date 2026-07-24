"""Deterministic stand-in for the external Verifier role.

Receives only `claim` and the `evidence` it references — never the Generator's
prompt or session history (isolation rule, TC-14). Detects contradictions
between the referenced Evidence items themselves (not against the Claim's
wording) and flags incompleteness from explicit "...=absent" markers.
"""

from datetime import datetime, timezone

from mcp_server.llm_roles.base import Verifier

# Each pair (marker_a, marker_b) found across different referenced Evidence
# items indicates the Evidence set disagrees with itself.
_CONTRADICTION_MARKERS = [
    ("result=clean", "stillpresent"),
    ("pv_status=signed", "pv_status=invalidated"),
]


class MockVerifier(Verifier):

    def verify(self, *, claim: dict, evidence: list[dict], verification_id: str,
               session_id: str, correlation_id: str) -> dict:
        raw_by_id = {e["id"]: e["content"]["raw_data"].lower() for e in evidence}

        contradicting: list[str] = []
        supporting: list[str] = []
        for marker_a, marker_b in _CONTRADICTION_MARKERS:
            ids_a = [eid for eid, raw in raw_by_id.items() if marker_a in raw]
            ids_b = [eid for eid, raw in raw_by_id.items() if marker_b in raw]
            if ids_a and ids_b:
                supporting.extend(ids_a)
                contradicting.extend(ids_b)

        if contradicting:
            status = "contradicted"
            reasoning = (
                f"Les Evidence {sorted(set(supporting))} et {sorted(set(contradicting))} "
                "se contredisent sur le meme indicateur ou actif."
            )
            missing: list[str] = []
        else:
            absent_ids = [eid for eid, raw in raw_by_id.items() if "absent" in raw]
            if absent_ids:
                status = "insufficient_evidence"
                supporting = [eid for eid in raw_by_id if eid not in absent_ids]
                missing = [f"{eid}: champ(s) marque(s) absent dans raw_data" for eid in absent_ids]
                reasoning = (
                    f"Les Evidence {sorted(absent_ids)} indiquent des champs manquants "
                    "empechant de conclure."
                )
            else:
                status = "supported"
                supporting = list(raw_by_id.keys())
                missing = []
                reasoning = (
                    f"Les Evidence {sorted(supporting)} sont coherentes entre elles et "
                    "confirment l'affirmation du Claim."
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
