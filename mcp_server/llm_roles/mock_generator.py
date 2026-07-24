"""Deterministic stand-in for the Copilot Studio Generator role.

Builds a Claim purely from the Evidence it is handed — no hidden knowledge, no
access to anything outside the `evidence` argument, matching what the real
Copilot Studio integration will receive.
"""

from datetime import datetime, timezone

from mcp_server.llm_roles.base import Generator


class MockGenerator(Generator):

    def generate(self, *, request_statement: str, evidence: list[dict], claim_id: str,
                 session_id: str, correlation_id: str) -> dict:
        summaries = [e["content"]["summary"] for e in evidence]
        statement = request_statement or " ".join(summaries)
        statement = statement[:1000]

        # Confidence is purely declarative and excluded from MCPScore (L3):
        # it grows with corroborating Evidence and drops when raw_data shows
        # explicit gaps ("...=absent").
        absent_hits = sum(e["content"]["raw_data"].lower().count("absent") for e in evidence)
        base = 0.55 + 0.1 * min(len(evidence), 3)
        confidence = max(0.1, min(0.97, base - 0.08 * absent_hits))

        context = "; ".join(f"{e['id']}:{e['type']}" for e in evidence)[:500]

        return {
            "schema_version": "1.0",
            "session_id": session_id,
            "correlation_id": correlation_id,
            "id": claim_id,
            "evidence_ids": [e["id"] for e in evidence],
            "statement": statement,
            "confidence": round(confidence, 2),
            "context": context,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator_role": "GENERATOR",
        }
