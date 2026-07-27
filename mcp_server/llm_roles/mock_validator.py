"""Deterministic stand-in for the external Validator role.

Receives only `verification_result`, `mcp_score`, and `diagnostic_warnings` —
never the Evidence catalogue, the Claim, or the Verifier's context (isolation
rule, TC-14). Delegates to mcp_server.policy.decide(), the same policy engine
PolicyValidator uses, so mock mode and the real pipeline are guaranteed to apply
identical business rules (see mcp_server/policy.py for the mapping and the
requires_ciso_approval rule).
"""

from mcp_server.llm_roles.base import Validator
from mcp_server.policy import decide


class MockValidator(Validator):

    def validate(self, *, verification_result: dict, mcp_score: dict, diagnostic_warnings: list[str],
                 decision_id: str, session_id: str, correlation_id: str) -> dict:
        return decide(
            verification_result=verification_result, mcp_score=mcp_score,
            diagnostic_warnings=diagnostic_warnings,
            decision_id=decision_id, session_id=session_id, correlation_id=correlation_id,
        )
