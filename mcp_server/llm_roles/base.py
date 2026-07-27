"""Abstract interfaces for the three isolated LLM roles.

Isolation rule (S1 governance + TC-14): the Verifier receives only the Claim and
the Evidence it references — never the Generator's prompt, history, or session
context. The Validator receives only the VerificationResult and the MCPScore —
never the Evidence catalogue, the Claim text, or the Verifier's context. These
signatures enforce that shape: it is not possible to pass a Generator context
into verify(), or an Evidence list into validate().
"""

from abc import ABC, abstractmethod
from typing import Any


class Generator(ABC):
    """Produces a Claim from a request and a set of selected Evidence."""

    role_name = "GENERATOR"

    @abstractmethod
    def generate(self, *, request_statement: str, evidence: list[dict], claim_id: str,
                 session_id: str, correlation_id: str) -> dict[str, Any]:
        """Return a Claim dict conforming to CLAIM_SCHEMA."""
        raise NotImplementedError


class Verifier(ABC):
    """Checks a Claim against Evidence, in a context isolated from the Generator."""

    role_name = "VERIFIER"

    @abstractmethod
    def verify(self, *, claim: dict, evidence: list[dict], verification_id: str,
               session_id: str, correlation_id: str) -> dict[str, Any]:
        """Return a VerificationResult dict conforming to VERIFICATION_RESULT_SCHEMA."""
        raise NotImplementedError


class Validator(ABC):
    """Produces a ValidationDecision from a VerificationResult + MCPScore + diagnostic
    warnings only."""

    role_name = "VALIDATOR"

    @abstractmethod
    def validate(self, *, verification_result: dict, mcp_score: dict, diagnostic_warnings: list[str],
                 decision_id: str, session_id: str, correlation_id: str) -> dict[str, Any]:
        """Return a ValidationDecision dict conforming to VALIDATION_DECISION_SCHEMA.

        Must NOT receive the Evidence catalogue, the Claim, or the Generator's
        context — only verification_result, mcp_score, and the list of diagnostic
        warning codes (strings only, never raw Evidence content) computed by
        mcp_server.diagnostics, per the isolation rule.
        """
        raise NotImplementedError
