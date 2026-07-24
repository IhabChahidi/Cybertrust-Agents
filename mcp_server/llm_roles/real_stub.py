"""Placeholders for the real Copilot Studio / external LLM adapters.

Fill these in once access is granted. Each class implements the same abstract
interface as its mock_*.py counterpart in this package, so orchestrator.py and
factory() below are the ONLY places that need to change — nothing in
orchestrator.py, scoring.py, or the tests should need to change.

Wiring checklist for when access arrives:
  1. Read endpoint + credentials from environment variables only (never commit
     secrets — see mcp_server/config.py and the S2 IAM matrix). Suggested vars:
     COPILOT_STUDIO_ENDPOINT / COPILOT_STUDIO_TOKEN for the Generator,
     VERIFIER_LLM_ENDPOINT / VERIFIER_LLM_TOKEN for the Verifier,
     VALIDATOR_LLM_ENDPOINT / VALIDATOR_LLM_TOKEN for the Validator.
  2. Enforce config.ENDPOINT_WHITELIST before every outbound call (TC-12).
  3. Wrap the call with config.llm_timeout_seconds / llm_max_retries and raise
     MCPTechnicalFailure(EventCode.LLM_TIMEOUT | LLM_EMPTY_RESPONSE |
     LLM_PROVIDER_ERROR, ...) on failure — never MCPBlockedError, these are
     technical failures, not security violations (L4 section 5).
  4. The Verifier must not receive the Generator's prompt/session history; the
     Validator must not receive the Evidence catalogue or the Claim. Enforce
     this by construction: only pass the arguments already in base.py's
     method signatures, do not add extra kwargs that leak context.
  5. Validate every LLM response against the corresponding schema in
     schemas.py before returning it — a schema-invalid response must surface
     as MCPBlockedError(EventCode.SCHEMA_ERROR, ...), not be silently coerced.
"""

from mcp_server.config import MCPConfig
from mcp_server.errors import EventCode, MCPTechnicalFailure
from mcp_server.llm_roles.base import Generator, Validator, Verifier


class RealGenerator(Generator):
    """TODO: wire to Copilot Studio once the pilot has API access."""

    def __init__(self, config: MCPConfig):
        self.config = config

    def generate(self, *, request_statement, evidence, claim_id, session_id, correlation_id):
        raise MCPTechnicalFailure(
            EventCode.LLM_PROVIDER_ERROR,
            "RealGenerator is not wired yet — no Copilot Studio access. Use MCP_LLM_MODE=mock.",
        )


class RealVerifier(Verifier):
    """TODO: wire to the external Verifier LLM once access is available."""

    def __init__(self, config: MCPConfig):
        self.config = config

    def verify(self, *, claim, evidence, verification_id, session_id, correlation_id):
        raise MCPTechnicalFailure(
            EventCode.LLM_PROVIDER_ERROR,
            "RealVerifier is not wired yet — no external LLM access. Use MCP_LLM_MODE=mock.",
        )


class RealValidator(Validator):
    """TODO: wire to the external Validator LLM once access is available."""

    def __init__(self, config: MCPConfig):
        self.config = config

    def validate(self, *, verification_result, mcp_score, decision_id, session_id, correlation_id):
        raise MCPTechnicalFailure(
            EventCode.LLM_PROVIDER_ERROR,
            "RealValidator is not wired yet — no external LLM access. Use MCP_LLM_MODE=mock.",
        )
