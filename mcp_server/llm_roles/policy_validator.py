"""Validator role — deterministic policy engine.

This class calls no LLM. It never did anything else since the review that
removed the Validator LLM call entirely: the status -> decision mapping and the
requires_ciso_approval rule are fixed business policy, not something that
benefits from free-form reasoning — and a live incident (docs/s3_llama_test_results.md)
showed a real Validator LLM silently returning requires_ciso_approval=false on a
CRITICAL-risk dossier. The orchestrator's CISO_APPROVAL_REQUIRED guard caught it
that time, but "the LLM might forget the rule" should never be the only thing
standing between a bad call and an under-protected dossier.

This module was previously named llama_validator.py / LlamaValidator, which was
misleading (there was never an LLM here once the rewrite landed). It has been
renamed to policy_validator.py / PolicyValidator. mcp_server/llm_roles/llama_validator.py
still exists as a deprecated compatibility alias (`LlamaValidator = PolicyValidator`)
and emits a DeprecationWarning on import — update any remaining imports to use
this module directly.

There is no validator_model / VALIDATOR_OLLAMA_MODEL config knob: it was removed
from MCPConfig entirely rather than kept-but-unused, since this class never
calls a model.
"""

from mcp_server.config import MCPConfig
from mcp_server.llm_roles.base import Validator
from mcp_server.policy import decide


class PolicyValidator(Validator):

    def __init__(self, config: MCPConfig):
        self.config = config

    def validate(self, *, verification_result: dict, mcp_score: dict, diagnostic_warnings: list[str],
                 decision_id: str, session_id: str, correlation_id: str) -> dict:
        return decide(
            verification_result=verification_result, mcp_score=mcp_score,
            diagnostic_warnings=diagnostic_warnings,
            decision_id=decision_id, session_id=session_id, correlation_id=correlation_id,
        )
