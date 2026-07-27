"""DEPRECATED compatibility shim.

This module used to contain the Validator implementation. It never called an
LLM after the review that removed the Validator LLM call entirely, so the name
was misleading; the real implementation now lives in policy_validator.py as
PolicyValidator. This module re-exports it under the old name so existing
imports (`from mcp_server.llm_roles.llama_validator import LlamaValidator`)
keep working, and emits a DeprecationWarning on import.

Update any remaining import of LlamaValidator to import PolicyValidator from
mcp_server.llm_roles.policy_validator instead. This shim will be removed in a
future revision.
"""

import warnings

from mcp_server.llm_roles.policy_validator import PolicyValidator

warnings.warn(
    "mcp_server.llm_roles.llama_validator.LlamaValidator is deprecated and will be "
    "removed; import PolicyValidator from mcp_server.llm_roles.policy_validator instead.",
    DeprecationWarning, stacklevel=2,
)

LlamaValidator = PolicyValidator
