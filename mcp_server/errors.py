"""Event codes and exceptions used by the MCP orchestrator (L4 routing diagram)."""

from enum import Enum


class EventCode(str, Enum):
    """Synthetic catalogue of MCP event codes (L4 section 6)."""

    SCHEMA_ERROR = "SCHEMA_ERROR"
    UNAUTHORIZED_ENDPOINT = "UNAUTHORIZED_ENDPOINT"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    EXFILTRATION_ATTEMPT = "EXFILTRATION_ATTEMPT"
    INVALID_EVIDENCE_ID = "INVALID_EVIDENCE_ID"
    MISSING_EVIDENCE_IDS = "MISSING_EVIDENCE_IDS"
    INVALID_CLAIM_REFERENCE = "INVALID_CLAIM_REFERENCE"
    INVALID_VERIFICATION_REFERENCE = "INVALID_VERIFICATION_REFERENCE"
    INVALID_SCORE_REFERENCE = "INVALID_SCORE_REFERENCE"
    SESSION_MISMATCH = "SESSION_MISMATCH"
    UNSUPPORTED_SCHEMA_VERSION = "UNSUPPORTED_SCHEMA_VERSION"
    SCORE_OWNERSHIP_VIOLATION = "SCORE_OWNERSHIP_VIOLATION"
    CISO_APPROVAL_REQUIRED = "CISO_APPROVAL_REQUIRED"
    CISO_REJECTION = "CISO_REJECTION"
    LLM_TIMEOUT = "LLM_TIMEOUT"
    LLM_EMPTY_RESPONSE = "LLM_EMPTY_RESPONSE"
    LLM_PROVIDER_ERROR = "LLM_PROVIDER_ERROR"
    EVIDENCE_CATALOG_UNAVAILABLE = "EVIDENCE_CATALOG_UNAVAILABLE"
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"
    SCORING_ENGINE_ERROR = "SCORING_ENGINE_ERROR"


class MCPBlockedError(Exception):
    """Raised when the pipeline must transition to BLOCKED. Non-recoverable within the session."""

    def __init__(self, code: EventCode, detail: str):
        self.code = code
        self.detail = detail
        super().__init__(f"{code.value}: {detail}")


class MCPTechnicalFailure(Exception):
    """Raised when the pipeline must transition to TECHNICAL_FAILURE (not a security violation)."""

    def __init__(self, code: EventCode, detail: str):
        self.code = code
        self.detail = detail
        super().__init__(f"{code.value}: {detail}")
