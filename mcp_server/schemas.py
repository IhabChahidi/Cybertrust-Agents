"""JSON Schemas for the four business contracts + the MCPScore technical object (L3).

All contracts share schema_version (const "1.0"), session_id, correlation_id, and
enforce additionalProperties: false, per the S1 data-contracts note.
"""

_COMMON = {
    "schema_version": {"type": "string", "const": "1.0"},
    "session_id": {"type": "string", "pattern": "^SES-[A-Z0-9-]{8,50}$"},
    "correlation_id": {"type": "string", "pattern": "^COR-[A-Z0-9-]{8,50}$"},
}

EVIDENCE_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Evidence",
    "type": "object",
    "required": [
        "schema_version", "session_id", "correlation_id", "id", "source",
        "date", "type", "content", "severity", "integrity_hash",
    ],
    "additionalProperties": False,
    "properties": {
        **_COMMON,
        "id": {"type": "string", "pattern": "^EVD-[0-9]{4}$"},
        "source": {"type": "string", "maxLength": 100},
        "date": {"type": "string", "format": "date-time"},
        "type": {
            "type": "string",
            "enum": ["ticket", "report", "scan_result", "audit_record", "validation_record"],
        },
        "content": {
            "type": "object",
            "required": ["summary", "raw_data"],
            "additionalProperties": False,
            "properties": {
                "summary": {"type": "string", "minLength": 1, "maxLength": 500},
                "raw_data": {"type": "string", "maxLength": 5000},
                "affected_assets": {
                    "type": "array", "maxItems": 20, "uniqueItems": True,
                    "items": {"type": "string", "maxLength": 100},
                },
                "indicators": {
                    "type": "array", "maxItems": 20, "uniqueItems": True,
                    "items": {"type": "string", "maxLength": 100},
                },
            },
        },
        "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
        "integrity_hash": {"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"},
    },
}

CLAIM_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Claim",
    "type": "object",
    "required": [
        "schema_version", "session_id", "correlation_id", "id", "evidence_ids",
        "statement", "confidence", "generated_at", "generator_role",
    ],
    "additionalProperties": False,
    "properties": {
        **_COMMON,
        "id": {"type": "string", "pattern": "^CLM-[0-9]{4}$"},
        "evidence_ids": {
            "type": "array", "minItems": 1, "maxItems": 12, "uniqueItems": True,
            "items": {"type": "string", "pattern": "^EVD-[0-9]{4}$"},
        },
        "statement": {"type": "string", "minLength": 1, "maxLength": 1000},
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "context": {"type": "string", "maxLength": 500},
        "generated_at": {"type": "string", "format": "date-time"},
        "generator_role": {"type": "string", "const": "GENERATOR"},
    },
}

VERIFICATION_RESULT_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "VerificationResult",
    "type": "object",
    "required": [
        "schema_version", "session_id", "correlation_id", "id", "claim_id", "status",
        "reasoning_summary", "supporting_evidence", "contradicting_evidence",
        "missing_evidence", "verified_at", "verifier_role",
    ],
    "additionalProperties": False,
    "properties": {
        **_COMMON,
        "id": {"type": "string", "pattern": "^VER-[0-9]{4}$"},
        "claim_id": {"type": "string", "pattern": "^CLM-[0-9]{4}$"},
        "status": {
            "type": "string",
            "enum": ["supported", "unsupported", "contradicted", "insufficient_evidence"],
        },
        "reasoning_summary": {"type": "string", "minLength": 1, "maxLength": 1500},
        "supporting_evidence": {
            "type": "array", "uniqueItems": True, "items": {"type": "string", "pattern": "^EVD-[0-9]{4}$"},
        },
        "contradicting_evidence": {
            "type": "array", "uniqueItems": True, "items": {"type": "string", "pattern": "^EVD-[0-9]{4}$"},
        },
        "missing_evidence": {
            "type": "array", "uniqueItems": True, "items": {"type": "string", "maxLength": 250},
        },
        "verified_at": {"type": "string", "format": "date-time"},
        "verifier_role": {"type": "string", "const": "VERIFIER"},
    },
}

MCP_SCORE_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "MCPScore",
    "type": "object",
    "required": [
        "schema_version", "session_id", "correlation_id", "id", "verification_result_id",
        "value", "risk_level", "factors", "calculation_version", "calculated_at",
    ],
    "additionalProperties": False,
    "properties": {
        **_COMMON,
        "id": {"type": "string", "pattern": "^MCP-SCORE-[0-9]{4}$"},
        "verification_result_id": {"type": "string", "pattern": "^VER-[0-9]{4}$"},
        "value": {"type": "number", "minimum": 0, "maximum": 100},
        "risk_level": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
        "factors": {
            "type": "object",
            "required": ["severity", "exposure", "impact", "evidence_quality", "verification", "contradiction_penalty"],
            "additionalProperties": False,
            "properties": {
                "severity": {"type": "number", "minimum": 0},
                "exposure": {"type": "number", "minimum": 0},
                "impact": {"type": "number", "minimum": 0},
                "evidence_quality": {"type": "number", "minimum": 0},
                "verification": {"type": "number", "minimum": -10},
                "contradiction_penalty": {"type": "number", "maximum": 0},
            },
        },
        "calculation_version": {"type": "string", "pattern": r"^[0-9]+\.[0-9]+$"},
        "calculated_at": {"type": "string", "format": "date-time"},
    },
}

VALIDATION_DECISION_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "ValidationDecision",
    "type": "object",
    "required": [
        "schema_version", "session_id", "correlation_id", "id", "verification_result_id",
        "mcp_score_reference", "decision", "justification", "risk_level",
        "requires_ciso_approval", "decided_at", "validator_role",
    ],
    "additionalProperties": False,
    "properties": {
        **_COMMON,
        "id": {"type": "string", "pattern": "^VAL-[0-9]{4}$"},
        "verification_result_id": {"type": "string", "pattern": "^VER-[0-9]{4}$"},
        "mcp_score_reference": {"type": "string", "pattern": "^MCP-SCORE-[0-9]{4}$"},
        "decision": {
            "type": "string",
            "enum": ["APPROVED_FOR_CISO_REVIEW", "HUMAN_REVIEW", "REJECTED", "INSUFFICIENT_EVIDENCE"],
        },
        "justification": {"type": "string", "minLength": 1, "maxLength": 2000},
        "risk_level": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
        "requires_ciso_approval": {"type": "boolean"},
        "decided_at": {"type": "string", "format": "date-time"},
        "validator_role": {"type": "string", "const": "VALIDATOR"},
    },
}

SUPPORTED_SCHEMA_VERSIONS = {"1.0"}
