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
            # "incident_action" and "committee_action" are additive (UC-04/UC-05,
            # backward compatible: existing Evidence/consumers are unaffected).
            "enum": [
                "ticket", "report", "scan_result", "audit_record", "validation_record",
                "incident_action", "committee_action",
            ],
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
        # Optional (not in `required`): populated only when the Generator's
        # optional local RAG layer (mcp_server/rag/) was enabled and used for
        # this Claim. Absent entirely when RAG is disabled (the default) --
        # additive-only, no existing contract is broken by these fields.
        "reference_ids": {
            "type": "array", "uniqueItems": True,
            "items": {"type": "string", "maxLength": 50},
        },
        "limitations": {
            "type": "array", "items": {"type": "string", "maxLength": 200},
        },
        "retrieval_trace_id": {"type": "string", "maxLength": 50},
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
        "mcp_score_reference", "decision", "diagnostic_warnings", "justification", "risk_level",
        "requires_ciso_approval", "decided_at", "validator_role",
    ],
    "additionalProperties": False,
    "properties": {
        **_COMMON,
        "id": {"type": "string", "pattern": "^VAL-[0-9]{4}$"},
        "verification_result_id": {"type": "string", "pattern": "^VER-[0-9]{4}$"},
        "mcp_score_reference": {"type": "string", "pattern": "^MCP-SCORE-[0-9]{4}$"},
        # Governance constraint (see mcp_server/policy.py for the full rationale):
        # the CISO is the sole human decision authority in this pipeline. There is
        # no HUMAN_REVIEW and no APPROVED_FOR_CISO_REVIEW here -- every case
        # needing attention is routed via READY_FOR_CISO_DECISION.
        # READY_FOR_CISO_INFORMATION is NOT an approval: it means the case is
        # included in the CISO's information synthesis without requiring an
        # immediate decision. REJECTED and INSUFFICIENT_EVIDENCE are pipeline
        # recommendations, not a final CISO rejection (see section 8 governance
        # note: the CISO's own APPROVE/REJECT/REQUEST_MORE_EVIDENCE/DEFER action
        # is recorded separately, never automatically).
        "decision": {
            "type": "string",
            "enum": [
                "READY_FOR_CISO_DECISION", "READY_FOR_CISO_INFORMATION",
                "REJECTED", "INSUFFICIENT_EVIDENCE",
            ],
        },
        # Deterministic diagnostic warning codes (mcp_server.diagnostics) -- advisory
        # signals derived from Evidence content that can escalate routing but never
        # rewrite VerificationResult.status. Always present (possibly empty).
        "diagnostic_warnings": {
            "type": "array", "items": {"type": "string", "maxLength": 100},
        },
        # Optional (not in `required`): structured companion to diagnostic_warnings
        # (mcp_server.diagnostics.compute_diagnostic_details) -- one object per
        # warning with severity/evidence_ids/field/message/rule_id. Additive-only:
        # diagnostic_warnings (the list of bare codes) remains the required,
        # backward-compatible field; this is richer detail for consumers that want it.
        "diagnostic_details": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["code", "severity", "evidence_ids", "message", "rule_id"],
                "additionalProperties": True,
                "properties": {
                    "code": {"type": "string", "maxLength": 100},
                    "severity": {"type": "string", "enum": ["SERIOUS", "INFORMATIONAL"]},
                    "evidence_ids": {"type": "array", "items": {"type": "string", "pattern": "^EVD-[0-9]{4}$"}},
                    "field": {"type": ["string", "null"]},
                    "message": {"type": "string", "maxLength": 500},
                    "rule_id": {"type": "string", "maxLength": 50},
                },
            },
        },
        "justification": {"type": "string", "minLength": 1, "maxLength": 2000},
        "risk_level": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
        "requires_ciso_approval": {"type": "boolean"},
        "decided_at": {"type": "string", "format": "date-time"},
        "validator_role": {"type": "string", "const": "VALIDATOR"},
        # Optional (not in `required`): which row of mcp_server.policy's routing
        # table produced this decision, for audit traceability. Additive-only.
        "policy_rule": {"type": "string", "maxLength": 100},
        # Workstream B traceability fields (mcp_server/policy_config.py). All
        # optional/additive. configuration_hash is a short content hash of the
        # loaded config/policy_rules.yaml, never a filesystem path (no internal
        # path is ever exposed in a ValidationDecision).
        "policy_version": {"type": "string", "maxLength": 20},
        "policy_reason": {"type": "string", "maxLength": 300},
        "applied_exception": {"type": "boolean"},
        "configuration_hash": {"type": "string", "maxLength": 64},
    },
}

SUPPORTED_SCHEMA_VERSIONS = {"1.0"}
