"""Configuration-driven business-exception rules for the policy engine (Workstream B).

Rules are declarative YAML (config/policy_rules.yaml), validated against
POLICY_CONFIG_SCHEMA before use. They can only ever narrow or redirect routing
within the allowed decision values, for verification_status in {supported,
unsupported, contradicted} — insufficient_evidence is excluded from the schema's
matchable statuses entirely, so no rule can ever touch it (MCPScore/business
rules must never compensate for missing Evidence). HUMAN_REVIEW cannot appear in
`action.decision` because the schema's enum for that field does not include it —
a config file naming it fails validation at load time.

Malformed configuration (bad YAML, schema violation, duplicate rule id, or
duplicate priority among overlapping enabled rules) raises PolicyConfigError.
Callers (mcp_server/policy.py) must catch this and fall back to the hard-coded
default table — never crash the pipeline, never apply a partially-invalid
configuration, never silently ignore the failure (it is logged).

This module executes no code from the configuration: yaml.safe_load only ever
produces plain dicts/lists/scalars, and every field is validated against a
fixed, explicit JSON Schema before any rule is used.
"""

import hashlib
import json
from pathlib import Path

import yaml
from jsonschema import Draft7Validator

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "policy_rules.yaml"

# verification_status is deliberately restricted to these three: insufficient_evidence
# must never be configurable (spec 4.2 "MCPScore must never compensate for missing
# evidence" — allowing a rule to match on it would be exactly that door).
_MATCHABLE_STATUSES = ["supported", "unsupported", "contradicted"]

# READY_FOR_CISO_INFORMATION is intentionally omitted from the allowed actions for
# unsupported/contradicted at the schema level below (per-status restriction),
# and HUMAN_REVIEW / INSUFFICIENT_EVIDENCE are never offered at all: a rule
# cannot even express them, let alone apply them.
_ALL_ACTION_DECISIONS = ["READY_FOR_CISO_DECISION", "READY_FOR_CISO_INFORMATION", "REJECTED"]

POLICY_CONFIG_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["policy_version", "rules"],
    "additionalProperties": False,
    "properties": {
        "policy_version": {"type": "string", "maxLength": 20},
        "rules": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "enabled", "priority", "match", "action", "reason"],
                "additionalProperties": False,
                "properties": {
                    "id": {"type": "string", "pattern": "^POL-[0-9]{3,}$"},
                    "enabled": {"type": "boolean"},
                    "priority": {"type": "integer", "minimum": 0, "maximum": 10000},
                    "match": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "verification_status": {"type": "string", "enum": _MATCHABLE_STATUSES},
                            "risk_levels": {
                                "type": "array", "minItems": 1,
                                "items": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                            },
                        },
                    },
                    "action": {
                        "type": "object",
                        "required": ["decision", "requires_ciso_approval"],
                        "additionalProperties": False,
                        "properties": {
                            "decision": {"type": "string", "enum": _ALL_ACTION_DECISIONS},
                            "requires_ciso_approval": {"type": "boolean"},
                        },
                    },
                    "reason": {"type": "string", "minLength": 1, "maxLength": 300},
                },
            },
        },
    },
}


class PolicyConfigError(ValueError):
    """Raised when policy_rules.yaml is missing, malformed, or fails schema
    validation, or contains ambiguous (duplicate id/priority) rules. Callers must
    fail closed to the built-in default table — never crash the pipeline."""


def load_policy_config(path: str | Path = DEFAULT_CONFIG_PATH) -> dict:
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyConfigError(f"cannot read policy config: {exc}") from exc

    try:
        data = yaml.safe_load(raw)  # safe_load: no arbitrary object/code construction
    except yaml.YAMLError as exc:
        raise PolicyConfigError(f"malformed YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise PolicyConfigError("policy config must be a YAML mapping at the top level")

    errors = list(Draft7Validator(POLICY_CONFIG_SCHEMA).iter_errors(data))
    if errors:
        detail = "; ".join(f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors)
        raise PolicyConfigError(f"schema validation failed: {detail}")

    ids = [r["id"] for r in data["rules"]]
    if len(ids) != len(set(ids)):
        raise PolicyConfigError("duplicate rule id in policy config")

    seen_priorities: dict[tuple, set[int]] = {}
    for rule in data["rules"]:
        if not rule["enabled"]:
            continue
        key = (rule["match"].get("verification_status"), tuple(sorted(rule["match"].get("risk_levels", []))))
        bucket = seen_priorities.setdefault(key, set())
        if rule["priority"] in bucket:
            raise PolicyConfigError(
                f"duplicate priority {rule['priority']} among enabled rules matching {key!r}"
            )
        bucket.add(rule["priority"])

    return data


def config_hash(config: dict) -> str:
    """Short, stable content hash for audit traceability. Never a filesystem path."""
    canonical = json.dumps(config, sort_keys=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()[:16]


def find_matching_rule(config: dict, *, status: str, risk_level: str) -> dict | None:
    """Highest-priority enabled rule matching (status, risk_level), or None.
    Never call this for status == "insufficient_evidence" — the schema does not
    allow any rule to match it, so this would always return None for it anyway,
    but callers should not rely on that: apply the fixed mapping directly.
    """
    candidates = []
    for rule in config["rules"]:
        if not rule["enabled"]:
            continue
        match = rule["match"]
        if match.get("verification_status") not in (None, status):
            continue
        risk_levels = match.get("risk_levels")
        if risk_levels and risk_level not in risk_levels:
            continue
        candidates.append(rule)
    if not candidates:
        return None
    return max(candidates, key=lambda r: r["priority"])
