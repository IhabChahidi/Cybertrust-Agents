"""Deterministic diagnostics derived from Evidence content (L4/L5 governance layer).

These are advisory signals attached to the routing decision — they are NEVER used
to rewrite VerificationResult.status. The Verifier LLM remains the sole authority
for that field (see mcp_server/llm_roles/llama_verifier.py, which has no
deterministic override at all anymore).

What diagnostics CAN do is tell the policy engine (mcp_server/policy.py) that the
Verifier's "supported" verdict disagrees with what the raw Evidence fields alone
would suggest — e.g. an explicit `field=absent` marker, or two Evidence items
contradicting each other on a correlated field. When that happens, the policy
engine escalates the routing decision to READY_FOR_CISO_DECISION so a human (the
CISO — the only human decision authority in this pipeline) sees the disagreement,
instead of it being silently resolved in either direction. The Verifier's own
`status` value is never edited.

Every diagnostic is emitted twice: as a bare code string (`compute_diagnostics`,
unchanged signature — existing callers, including the orchestrator, keep working)
and as a structured detail dict (`compute_diagnostic_details`) carrying severity,
the Evidence id(s) involved, the affected field, a human-readable message, and a
stable rule_id for audit. Both are derived from the same internal computation, so
they can never drift apart.
"""

import re
from datetime import datetime, timezone

from mcp_server.evidence_parsing import fields_marked_absent, find_contradictions, parse_raw_data

EXPLICIT_ABSENCE_MARKER_DETECTED = "EXPLICIT_ABSENCE_MARKER_DETECTED"
POTENTIAL_INTER_EVIDENCE_CONFLICT = "POTENTIAL_INTER_EVIDENCE_CONFLICT"
VERIFIER_DIAGNOSTIC_DISAGREEMENT = "VERIFIER_DIAGNOSTIC_DISAGREEMENT"
CONTRADICTION_REQUIRES_CISO_DECISION = "CONTRADICTION_REQUIRES_CISO_DECISION"
LOW_EVIDENCE_COVERAGE = "LOW_EVIDENCE_COVERAGE"
STALE_EVIDENCE = "STALE_EVIDENCE"
MISSING_EXPECTED_FIELD = "MISSING_EXPECTED_FIELD"
AMBIGUOUS_EVIDENCE = "AMBIGUOUS_EVIDENCE"

ALL_WARNING_CODES = frozenset({
    EXPLICIT_ABSENCE_MARKER_DETECTED, POTENTIAL_INTER_EVIDENCE_CONFLICT,
    VERIFIER_DIAGNOSTIC_DISAGREEMENT, CONTRADICTION_REQUIRES_CISO_DECISION,
    LOW_EVIDENCE_COVERAGE, STALE_EVIDENCE, MISSING_EXPECTED_FIELD, AMBIGUOUS_EVIDENCE,
})

SEVERITY_SERIOUS = "SERIOUS"
SEVERITY_INFORMATIONAL = "INFORMATIONAL"

# Centralized severity per code. MISSING_EXPECTED_FIELD and AMBIGUOUS_EVIDENCE are
# always SERIOUS whenever they fire at all -- both only ever fire when the missing
# field / detected ambiguity is directly material to the Evidence type's own basic
# conclusion (see the trigger rules below), so "does this affect the conclusion"
# is folded into the trigger condition itself rather than a second judgment call.
# STALE_EVIDENCE stays INFORMATIONAL unconditionally: this module has no
# claim-specific notion of "impossible to conclude," only Evidence content, so it
# does not attempt that distinction (documented simplification, see docs).
DIAGNOSTIC_SEVERITY = {
    EXPLICIT_ABSENCE_MARKER_DETECTED: SEVERITY_SERIOUS,
    POTENTIAL_INTER_EVIDENCE_CONFLICT: SEVERITY_SERIOUS,
    VERIFIER_DIAGNOSTIC_DISAGREEMENT: SEVERITY_SERIOUS,
    CONTRADICTION_REQUIRES_CISO_DECISION: SEVERITY_SERIOUS,
    MISSING_EXPECTED_FIELD: SEVERITY_SERIOUS,
    AMBIGUOUS_EVIDENCE: SEVERITY_SERIOUS,
    LOW_EVIDENCE_COVERAGE: SEVERITY_INFORMATIONAL,
    STALE_EVIDENCE: SEVERITY_INFORMATIONAL,
}

# Single source of truth for "does this warning force CISO escalation" — derived
# from DIAGNOSTIC_SEVERITY rather than a second, independently-maintained set, so
# severity and escalation can never drift apart.
SERIOUS_WARNINGS = frozenset(code for code, sev in DIAGNOSTIC_SEVERITY.items() if sev == SEVERITY_SERIOUS)

_STALE_THRESHOLD_DAYS = 90

# --- Workstream A.1: MISSING_EXPECTED_FIELD -----------------------------------
#
# Centralized, explicit mapping (never scattered field checks). Keyed on
# Evidence.type (EVIDENCE_SCHEMA's enum). "incident_action" and "committee_action"
# are additive enum values for the incident-response and committee-decision
# Evidence categories (UC-04/UC-05); adding them to EVIDENCE_SCHEMA.type is a
# backward-compatible, additive-only schema change (see schemas.py).
EXPECTED_FIELDS_BY_EVIDENCE_TYPE: dict[str, list[str]] = {
    "ticket": ["status"],
    "scan_result": ["result"],
    "audit_record": ["status", "owner", "deadline"],
    "validation_record": ["validation_status"],
    "report": ["patch_report"],
    "incident_action": ["status", "owner"],
    "committee_action": ["status", "owner"],
}


def _missing_expected_fields(evidence_item: dict) -> list[str]:
    """Fields required for this Evidence.type that are entirely absent from the
    parsed raw_data (not merely present-but-marked-absent — that is
    fields_marked_absent's job). Unknown Evidence types (not in the mapping)
    never crash the pipeline: they simply have no expected-field rule and produce
    no MISSING_EXPECTED_FIELD warning here (schema validation, upstream of
    diagnostics, is what actually rejects a truly unknown/invalid Evidence.type).
    """
    expected = EXPECTED_FIELDS_BY_EVIDENCE_TYPE.get(evidence_item.get("type"))
    if not expected:
        return []
    fields = parse_raw_data(evidence_item["content"]["raw_data"])
    return [name for name in expected if name not in fields]


# --- Workstream A.2: AMBIGUOUS_EVIDENCE ---------------------------------------
#
# Deterministic, explainable phrase/value rules -- no second LLM. Each pattern
# carries its own rule_id so the structured detail can cite exactly which rule
# fired. Patterns are checked against `summary` (free text) and, for the
# proof-without-closure rule, against parsed raw_data fields.
_AMBIGUOUS_TEXT_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"probably closed|probablement clôtur|probablement ferm", re.IGNORECASE),
     "DIAG-AMB-001", "vague closure language ('probably closed')"),
    (re.compile(r"seems resolved|semble résolu|semble r[ée]gl", re.IGNORECASE),
     "DIAG-AMB-002", "vague resolution language ('seems resolved')"),
    (re.compile(r"in progress\s*/\s*completed|en cours\s*/\s*termin", re.IGNORECASE),
     "DIAG-AMB-003", "conflicting status stated in the same text ('in progress / completed')"),
    (re.compile(r"pending confirmation|en attente de confirmation", re.IGNORECASE),
     "DIAG-AMB-004", "unconfirmed status ('pending confirmation')"),
    (re.compile(r"partially remediated|partiellement corrig|partiellement rem[ée]di", re.IGNORECASE),
     "DIAG-AMB-005", "partial remediation language"),
    (re.compile(r"status unknown|statut inconnu", re.IGNORECASE),
     "DIAG-AMB-006", "explicitly unknown status"),
    (re.compile(r"\bnormally fixed\b|normalement corrig", re.IGNORECASE),
     "DIAG-AMB-007", "vague fix language ('normally fixed')"),
]

# Status-like values that assert closure/completion but, without an accompanying
# proof-bearing field, do not establish it (spec: "'done' without proof").
_VAGUE_CLOSURE_VALUES = {"done", "closed", "termine", "terminé", "complete", "completed"}
_PROOF_FIELDS = {"patch_report", "pv_reference", "deliverable", "rescan_result", "validation_status"}


def _ambiguous_details(evidence_item: dict) -> list[dict]:
    details = []
    eid = evidence_item["id"]
    summary = evidence_item["content"].get("summary", "")
    raw = evidence_item["content"].get("raw_data", "")
    text = f"{summary} {raw}"

    for pattern, rule_id, description in _AMBIGUOUS_TEXT_PATTERNS:
        match = pattern.search(text)
        if match:
            details.append({
                "code": AMBIGUOUS_EVIDENCE, "severity": SEVERITY_SERIOUS,
                "evidence_ids": [eid], "field": "summary/raw_data",
                "message": f"Ambiguous language detected: {description}.",
                "rule_id": rule_id, "detected_value": match.group(0),
            })

    fields = parse_raw_data(raw)
    for field_name in ("status", "validation_status"):
        value = fields.get(field_name, "").strip().lower()
        if value in _VAGUE_CLOSURE_VALUES and not (_PROOF_FIELDS & fields.keys()):
            details.append({
                "code": AMBIGUOUS_EVIDENCE, "severity": SEVERITY_SERIOUS,
                "evidence_ids": [eid], "field": field_name,
                "message": f"'{field_name}={value}' asserts closure/completion with no accompanying proof field.",
                "rule_id": "DIAG-AMB-008", "detected_value": value,
            })

    return details


def _is_stale(evidence_item: dict) -> bool:
    date_str = evidence_item.get("date")
    if not date_str:
        return False
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except ValueError:
        return False
    return (datetime.now(timezone.utc) - dt).days > _STALE_THRESHOLD_DAYS


def _collect_details(evidence: list[dict], verification_status: str) -> list[dict]:
    details: list[dict] = []

    absent_ids = [e["id"] for e in evidence if fields_marked_absent(e)]
    if absent_ids:
        details.append({
            "code": EXPLICIT_ABSENCE_MARKER_DETECTED, "severity": SEVERITY_SERIOUS,
            "evidence_ids": absent_ids, "field": None,
            "message": "One or more Evidence items have a field explicitly marked absent.",
            "rule_id": "DIAG-ABS-001",
        })

    contradictions = find_contradictions(evidence)
    if contradictions:
        involved = sorted({h["baseline_id"] for h in contradictions} | {h["anomaly_id"] for h in contradictions})
        details.append({
            "code": POTENTIAL_INTER_EVIDENCE_CONFLICT, "severity": SEVERITY_SERIOUS,
            "evidence_ids": involved, "field": contradictions[0]["field"],
            "message": "Two or more Evidence items contradict each other on a correlated field.",
            "rule_id": "DIAG-CONF-001",
        })

    if contradictions and verification_status != "contradicted":
        details.append({
            "code": VERIFIER_DIAGNOSTIC_DISAGREEMENT, "severity": SEVERITY_SERIOUS,
            "evidence_ids": involved, "field": None,
            "message": f"Structured facts show a contradiction, but the Verifier status is {verification_status!r}.",
            "rule_id": "DIAG-DIS-001",
        })
    elif absent_ids and verification_status not in ("insufficient_evidence", "contradicted"):
        details.append({
            "code": VERIFIER_DIAGNOSTIC_DISAGREEMENT, "severity": SEVERITY_SERIOUS,
            "evidence_ids": absent_ids, "field": None,
            "message": f"An explicit absent-field marker exists, but the Verifier status is {verification_status!r}.",
            "rule_id": "DIAG-DIS-002",
        })

    if verification_status == "contradicted":
        details.append({
            "code": CONTRADICTION_REQUIRES_CISO_DECISION, "severity": SEVERITY_SERIOUS,
            "evidence_ids": [e["id"] for e in evidence], "field": None,
            "message": "Verifier status is 'contradicted'; this always requires a CISO decision.",
            "rule_id": "DIAG-CONTRA-001",
        })

    for item in evidence:
        missing = _missing_expected_fields(item)
        if missing:
            details.append({
                "code": MISSING_EXPECTED_FIELD, "severity": SEVERITY_SERIOUS,
                "evidence_ids": [item["id"]], "field": ", ".join(missing),
                "message": f"Evidence type {item.get('type')!r} is missing expected field(s): {missing}.",
                "rule_id": "DIAG-MISS-001",
            })
        details.extend(_ambiguous_details(item))

    if len(evidence) <= 1:
        details.append({
            "code": LOW_EVIDENCE_COVERAGE, "severity": SEVERITY_INFORMATIONAL,
            "evidence_ids": [e["id"] for e in evidence], "field": None,
            "message": "Conclusion is based on a single Evidence item.",
            "rule_id": "DIAG-COV-001",
        })

    stale_ids = [e["id"] for e in evidence if _is_stale(e)]
    if stale_ids:
        details.append({
            "code": STALE_EVIDENCE, "severity": SEVERITY_INFORMATIONAL,
            "evidence_ids": stale_ids, "field": "date",
            "message": f"Evidence older than {_STALE_THRESHOLD_DAYS} days.",
            "rule_id": "DIAG-STALE-001",
        })

    return details


def compute_diagnostics(evidence: list[dict], verification_status: str) -> list[str]:
    """Ordered list of diagnostic warning CODES (unchanged signature — existing
    callers, including the orchestrator, are unaffected). Pure function of
    Evidence content + status; never mutates or re-derives `verification_status`.
    """
    return [d["code"] for d in _collect_details(evidence, verification_status)]


def compute_diagnostic_details(evidence: list[dict], verification_status: str) -> list[dict]:
    """Structured diagnostic records (Workstream A.3): {code, severity,
    evidence_ids, field, message, rule_id, ...}. Additive companion to
    compute_diagnostics() — same underlying computation, richer shape.
    """
    return _collect_details(evidence, verification_status)
