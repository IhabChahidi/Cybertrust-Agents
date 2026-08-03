"""GeneratedClaim: the output contract for the new llama.cpp/Foundation-Sec
Generator API (spec section 14). Distinct from mcp_server.schemas.CLAIM_SCHEMA
(the existing MCP pipeline's Claim contract, JSON-Schema/jsonschema-validated) --
this is a richer, Pydantic-validated envelope for the new /api/v1/generator/claims
endpoint. `to_mcp_claim()` below converts one into the other so the new endpoint's
output remains consumable by the existing Verifier/Validator pipeline, preserving
backward compatibility rather than forking the contract.
"""

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from mcp_server.evidence_parsing import find_contradictions
from mcp_server.logging_utils import AuditLogger
from mcp_server.rag.identifiers import CVE_RE, EVIDENCE_ID_RE, MITRE_TECHNIQUE_RE, RUNBOOK_ID_RE

_ALL_CITABLE_ID_RE = re.compile(
    "|".join(p.pattern for p in (EVIDENCE_ID_RE, CVE_RE, MITRE_TECHNIQUE_RE, RUNBOOK_ID_RE))
)

# Evidence types that describe a ticket/action record rather than a technical
# verification of the actual system state (spec section 4: "a ticket status
# alone cannot prove technical remediation when verification evidence is
# mandatory"). Extend this table, not ad-hoc string checks at call sites.
_TICKET_ONLY_EVIDENCE_TYPES = {"remediation_ticket", "change_ticket", "incident_action", "committee_action"}
_VERIFICATION_EVIDENCE_TYPES = {
    "vulnerability_scan", "verification_scan", "rescan", "penetration_test_result", "configuration_audit",
}
_REMEDIATION_CLAIM_PATTERN = re.compile(
    r"\b(remedi\w*|patch\w*|closed|resolved|complian\w*|implement\w*|fixed)\b", re.IGNORECASE,
)


class GeneratorOutputError(ValueError):
    """Raised when the model's JSON is malformed, fails Pydantic validation, or
    cites an id that was never actually retrieved. Callers (generator_service.py)
    catch this to drive the single deterministic repair attempt, then fail
    closed with a controlled error if repair also fails -- never silently
    coerced into a valid-looking response.
    """


class GeneratedClaim(BaseModel):
    model_config = {"extra": "forbid"}

    claim_id: str
    request_id: str
    status: Literal["CLAIM_GENERATED", "INSUFFICIENT_EVIDENCE"]
    claim: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    reference_ids: list[str] = Field(default_factory=list)
    reasoning_summary: str
    confidence: float = Field(ge=0.0, le=1.0)
    limitations: list[str] = Field(default_factory=list)
    generated_at: datetime
    model_name: str
    retrieval_trace_id: str

    @field_validator("evidence_ids")
    @classmethod
    def _validate_evidence_id_shape(cls, value: list[str]) -> list[str]:
        for eid in value:
            if not EVIDENCE_ID_RE.fullmatch(eid):
                raise ValueError(f"evidence_ids entry {eid!r} does not match ^EVD-\\d{{4}}$")
        return value

    @model_validator(mode="after")
    def _insufficient_evidence_has_no_conclusive_claim(self) -> "GeneratedClaim":
        if self.status == "INSUFFICIENT_EVIDENCE" and self.claim:
            # Not fatal by itself (a model might still narrate why evidence is
            # insufficient in `claim`), but it must not read as a completed
            # conclusion. The stronger, code-enforced guarantee is that no
            # decision routing anywhere treats INSUFFICIENT_EVIDENCE as
            # conclusive -- see mcp_server/policy.py, unaffected by this endpoint.
            pass
        return self


def _known_ids(*id_lists: list[str]) -> set[str]:
    known: set[str] = set()
    for ids in id_lists:
        known.update(ids)
    return known


def validate_citations(parsed: dict, *, retrieved_evidence_ids: set[str], retrieved_reference_ids: set[str]) -> None:
    """Reject any evidence_ids/reference_ids entry, OR any id-shaped token
    mentioned inside `claim`/`reasoning_summary`, that was not actually part of
    the retrieved context for this request. This is the code-level guarantee
    behind "the API must reject output containing IDs that were not in the
    retrieved context" (spec section 14) -- not a prompt instruction alone.
    """
    for eid in parsed.get("evidence_ids") or []:
        if eid not in retrieved_evidence_ids:
            raise GeneratorOutputError(f"evidence_ids cites {eid!r}, which was not in the retrieved context")
    for rid in parsed.get("reference_ids") or []:
        if rid not in retrieved_reference_ids:
            raise GeneratorOutputError(f"reference_ids cites {rid!r}, which was not in the retrieved context")

    known = _known_ids(list(retrieved_evidence_ids), list(retrieved_reference_ids))
    for field_name in ("claim", "reasoning_summary"):
        text = parsed.get(field_name) or ""
        for token in _ALL_CITABLE_ID_RE.findall(text):
            if token not in known:
                raise GeneratorOutputError(
                    f"{field_name} mentions id {token!r}, which was not in the retrieved context"
                )


def parse_generated_claim(
    raw_json: dict, *, request_id: str, retrieved_evidence_ids: set[str], retrieved_reference_ids: set[str],
    model_name: str, retrieval_trace_id: str,
) -> GeneratedClaim:
    """Validates a parsed JSON dict (already json.loads'd by the caller) against
    both the Pydantic shape AND the citation rule above. Raises
    GeneratorOutputError on any violation -- callers drive the one-time repair
    attempt around this function, it does not retry anything itself.
    """
    validate_citations(raw_json, retrieved_evidence_ids=retrieved_evidence_ids, retrieved_reference_ids=retrieved_reference_ids)

    payload = dict(raw_json)
    payload.setdefault("claim_id", f"GCLM-{uuid.uuid4().hex[:12].upper()}")
    payload["request_id"] = request_id
    payload["model_name"] = model_name
    payload["retrieval_trace_id"] = retrieval_trace_id
    payload.setdefault("generated_at", datetime.now(timezone.utc).isoformat())

    try:
        return GeneratedClaim.model_validate(payload)
    except Exception as exc:  # pydantic.ValidationError, re-raised as our own controlled type
        raise GeneratorOutputError(f"model output failed schema validation: {exc}") from exc


def enforce_source_authority(
    claim: GeneratedClaim, *, included_results: list[Any],
    case_id: str | None = None, ticket_id: str | None = None, asset_id: str | None = None,
) -> None:
    """Deterministic, code-enforced source-authority rules (spec section 4).
    These are checked here -- in code, after the model has already produced
    (and Pydantic has already validated) its output -- specifically because
    the system prompt's equivalent instructions are advisory to the model,
    not a guarantee: "Do not rely on the LLM prompt for these controls."

    `included_results` are the actual mcp_server.rag.schemas.RetrievalResult
    objects that were included in the context for this request, used to look
    up each cited id's real collection/evidence_type/observed_at/scope.
    """
    if claim.status != "CLAIM_GENERATED":
        return  # nothing to check for a non-conclusive result

    by_id = {r.record_id: r for r in included_results}

    # Rule: a conclusive claim requires at least one authoritative corporate
    # evidence citation -- CVE/MITRE/KEV/runbook references alone (or none at
    # all) can never be sufficient ("A CVE record cannot prove remediation.
    # A MITRE record cannot prove remediation. A runbook cannot prove that its
    # steps were executed.").
    if not claim.evidence_ids:
        raise GeneratorOutputError(
            "status=CLAIM_GENERATED requires at least one corporate evidence citation in evidence_ids; "
            "reference-only support (MITRE/CVE/KEV/runbook) is never sufficient by itself"
        )

    cited_evidence = [by_id[eid] for eid in claim.evidence_ids if eid in by_id]

    # Rule: evidence cited for a conclusive claim must belong to the
    # requested case/ticket/asset scope, if one was requested ("Evidence from
    # a different case, ticket or asset cannot support the claim"). Retrieval
    # already enforces this before a record can even be retrieved/cited
    # (mcp_server.rag.retrieval._belongs_to_scope) -- this is defense in
    # depth against that check ever being bypassed or a future regression.
    if case_id or ticket_id or asset_id:
        from mcp_server.rag.retrieval import _belongs_to_scope
        for r in cited_evidence:
            if not _belongs_to_scope(r.metadata, case_id, ticket_id, asset_id):
                raise GeneratorOutputError(
                    f"evidence {r.record_id!r} does not belong to the requested case/ticket/asset scope"
                )

    # Rule: "a ticket marked closed is not, by itself, sufficient proof of
    # remediation when a verification scan is the evidence type that would
    # normally be required" -- enforced whenever the claim text asserts a
    # remediation/closure/compliance outcome but only ticket/action-type
    # evidence (no verification-type evidence) was cited.
    evidence_types = {r.metadata.get("evidence_type") for r in cited_evidence}
    claim_text = claim.claim
    asserts_remediation = claim_text is not None and bool(_REMEDIATION_CLAIM_PATTERN.search(claim_text))
    has_verification_evidence = bool(evidence_types & _VERIFICATION_EVIDENCE_TYPES)
    ticket_only = bool(evidence_types) and evidence_types <= _TICKET_ONLY_EVIDENCE_TYPES
    if asserts_remediation and ticket_only and not has_verification_evidence:
        raise GeneratorOutputError(
            "the claim asserts a remediation/closure/compliance outcome supported only by ticket/action "
            f"evidence (types: {', '.join(sorted(t for t in evidence_types if t))}); a verification scan "
            "or equivalent technical evidence is required for this kind of conclusion"
        )

    # Rule: "a newer contradictory record must prevent a positive remediation
    # claim." Reuses the existing structured key=value contradiction detector
    # (mcp_server/evidence_parsing.py, already used by the Ollama-backed
    # Verifier) rather than inventing a second one. Evidence content that
    # does not follow the "key=value; key=value" convention yields no signal
    # here -- a documented limitation (see README), not a silent guarantee.
    if asserts_remediation and len(cited_evidence) >= 2:
        pseudo_evidence = [
            {"id": r.record_id, "date": r.metadata.get("observed_at", ""), "content": {"raw_data": r.content}}
            for r in cited_evidence
        ]
        contradictions = find_contradictions(pseudo_evidence)
        if contradictions:
            hit = contradictions[0]
            raise GeneratorOutputError(
                f"cited evidence contains an unresolved factual contradiction ({hit['field']}: "
                f"{hit['baseline_id']}={hit['baseline_value']} vs {hit['anomaly_id']}={hit['anomaly_value']}); "
                "a positive remediation claim cannot stand while cited evidence conflicts"
            )


def enforce_no_repair_drift(*, original_parsed: dict | None, repaired: GeneratedClaim) -> None:
    """Guards the one-time JSON repair pass (spec section 14): the repair
    prompt instructs the model to fix serialization/shape only, but that
    instruction is advisory, not a guarantee -- this is the code-level check.
    Rejects a repaired output that:
      - cites any evidence_ids/reference_ids not present in the original
        (pre-repair) parsed output -- repair must not ADD citations;
      - reports a higher confidence than the original;
      - flips status from INSUFFICIENT_EVIDENCE to CLAIM_GENERATED -- that
        would mean the repair reinterpreted missing evidence into a
        conclusion, not merely fixed its shape.

    `original_parsed` is None when the original model output was not even
    valid JSON (the common repair case) -- there is nothing to compare
    against then, so this is a no-op (the citation/authority rules on the
    repaired output itself still apply via validate_citations() and
    enforce_source_authority(), called separately).
    """
    if not original_parsed or not isinstance(original_parsed, dict):
        return

    original_evidence = set(original_parsed.get("evidence_ids") or [])
    original_reference = set(original_parsed.get("reference_ids") or [])
    new_evidence = set(repaired.evidence_ids) - original_evidence
    new_reference = set(repaired.reference_ids) - original_reference
    if new_evidence or new_reference:
        raise GeneratorOutputError(
            f"repair introduced citations not present in the original output: "
            f"evidence={sorted(new_evidence)} reference={sorted(new_reference)}"
        )

    original_confidence = original_parsed.get("confidence")
    if isinstance(original_confidence, (int, float)) and repaired.confidence > float(original_confidence) + 1e-9:
        raise GeneratorOutputError(
            f"repair increased confidence from {original_confidence} to {repaired.confidence}, which is not permitted"
        )

    original_status = original_parsed.get("status")
    if original_status == "INSUFFICIENT_EVIDENCE" and repaired.status == "CLAIM_GENERATED":
        raise GeneratorOutputError(
            "repair changed status from INSUFFICIENT_EVIDENCE to CLAIM_GENERATED, which is not permitted "
            "(repair may only fix serialization/shape, never reinterpret missing evidence)"
        )


def to_mcp_claim(
    generated: GeneratedClaim, *, session_id: str, correlation_id: str, claim_id: str,
    audit: AuditLogger | None = None,
) -> dict[str, Any]:
    """Adapts a GeneratedClaim into the existing MCP pipeline's Claim contract
    (mcp_server.schemas.CLAIM_SCHEMA) so the new endpoint's output can still flow
    into the unchanged Verifier/Validator (spec: "Generator output must remain
    compatible with them"). Only ever called when status == CLAIM_GENERATED and
    a real evidence_ids list exists -- CLAIM_SCHEMA requires at least one Evidence
    id and a non-null statement, which INSUFFICIENT_EVIDENCE output cannot satisfy.

    CLAIM_SCHEMA has `additionalProperties: False` and no field for
    `generated.claim_id` (its own GCLM-... id, distinct from the MCP `id`
    this function assigns), `generated.request_id`, or `generated.model_name`
    -- these cannot be added to the returned dict without breaking schema
    validation. Rather than silently discard them, they are written to the
    audit journal when an `audit` (mcp_server.logging_utils.AuditLogger) is
    supplied -- an existing, already-durable structure -- so the mapping from
    a Foundation-Sec GeneratedClaim to its resulting MCP Claim stays
    reconstructable. `retrieval_trace_id`/`reference_ids`/`limitations` ARE
    representable in CLAIM_SCHEMA (additive optional fields) and are passed
    through directly, not just logged.
    """
    if generated.status != "CLAIM_GENERATED" or not generated.claim or not generated.evidence_ids:
        raise GeneratorOutputError(
            "cannot adapt an INSUFFICIENT_EVIDENCE (or evidence-less) GeneratedClaim into an MCP Claim; "
            "the MCP pipeline's own Verifier must instead receive this as insufficient_evidence upstream"
        )

    if audit is not None:
        audit.log(
            session_id=session_id, correlation_id=correlation_id, state="GENERATOR",
            event_type="GENERATOR_CLAIM_ADAPTED_TO_MCP", role="GENERATOR", result="OK",
            detail=(
                f"source=foundation_sec_rag original_claim_id={generated.claim_id} "
                f"request_id={generated.request_id} model_name={generated.model_name} mcp_claim_id={claim_id}"
            ),
        )

    return {
        "schema_version": "1.0",
        "session_id": session_id,
        "correlation_id": correlation_id,
        "id": claim_id,
        "evidence_ids": generated.evidence_ids,
        "statement": generated.claim[:1000],
        "confidence": generated.confidence,
        "context": generated.reasoning_summary[:500],
        "generated_at": generated.generated_at.isoformat(),
        "generator_role": "GENERATOR",
        "reference_ids": generated.reference_ids,
        "limitations": generated.limitations,
        "retrieval_trace_id": generated.retrieval_trace_id,
    }
