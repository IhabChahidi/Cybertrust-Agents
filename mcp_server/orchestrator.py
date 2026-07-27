"""MCP server orchestrator: the state machine described in L4.

INIT -> VALIDATION_ENTREE -> SELECTION_EVIDENCE -> GENERATION_CLAIM ->
VERIFICATION -> DIAGNOSTICS -> SCORING -> VALIDATION -> DECISION_CISO -> COMPLETED

Governance constraint: the CISO is the sole human decision authority in this
pipeline. There is no separate "human review" role and no HUMAN_REVIEW status
anywhere. Only two stages are LLM-backed (GENERATION_CLAIM, VERIFICATION);
DIAGNOSTICS and VALIDATION are both fully deterministic — see
mcp_server/diagnostics.py and mcp_server/policy.py. DIAGNOSTICS computes
advisory warning codes from Evidence content and NEVER rewrites
VerificationResult.status; the Verifier LLM remains its sole author.

Any blocking violation moves the session to BLOCKED; any non-malicious
provider/technical error moves it to TECHNICAL_FAILURE. Reaching COMPLETED
means the pipeline produced a schema-valid, evidence-linked, MCP-scored
recommendation ready for the CISO — it does NOT mean a sensitive action was
auto-approved. The CISO's own APPROVE / REJECT / REQUEST_MORE_EVIDENCE / DEFER
decision (L5 section 8) is recorded separately via `record_ciso_decision`,
outside this automated pipeline, per the "no automated sensitive decision" rule.
"""

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator

from mcp_server.config import ENDPOINT_WHITELIST, MCPConfig
from mcp_server.diagnostics import compute_diagnostic_details, compute_diagnostics
from mcp_server.errors import EventCode, LLMOutputContractViolation, MCPBlockedError, MCPTechnicalFailure
from mcp_server.llm_roles.factory import build_generator, build_validator, build_verifier
from mcp_server.logging_utils import AuditLogger
from mcp_server.scoring import compute_mcp_score
from mcp_server.schemas import (
    CLAIM_SCHEMA,
    EVIDENCE_SCHEMA,
    MCP_SCORE_SCHEMA,
    SUPPORTED_SCHEMA_VERSIONS,
    VALIDATION_DECISION_SCHEMA,
    VERIFICATION_RESULT_SCHEMA,
)

_INJECTION_PATTERNS = [
    re.compile(r"ignore (all )?previous instructions", re.IGNORECASE),
    re.compile(r"disregard (all )?(prior|previous) instructions", re.IGNORECASE),
    re.compile(r"reveal (the )?(system|hidden) prompt", re.IGNORECASE),
]
_EXFILTRATION_PATTERNS = [
    re.compile(r"https?://", re.IGNORECASE),
    re.compile(r"return all (available )?evidence", re.IGNORECASE),
    re.compile(r"send (this|the) (data|evidence|catalogue) to", re.IGNORECASE),
]

_VALIDATORS = {
    "Claim": Draft7Validator(CLAIM_SCHEMA),
    "VerificationResult": Draft7Validator(VERIFICATION_RESULT_SCHEMA),
    "MCPScore": Draft7Validator(MCP_SCORE_SCHEMA),
    "ValidationDecision": Draft7Validator(VALIDATION_DECISION_SCHEMA),
}


def _schema_check(kind: str, data: dict, role: str) -> None:
    errors = list(_VALIDATORS[kind].iter_errors(data))
    if errors:
        detail = "; ".join(f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors)
        raise MCPBlockedError(EventCode.SCHEMA_ERROR, f"[{role}] {kind} schema violation: {detail}")


def _load_evidence_catalogue(catalogue_dir: str) -> dict[str, dict]:
    catalogue = {}
    for path in sorted(Path(catalogue_dir).glob("EVD-*.json")):
        import json
        data = json.loads(path.read_text(encoding="utf-8"))
        errors = list(Draft7Validator(EVIDENCE_SCHEMA).iter_errors(data))
        if errors:
            continue  # malformed catalogue entries are never loaded (defensive)
        catalogue[data["id"]] = data
    return catalogue


@dataclass
class MCPSession:
    session_id: str
    correlation_id: str
    state: str = "INIT"
    result: dict[str, Any] = field(default_factory=dict)


class MCPServer:

    def __init__(self, config: MCPConfig | None = None):
        self.config = config or MCPConfig()
        self.evidence_catalogue = _load_evidence_catalogue(self.config.catalogue_valid_dir)
        self.audit = AuditLogger(journal_path=self.config.journal_path)
        self.generator = build_generator(self.config)
        self.verifier = build_verifier(self.config)
        self.validator = build_validator(self.config)
        self._counters = {"CLM": 0, "VER": 0, "MCP-SCORE": 0, "VAL": 0}

    def _next_id(self, prefix: str) -> str:
        self._counters[prefix] += 1
        return f"{prefix}-{self._counters[prefix]:04d}"

    def _log(self, session: MCPSession, *, event_type: str, role: str, result: str, detail: str = ""):
        self.audit.log(
            session_id=session.session_id, correlation_id=session.correlation_id,
            state=session.state, event_type=event_type, role=role, result=result, detail=detail,
        )

    def _invoke_role(self, role_name: str, fn, **kwargs):
        """Call an LLM role method with bounded retries (L4 section 5).

        Technical provider errors (timeout, empty response, 5xx) are retried up
        to config.llm_max_retries times, then surfaced as MCPTechnicalFailure —
        never as a security block. MCPBlockedError raised by a role (e.g. the
        score-ownership guard) always propagates immediately.
        """
        attempts = 0
        last_exc: Exception | None = None
        while attempts <= self.config.llm_max_retries:
            try:
                return fn(**kwargs)
            except MCPBlockedError:
                raise
            except MCPTechnicalFailure:
                raise
            except TimeoutError as exc:
                last_exc = exc
                attempts += 1
            except Exception as exc:  # provider error, empty response, etc.
                last_exc = exc
                attempts += 1

        if isinstance(last_exc, TimeoutError):
            raise MCPTechnicalFailure(EventCode.LLM_TIMEOUT, f"{role_name} timed out after {attempts} attempt(s)")
        if isinstance(last_exc, LLMOutputContractViolation):
            raise MCPTechnicalFailure(
                EventCode.LLM_OUTPUT_VALIDATION_FAILED,
                f"{role_name} produced contract-violating output after {attempts} attempt(s): {last_exc}",
            )
        raise MCPTechnicalFailure(EventCode.LLM_PROVIDER_ERROR, f"{role_name} failed after {attempts} attempt(s): {last_exc}")

    def process_request(self, request: dict) -> dict:
        """Run one Evidence -> ... -> ValidationDecision pipeline for a single request.

        `request` must contain: session_id, correlation_id, endpoint,
        statement, evidence_ids (list[str]), schema_version (optional,
        defaults to "1.0").
        """
        session_id = request.get("session_id") or f"SES-{uuid.uuid4().hex[:12].upper()}"
        correlation_id = request.get("correlation_id") or f"COR-{uuid.uuid4().hex[:12].upper()}"
        session = MCPSession(session_id=session_id, correlation_id=correlation_id, state="INIT")
        self._log(session, event_type="SESSION_START", role="MCP", result="OK")

        # Whatever gets computed before a block/failure is kept and surfaced —
        # e.g. a HIGH-risk MCPScore that a misbehaving Validator then failed to
        # flag for CISO approval is valuable diagnostic context, not garbage.
        claim = verification_result = mcp_score = decision = None
        diagnostic_warnings: list[str] = []
        diagnostic_details: list[dict] = []

        try:
            session.state = "VALIDATION_ENTREE"
            self._validate_entree(session, request)

            session.state = "SELECTION_EVIDENCE"
            evidence = self._select_evidence(session, request.get("evidence_ids") or [])

            session.state = "GENERATION_CLAIM"
            claim = self._generation_claim(session, request, evidence)

            session.state = "VERIFICATION"
            verification_result = self._verification(session, claim, evidence)

            session.state = "DIAGNOSTICS"
            diagnostic_warnings, diagnostic_details = self._diagnostics(session, evidence, verification_result)

            session.state = "SCORING"
            mcp_score = self._scoring(session, evidence, verification_result)

            session.state = "VALIDATION"
            decision = self._validation(session, verification_result, mcp_score, diagnostic_warnings, diagnostic_details)

            session.state = "DECISION_CISO"
            ciso_routing = self._decision_ciso(session, decision)

            session.state = "COMPLETED"
            self._log(session, event_type="SESSION_COMPLETED", role="MCP", result="OK")

            session.result = {
                "mcp_state": "COMPLETED",
                "session_id": session.session_id,
                "correlation_id": session.correlation_id,
                "claim": claim,
                "verification_result": verification_result,
                "mcp_score": mcp_score,
                "validation_decision": decision,
                "ciso_routing": ciso_routing,
                "transitions": self.audit.transitions(),
            }
            return session.result

        except MCPBlockedError as exc:
            attempted_stage = session.state  # the stage in progress when the block fired
            session.state = "BLOCKED"
            self._log(session, event_type=exc.code.value, role="MCP", result="BLOCKED", detail=exc.detail)
            session.result = {
                "mcp_state": "BLOCKED",
                "session_id": session.session_id,
                "correlation_id": session.correlation_id,
                "blocked_reason": exc.code.value,
                "detail": exc.detail,
                "last_stage": attempted_stage,
                "partial": {
                    "claim": claim,
                    "verification_result": verification_result,
                    "diagnostic_warnings": diagnostic_warnings,
                    "diagnostic_details": diagnostic_details,
                    "mcp_score": mcp_score,
                    "validation_decision": decision,
                },
                "transitions": self.audit.transitions(),
            }
            return session.result

        except MCPTechnicalFailure as exc:
            attempted_stage = session.state  # the stage in progress when the failure fired
            session.state = "TECHNICAL_FAILURE"
            self._log(session, event_type=exc.code.value, role="MCP", result="TECHNICAL_FAILURE", detail=exc.detail)
            session.result = {
                "mcp_state": "TECHNICAL_FAILURE",
                "session_id": session.session_id,
                "correlation_id": session.correlation_id,
                "failure_reason": exc.code.value,
                "detail": exc.detail,
                "last_stage": attempted_stage,
                "partial": {
                    "claim": claim,
                    "verification_result": verification_result,
                    "diagnostic_warnings": diagnostic_warnings,
                    "diagnostic_details": diagnostic_details,
                    "mcp_score": mcp_score,
                    "validation_decision": decision,
                },
                "transitions": self.audit.transitions(),
            }
            return session.result

    # -- pipeline steps -----------------------------------------------------

    def _validate_entree(self, session: MCPSession, request: dict) -> None:
        endpoint = request.get("endpoint")
        if endpoint not in ENDPOINT_WHITELIST:
            raise MCPBlockedError(EventCode.UNAUTHORIZED_ENDPOINT, f"endpoint {endpoint!r} not whitelisted")

        schema_version = request.get("schema_version", "1.0")
        if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
            raise MCPBlockedError(EventCode.UNSUPPORTED_SCHEMA_VERSION, f"schema_version {schema_version!r} unsupported")

        statement = request.get("statement") or ""
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(statement):
                raise MCPBlockedError(EventCode.PROMPT_INJECTION, f"pattern matched: {pattern.pattern}")
        for pattern in _EXFILTRATION_PATTERNS:
            if pattern.search(statement):
                raise MCPBlockedError(EventCode.EXFILTRATION_ATTEMPT, f"pattern matched: {pattern.pattern}")

        self._log(session, event_type="VALIDATION_ENTREE", role="MCP", result="OK")

    def _select_evidence(self, session: MCPSession, evidence_ids: list[str]) -> list[dict]:
        evidence = []
        for eid in evidence_ids:
            item = self.evidence_catalogue.get(eid)
            if item is None:
                raise MCPBlockedError(EventCode.INVALID_EVIDENCE_ID, f"evidence_id {eid!r} not found in static catalogue")
            evidence.append(item)

        # Injection/exfiltration can be embedded in Evidence content itself, not
        # only in the request statement (TC-10/TC-11 via a hostile raw_data, as
        # in catalogue/negative/EVD-N003.json) — scan it before it ever reaches
        # a Generator/Verifier prompt.
        for item in evidence:
            text = f"{item['content'].get('summary', '')} {item['content'].get('raw_data', '')}"
            for pattern in _INJECTION_PATTERNS:
                if pattern.search(text):
                    raise MCPBlockedError(EventCode.PROMPT_INJECTION, f"{item['id']}.content matched: {pattern.pattern}")
            for pattern in _EXFILTRATION_PATTERNS:
                if pattern.search(text):
                    raise MCPBlockedError(EventCode.EXFILTRATION_ATTEMPT, f"{item['id']}.content matched: {pattern.pattern}")

        self._log(session, event_type="SELECTION_EVIDENCE", role="MCP", result="OK",
                   detail=f"{len(evidence)} evidence selected")
        return evidence

    def _generation_claim(self, session: MCPSession, request: dict, evidence: list[dict]) -> dict:
        if not evidence:
            raise MCPBlockedError(EventCode.MISSING_EVIDENCE_IDS, "Claim.evidence_ids would be empty")

        claim = self._invoke_role(
            "GENERATOR", self.generator.generate,
            request_statement=request.get("statement", ""),
            evidence=evidence,
            claim_id=self._next_id("CLM"),
            session_id=session.session_id,
            correlation_id=session.correlation_id,
        )
        if "score" in claim or "mcp_score" in claim:
            raise MCPBlockedError(EventCode.SCORE_OWNERSHIP_VIOLATION, "Generator output must not contain a score field")
        _schema_check("Claim", claim, role="GENERATOR")

        unknown = set(claim["evidence_ids"]) - {e["id"] for e in evidence}
        if unknown:
            raise MCPBlockedError(EventCode.INVALID_EVIDENCE_ID, f"Claim references unknown evidence: {unknown}")

        self._log(session, event_type="GENERATION_CLAIM", role="GENERATOR", result="OK", detail=claim["id"])
        return claim

    def _verification(self, session: MCPSession, claim: dict, evidence: list[dict]) -> dict:
        verification_result = self._invoke_role(
            "VERIFIER", self.verifier.verify,
            claim=claim, evidence=evidence, verification_id=self._next_id("VER"),
            session_id=session.session_id, correlation_id=session.correlation_id,
        )
        if "score" in verification_result or "mcp_score" in verification_result:
            raise MCPBlockedError(EventCode.SCORE_OWNERSHIP_VIOLATION, "Verifier output must not contain a score field")
        _schema_check("VerificationResult", verification_result, role="VERIFIER")

        if verification_result["claim_id"] != claim["id"]:
            raise MCPBlockedError(EventCode.INVALID_CLAIM_REFERENCE, "VerificationResult.claim_id does not match Claim.id")

        self._log(session, event_type="VERIFICATION", role="VERIFIER", result="OK",
                   detail=f"{verification_result['id']}:{verification_result['status']}")
        return verification_result

    def _diagnostics(self, session: MCPSession, evidence: list[dict], verification_result: dict) -> tuple[list[str], list[dict]]:
        """Deterministic advisory warnings derived from Evidence content
        (mcp_server.diagnostics). Never rewrites verification_result["status"] —
        the Verifier LLM remains its sole author; this stage only ever reads it,
        never assigns back to it. Returns (codes, structured details) — both
        derived from the same computation (mcp_server.diagnostics), so they can
        never drift apart.
        """
        warnings = compute_diagnostics(evidence, verification_result["status"])
        details = compute_diagnostic_details(evidence, verification_result["status"])
        self._log(session, event_type="DIAGNOSTICS", role="MCP", result="OK",
                   detail=f"warnings={warnings}" if warnings else "no warnings")
        return warnings, details

    def _scoring(self, session: MCPSession, evidence: list[dict], verification_result: dict) -> dict:
        mcp_score = compute_mcp_score(
            evidence=evidence, verification_result=verification_result,
            score_id=self._next_id("MCP-SCORE"), session_id=session.session_id,
            correlation_id=session.correlation_id,
        )
        _schema_check("MCPScore", mcp_score, role="MCP")

        if mcp_score["verification_result_id"] != verification_result["id"]:
            raise MCPBlockedError(EventCode.INVALID_VERIFICATION_REFERENCE, "MCPScore.verification_result_id mismatch")

        self._log(session, event_type="SCORING", role="MCP", result="OK",
                   detail=f"{mcp_score['id']}:{mcp_score['value']}:{mcp_score['risk_level']}")
        return mcp_score

    def _validation(self, session: MCPSession, verification_result: dict, mcp_score: dict,
                     diagnostic_warnings: list[str], diagnostic_details: list[dict]) -> dict:
        decision = self._invoke_role(
            "VALIDATOR", self.validator.validate,
            verification_result=verification_result, mcp_score=mcp_score,
            diagnostic_warnings=diagnostic_warnings,
            decision_id=self._next_id("VAL"), session_id=session.session_id,
            correlation_id=session.correlation_id,
        )
        # Structured companion to diagnostic_warnings, attached here (not inside
        # the Validator itself) since it is pure audit detail already computed in
        # the DIAGNOSTICS stage — not something the Validator's own logic needs.
        decision["diagnostic_details"] = diagnostic_details
        _schema_check("ValidationDecision", decision, role="VALIDATOR")

        if decision["verification_result_id"] != verification_result["id"]:
            raise MCPBlockedError(EventCode.INVALID_VERIFICATION_REFERENCE, "ValidationDecision.verification_result_id mismatch")
        if decision["mcp_score_reference"] != mcp_score["id"]:
            raise MCPBlockedError(EventCode.INVALID_SCORE_REFERENCE, "ValidationDecision.mcp_score_reference mismatch")

        # Risk-level floor: a "supported" Claim at HIGH/CRITICAL risk must always
        # require CISO approval. Scoped to status=="supported" deliberately —
        # insufficient_evidence and unsupported must NOT be escalated by risk_level
        # (MCPScore must never "compensate" for missing Evidence into a false
        # sense of urgency, or the reverse); those two statuses have their own
        # fixed routing in mcp_server/policy.py regardless of risk_level.
        if (verification_result["status"] == "supported" and mcp_score["risk_level"] in ("HIGH", "CRITICAL")
                and not decision["requires_ciso_approval"]):
            raise MCPBlockedError(
                EventCode.CISO_APPROVAL_REQUIRED, "supported + HIGH/CRITICAL risk without requires_ciso_approval=true",
            )

        # Governance invariant: READY_FOR_CISO_DECISION always means mandatory
        # CISO sign-off. If a Validator implementation ever produced that
        # decision without the approval flag, that would silently understate how
        # urgent the case is — block rather than let it through quietly.
        if decision["decision"] == "READY_FOR_CISO_DECISION" and not decision["requires_ciso_approval"]:
            raise MCPBlockedError(
                EventCode.CISO_APPROVAL_REQUIRED, "READY_FOR_CISO_DECISION without requires_ciso_approval=true",
            )

        self._log(
            session, event_type="VALIDATION", role="VALIDATOR", result="OK",
            detail=(
                f"decision={decision['decision']} policy_rule={decision.get('policy_rule')} "
                f"policy_version={decision.get('policy_version')} applied_exception={decision.get('applied_exception')}"
            ),
        )
        return decision

    def _decision_ciso(self, session: MCPSession, decision: dict) -> str:
        # The ValidationDecision's `decision` field IS the routing value now
        # (READY_FOR_CISO_DECISION / READY_FOR_CISO_INFORMATION / REJECTED /
        # INSUFFICIENT_EVIDENCE — see mcp_server/policy.py) — there is nothing
        # left to re-derive here. This stage is kept only for the audit-log
        # entry and to preserve the `ciso_routing` field existing callers read.
        routing = decision["decision"]
        self._log(session, event_type="DECISION_CISO", role="MCP", result="OK", detail=routing)
        return routing

    def record_ciso_decision(self, session_id: str, correlation_id: str, ciso_decision: str) -> dict:
        """Record the CISO's own APPROVE/REJECT/REQUEST_MORE_EVIDENCE/DEFER action.

        This is a separate, explicit human action — never invoked automatically
        by process_request().
        """
        if ciso_decision not in ("APPROVE", "REJECT", "REQUEST_MORE_EVIDENCE", "DEFER"):
            raise ValueError(f"Unknown CISO decision: {ciso_decision!r}")
        event = self.audit.log(
            session_id=session_id, correlation_id=correlation_id, state="CISO_DECISION",
            event_type="CISO_DECISION", role="CISO", result=ciso_decision,
        )
        return event
