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
from mcp_server.rag.config import CORPORATE_EVIDENCE, VULNERABILITIES
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


# RAG evidence_type (mcp_server.rag.schemas.RagIngestionEvidence, free-form
# ingestion vocabulary) -> EVIDENCE_SCHEMA's fixed "type" enum. Unrecognized
# values fall back to "report" rather than raising -- a RAG evidence_type this
# adapter doesn't know about should degrade to a generic, still-valid Evidence
# rather than block a Claim outright (the real safety checks live in
# _diagnostics()/policy.py, not in this label).
_RAG_EVIDENCE_TYPE_MAP = {
    "remediation_ticket": "ticket",
    "vulnerability_scan": "scan_result",
    "audit_record": "audit_record",
    "validation_record": "validation_record",
    "incident_action": "incident_action",
    "committee_action": "committee_action",
}


def _adapt_rag_evidence_to_schema(record_id: str, document: str, metadata: dict, *, severity: str) -> dict:
    """Converts one RAG-ingested corporate_evidence record (Chroma document +
    metadata, mcp_server.rag.ingestion.ingest_evidence()'s own shape) into an
    EVIDENCE_SCHEMA-conformant dict, so it can be handed to the same
    Verifier/Validator the static catalogue path already uses.

    content.raw_data is the RAG document's own free text, unmodified -- this
    is deliberately NOT forced into the "key=value; key=value" convention
    mcp_server.evidence_parsing expects, since a real RAG record's prose
    should never be misread as having an explicit field "marked absent"
    just because it doesn't happen to use that convention.
    """
    evidence_type = _RAG_EVIDENCE_TYPE_MAP.get(metadata.get("evidence_type"), "report")
    summary = document if len(document) <= 500 else document[:497] + "..."
    raw_data = document if len(document) <= 5000 else document[:4997] + "..."
    return {
        "schema_version": "1.0",
        "session_id": metadata.get("session_id", "SES-RAGADAPTER00"),
        "correlation_id": metadata.get("correlation_id", "COR-RAGADAPTER00"),
        "id": record_id,
        "source": metadata.get("source", "RAG"),
        "date": metadata.get("observed_at", datetime.now(timezone.utc).isoformat()),
        "type": evidence_type,
        "content": {"summary": summary, "raw_data": raw_data},
        "severity": severity,
        "integrity_hash": metadata.get("integrity_hash", "sha256:" + "0" * 64),
    }


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

    def __init__(self, config: MCPConfig | None = None, *, chroma=None):
        self.config = config or MCPConfig()
        self.evidence_catalogue = _load_evidence_catalogue(self.config.catalogue_valid_dir)
        self.audit = AuditLogger(journal_path=self.config.journal_path)
        # Lazy: only process_request() (the classic pipeline) ever calls
        # self.generator. process_claim() (the live Foundation-Sec/RAG bridge
        # used by /api/v1/generator/verified-claims) never touches it, so a
        # caller building an MCPServer(llm_mode="llama") purely to reuse its
        # Verifier/Validator (e.g. web/generator_api.py) must not be forced to
        # eagerly satisfy build_generator() for a role it will never invoke.
        self._generator = None
        self.verifier = build_verifier(self.config)
        self.validator = build_validator(self.config)
        self._counters = {"CLM": 0, "VER": 0, "MCP-SCORE": 0, "VAL": 0}
        # Optional: mcp_server.rag.chroma_client.ChromaCollections, passed by
        # web/generator_api.py's _get_mcp_server() so process_claim() (the
        # Foundation-Sec/RAG bridge) can resolve evidence_ids against the REAL
        # RAG store instead of only self.evidence_catalogue -- see
        # _select_evidence_for_claim(). None for the classic process_request()
        # pipeline, which never needs it (its own Generator only ever cites
        # ids already drawn from self.evidence_catalogue).
        self.chroma = chroma

    @property
    def generator(self):
        if self._generator is None:
            self._generator = build_generator(self.config)
        return self._generator

    @generator.setter
    def generator(self, value):
        # Several tests substitute a stub/rogue Generator directly (e.g.
        # tests/test_negative.py, test_technical_failures.py) -- this setter
        # keeps that pattern working with the lazy property above.
        self._generator = value

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

        claim = None
        try:
            session.state = "VALIDATION_ENTREE"
            self._validate_entree(session, request)

            session.state = "SELECTION_EVIDENCE"
            evidence = self._select_evidence(session, request.get("evidence_ids") or [])

            session.state = "GENERATION_CLAIM"
            claim = self._generation_claim(session, request, evidence)
        except MCPBlockedError as exc:
            return self._blocked_result(session, exc, claim=claim)
        except MCPTechnicalFailure as exc:
            return self._technical_failure_result(session, exc, claim=claim)

        return self._run_chain_from_claim(session, claim, evidence)

    def process_claim(self, claim: dict) -> dict:
        """Entry point for a Claim generated OUTSIDE this orchestrator's own
        Generator role -- e.g. the Foundation-Sec/RAG Generator, via
        mcp_server.generator_claims.to_mcp_claim() -- runs VERIFICATION ->
        DIAGNOSTICS -> SCORING -> VALIDATION -> DECISION_CISO against it,
        reusing the exact same downstream chain and governance guarantees as
        process_request(): whichever backend produced the Claim, the Verifier
        and Validator run identically and stay unaware of where it came from.

        Evidence for the Verifier is resolved by _select_evidence_for_claim(),
        which checks the REAL RAG corporate_evidence collection first (via
        self.chroma, adapting hits into EVIDENCE_SCHEMA shape) and only falls
        back to this orchestrator's own static catalogue
        (self.evidence_catalogue) for ids genuinely absent from RAG. Earlier
        versions of this method resolved exclusively against the static
        catalogue, which both blocked legitimately RAG-sourced evidence
        (INVALID_EVIDENCE_ID for ids never mirrored into catalogue/valid/) and,
        worse, could silently substitute an unrelated static demo record when
        an id happened to collide between the two stores. self.chroma is None
        for the classic process_request() pipeline (never needed there, since
        its own Generator only ever cites ids already drawn from
        self.evidence_catalogue), in which case this method behaves exactly
        as the old catalogue-only resolution did.
        """
        session_id = claim.get("session_id") or f"SES-{uuid.uuid4().hex[:12].upper()}"
        correlation_id = claim.get("correlation_id") or f"COR-{uuid.uuid4().hex[:12].upper()}"
        session = MCPSession(session_id=session_id, correlation_id=correlation_id, state="INIT")
        self._log(session, event_type="SESSION_START", role="MCP", result="OK")

        try:
            session.state = "VALIDATION_ENTREE"
            _schema_check("Claim", claim, role="EXTERNAL_GENERATOR")

            session.state = "SELECTION_EVIDENCE"
            evidence = self._select_evidence_for_claim(session, claim, claim.get("evidence_ids") or [])
        except MCPBlockedError as exc:
            return self._blocked_result(session, exc, claim=claim)
        except MCPTechnicalFailure as exc:
            return self._technical_failure_result(session, exc, claim=claim)

        return self._run_chain_from_claim(session, claim, evidence)

    def _run_chain_from_claim(self, session: MCPSession, claim: dict, evidence: list[dict]) -> dict:
        """Shared tail of process_request() (Claim from this orchestrator's own
        Generator) and process_claim() (Claim produced externally): runs
        VERIFICATION -> DIAGNOSTICS -> SCORING -> VALIDATION -> DECISION_CISO
        -> COMPLETED, so both callers get identical governance guarantees.
        """
        # Whatever gets computed before a block/failure is kept and surfaced —
        # e.g. a HIGH-risk MCPScore that a misbehaving Validator then failed to
        # flag for CISO approval is valuable diagnostic context, not garbage.
        verification_result = mcp_score = decision = None
        diagnostic_warnings: list[str] = []
        diagnostic_details: list[dict] = []

        try:
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
                "transitions": self.audit.transitions(session_id=session.session_id),
            }
            return session.result

        except MCPBlockedError as exc:
            return self._blocked_result(
                session, exc, claim=claim, verification_result=verification_result,
                diagnostic_warnings=diagnostic_warnings, diagnostic_details=diagnostic_details,
                mcp_score=mcp_score, decision=decision,
            )
        except MCPTechnicalFailure as exc:
            return self._technical_failure_result(
                session, exc, claim=claim, verification_result=verification_result,
                diagnostic_warnings=diagnostic_warnings, diagnostic_details=diagnostic_details,
                mcp_score=mcp_score, decision=decision,
            )

    def _blocked_result(self, session: MCPSession, exc: MCPBlockedError, *, claim,
                         verification_result=None, diagnostic_warnings=None, diagnostic_details=None,
                         mcp_score=None, decision=None) -> dict:
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
                "diagnostic_warnings": diagnostic_warnings or [],
                "diagnostic_details": diagnostic_details or [],
                "mcp_score": mcp_score,
                "validation_decision": decision,
            },
            "transitions": self.audit.transitions(session_id=session.session_id),
        }
        return session.result

    def _technical_failure_result(self, session: MCPSession, exc: MCPTechnicalFailure, *, claim,
                                   verification_result=None, diagnostic_warnings=None, diagnostic_details=None,
                                   mcp_score=None, decision=None) -> dict:
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
                "diagnostic_warnings": diagnostic_warnings or [],
                "diagnostic_details": diagnostic_details or [],
                "mcp_score": mcp_score,
                "validation_decision": decision,
            },
            "transitions": self.audit.transitions(session_id=session.session_id),
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

    def _scan_evidence_for_injection(self, evidence: list[dict]) -> None:
        # Injection/exfiltration can be embedded in Evidence content itself, not
        # only in the request statement (TC-10/TC-11 via a hostile raw_data, as
        # in catalogue/negative/EVD-N003.json) — scan it before it ever reaches
        # a Generator/Verifier prompt. Shared by both evidence-resolution paths
        # (static catalogue and RAG-backed) so neither can skip this check.
        for item in evidence:
            text = f"{item['content'].get('summary', '')} {item['content'].get('raw_data', '')}"
            for pattern in _INJECTION_PATTERNS:
                if pattern.search(text):
                    raise MCPBlockedError(EventCode.PROMPT_INJECTION, f"{item['id']}.content matched: {pattern.pattern}")
            for pattern in _EXFILTRATION_PATTERNS:
                if pattern.search(text):
                    raise MCPBlockedError(EventCode.EXFILTRATION_ATTEMPT, f"{item['id']}.content matched: {pattern.pattern}")

    def _select_evidence(self, session: MCPSession, evidence_ids: list[str]) -> list[dict]:
        evidence = []
        for eid in evidence_ids:
            item = self.evidence_catalogue.get(eid)
            if item is None:
                raise MCPBlockedError(EventCode.INVALID_EVIDENCE_ID, f"evidence_id {eid!r} not found in static catalogue")
            evidence.append(item)

        self._scan_evidence_for_injection(evidence)

        self._log(session, event_type="SELECTION_EVIDENCE", role="MCP", result="OK",
                   detail=f"{len(evidence)} evidence selected")
        return evidence

    def _lookup_cve_severity(self, cve_id: str) -> str | None:
        """Best-effort severity lookup from the RAG vulnerabilities collection
        (mcp_server.rag.ingestion.ingest_cve() stores 'severity' in metadata).
        Returns None if unavailable (no chroma client, cve_id not found, or
        the store is unreachable) -- callers must fall back to a default."""
        if self.chroma is None:
            return None
        try:
            got = self.chroma.get_by_ids(collection=VULNERABILITIES, ids=[cve_id])
        except Exception:
            return None
        metadatas = got.get("metadatas") or []
        if not metadatas or metadatas[0] is None:
            return None
        return metadatas[0].get("severity")

    def _select_evidence_for_claim(self, session: MCPSession, claim: dict, evidence_ids: list[str]) -> list[dict]:
        """Evidence resolution for process_claim() (the Foundation-Sec/RAG
        bridge): tries the REAL RAG corporate_evidence collection first via
        self.chroma, adapting each hit into an EVIDENCE_SCHEMA-conformant dict
        (_adapt_rag_evidence_to_schema), and only falls back to
        self.evidence_catalogue (the classic pipeline's static demo fixtures)
        for ids genuinely absent from RAG. This fixes two related defects
        found in production: (1) an id present in BOTH stores under
        unrelated content silently substituting the wrong record (the RAG
        store is authoritative for RAG-sourced Claims, so it is checked
        first, never second), and (2) a freshly RAG-ingested id that was
        never mirrored into the static catalogue failing closed with
        INVALID_EVIDENCE_ID even though it is real, retrievable evidence.
        """
        evidence: list[dict] = []
        missing: list[str] = []

        rag_hits: dict[str, tuple[str, dict]] = {}
        if self.chroma is not None and evidence_ids:
            try:
                got = self.chroma.get_by_ids(collection=CORPORATE_EVIDENCE, ids=evidence_ids)
                ids = got.get("ids") or []
                documents = got.get("documents") or []
                metadatas = got.get("metadatas") or []
                for eid, document, metadata in zip(ids, documents, metadatas):
                    if document is not None and metadata is not None:
                        rag_hits[eid] = (document, metadata)
            except Exception:
                rag_hits = {}  # RAG unreachable -- fall back entirely to the static catalogue below

        for eid in evidence_ids:
            if eid in rag_hits:
                document, metadata = rag_hits[eid]
                cve_ids = [c for c in (metadata.get("cve_ids") or "").split(",") if c]
                severity = next((s for c in cve_ids if (s := self._lookup_cve_severity(c))), None) or "MEDIUM"
                evidence.append(_adapt_rag_evidence_to_schema(eid, document, metadata, severity=severity))
                continue
            item = self.evidence_catalogue.get(eid)
            if item is not None:
                evidence.append(item)
                continue
            missing.append(eid)

        if missing:
            raise MCPBlockedError(
                EventCode.INVALID_EVIDENCE_ID,
                f"evidence_id {missing[0]!r} not found in RAG store or static catalogue",
            )

        self._scan_evidence_for_injection(evidence)

        self._log(session, event_type="SELECTION_EVIDENCE", role="MCP", result="OK",
                   detail=f"{len(evidence)} evidence selected ({len(rag_hits)} from RAG)")
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
