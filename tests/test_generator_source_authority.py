"""Deterministic source-authority rules (spec section 4) and JSON-repair
drift guards (spec section 5), enforced in code -- not left to the LLM
prompt alone. Covers mcp_server/generator_claims.py's
enforce_source_authority() and enforce_no_repair_drift().
"""

from datetime import datetime, timezone

import pytest

from mcp_server.generator_claims import (
    GeneratedClaim,
    GeneratorOutputError,
    enforce_no_repair_drift,
    enforce_source_authority,
    validate_citations,
)
from mcp_server.rag.schemas import RetrievalResult

pytestmark = pytest.mark.unit


def _claim(**overrides) -> GeneratedClaim:
    payload = {
        "claim_id": "GCLM-TEST0001", "request_id": "REQ-TEST", "status": "CLAIM_GENERATED",
        "claim": "The ticket is closed.", "evidence_ids": [], "reference_ids": [],
        "reasoning_summary": "reasoning", "confidence": 0.5, "limitations": [],
        "generated_at": datetime.now(timezone.utc), "model_name": "test-model", "retrieval_trace_id": "RAGTRC-TEST",
    }
    payload.update(overrides)
    return GeneratedClaim.model_validate(payload)


def _evidence_result(record_id, *, evidence_type="remediation_ticket", content="", metadata_extra=None,
                      case_id="VUL-018", ticket_id="SEC-104", asset_id="SRV-ERP-01", observed_at="2026-07-22T09:00:00Z"):
    metadata = {
        "evidence_type": evidence_type, "case_id": case_id, "ticket_id": ticket_id, "asset_id": asset_id,
        "observed_at": observed_at,
    }
    if metadata_extra:
        metadata.update(metadata_extra)
    return RetrievalResult(
        record_id=record_id, collection="corporate_evidence", source_type="corporate_evidence",
        content=content, metadata=metadata, retrieval_method="exact_identifier", retrieval_score=1.0,
        authoritative=True,
    )


# --- Rule: conclusive claim requires >=1 corporate evidence citation --------

def test_conclusive_claim_with_no_evidence_ids_is_rejected():
    claim = _claim(status="CLAIM_GENERATED", claim="Fully remediated.", evidence_ids=[], reference_ids=["CVE-2026-00001"])
    with pytest.raises(GeneratorOutputError, match="requires at least one corporate evidence citation"):
        enforce_source_authority(claim, included_results=[])


def test_insufficient_evidence_status_is_never_checked():
    claim = _claim(status="INSUFFICIENT_EVIDENCE", claim=None, evidence_ids=[])
    enforce_source_authority(claim, included_results=[])  # must not raise


# --- Rule: ticket-only evidence cannot prove remediation --------------------

def test_ticket_only_evidence_with_remediation_claim_is_rejected():
    claim = _claim(claim="The remediation ticket is closed.", evidence_ids=["EVD-0001"])
    results = [_evidence_result("EVD-0001", evidence_type="remediation_ticket")]
    with pytest.raises(GeneratorOutputError, match="verification scan"):
        enforce_source_authority(claim, included_results=results)


def test_ticket_plus_verification_scan_is_accepted():
    claim = _claim(claim="The ticket is closed and a rescan confirms remediation.", evidence_ids=["EVD-0001", "EVD-0002"])
    results = [
        _evidence_result("EVD-0001", evidence_type="remediation_ticket"),
        _evidence_result("EVD-0002", evidence_type="vulnerability_scan", observed_at="2026-07-23T09:00:00Z"),
    ]
    enforce_source_authority(claim, included_results=results)  # must not raise


def test_non_remediation_claim_with_ticket_only_evidence_is_accepted():
    claim = _claim(claim="A ticket exists describing the incident.", evidence_ids=["EVD-0001"])
    results = [_evidence_result("EVD-0001", evidence_type="incident_action")]
    enforce_source_authority(claim, included_results=results)  # no remediation assertion -- not blocked


# --- Rule: cross-case/ticket/asset evidence cannot support the claim --------

def test_cross_case_evidence_is_rejected_when_scope_was_requested():
    claim = _claim(claim="Remediated per verification.", evidence_ids=["EVD-0001", "EVD-0002"])
    results = [
        _evidence_result("EVD-0001", evidence_type="remediation_ticket", case_id="VUL-018"),
        _evidence_result("EVD-0002", evidence_type="vulnerability_scan", case_id="VUL-999",
                          ticket_id="SEC-999", asset_id="SRV-OTHER", observed_at="2026-07-23T09:00:00Z"),
    ]
    with pytest.raises(GeneratorOutputError, match="does not belong to the requested"):
        enforce_source_authority(claim, included_results=results, case_id="VUL-018")


def test_same_case_evidence_is_accepted_when_scope_was_requested():
    claim = _claim(claim="Remediated per verification.", evidence_ids=["EVD-0001", "EVD-0002"])
    results = [
        _evidence_result("EVD-0001", evidence_type="remediation_ticket", case_id="VUL-018"),
        _evidence_result("EVD-0002", evidence_type="vulnerability_scan", case_id="VUL-018",
                          observed_at="2026-07-23T09:00:00Z"),
    ]
    enforce_source_authority(claim, included_results=results, case_id="VUL-018")  # must not raise


# --- Rule: newer contradictory record blocks a positive remediation claim --

def test_contradictory_evidence_blocks_positive_remediation_claim():
    claim = _claim(claim="The ticket is closed and remediation is verified.", evidence_ids=["EVD-0001", "EVD-0002"])
    results = [
        _evidence_result("EVD-0001", evidence_type="vulnerability_scan",
                          content="ticket_id=SEC-104; status=closed", observed_at="2026-07-22T09:00:00Z"),
        _evidence_result("EVD-0002", evidence_type="vulnerability_scan",
                          content="ticket_id=SEC-104; status=reopened", observed_at="2026-07-23T09:00:00Z"),
    ]
    with pytest.raises(GeneratorOutputError, match="unresolved factual contradiction"):
        enforce_source_authority(claim, included_results=results)


def test_non_contradictory_evidence_does_not_block_the_claim():
    claim = _claim(claim="The ticket is closed and remediation is verified.", evidence_ids=["EVD-0001", "EVD-0002"])
    results = [
        _evidence_result("EVD-0001", evidence_type="remediation_ticket",
                          content="ticket_id=SEC-104; status=closed", observed_at="2026-07-22T09:00:00Z"),
        _evidence_result("EVD-0002", evidence_type="vulnerability_scan",
                          content="ticket_id=SEC-104; status=closed", observed_at="2026-07-23T09:00:00Z"),
    ]
    enforce_source_authority(claim, included_results=results)  # must not raise


# --- Rule: all returned IDs must exist in the retrieval result -------------

def test_validate_citations_rejects_an_evidence_id_never_retrieved():
    with pytest.raises(GeneratorOutputError, match="not in the retrieved context"):
        validate_citations(
            {"evidence_ids": ["EVD-9999"], "reference_ids": []},
            retrieved_evidence_ids={"EVD-0001"}, retrieved_reference_ids=set(),
        )


def test_validate_citations_accepts_ids_that_were_retrieved():
    validate_citations(
        {"evidence_ids": ["EVD-0001"], "reference_ids": ["CVE-2026-00001"]},
        retrieved_evidence_ids={"EVD-0001"}, retrieved_reference_ids={"CVE-2026-00001"},
    )  # must not raise


# --- JSON-repair drift guard -------------------------------------------------

def test_repair_cannot_introduce_new_evidence_citations():
    original = {"status": "CLAIM_GENERATED", "evidence_ids": ["EVD-0001"], "reference_ids": [], "confidence": 0.5}
    repaired = _claim(evidence_ids=["EVD-0001", "EVD-0002"])
    with pytest.raises(GeneratorOutputError, match="introduced citations"):
        enforce_no_repair_drift(original_parsed=original, repaired=repaired)


def test_repair_cannot_introduce_new_reference_citations():
    original = {"status": "CLAIM_GENERATED", "evidence_ids": ["EVD-0001"], "reference_ids": [], "confidence": 0.5}
    repaired = _claim(evidence_ids=["EVD-0001"], reference_ids=["CVE-2026-00001"])
    with pytest.raises(GeneratorOutputError, match="introduced citations"):
        enforce_no_repair_drift(original_parsed=original, repaired=repaired)


def test_repair_cannot_increase_confidence():
    original = {"status": "CLAIM_GENERATED", "evidence_ids": ["EVD-0001"], "reference_ids": [], "confidence": 0.4}
    repaired = _claim(evidence_ids=["EVD-0001"], confidence=0.9)
    with pytest.raises(GeneratorOutputError, match="increased confidence"):
        enforce_no_repair_drift(original_parsed=original, repaired=repaired)


def test_repair_may_decrease_or_keep_confidence_the_same():
    original = {"status": "CLAIM_GENERATED", "evidence_ids": ["EVD-0001"], "reference_ids": [], "confidence": 0.8}
    repaired = _claim(evidence_ids=["EVD-0001"], confidence=0.8)
    enforce_no_repair_drift(original_parsed=original, repaired=repaired)  # must not raise
    repaired_lower = _claim(evidence_ids=["EVD-0001"], confidence=0.3)
    enforce_no_repair_drift(original_parsed=original, repaired=repaired_lower)  # must not raise


def test_repair_cannot_flip_insufficient_evidence_to_claim_generated():
    original = {"status": "INSUFFICIENT_EVIDENCE", "evidence_ids": [], "reference_ids": [], "confidence": 0.1}
    repaired = _claim(status="CLAIM_GENERATED", evidence_ids=[], confidence=0.1)
    with pytest.raises(GeneratorOutputError, match="INSUFFICIENT_EVIDENCE to CLAIM_GENERATED"):
        enforce_no_repair_drift(original_parsed=original, repaired=repaired)


def test_repair_drift_check_is_a_noop_when_original_was_not_valid_json():
    repaired = _claim(evidence_ids=["EVD-0001"], confidence=0.99)
    enforce_no_repair_drift(original_parsed=None, repaired=repaired)  # must not raise -- nothing to compare against


# --- retrieved_*_ids relaxation (diagnosed this session: scenarios B/F/G/I/ML2/ML4 --
# the repair prompt now names real available ids so the model can swap a fabricated
# citation for a genuine one; rejecting that swap just because it differs from the
# original attempt defeated the repair's own purpose) --------------------------------

def test_repair_may_switch_a_reference_citation_to_one_actually_retrieved():
    original = {"status": "CLAIM_GENERATED", "evidence_ids": ["EVD-0001"], "reference_ids": ["RB-ERP-001"], "confidence": 0.5}
    repaired = _claim(evidence_ids=["EVD-0001"], reference_ids=["RB-ERP-001#chunk-0"])
    enforce_no_repair_drift(
        original_parsed=original, repaired=repaired,
        retrieved_evidence_ids={"EVD-0001"}, retrieved_reference_ids={"RB-ERP-001#chunk-0"},
    )  # must not raise -- RB-ERP-001#chunk-0 is genuinely in the retrieved context


def test_repair_still_rejects_a_reference_citation_absent_from_retrieved_context():
    original = {"status": "CLAIM_GENERATED", "evidence_ids": ["EVD-0001"], "reference_ids": [], "confidence": 0.5}
    repaired = _claim(evidence_ids=["EVD-0001"], reference_ids=["CVE-9999-FABRICATED"])
    with pytest.raises(GeneratorOutputError, match="introduced citations"):
        enforce_no_repair_drift(
            original_parsed=original, repaired=repaired,
            retrieved_evidence_ids={"EVD-0001"}, retrieved_reference_ids={"RB-ERP-001#chunk-0"},
        )  # CVE-9999-FABRICATED is in neither the original nor the retrieved context -- still a real fabrication


def test_repair_still_rejects_new_evidence_citation_absent_from_retrieved_context():
    original = {"status": "CLAIM_GENERATED", "evidence_ids": ["EVD-0001"], "reference_ids": [], "confidence": 0.5}
    repaired = _claim(evidence_ids=["EVD-0001", "EVD-9999"])
    with pytest.raises(GeneratorOutputError, match="introduced citations"):
        enforce_no_repair_drift(
            original_parsed=original, repaired=repaired,
            retrieved_evidence_ids={"EVD-0001"}, retrieved_reference_ids=set(),
        )
