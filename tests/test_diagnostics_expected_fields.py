"""Workstream A: MISSING_EXPECTED_FIELD, AMBIGUOUS_EVIDENCE, and the centralized
severity model (mcp_server/diagnostics.py)."""

import pytest

from mcp_server.diagnostics import (
    AMBIGUOUS_EVIDENCE,
    DIAGNOSTIC_SEVERITY,
    LOW_EVIDENCE_COVERAGE,
    MISSING_EXPECTED_FIELD,
    SERIOUS_WARNINGS,
    SEVERITY_INFORMATIONAL,
    SEVERITY_SERIOUS,
    STALE_EVIDENCE,
    compute_diagnostic_details,
    compute_diagnostics,
)

pytestmark = pytest.mark.unit


def _evd(eid, etype, raw_data, summary="s", date="2026-07-22T00:00:00Z"):
    return {"id": eid, "type": etype, "date": date, "content": {"summary": summary, "raw_data": raw_data}}


# -- MISSING_EXPECTED_FIELD ---------------------------------------------------

def test_ticket_missing_status_triggers_missing_expected_field():
    e = _evd("EVD-0001", "ticket", "ticket_id=TCK-001")  # no status= field
    codes = compute_diagnostics([e], "supported")
    assert MISSING_EXPECTED_FIELD in codes


def test_ticket_with_status_does_not_trigger_missing_expected_field():
    e = _evd("EVD-0001", "ticket", "ticket_id=TCK-001; status=Closed")
    codes = compute_diagnostics([e], "supported")
    assert MISSING_EXPECTED_FIELD not in codes


def test_audit_action_missing_owner_and_deadline():
    e = _evd("EVD-0001", "audit_record", "action_id=AUD-017; status=Completed")  # no owner/deadline
    details = compute_diagnostic_details([e], "supported")
    missing = [d for d in details if d["code"] == MISSING_EXPECTED_FIELD]
    assert len(missing) == 1
    assert "owner" in missing[0]["field"]
    assert "deadline" in missing[0]["field"]


def test_scan_result_missing_result_field():
    e = _evd("EVD-0001", "scan_result", "cve_id=CVE-2024-0001")  # no result=
    assert MISSING_EXPECTED_FIELD in compute_diagnostics([e], "supported")


def test_unknown_evidence_type_does_not_crash_and_produces_no_missing_field_warning():
    """Unknown/unmapped Evidence type: no crash, no MISSING_EXPECTED_FIELD (there is
    no rule for it) -- schema validation upstream is what actually rejects a truly
    invalid type; diagnostics must stay defensive regardless."""
    e = _evd("EVD-0001", "something_not_in_the_mapping", "field=value")
    codes = compute_diagnostics([e], "supported")  # must not raise
    assert MISSING_EXPECTED_FIELD not in codes


def test_missing_expected_field_detail_has_required_structure():
    e = _evd("EVD-0001", "ticket", "ticket_id=TCK-001")
    details = compute_diagnostic_details([e], "supported")
    hit = next(d for d in details if d["code"] == MISSING_EXPECTED_FIELD)
    assert hit["severity"] == SEVERITY_SERIOUS
    assert hit["evidence_ids"] == ["EVD-0001"]
    assert hit["rule_id"] == "DIAG-MISS-001"
    assert "status" in hit["field"]


# -- AMBIGUOUS_EVIDENCE --------------------------------------------------------

@pytest.mark.parametrize("phrase", [
    "Le ticket est probably closed selon le dernier rapport",
    "Le cas seems resolved mais aucune verification independante",
    "Statut : in progress / completed",
    "pending confirmation du proprietaire",
    "Correctif partially remediated",
    "status unknown depuis le dernier scan",
    "Le correctif est normally fixed",
])
def test_ambiguous_phrase_triggers_ambiguous_evidence(phrase):
    e = _evd("EVD-0001", "ticket", "ticket_id=TCK-001; status=Closed", summary=phrase)
    codes = compute_diagnostics([e], "supported")
    assert AMBIGUOUS_EVIDENCE in codes


def test_vague_closure_without_proof_triggers_ambiguous_evidence():
    """'done'/'closed' with no accompanying proof-bearing field is ambiguous."""
    e = _evd("EVD-0001", "ticket", "ticket_id=TCK-001; status=Closed")  # no patch_report/rescan_result/etc.
    details = compute_diagnostic_details([e], "supported")
    hits = [d for d in details if d["code"] == AMBIGUOUS_EVIDENCE and d["rule_id"] == "DIAG-AMB-008"]
    assert len(hits) == 1


def test_closure_with_proof_does_not_trigger_vague_closure_rule():
    e = _evd("EVD-0001", "ticket", "ticket_id=TCK-001; status=Closed; patch_report=PATCH-RPT-001")
    details = compute_diagnostic_details([e], "supported")
    hits = [d for d in details if d["code"] == AMBIGUOUS_EVIDENCE and d["rule_id"] == "DIAG-AMB-008"]
    assert hits == []


def test_ambiguous_evidence_detail_cites_rule_and_value():
    e = _evd("EVD-0001", "ticket", "ticket_id=TCK-001; status=Closed", summary="seems resolved")
    details = compute_diagnostic_details([e], "supported")
    hit = next(d for d in details if d["code"] == AMBIGUOUS_EVIDENCE and d["rule_id"] == "DIAG-AMB-002")
    assert hit["evidence_ids"] == ["EVD-0001"]
    assert "detected_value" in hit


def test_clean_unambiguous_evidence_triggers_no_ambiguous_warning():
    e = _evd("EVD-0003", "ticket", "ticket_id=SEC-2201; status=Closed; patch_report=PATCH-RPT-2201")
    assert AMBIGUOUS_EVIDENCE not in compute_diagnostics([e], "supported")


# -- severity model ------------------------------------------------------------

def test_severity_table_matches_spec():
    assert DIAGNOSTIC_SEVERITY[MISSING_EXPECTED_FIELD] == SEVERITY_SERIOUS
    assert DIAGNOSTIC_SEVERITY[AMBIGUOUS_EVIDENCE] == SEVERITY_SERIOUS
    assert DIAGNOSTIC_SEVERITY[LOW_EVIDENCE_COVERAGE] == SEVERITY_INFORMATIONAL
    assert DIAGNOSTIC_SEVERITY[STALE_EVIDENCE] == SEVERITY_INFORMATIONAL


def test_serious_warnings_derived_from_single_severity_table():
    """SERIOUS_WARNINGS must never be maintained independently of DIAGNOSTIC_SEVERITY."""
    expected = {code for code, sev in DIAGNOSTIC_SEVERITY.items() if sev == SEVERITY_SERIOUS}
    assert SERIOUS_WARNINGS == frozenset(expected)


def test_missing_expected_field_and_ambiguous_are_serious_end_to_end():
    e = _evd("EVD-0001", "ticket", "ticket_id=TCK-001")  # missing status -> serious
    details = compute_diagnostic_details([e], "supported")
    for d in details:
        if d["code"] in (MISSING_EXPECTED_FIELD, AMBIGUOUS_EVIDENCE):
            assert d["severity"] == SEVERITY_SERIOUS
