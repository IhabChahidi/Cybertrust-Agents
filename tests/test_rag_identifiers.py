"""Exact identifier extraction (spec section 3 / section 12 test list)."""

from mcp_server.rag.identifiers import extract_identifiers

pytestmark = __import__("pytest").mark.unit


def test_extracts_cve_id():
    ids = extract_identifiers("Assess remediation for CVE-2026-12345 on SRV-ERP-01.")
    assert ids["cve_id"] == ["CVE-2026-12345"]


def test_extracts_mitre_technique_with_and_without_subtechnique():
    ids = extract_identifiers("Related to T1059 and T1059.001.")
    assert set(ids["mitre_technique"]) == {"T1059", "T1059.001"}


def test_extracts_evidence_id():
    ids = extract_identifiers("See EVD-0042 for details.")
    assert ids["evidence_id"] == ["EVD-0042"]


def test_extracts_runbook_id():
    ids = extract_identifiers("Follow RB-INCIDENT-RESPONSE-01.")
    assert ids["runbook_id"] == ["RB-INCIDENT-RESPONSE-01"]


def test_extracts_case_ticket_asset_ids():
    ids = extract_identifiers("Case VUL-018, ticket SEC-104, asset SRV-ERP-01.")
    assert ids["case_id"] == ["VUL-018"]
    assert ids["ticket_id"] == ["SEC-104"]
    assert ids["asset_id"] == ["SRV-ERP-01"]


def test_extracts_hashes():
    ids = extract_identifiers("File hash: " + "a" * 64)
    assert ids["sha256"] == ["a" * 64]


def test_no_identifiers_returns_empty_dict_no_crash():
    assert extract_identifiers("just a plain sentence with nothing special") == {}


def test_empty_and_none_text_do_not_crash():
    assert extract_identifiers("") == {}
    assert extract_identifiers(None) == {}
