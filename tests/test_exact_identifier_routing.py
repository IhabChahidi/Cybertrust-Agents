"""Exact identifier routing (spec: "Complete exact identifier routing"):
hostname, IPv4/IPv6, SHA-256/SHA-1/MD5, case/ticket/asset IDs must all
trigger deterministic exact-or-metadata retrieval on corporate_evidence,
ranked above vector-only matches, scope- and classification-filtered exactly
like every other retrieval path. Covers mcp_server/rag/identifiers.py's
typed ExtractedIdentifier/normalize_identifier and the routing table in
mcp_server/rag/retrieval.py.
"""

import pytest

from mcp_server.logging_utils import AuditLogger
from mcp_server.rag.chroma_client import ChromaCollections
from mcp_server.rag.config import RagConfig
from mcp_server.rag.embeddings import get_embedding_backend
from mcp_server.rag.identifiers import ExtractedIdentifier, IdentifierType, normalize_identifier
from mcp_server.rag.ingestion import ingest_evidence
from mcp_server.rag.retrieval import retrieve

pytestmark = pytest.mark.integration


@pytest.fixture()
def rag_env(tmp_path):
    config = RagConfig(chroma_persist_dir=str(tmp_path / "chroma"), min_score=0.0)
    chroma = ChromaCollections(config)
    embeddings = get_embedding_backend(config, force_fake=True)
    audit = AuditLogger(journal_path=str(tmp_path / "rag_journal.jsonl"))
    return config, chroma, embeddings, audit


def _evidence_record(eid="EVD-0001", *, case_id="VUL-018", ticket_id="SEC-104", asset_id="SRV-ERP-01",
                      hostname=None, ip_addresses=None, file_hashes=None,
                      classification="CONFIDENTIAL", content="Investigation notes for the affected host."):
    return {
        "id": eid, "case_id": case_id, "ticket_id": ticket_id, "asset_id": asset_id,
        "cve_ids": [], "source": "ITSM-FICTIF", "observed_at": "2026-07-22T09:00:00Z",
        "evidence_type": "vulnerability_scan", "content": content, "classification": classification,
        "hostname": hostname, "ip_addresses": ip_addresses or [], "file_hashes": file_hashes or [],
    }


def _ingest(chroma, embeddings, config, audit, records):
    return ingest_evidence(records, chroma=chroma, embeddings=embeddings, config=config, audit=audit,
                            session_id="SES-EXACT0000", correlation_id="COR-EXACT0000")


# --- ExtractedIdentifier / normalize_identifier -----------------------------

def test_normalize_identifier_uppercases_cve_and_mitre():
    assert normalize_identifier(IdentifierType.CVE_ID, "cve-2026-12345") == "CVE-2026-12345"
    assert normalize_identifier(IdentifierType.MITRE_TECHNIQUE, "t1190") == "T1190"


def test_normalize_identifier_lowercases_hostname_and_hash():
    assert normalize_identifier(IdentifierType.HOSTNAME, "WEB01.EXAMPLE.COM.") == "web01.example.com"
    assert normalize_identifier(IdentifierType.SHA256, "A" * 64) == "a" * 64


def test_normalize_identifier_canonicalizes_ip_addresses():
    assert normalize_identifier(IdentifierType.IPV4, "10.0.0.5") == "10.0.0.5"
    assert normalize_identifier(IdentifierType.IPV6, "2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"


def test_normalize_identifier_rejects_malformed_ip_and_hash():
    assert normalize_identifier(IdentifierType.IPV4, "999.999.999.999") is None
    assert normalize_identifier(IdentifierType.IPV6, "not:an:ip:address:at:all:zzzz:zzzz") is None
    assert normalize_identifier(IdentifierType.MD5, "not-hexadecimal-text-at-all-here") is None
    assert normalize_identifier(IdentifierType.SHA256, "abc") is None  # too short


def test_extracted_identifier_is_a_typed_pydantic_model():
    identifier = ExtractedIdentifier(type=IdentifierType.CVE_ID, value="cve-2026-12345", normalized_value="CVE-2026-12345")
    assert identifier.type == IdentifierType.CVE_ID
    assert identifier.normalized_value == "CVE-2026-12345"


# --- exact retrieval: hostname -----------------------------------------------

def test_exact_hostname_lookup(rag_env):
    config, chroma, embeddings, audit = rag_env
    _ingest(chroma, embeddings, config, audit, [_evidence_record(hostname="web01.example.com")])

    results, trace = retrieve(query="Any findings for web01.example.com?", chroma=chroma, embeddings=embeddings, config=config)
    hits = [r for r in results if r.record_id == "EVD-0001"]
    assert hits
    assert hits[0].retrieval_method == "exact_identifier"
    assert trace.identifiers_extracted.get("hostname") == ["web01.example.com"]


def test_case_insensitive_hostname_lookup(rag_env):
    config, chroma, embeddings, audit = rag_env
    _ingest(chroma, embeddings, config, audit, [_evidence_record(hostname="Web01.Example.COM")])

    results, _ = retrieve(query="Any findings for WEB01.EXAMPLE.COM?", chroma=chroma, embeddings=embeddings, config=config)
    hits = [r for r in results if r.record_id == "EVD-0001"]
    assert hits
    assert hits[0].retrieval_method == "exact_identifier"


# --- exact retrieval: IPv4 / IPv6 --------------------------------------------

def test_exact_ipv4_lookup(rag_env):
    config, chroma, embeddings, audit = rag_env
    _ingest(chroma, embeddings, config, audit, [_evidence_record(ip_addresses=["10.0.0.5"])])

    results, trace = retrieve(query="Traffic from 10.0.0.5 was observed.", chroma=chroma, embeddings=embeddings, config=config)
    hits = [r for r in results if r.record_id == "EVD-0001"]
    assert hits
    assert hits[0].retrieval_method == "exact_identifier"
    assert trace.identifiers_extracted.get("ipv4") == ["10.0.0.5"]


def test_canonical_ipv6_lookup(rag_env):
    config, chroma, embeddings, audit = rag_env
    _ingest(chroma, embeddings, config, audit, [_evidence_record(ip_addresses=["2001:db8::1"])])

    # Query uses the fully-expanded, non-canonical form -- normalization must
    # still match the canonically-stored value.
    results, _ = retrieve(
        query="Traffic from 2001:0db8:0000:0000:0000:0000:0000:0001 was observed.",
        chroma=chroma, embeddings=embeddings, config=config,
    )
    hits = [r for r in results if r.record_id == "EVD-0001"]
    assert hits
    assert hits[0].retrieval_method == "exact_identifier"


def test_multiple_ip_addresses_on_one_record_are_all_exact_lookupable(rag_env):
    config, chroma, embeddings, audit = rag_env
    _ingest(chroma, embeddings, config, audit, [_evidence_record(ip_addresses=["10.0.0.5", "10.0.0.6", "10.0.0.7"])])

    for ip in ("10.0.0.5", "10.0.0.6", "10.0.0.7"):
        results, _ = retrieve(query=f"Host at {ip} flagged.", chroma=chroma, embeddings=embeddings, config=config)
        hits = [r for r in results if r.record_id == "EVD-0001"]
        assert hits, f"{ip} was not found via exact lookup"
        assert hits[0].retrieval_method == "exact_identifier"


# --- exact retrieval: hashes -------------------------------------------------

def test_exact_sha256_lookup(rag_env):
    config, chroma, embeddings, audit = rag_env
    digest = "a" * 64
    _ingest(chroma, embeddings, config, audit, [_evidence_record(file_hashes=[digest])])

    results, trace = retrieve(query=f"Malware sample {digest} found.", chroma=chroma, embeddings=embeddings, config=config)
    hits = [r for r in results if r.record_id == "EVD-0001"]
    assert hits
    assert hits[0].retrieval_method == "exact_identifier"
    assert trace.identifiers_extracted.get("sha256") == [digest]


def test_exact_sha1_lookup(rag_env):
    config, chroma, embeddings, audit = rag_env
    digest = "b" * 40
    _ingest(chroma, embeddings, config, audit, [_evidence_record(file_hashes=[digest])])

    results, _ = retrieve(query=f"Malware sample {digest} found.", chroma=chroma, embeddings=embeddings, config=config)
    hits = [r for r in results if r.record_id == "EVD-0001"]
    assert hits
    assert hits[0].retrieval_method == "exact_identifier"


def test_exact_md5_lookup(rag_env):
    config, chroma, embeddings, audit = rag_env
    digest = "c" * 32
    _ingest(chroma, embeddings, config, audit, [_evidence_record(file_hashes=[digest])])

    results, _ = retrieve(query=f"Malware sample {digest} found.", chroma=chroma, embeddings=embeddings, config=config)
    hits = [r for r in results if r.record_id == "EVD-0001"]
    assert hits
    assert hits[0].retrieval_method == "exact_identifier"


# --- exact retrieval: case / ticket / asset ----------------------------------

def test_exact_case_lookup(rag_env):
    config, chroma, embeddings, audit = rag_env
    _ingest(chroma, embeddings, config, audit, [_evidence_record(case_id="VUL-018")])

    results, _ = retrieve(query="Status of case VUL-018?", chroma=chroma, embeddings=embeddings, config=config)
    hits = [r for r in results if r.record_id == "EVD-0001"]
    assert hits
    assert hits[0].retrieval_method == "exact_identifier"


def test_exact_ticket_lookup(rag_env):
    config, chroma, embeddings, audit = rag_env
    _ingest(chroma, embeddings, config, audit, [_evidence_record(ticket_id="SEC-104")])

    results, _ = retrieve(query="Status of ticket SEC-104?", chroma=chroma, embeddings=embeddings, config=config)
    hits = [r for r in results if r.record_id == "EVD-0001"]
    assert hits
    assert hits[0].retrieval_method == "exact_identifier"


def test_exact_asset_lookup(rag_env):
    config, chroma, embeddings, audit = rag_env
    _ingest(chroma, embeddings, config, audit, [_evidence_record(asset_id="SRV-ERP-01")])

    results, _ = retrieve(query="Status of asset SRV-ERP-01?", chroma=chroma, embeddings=embeddings, config=config)
    hits = [r for r in results if r.record_id == "EVD-0001"]
    assert hits
    assert hits[0].retrieval_method == "exact_identifier"


# --- malformed identifier rejection ------------------------------------------

def test_malformed_ip_in_query_is_never_treated_as_an_identifier(rag_env):
    config, chroma, embeddings, audit = rag_env
    _ingest(chroma, embeddings, config, audit, [_evidence_record(ip_addresses=["10.0.0.5"])])

    results, trace = retrieve(query="Traffic from 999.999.999.999 was observed.", chroma=chroma,
                               embeddings=embeddings, config=config)
    assert "ipv4" not in trace.identifiers_extracted
    assert "EVD-0001" not in {r.record_id for r in results if r.retrieval_method == "exact_identifier"}


def test_evidence_ingestion_rejects_malformed_ip_address():
    from pydantic import ValidationError

    from mcp_server.rag.schemas import RagIngestionEvidence
    with pytest.raises(ValidationError):
        RagIngestionEvidence.model_validate({**_evidence_record(), "ip_addresses": ["999.999.999.999"]})


def test_evidence_ingestion_rejects_malformed_file_hash():
    from pydantic import ValidationError

    from mcp_server.rag.schemas import RagIngestionEvidence
    with pytest.raises(ValidationError):
        RagIngestionEvidence.model_validate({**_evidence_record(), "file_hashes": ["not-a-real-hash"]})


# --- ranking, scope, classification, dedup ----------------------------------

def test_exact_identifier_outranks_higher_semantic_similarity(rag_env):
    config, chroma, embeddings, audit = rag_env
    _ingest(chroma, embeddings, config, audit, [
        _evidence_record(eid="EVD-0001", ip_addresses=["10.0.0.5"], content="unrelated filler text"),
        _evidence_record(eid="EVD-0002", case_id="VUL-999", ticket_id="SEC-999", asset_id="SRV-OTHER",
                          content="10.0.0.5 mentioned heavily here for vector similarity purposes 10.0.0.5"),
    ])
    results, _ = retrieve(query="10.0.0.5", chroma=chroma, embeddings=embeddings, config=config)
    assert results[0].retrieval_method == "exact_identifier"


def test_exact_hostname_from_different_case_does_not_bypass_scope(rag_env):
    config, chroma, embeddings, audit = rag_env
    _ingest(chroma, embeddings, config, audit, [
        _evidence_record(eid="EVD-0001", case_id="VUL-018", hostname="shared-host.example.com"),
        _evidence_record(eid="EVD-0002", case_id="VUL-999", ticket_id="SEC-999", asset_id="SRV-OTHER",
                          hostname="shared-host.example.com"),
    ])
    results, _ = retrieve(query="shared-host.example.com status", case_id="VUL-018",
                           chroma=chroma, embeddings=embeddings, config=config)
    ids = {r.record_id for r in results}
    assert "EVD-0001" in ids
    assert "EVD-0002" not in ids


def test_exact_ip_from_different_asset_does_not_bypass_scope(rag_env):
    config, chroma, embeddings, audit = rag_env
    _ingest(chroma, embeddings, config, audit, [
        _evidence_record(eid="EVD-0001", asset_id="SRV-ERP-01", ip_addresses=["10.0.0.9"]),
        _evidence_record(eid="EVD-0002", case_id="VUL-999", ticket_id="SEC-999", asset_id="SRV-OTHER",
                          ip_addresses=["10.0.0.9"]),
    ])
    results, _ = retrieve(query="10.0.0.9 activity", asset_id="SRV-ERP-01",
                           chroma=chroma, embeddings=embeddings, config=config)
    ids = {r.record_id for r in results}
    assert "EVD-0001" in ids
    assert "EVD-0002" not in ids


def test_exact_hash_lookup_still_enforces_classification(rag_env):
    config, chroma, embeddings, audit = rag_env
    digest = "d" * 64
    _ingest(chroma, embeddings, config, audit, [_evidence_record(file_hashes=[digest], classification="CONFIDENTIAL")])

    results, _ = retrieve(query=digest, allowed_classification="PUBLIC", chroma=chroma, embeddings=embeddings, config=config)
    assert "EVD-0001" not in {r.record_id for r in results}

    results, _ = retrieve(query=digest, allowed_classification="CONFIDENTIAL", chroma=chroma, embeddings=embeddings, config=config)
    assert "EVD-0001" in {r.record_id for r in results}


def test_exact_and_vector_hits_for_the_same_record_are_merged_not_duplicated(rag_env):
    config, chroma, embeddings, audit = rag_env
    _ingest(chroma, embeddings, config, audit, [
        _evidence_record(eid="EVD-0001", hostname="dupe-check.example.com", content="dupe-check.example.com findings"),
    ])
    results, _ = retrieve(query="dupe-check.example.com findings", chroma=chroma, embeddings=embeddings, config=config)
    matching = [r for r in results if r.record_id == "EVD-0001"]
    assert len(matching) == 1
    assert matching[0].retrieval_method == "exact_identifier"
