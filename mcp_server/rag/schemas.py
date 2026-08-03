"""Pydantic v2 models for RAG ingestion and retrieval (spec sections 2 and 5).

These are separate from mcp_server/schemas.py (the raw JSON-Schema MCP
contracts, checked via jsonschema.Draft7Validator) by design: the MCP contracts
are the wire format for the Evidence -> Claim -> ... pipeline and are not
touched here. These Pydantic models validate data on the way INTO the RAG store
(ingestion) and OUT of it (retrieval results) — a different layer, reusing
Pydantic because the ingestion payloads (STIX objects, CVE/NVD fixtures,
runbook front-matter) are naturally nested/optional in a way the existing
additionalProperties:false JSON Schemas are not designed for.
"""

import hashlib
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from mcp_server.rag.config import ALL_COLLECTIONS
from mcp_server.rag.identifiers import IdentifierType, normalize_identifier


class RagIngestionEvidence(BaseModel):
    """Corporate evidence ingestion model (spec section 5). Distinct from
    mcp_server.schemas.EVIDENCE_SCHEMA (the MCP pipeline's own Evidence contract,
    id pattern ^EVD-[0-9]{4}$, additionalProperties:false) -- this is the richer,
    looser shape real ingestion sources (tickets, scans, audit exports) actually
    arrive in, before being normalized/chunked for the vector store. The two are
    intentionally not merged: this model must accept extra ingestion-only
    metadata (case_id, integrity_hash, arbitrary metadata) the strict pipeline
    contract forbids.
    """

    model_config = {"extra": "forbid"}

    id: str
    case_id: str | None = None
    ticket_id: str | None = None
    asset_id: str | None = None
    cve_ids: list[str] = Field(default_factory=list)
    # Exact-identifier-routing fields (spec: "preserve searchable metadata
    # fields such as hostname, ip_addresses, file_hashes"). Optional/additive
    # -- existing callers that never supplied these keep working unchanged.
    hostname: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    file_hashes: list[str] = Field(default_factory=list)
    source: str
    observed_at: datetime
    evidence_type: str
    content: str
    classification: str
    integrity_hash: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        import re
        if not re.match(r"^EVD-\d{4}$", value):
            raise ValueError(f"evidence id {value!r} must match ^EVD-\\d{{4}}$")
        return value

    @field_validator("hostname")
    @classmethod
    def _normalize_hostname(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = normalize_identifier(IdentifierType.HOSTNAME, value)
        if normalized is None:
            raise ValueError(f"hostname {value!r} is not a valid hostname")
        return normalized

    @field_validator("ip_addresses")
    @classmethod
    def _normalize_ip_addresses(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            # Try both families -- normalize_identifier() rejects (returns
            # None) whichever family the value does not actually belong to.
            result = normalize_identifier(IdentifierType.IPV4, value) or normalize_identifier(IdentifierType.IPV6, value)
            if result is None:
                raise ValueError(f"ip address {value!r} is not a valid IPv4 or IPv6 address")
            normalized.append(result)
        return normalized

    @field_validator("file_hashes")
    @classmethod
    def _normalize_file_hashes(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            stripped = (value or "").strip()
            result = (
                normalize_identifier(IdentifierType.SHA256, stripped)
                or normalize_identifier(IdentifierType.SHA1, stripped)
                or normalize_identifier(IdentifierType.MD5, stripped)
            )
            if result is None:
                raise ValueError(f"file hash {value!r} is not a valid SHA-256/SHA-1/MD5 hex digest")
            normalized.append(result)
        return normalized

    def with_integrity_hash(self) -> "RagIngestionEvidence":
        """Return a copy with integrity_hash computed (SHA-256 of content) if it
        was not already supplied — never overwrites a hash that was provided."""
        if self.integrity_hash:
            return self
        digest = hashlib.sha256(self.content.encode("utf-8")).hexdigest()
        return self.model_copy(update={"integrity_hash": f"sha256:{digest}"})


class MitreObject(BaseModel):
    model_config = {"extra": "forbid"}

    attack_id: str
    stix_id: str
    name: str
    description: str = ""
    object_type: str
    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    domain: str = "enterprise-attack"
    created: datetime | None = None
    modified: datetime | None = None
    revoked: bool = False
    deprecated: bool = False
    relationships: list[str] = Field(default_factory=list)


class CveRecord(BaseModel):
    model_config = {"extra": "forbid"}

    cve_id: str
    description: str = ""
    published: datetime | None = None
    modified: datetime | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    vendor: str | None = None
    product: str | None = None
    affected_versions: list[str] = Field(default_factory=list)
    cpe: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    kev: bool = False
    # KEV enrichment fields (populated by ingest_kev(), never by ingest_cve()
    # itself). KEV status may influence prioritization/display but must never
    # be read as proof of corporate exposure or remediation — that requires
    # corporate_evidence, per the authority-separation rule (spec section 3/9).
    kev_date_added: datetime | None = None
    kev_due_date: datetime | None = None
    kev_required_action: str | None = None
    kev_known_ransomware_use: bool = False
    kev_notes: str | None = None

    @field_validator("cve_id")
    @classmethod
    def _validate_cve_id(cls, value: str) -> str:
        import re
        if not re.match(r"^CVE-\d{4}-\d{4,}$", value):
            raise ValueError(f"cve_id {value!r} does not match CVE-YYYY-NNNN+")
        return value


class KevEnrichment(BaseModel):
    """One CISA KEV catalog entry, applied as an enrichment to an existing
    vulnerabilities record (ingest_kev() merges these fields into the CVE's
    metadata; it never creates a new collection or a new authoritative record)."""

    model_config = {"extra": "forbid"}

    cve_id: str
    date_added: datetime | None = None
    due_date: datetime | None = None
    required_action: str | None = None
    known_ransomware_campaign_use: bool = False
    notes: str | None = None

    @field_validator("cve_id")
    @classmethod
    def _validate_cve_id(cls, value: str) -> str:
        import re
        if not re.match(r"^CVE-\d{4}-\d{4,}$", value):
            raise ValueError(f"cve_id {value!r} does not match CVE-YYYY-NNNN+")
        return value


class Runbook(BaseModel):
    model_config = {"extra": "forbid"}

    runbook_id: str
    title: str
    version: str
    status: Literal["DRAFT", "APPROVED", "RETIRED"] = "DRAFT"
    owner: str | None = None
    classification: str = "INTERNAL"
    incident_type: str | None = None
    effective_date: datetime | None = None
    review_date: datetime | None = None
    superseded_by: str | None = None
    operational_steps: list[str] = Field(default_factory=list)
    required_evidence: list[str] = Field(default_factory=list)
    escalation_conditions: list[str] = Field(default_factory=list)
    content: str = ""

    def is_retrievable(self, *, as_of: datetime | None = None, allowed_classification: str | None = None) -> bool:
        """Normal retrieval must only return runbooks that are APPROVED, already
        effective, not superseded, and within an allowed classification
        (spec section 6)."""
        now = as_of or datetime.now(timezone.utc)
        if self.status != "APPROVED":
            return False
        if self.effective_date and self.effective_date > now:
            return False
        if self.superseded_by:
            return False
        if allowed_classification and self.classification != allowed_classification:
            return False
        return True


class RetrievalResult(BaseModel):
    """One retrieved record, uniform across all four collections (spec section 2)."""

    model_config = {"extra": "forbid"}

    record_id: str
    collection: str
    source_type: str
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    retrieval_method: Literal["exact_identifier", "metadata", "full_text", "vector", "hybrid"]
    retrieval_score: float = Field(ge=0.0, le=1.0)
    authoritative: bool = False

    @field_validator("collection")
    @classmethod
    def _validate_collection(cls, value: str) -> str:
        if value not in ALL_COLLECTIONS:
            raise ValueError(f"unknown collection {value!r}; must be one of {sorted(ALL_COLLECTIONS)}")
        return value


class RetrievalTrace(BaseModel):
    """Returned alongside retrieval results for audit (spec section 7)."""

    model_config = {"extra": "forbid"}

    trace_id: str
    query: str
    identifiers_extracted: dict[str, list[str]] = Field(default_factory=dict)
    collections_queried: list[str] = Field(default_factory=list)
    result_count: int = 0
