"""Ingestion into the four controlled Chroma collections (spec section 6).

These functions are called both directly (Python) and from the new
authenticated FastAPI endpoints in web/generator_api.py
(POST /api/v1/ingestion/{mitre,cve,kev,runbooks,evidence}) — the endpoints are
thin wrappers that handle auth/job-tracking and delegate the actual work here,
so the ingestion logic itself has exactly one implementation regardless of
caller.

Each ingestion function: validates (Pydantic) -> normalizes -> computes a
content hash -> detects duplicates/updates -> chunks -> embeds -> upserts ->
logs a structured audit event. No internet access is required — callers pass
already-loaded local JSON/Markdown/text records.
"""

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from mcp_server.logging_utils import AuditLogger
from mcp_server.rag.chroma_client import ChromaCollections
from mcp_server.rag.config import CORPORATE_EVIDENCE, MITRE_ATTACK, RUNBOOKS, VULNERABILITIES, RagConfig
from mcp_server.rag.embeddings import EmbeddingBackend
from mcp_server.rag.identifiers import MAX_INDEXED_IDENTIFIER_VALUES
from mcp_server.rag.sanitization import scan_for_injection
from mcp_server.rag.schemas import CveRecord, KevEnrichment, MitreObject, RagIngestionEvidence, Runbook

_INJECTION_TAG_STRIP_RE = re.compile(r"<\s*/?\s*(script|iframe)[^>]*>", re.IGNORECASE)


def _indexed_metadata(prefix: str, values: list[str]) -> dict[str, str]:
    """Writer side of the indexed-column pattern documented in
    mcp_server/rag/identifiers.py::MAX_INDEXED_IDENTIFIER_VALUES; see
    mcp_server/rag/retrieval.py for the corresponding reader (`$or` lookup
    across these same columns)."""
    return {
        f"{prefix}_{i}": values[i] if i < len(values) else ""
        for i in range(MAX_INDEXED_IDENTIFIER_VALUES)
    }


@dataclass
class IngestionResult:
    ingested: int
    updated: int
    duplicates: int
    skipped_suspicious: int
    record_ids: list[str]


def _content_hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _sanitize_untrusted_text(text: str) -> tuple[str, bool]:
    """Strip obvious script/iframe tags and report whether an injection
    heuristic matched (spec: 'sanitize untrusted text', 'log injection
    indicators'). Never claims to be a complete defense — see
    mcp_server/rag/sanitization.py's own docstring."""
    scan = scan_for_injection(text)
    cleaned = _INJECTION_TAG_STRIP_RE.sub("", text or "")
    return cleaned, scan.suspicious


def _chunk_by_headings(text: str, max_chars: int = 1200) -> list[str]:
    """Chunk by Markdown headings/blank-line sections rather than arbitrary
    character counts (spec: runbook chunking requirement, applied generically
    here to any structured text)."""
    sections = re.split(r"\n(?=#{1,6}\s)", text or "")
    chunks: list[str] = []
    for section in sections:
        section = section.strip()
        if not section:
            continue
        if len(section) <= max_chars:
            chunks.append(section)
        else:
            for i in range(0, len(section), max_chars):
                chunks.append(section[i:i + max_chars])
    return chunks or [text or ""]


def _existing_hash(chroma: ChromaCollections, collection: str, record_id: str) -> str | None:
    existing = chroma.get_by_ids(collection=collection, ids=[record_id])
    metas = existing.get("metadatas") or []
    if metas and metas[0]:
        return metas[0].get("content_hash")
    return None


def ingest_evidence(
    records: list[dict[str, Any]], *, chroma: ChromaCollections, embeddings: EmbeddingBackend,
    config: RagConfig, audit: AuditLogger, session_id: str, correlation_id: str,
) -> IngestionResult:
    ingested = updated = duplicates = skipped = 0
    ids: list[str] = []
    for raw in records:
        model = RagIngestionEvidence.model_validate(raw).with_integrity_hash()
        cleaned_content, suspicious = _sanitize_untrusted_text(model.content)
        if suspicious:
            skipped += 1
            audit.log(
                session_id=session_id, correlation_id=correlation_id, state="RAG_INGESTION",
                event_type="INGESTION_INJECTION_DETECTED", role="RAG", result="EXCLUDED",
                detail=f"evidence_id={model.id} source={model.source}",
            )
            continue

        content_hash = _content_hash(cleaned_content)
        existing_hash = _existing_hash(chroma, CORPORATE_EVIDENCE, model.id)
        if existing_hash == content_hash:
            duplicates += 1
            continue
        action = "INGESTION_UPDATED" if existing_hash else "INGESTION_NEW"
        updated += 1 if existing_hash else 0
        ingested += 0 if existing_hash else 1

        metadata = {
            "id": model.id, "source_type": "corporate_evidence", "case_id": model.case_id,
            "ticket_id": model.ticket_id, "asset_id": model.asset_id, "cve_ids": ",".join(model.cve_ids),
            "hostname": model.hostname or "", "ip_addresses": ",".join(model.ip_addresses),
            "file_hashes": ",".join(model.file_hashes),
            "source": model.source, "observed_at": model.observed_at.isoformat(),
            "evidence_type": model.evidence_type, "classification": model.classification,
            "integrity_hash": model.integrity_hash, "content_hash": content_hash,
        }
        metadata.update(_indexed_metadata("ip_address", model.ip_addresses))
        metadata.update(_indexed_metadata("file_hash", model.file_hashes))

        vector = embeddings.embed([cleaned_content])[0]
        chroma.upsert(
            collection=CORPORATE_EVIDENCE, ids=[model.id], embeddings=[vector], documents=[cleaned_content],
            metadatas=[metadata],
        )
        ids.append(model.id)
        audit.log(
            session_id=session_id, correlation_id=correlation_id, state="RAG_INGESTION",
            event_type=action, role="RAG", result="OK",
            detail=f"evidence_id={model.id} case_id={model.case_id} ticket_id={model.ticket_id}",
        )
    return IngestionResult(ingested, updated, duplicates, skipped, ids)


def ingest_mitre(
    records: list[dict[str, Any]], *, chroma: ChromaCollections, embeddings: EmbeddingBackend,
    config: RagConfig, audit: AuditLogger, session_id: str, correlation_id: str,
) -> IngestionResult:
    ingested = updated = duplicates = skipped = 0
    ids: list[str] = []
    for raw in records:
        model = MitreObject.model_validate(raw)
        # Revoked/deprecated objects are still stored (for audit/explicit
        # lookup) but flagged so normal retrieval excludes them (spec section 6).
        content_hash = _content_hash(model.description)
        existing_hash = _existing_hash(chroma, MITRE_ATTACK, model.stix_id)
        if existing_hash == content_hash:
            duplicates += 1
            continue
        updated += 1 if existing_hash else 0
        ingested += 0 if existing_hash else 1

        vector = embeddings.embed([f"{model.name}\n{model.description}"])[0]
        chroma.upsert(
            collection=MITRE_ATTACK, ids=[model.stix_id], embeddings=[vector],
            documents=[f"{model.name}\n{model.description}"],
            metadatas=[{
                "source_type": "mitre_attack", "attack_id": model.attack_id, "object_type": model.object_type,
                "tactics": ",".join(model.tactics), "platforms": ",".join(model.platforms), "domain": model.domain,
                "revoked": model.revoked, "deprecated": model.deprecated, "content_hash": content_hash,
            }],
        )
        ids.append(model.stix_id)
        audit.log(
            session_id=session_id, correlation_id=correlation_id, state="RAG_INGESTION",
            event_type="INGESTION_NEW" if not existing_hash else "INGESTION_UPDATED", role="RAG", result="OK",
            detail=f"attack_id={model.attack_id}",
        )
    return IngestionResult(ingested, updated, duplicates, skipped, ids)


def ingest_cve(
    records: list[dict[str, Any]], *, chroma: ChromaCollections, embeddings: EmbeddingBackend,
    config: RagConfig, audit: AuditLogger, session_id: str, correlation_id: str,
) -> IngestionResult:
    ingested = updated = duplicates = skipped = 0
    ids: list[str] = []
    for raw in records:
        model = CveRecord.model_validate(raw)
        content_hash = _content_hash(model.description)
        existing_hash = _existing_hash(chroma, VULNERABILITIES, model.cve_id)
        if existing_hash == content_hash:
            duplicates += 1
            continue
        updated += 1 if existing_hash else 0
        ingested += 0 if existing_hash else 1

        vector = embeddings.embed([f"{model.cve_id}\n{model.description}"])[0]
        chroma.upsert(
            collection=VULNERABILITIES, ids=[model.cve_id], embeddings=[vector],
            documents=[f"{model.cve_id}\n{model.description}"],
            metadatas=[{
                "source_type": "vulnerabilities", "cve_id": model.cve_id, "severity": model.severity,
                "cvss_score": model.cvss_score, "vendor": model.vendor, "product": model.product,
                "kev": model.kev, "content_hash": content_hash,
            }],
        )
        ids.append(model.cve_id)
        audit.log(
            session_id=session_id, correlation_id=correlation_id, state="RAG_INGESTION",
            event_type="INGESTION_NEW" if not existing_hash else "INGESTION_UPDATED", role="RAG", result="OK",
            detail=f"cve_id={model.cve_id}",
        )
    return IngestionResult(ingested, updated, duplicates, skipped, ids)


def ingest_kev(
    records: list[dict[str, Any]], *, chroma: ChromaCollections, embeddings: EmbeddingBackend,
    config: RagConfig, audit: AuditLogger, session_id: str, correlation_id: str,
) -> IngestionResult:
    """Enriches EXISTING vulnerabilities records with CISA KEV fields (spec
    section 9). Never creates a new collection or a new authoritative record --
    a KEV entry for a CVE that was never ingested via ingest_cve() is skipped
    and audited, not silently created as a bare KEV-only record (that would let
    reference-only data masquerade as a vulnerability record with no underlying
    CVE description at all).
    """
    ingested = updated = duplicates = skipped = 0
    ids: list[str] = []
    for raw in records:
        model = KevEnrichment.model_validate(raw)
        existing = chroma.get_by_ids(collection=VULNERABILITIES, ids=[model.cve_id])
        docs = existing.get("documents") or []
        metas = existing.get("metadatas") or []
        if not docs or not docs[0]:
            skipped += 1
            audit.log(
                session_id=session_id, correlation_id=correlation_id, state="RAG_INGESTION",
                event_type="INGESTION_KEV_SKIPPED_UNKNOWN_CVE", role="RAG", result="SKIPPED",
                detail=f"cve_id={model.cve_id} has no existing vulnerabilities record to enrich",
            )
            continue

        document = docs[0]
        metadata = dict(metas[0] or {})
        metadata.update({
            "kev": True,
            "kev_date_added": model.date_added.isoformat() if model.date_added else None,
            "kev_due_date": model.due_date.isoformat() if model.due_date else None,
            "kev_required_action": model.required_action,
            "kev_known_ransomware_use": model.known_ransomware_campaign_use,
            "kev_notes": model.notes,
        })
        vector = embeddings.embed([document])[0]
        chroma.upsert(
            collection=VULNERABILITIES, ids=[model.cve_id], embeddings=[vector],
            documents=[document], metadatas=[metadata],
        )
        ids.append(model.cve_id)
        updated += 1
        audit.log(
            session_id=session_id, correlation_id=correlation_id, state="RAG_INGESTION",
            event_type="INGESTION_KEV_ENRICHED", role="RAG", result="OK",
            detail=f"cve_id={model.cve_id}",
        )
    return IngestionResult(ingested, updated, duplicates, skipped, ids)


def ingest_runbooks(
    records: list[dict[str, Any]], *, chroma: ChromaCollections, embeddings: EmbeddingBackend,
    config: RagConfig, audit: AuditLogger, session_id: str, correlation_id: str,
) -> IngestionResult:
    ingested = updated = duplicates = skipped = 0
    ids: list[str] = []
    for raw in records:
        model = Runbook.model_validate(raw)
        cleaned_content, suspicious = _sanitize_untrusted_text(model.content)
        if suspicious:
            skipped += 1
            continue

        chunks = _chunk_by_headings(cleaned_content)
        content_hash = _content_hash(cleaned_content)
        existing_hash = _existing_hash(chroma, RUNBOOKS, model.runbook_id)
        if existing_hash == content_hash:
            duplicates += 1
            continue
        updated += 1 if existing_hash else 0
        ingested += 0 if existing_hash else 1

        vectors = embeddings.embed(chunks)
        chunk_ids = [f"{model.runbook_id}#chunk-{i}" for i in range(len(chunks))]
        chroma.upsert(
            collection=RUNBOOKS, ids=chunk_ids, embeddings=vectors, documents=chunks,
            metadatas=[{
                "source_type": "runbooks", "runbook_id": model.runbook_id, "title": model.title,
                "version": model.version, "status": model.status, "owner": model.owner,
                "classification": model.classification, "incident_type": model.incident_type,
                "effective_date": model.effective_date.isoformat() if model.effective_date else None,
                "superseded_by": model.superseded_by, "content_hash": content_hash,
            }] * len(chunks),
        )
        ids.extend(chunk_ids)
        audit.log(
            session_id=session_id, correlation_id=correlation_id, state="RAG_INGESTION",
            event_type="INGESTION_NEW" if not existing_hash else "INGESTION_UPDATED", role="RAG", result="OK",
            detail=f"runbook_id={model.runbook_id} chunks={len(chunks)}",
        )
    return IngestionResult(ingested, updated, duplicates, skipped, ids)
