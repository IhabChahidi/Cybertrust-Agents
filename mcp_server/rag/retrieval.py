"""Hybrid retrieval (spec section 3): exact identifiers -> metadata filters ->
full-text -> vector similarity -> merge/dedupe -> rerank. Vector similarity is
never used alone, and exact/metadata matches always outrank vector-only matches.

Cross-case isolation (spec section 3): when case_id/ticket_id/asset_id is
supplied, corporate_evidence vector queries are constrained to that
case/ticket/asset via a Chroma `where` filter, and the result set is
defensively re-filtered after retrieval too (belt-and-suspenders — a
misconfigured collection/where clause must not silently leak cross-case data).
"""

import uuid
from datetime import datetime, timezone

from mcp_server.rag.chroma_client import ChromaCollections, ChromaUnavailable
from mcp_server.rag.config import ALL_COLLECTIONS, CORPORATE_EVIDENCE, MITRE_ATTACK, RUNBOOKS, RagConfig
from mcp_server.rag.embeddings import EmbeddingBackend, EmbeddingBackendUnavailable
from mcp_server.rag.identifiers import MAX_INDEXED_IDENTIFIER_VALUES, IdentifierType, extract_typed_identifiers
from mcp_server.rag.schemas import RetrievalResult, RetrievalTrace

# Retrieval-method priority for reranking: exact/metadata matches are
# deterministic ground truth and always outrank vector similarity, which is
# probabilistic (spec section 3: "Exact identifiers and metadata-filtered
# results must rank above vector-only results").
_METHOD_PRIORITY = {"exact_identifier": 4, "metadata": 3, "full_text": 2, "hybrid": 2, "vector": 1}

# Which extracted identifier types map to which collection + which metadata
# field(s) for exact-match lookups (spec: "Complete exact identifier
# routing"). A scalar field name means a direct `where={field: value}`
# lookup; "ip" / "hash" mean the value may be stored across the fixed set of
# indexed columns ingestion.py writes (ip_address_0.._4 / file_hash_0.._4) --
# see ingestion.py's module-level comment for why a single scalar field
# cannot reliably hold "one of several values" under Chroma's `where`
# operators. Extend this table rather than hardcoding new collection-specific
# branches elsewhere.
_IDENTIFIER_ROUTES: dict[IdentifierType, tuple[str, str]] = {
    IdentifierType.CVE_ID: ("vulnerabilities", "cve_id"),
    IdentifierType.MITRE_TECHNIQUE: ("mitre_attack", "attack_id"),
    IdentifierType.RUNBOOK_ID: ("runbooks", "runbook_id"),
    IdentifierType.EVIDENCE_ID: ("corporate_evidence", "id"),
    IdentifierType.CASE_ID: ("corporate_evidence", "case_id"),
    IdentifierType.TICKET_ID: ("corporate_evidence", "ticket_id"),
    IdentifierType.ASSET_ID: ("corporate_evidence", "asset_id"),
    IdentifierType.HOSTNAME: ("corporate_evidence", "hostname"),
    IdentifierType.IPV4: ("corporate_evidence", "ip_address"),
    IdentifierType.IPV6: ("corporate_evidence", "ip_address"),
    IdentifierType.SHA256: ("corporate_evidence", "file_hash"),
    IdentifierType.SHA1: ("corporate_evidence", "file_hash"),
    IdentifierType.MD5: ("corporate_evidence", "file_hash"),
}

# Identifier types whose metadata field is one of the fixed indexed columns
# (ip_address_0.._4 / file_hash_0.._4) rather than a single scalar field.
_INDEXED_FIELD_TYPES = frozenset(
    {IdentifierType.IPV4, IdentifierType.IPV6, IdentifierType.SHA256, IdentifierType.SHA1, IdentifierType.MD5}
)


def _exact_where_clause(field_name: str, value: str, *, indexed: bool) -> dict:
    if not indexed:
        return {field_name: value}
    return {"$or": [{f"{field_name}_{i}": value} for i in range(MAX_INDEXED_IDENTIFIER_VALUES)]}


def _group_identifiers_for_trace(identifiers: list) -> dict[str, list[str]]:
    """Projects the typed identifier list into the legacy dict shape
    RetrievalTrace.identifiers_extracted has always exposed (spec: keep the
    public trace shape backward compatible)."""
    grouped: dict[str, set[str]] = {}
    for identifier in identifiers:
        grouped.setdefault(identifier.type.value, set()).add(identifier.normalized_value)
    return {name: sorted(values) for name, values in grouped.items()}


class RagUnavailable(RuntimeError):
    """Raised when neither ChromaDB nor the embedding backend is usable. Callers
    (the Generator) must catch this and proceed without RAG context — never a
    pipeline crash (spec: "ChromaDB unavailable" / "embedding model unavailable"
    are explicit test cases, not fatal errors)."""


def _case_scope_filter(case_id: str | None, ticket_id: str | None, asset_id: str | None) -> dict | None:
    clauses = []
    if case_id:
        clauses.append({"case_id": case_id})
    if ticket_id:
        clauses.append({"ticket_id": ticket_id})
    if asset_id:
        clauses.append({"asset_id": asset_id})
    if not clauses:
        return None
    if len(clauses) == 1:
        return clauses[0]
    return {"$or": clauses}


def _belongs_to_scope(metadata: dict, case_id, ticket_id, asset_id) -> bool:
    """Defensive re-check after retrieval: a corporate_evidence record must
    match at least one supplied scope identifier if any were supplied at all."""
    if not (case_id or ticket_id or asset_id):
        return True
    return (
        (case_id and metadata.get("case_id") == case_id)
        or (ticket_id and metadata.get("ticket_id") == ticket_id)
        or (asset_id and metadata.get("asset_id") == asset_id)
    )


def _is_permitted(result: RetrievalResult, *, allowed_classification: str | None) -> bool:
    """Enforces access-control rules that must never depend on the caller's
    free-text query or on the LLM's own judgment (spec: "collection access and
    classification filtering happen before retrieval", "the LLM never decides
    authorization"). Applied as a single, centralized post-filter over every
    candidate regardless of which retrieval method produced it (exact/metadata/
    full_text/vector) so there is exactly one enforcement point, not four.

    Three independent rules:
    1. mitre_attack: revoked or deprecated objects are excluded from normal
       retrieval by default (spec section 6/9) -- they remain in Chroma for
       audit/explicit lookup (chroma.get_by_ids), just never surfaced here.
    2. runbooks: only APPROVED, already-effective, non-superseded runbooks are
       retrievable -- mirrors mcp_server.rag.schemas.Runbook.is_retrievable(),
       applied here to the stored metadata dict directly (retrieval results are
       raw Chroma records, not reconstructed Runbook model instances).
    3. classification: when the caller supplies allowed_classification, any
       record that carries an explicit `classification` value different from
       it is excluded. Records with no classification concept (mitre_attack,
       vulnerabilities -- public reference data) are unaffected.
    """
    meta = result.metadata

    if result.collection == MITRE_ATTACK:
        if meta.get("revoked") or meta.get("deprecated"):
            return False

    if result.collection == RUNBOOKS:
        if meta.get("status") != "APPROVED":
            return False
        if meta.get("superseded_by"):
            return False
        effective_date = meta.get("effective_date")
        if effective_date:
            try:
                if datetime.fromisoformat(effective_date) > datetime.now(timezone.utc):
                    return False
            except ValueError:
                pass  # unparseable date: fail open on effective-date only, other checks above still apply

    if allowed_classification:
        record_classification = meta.get("classification")
        if record_classification is not None and record_classification != allowed_classification:
            return False

    return True


def retrieve(
    *, query: str, chroma: ChromaCollections, embeddings: EmbeddingBackend, config: RagConfig,
    case_id: str | None = None, ticket_id: str | None = None, asset_id: str | None = None,
    collections: list[str] | None = None, top_k: int | None = None,
    allowed_classification: str | None = None,
) -> tuple[list[RetrievalResult], RetrievalTrace]:
    collections = collections or list(ALL_COLLECTIONS)
    unknown = set(collections) - ALL_COLLECTIONS
    if unknown:
        raise ValueError(f"unknown collection(s) requested: {sorted(unknown)}")

    trace = RetrievalTrace(trace_id=f"RAGTRC-{uuid.uuid4().hex[:12].upper()}", query=query, collections_queried=collections)
    typed_identifiers = extract_typed_identifiers(query)
    trace.identifiers_extracted = _group_identifiers_for_trace(typed_identifiers)

    results: dict[str, RetrievalResult] = {}  # record_id -> best result seen so far

    def _consider(candidate: RetrievalResult) -> None:
        existing = results.get(candidate.record_id)
        if existing is None:
            results[candidate.record_id] = candidate
            return
        # Keep whichever has higher method priority; break ties on score.
        if (_METHOD_PRIORITY[candidate.retrieval_method], candidate.retrieval_score) > (
            _METHOD_PRIORITY[existing.retrieval_method], existing.retrieval_score
        ):
            results[candidate.record_id] = candidate

    # -- 1/2/3: exact identifier extraction + metadata filter + exact match ---
    # Covers every identifier type in spec section 1 (CVE/MITRE/runbook route
    # to their own reference collection; evidence/case/ticket/asset/hostname/
    # IP/hash all route to corporate_evidence, scope- and classification-
    # filtered exactly like every other retrieval path below). Performed
    # BEFORE any semantic/vector step, and always ranked above it (spec:
    # "only then perform semantic retrieval; rank exact matches above all
    # vector-only matches").
    for identifier in typed_identifiers:
        route = _IDENTIFIER_ROUTES.get(identifier.type)
        if route is None or route[0] not in collections:
            continue
        collection, field_name = route
        where = _exact_where_clause(field_name, identifier.normalized_value, indexed=identifier.type in _INDEXED_FIELD_TYPES)
        try:
            hit = chroma.get_by_where(collection=collection, where=where, limit=5)
        except ChromaUnavailable:
            raise RagUnavailable("ChromaDB is unavailable for exact-identifier lookup") from None
        for rid, doc, meta in zip(hit.get("ids", []), hit.get("documents", []), hit.get("metadatas", [])):
            # Scope enforcement applies to EVERY corporate_evidence exact hit,
            # regardless of which identifier type found it: an exact hostname/
            # IP/hash/case/ticket/asset match from a different case or asset
            # must never bypass the requested scope (spec: "Do not allow an
            # exact identifier from one case or asset to bypass the current
            # scope filters").
            if collection == CORPORATE_EVIDENCE and not _belongs_to_scope(meta, case_id, ticket_id, asset_id):
                continue
            _consider(RetrievalResult(
                record_id=rid, collection=collection, source_type=meta.get("source_type", collection),
                content=doc, metadata=meta, retrieval_method="exact_identifier",
                retrieval_score=1.0, authoritative=(collection == CORPORATE_EVIDENCE),
            ))

    # -- metadata-only scope filter (case/ticket/asset, no free-text query) ---
    scope_filter = _case_scope_filter(case_id, ticket_id, asset_id)
    if scope_filter and CORPORATE_EVIDENCE in collections:
        try:
            hit = chroma.get_by_where(collection=CORPORATE_EVIDENCE, where=scope_filter, limit=config.vector_top_k)
        except ChromaUnavailable:
            raise RagUnavailable("ChromaDB is unavailable for metadata-filtered lookup") from None
        for rid, doc, meta in zip(hit.get("ids", []), hit.get("documents", []), hit.get("metadatas", [])):
            _consider(RetrievalResult(
                record_id=rid, collection=CORPORATE_EVIDENCE, source_type=meta.get("source_type", CORPORATE_EVIDENCE),
                content=doc, metadata=meta, retrieval_method="metadata", retrieval_score=0.95, authoritative=True,
            ))

    # -- 4: keyword / full-text matching (Chroma's where_document $contains) --
    keywords = [w for w in query.split() if len(w) > 3][:5]
    for collection in collections:
        for keyword in keywords:
            try:
                hit = chroma.get_or_create(collection).get(
                    where_document={"$contains": keyword},
                    where=(scope_filter if collection == CORPORATE_EVIDENCE else None),
                    limit=5,
                )
            except ChromaUnavailable:
                raise RagUnavailable("ChromaDB is unavailable for full-text lookup") from None
            except Exception:
                continue  # collection empty / backend doesn't support the clause -- degrade quietly
            for rid, doc, meta in zip(hit.get("ids", []), hit.get("documents", []), hit.get("metadatas", [])):
                if collection == CORPORATE_EVIDENCE and not _belongs_to_scope(meta, case_id, ticket_id, asset_id):
                    continue
                _consider(RetrievalResult(
                    record_id=rid, collection=collection, source_type=meta.get("source_type", collection),
                    content=doc, metadata=meta, retrieval_method="full_text",
                    retrieval_score=0.6, authoritative=(collection == CORPORATE_EVIDENCE),
                ))

    # -- 5: vector similarity (never used alone; scored, threshold-filtered) --
    try:
        embeddable = embeddings.is_available()
    except Exception:
        embeddable = False
    if embeddable:
        try:
            query_vector = embeddings.embed([query])[0]
        except EmbeddingBackendUnavailable:
            query_vector = None
        if query_vector is not None:
            for collection in collections:
                try:
                    hit = chroma.query(
                        collection=collection, query_embedding=query_vector, n_results=config.vector_top_k,
                        where=(scope_filter if collection == CORPORATE_EVIDENCE else None),
                    )
                except ChromaUnavailable:
                    raise RagUnavailable("ChromaDB is unavailable for vector search") from None
                except Exception:
                    continue
                ids = (hit.get("ids") or [[]])[0]
                docs = (hit.get("documents") or [[]])[0]
                metas = (hit.get("metadatas") or [[]])[0]
                dists = (hit.get("distances") or [[]])[0]
                for rid, doc, meta, dist in zip(ids, docs, metas, dists):
                    score = max(0.0, 1.0 - dist)  # cosine distance -> similarity, clamped
                    if score < config.min_score:
                        continue
                    if collection == CORPORATE_EVIDENCE and not _belongs_to_scope(meta, case_id, ticket_id, asset_id):
                        continue
                    _consider(RetrievalResult(
                        record_id=rid, collection=collection, source_type=meta.get("source_type", collection),
                        content=doc, metadata=meta, retrieval_method="vector",
                        retrieval_score=score, authoritative=(collection == CORPORATE_EVIDENCE),
                    ))

    # -- authorization: revoked/deprecated MITRE, non-approved runbooks, and
    # classification mismatches are excluded BEFORE ranking/limiting, never
    # left to the caller or the LLM to filter after the fact (spec section 6).
    permitted = {
        rid: r for rid, r in results.items() if _is_permitted(r, allowed_classification=allowed_classification)
    }

    # -- 6/7: already deduplicated by _consider(); rerank now -----------------
    ranked = sorted(
        permitted.values(),
        key=lambda r: (_METHOD_PRIORITY[r.retrieval_method], r.retrieval_score),
        reverse=True,
    )
    limit = top_k or config.final_top_k
    final = ranked[:limit]
    trace.result_count = len(final)
    return final, trace
