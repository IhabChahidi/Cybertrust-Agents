"""Glue between the existing Generator (mcp_server/llm_roles/llama_generator.py)
and the RAG layer (spec section 8). Kept as its own module so
llama_generator.py's diff stays small and this piece is independently testable
with a fake Chroma/embedding backend.

augment_with_rag() never raises: any failure (ChromaDB down, embedding model
missing, bad query) is caught and reported as `available=False` with a reason,
so the Generator can proceed exactly as it did before RAG existed. This is the
backward-compatibility guarantee: RAG can only ADD context, never break a
request that used to work.
"""

from dataclasses import dataclass, field

from mcp_server.rag.chroma_client import ChromaCollections, ChromaUnavailable
from mcp_server.rag.config import CORPORATE_EVIDENCE, RagConfig
from mcp_server.rag.context_builder import build_rag_context
from mcp_server.rag.embeddings import EmbeddingBackend, EmbeddingBackendUnavailable, get_embedding_backend
from mcp_server.rag.identifiers import extract_identifiers
from mcp_server.rag.retrieval import RagUnavailable, retrieve


@dataclass
class RagAugmentation:
    available: bool
    context_text: str = ""
    reference_ids: list[str] = field(default_factory=list)
    authoritative_ids: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    trace_id: str | None = None
    unavailable_reason: str | None = None


def augment_with_rag(
    *, request_statement: str, rag_config: RagConfig | None = None,
    chroma: ChromaCollections | None = None, embeddings: EmbeddingBackend | None = None,
) -> RagAugmentation:
    rag_config = rag_config or RagConfig()
    chroma = chroma or ChromaCollections(rag_config)
    embeddings = embeddings or get_embedding_backend(rag_config)

    ids = extract_identifiers(request_statement or "")
    case_id = ids["case_id"][0] if ids.get("case_id") else None
    ticket_id = ids["ticket_id"][0] if ids.get("ticket_id") else None
    asset_id = ids["asset_id"][0] if ids.get("asset_id") else None

    try:
        results, trace = retrieve(
            query=request_statement or "", chroma=chroma, embeddings=embeddings, config=rag_config,
            case_id=case_id, ticket_id=ticket_id, asset_id=asset_id,
        )
    except (RagUnavailable, ChromaUnavailable, EmbeddingBackendUnavailable) as exc:
        return RagAugmentation(available=False, unavailable_reason=str(exc))
    except Exception as exc:  # defensive: RAG must never take the pipeline down
        return RagAugmentation(available=False, unavailable_reason=f"unexpected RAG error: {exc}")

    context_text, included_ids = build_rag_context(results, rag_config)
    included = {r.record_id: r for r in results if r.record_id in included_ids}
    authoritative_ids = sorted(rid for rid, r in included.items() if r.collection == CORPORATE_EVIDENCE)
    reference_ids = sorted(rid for rid, r in included.items() if r.collection != CORPORATE_EVIDENCE)

    limitations: list[str] = []
    if not authoritative_ids:
        # Spec: "when the retrieved evidence is ... insufficient ... the
        # Generator must return INSUFFICIENT_EVIDENCE." Architecturally in this
        # pipeline, status/routing decisions belong to the Verifier and the
        # deterministic policy engine, not the Generator (see the review that
        # established this separation) -- so rather than having the Generator
        # emit a competing status value, the absence of authoritative RAG
        # support is surfaced here as a `limitations` entry the Claim carries
        # forward. The actual routing still runs through the existing
        # Verifier -> diagnostics -> policy pipeline, unchanged.
        limitations.append("RAG_NO_AUTHORITATIVE_EVIDENCE")

    return RagAugmentation(
        available=True, context_text=context_text, reference_ids=reference_ids,
        authoritative_ids=authoritative_ids, limitations=limitations, trace_id=trace.trace_id,
    )
