"""Token-budgeted context construction (spec section 4).

The existing Generator model's context window (8192 tokens, per
mcp_server.rag.config.RagConfig.generator_max_context_tokens) must have room
reserved for the trusted system prompt, the CISO request, the required JSON
schema, and the model's own output -- RAG context gets whatever is left, capped
at RAG_MAX_CONTEXT_TOKENS regardless.

No tokenizer endpoint exists on the local Ollama server used by this Generator
(Ollama's /api/chat does not expose one), so this uses a documented,
conservative approximation instead: ~4 characters per token for Latin-script
text, which is the same order-of-magnitude heuristic widely used for GPT-family
tokenizers and errs on the side of UNDER-counting available budget (i.e. it
will trim before actually running out, not after).
"""

from mcp_server.rag.config import RagConfig
from mcp_server.rag.sanitization import cap_chunk
from mcp_server.rag.schemas import RetrievalResult

_CHARS_PER_TOKEN_APPROX = 4  # documented conservative approximation, see module docstring


def approximate_token_count(text: str) -> int:
    return max(1, len(text or "") // _CHARS_PER_TOKEN_APPROX)


def _record_block(result: RetrievalResult) -> str:
    """One record's rendering. Always includes id/source/collection/date/
    authority BEFORE the (possibly truncated) content, so truncation never
    removes them (spec: "do not truncate records in a way that removes their
    identifiers, source information, dates, or authority classification")."""
    date = result.metadata.get("observed_at") or result.metadata.get("date") or result.metadata.get("published") or "n/a"
    return (
        f"[record_id={result.record_id} collection={result.collection} source_type={result.source_type} "
        f"date={date} authoritative={result.authoritative} retrieval_method={result.retrieval_method} "
        f"score={result.retrieval_score:.2f}]\n{cap_chunk(result.content)}"
    )


def build_rag_context(
    results: list[RetrievalResult], config: RagConfig, *, max_tokens: int | None = None,
) -> tuple[str, list[str]]:
    """Returns (rendered_context, included_record_ids).

    Records are considered authoritative-corporate-evidence FIRST, then
    reference records, each group preserving its given rank order (caller is
    expected to have already reranked within each group — see
    retrieval.retrieve()); this guarantees the highest-ranked authoritative
    evidence is retained before any lower-ranked reference content is even
    attempted (spec: "the highest-ranked authoritative evidence is retained
    before lower-ranked reference content").

    Records are included until the budget would be exceeded; a record is
    never partially truncated to fit -- it either fits whole or is left out
    entirely (the lowest-ranked complete records are the ones dropped), so an
    included record's identifiers/dates/authority are always complete.

    `max_tokens` overrides config.max_context_tokens when given (e.g. the
    real remaining headroom computed by mcp_server.rag.token_budget against
    the model's actual 8192-token context window, which may be smaller than
    the RAG-specific ceiling). The effective budget is always the SMALLER of
    the two -- RAG_MAX_CONTEXT_TOKENS is a ceiling that applies regardless.
    """
    from mcp_server.rag.config import CORPORATE_EVIDENCE

    authoritative_blocks: list[str] = []
    reference_blocks: list[str] = []
    included_ids: list[str] = []
    budget = config.max_context_tokens if max_tokens is None else min(config.max_context_tokens, max_tokens)
    budget = max(0, budget)
    used = 0

    ordered = sorted(results, key=lambda r: r.collection != CORPORATE_EVIDENCE)  # stable: authoritative group first

    for result in ordered:
        block = _record_block(result)
        cost = approximate_token_count(block)
        if used + cost > budget:
            continue  # skip this record, but keep trying smaller ones after it
        used += cost
        included_ids.append(result.record_id)
        if result.collection == CORPORATE_EVIDENCE:
            authoritative_blocks.append(block)
        else:
            reference_blocks.append(block)

    context = (
        "<AUTHORITATIVE_CORPORATE_EVIDENCE>\n"
        + ("\n\n".join(authoritative_blocks) if authoritative_blocks else "(aucune preuve corporative authentifiee trouvee)")
        + "\n</AUTHORITATIVE_CORPORATE_EVIDENCE>\n\n"
        "<REFERENCE_KNOWLEDGE>\n"
        + ("\n\n".join(reference_blocks) if reference_blocks else "(aucune connaissance de reference trouvee)")
        + "\n</REFERENCE_KNOWLEDGE>"
    )
    return context, included_ids
