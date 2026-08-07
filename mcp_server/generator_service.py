"""Orchestrates the new llama.cpp/Foundation-Sec Generator API end to end:

  query normalization -> identifier extraction (implicit in retrieval.retrieve)
  -> hybrid RAG retrieval -> token-budgeted context construction -> prompt
  construction -> llama.cpp call -> Pydantic + citation validation, with one
  deterministic repair attempt on failure -> GeneratedClaim.

This never decides the final CISO status (spec section 1): it returns a
GeneratedClaim with status CLAIM_GENERATED or INSUFFICIENT_EVIDENCE only. The
existing Verifier/deterministic Validator (mcp_server/llm_roles/llama_verifier.py,
mcp_server/policy.py) are untouched and out of scope here, per the request --
mcp_server.generator_claims.to_mcp_claim() bridges a CLAIM_GENERATED result into
their existing input contract when a caller wants to feed it into that pipeline.
"""

import json
import logging
from dataclasses import dataclass

from mcp_server.generator_claims import (
    GeneratedClaim,
    GeneratorOutputError,
    enforce_no_repair_drift,
    enforce_source_authority,
    parse_generated_claim,
)
from mcp_server.generator_prompts import SYSTEM_PROMPT, build_repair_prompt, build_user_prompt
from mcp_server.llamacpp_config import LlamaCppConfig
from mcp_server.llm_roles.llamacpp_client import chat_completion
from mcp_server.rag import token_budget
from mcp_server.rag.chroma_client import ChromaCollections
from mcp_server.rag.config import CORPORATE_EVIDENCE, RagConfig
from mcp_server.rag.context_builder import build_rag_context
from mcp_server.rag.embeddings import EmbeddingBackend
from mcp_server.rag.retrieval import retrieve
from mcp_server.rag.sanitization import scan_for_injection

_logger = logging.getLogger("mcp_server.generator_service")

# Prompt trimming is bounded and deterministic: each retry only shrinks the
# available RAG budget, so this always terminates within a fixed number of
# iterations (spec: "no request exceeds the configured 8,192-token context").
_MAX_TRIM_ATTEMPTS = 4


class GeneratorRequestError(ValueError):
    """Raised for a malformed/unauthorized request (e.g. an invalid
    allowed_classification) before any model call is attempted."""


@dataclass
class GeneratorClaimRequest:
    request_id: str
    question: str
    case_id: str | None = None
    ticket_id: str | None = None
    asset_id: str | None = None
    allowed_classification: str | None = None


async def generate_claim(
    req: GeneratorClaimRequest, *, chroma: ChromaCollections, embeddings: EmbeddingBackend,
    rag_config: RagConfig, llamacpp_config: LlamaCppConfig,
) -> GeneratedClaim:
    question = (req.question or "").strip()
    if not question:
        raise GeneratorRequestError("question must not be empty")

    # Retrieval happens BEFORE generation, always (spec section 1/13) -- the
    # model is never given a chance to decide what to retrieve or from where.
    # allowed_classification is enforced inside retrieve() itself (never left
    # to a post-hoc filter the LLM or caller could bypass).
    results, trace = retrieve(
        query=question, chroma=chroma, embeddings=embeddings, config=rag_config,
        case_id=req.case_id, ticket_id=req.ticket_id, asset_id=req.asset_id,
        allowed_classification=req.allowed_classification,
    )

    # Token budget (spec section 2): the full prompt -- system prompt (which
    # embeds the required JSON schema) + user question + retrieved context +
    # the model's own output reservation + a safety margin -- must never
    # exceed llamacpp_config.context_size (8192 by default). Computed BEFORE
    # any RAG content is added, using only the fixed (non-RAG) overhead.
    user_question_block = build_user_prompt(question=question, rag_context_text="")
    budget = await token_budget.compute_budget(
        system_prompt=SYSTEM_PROMPT, user_question_block=user_question_block, llamacpp_config=llamacpp_config,
    )

    available = budget.available_for_rag_context
    context_text, included_ids = build_rag_context(results, rag_config, max_tokens=available)
    user_prompt = build_user_prompt(question=question, rag_context_text=context_text)

    # Defensive final check against the actual assembled prompt: the
    # allocation above uses context_builder's conservative per-record
    # character-based approximation (never the real tokenizer per record, to
    # avoid one HTTP round-trip per retrieved chunk) -- this closes the gap
    # for the rare case where that approximation still undercounts, instead
    # of trusting it blindly. Bounded: each iteration only shrinks the
    # available budget, so this always terminates.
    hard_limit = llamacpp_config.context_size - llamacpp_config.max_output_tokens - token_budget.SAFETY_MARGIN_TOKENS
    for _ in range(_MAX_TRIM_ATTEMPTS):
        total_tokens, _exact = await token_budget.count_tokens(
            f"{SYSTEM_PROMPT}\n{user_prompt}", llamacpp_config=llamacpp_config,
        )
        if total_tokens <= hard_limit:
            break
        overshoot = total_tokens - hard_limit
        available = max(0, available - overshoot - 50)
        context_text, included_ids = build_rag_context(results, rag_config, max_tokens=available)
        user_prompt = build_user_prompt(question=question, rag_context_text=context_text)
    else:
        raise GeneratorRequestError(
            f"could not fit the prompt within the configured {llamacpp_config.context_size}-token context "
            "even after repeated trimming; the fixed overhead and output reservation alone may already be too large"
        )

    included = {r.record_id: r for r in results if r.record_id in included_ids}
    evidence_ids = {rid for rid, r in included.items() if r.collection == CORPORATE_EVIDENCE}
    reference_ids = {rid for rid, r in included.items() if r.collection != CORPORATE_EVIDENCE}

    # Injection indicators in the retrieved content are logged (spec section 15)
    # but not silently dropped here -- sanitization already capped/flagged
    # individual chunks inside context_builder/sanitization; this is a second,
    # coarse pass over the assembled context purely for audit visibility. Never
    # logs the context/prompt content itself, only which pattern(s) matched.
    injection_scan = scan_for_injection(context_text)
    if injection_scan.suspicious:
        _logger.warning(
            "prompt-injection indicator(s) detected in retrieved RAG context: patterns=%s",
            injection_scan.matched_patterns,
        )

    raw_content = await chat_completion(
        config=llamacpp_config, system_prompt=SYSTEM_PROMPT, user_prompt=user_prompt,
    )

    model_name = llamacpp_config.model_name

    try:
        parsed = _parse_json_or_raise(raw_content)
        claim = parse_generated_claim(
            parsed, request_id=req.request_id, retrieved_evidence_ids=evidence_ids,
            retrieved_reference_ids=reference_ids, model_name=model_name, retrieval_trace_id=trace.trace_id,
        )
        enforce_source_authority(
            claim, included_results=list(included.values()),
            case_id=req.case_id, ticket_id=req.ticket_id, asset_id=req.asset_id,
        )
        return claim
    except GeneratorOutputError as first_error:
        # One deterministic repair attempt (spec section 14) -- same context,
        # a fresh instruction naming exactly what was wrong. If this also
        # fails, fail closed with a controlled error; never silently accept
        # malformed output. original_parsed captures the pre-repair JSON (if
        # any) so enforce_no_repair_drift() can detect the repair silently
        # adding citations, raising confidence, or flipping the status.
        original_parsed = _try_parse_json(raw_content)
        repair_prompt = build_repair_prompt(original_output=raw_content, error_detail=str(first_error))
        repaired_content = await chat_completion(
            config=llamacpp_config, system_prompt=SYSTEM_PROMPT, user_prompt=repair_prompt,
        )
        try:
            parsed = _parse_json_or_raise(repaired_content)
            claim = parse_generated_claim(
                parsed, request_id=req.request_id, retrieved_evidence_ids=evidence_ids,
                retrieved_reference_ids=reference_ids, model_name=model_name, retrieval_trace_id=trace.trace_id,
            )
            enforce_no_repair_drift(original_parsed=original_parsed, repaired=claim)
            enforce_source_authority(
                claim, included_results=list(included.values()),
                case_id=req.case_id, ticket_id=req.ticket_id, asset_id=req.asset_id,
            )
            return claim
        except GeneratorOutputError as second_error:
            raise GeneratorOutputError(
                f"generation failed validation twice (repair did not fix it): first={first_error}; "
                f"after repair={second_error}"
            ) from second_error


def _parse_json_or_raise(text: str) -> dict:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise GeneratorOutputError(f"model did not return valid JSON: {exc}. Raw (truncated): {text[:300]}") from exc


def _try_parse_json(text: str) -> dict | None:
    """Never raises. Returns None when text is not valid JSON or not an
    object -- used only to capture a best-effort snapshot of the pre-repair
    output for enforce_no_repair_drift(), not to drive control flow."""
    try:
        result = json.loads(text)
    except json.JSONDecodeError:
        return None
    return result if isinstance(result, dict) else None
