"""Token-budget enforcement (spec section 2): the full prompt -- system
prompt + user request + JSON output schema (embedded in the system prompt
text) + retrieved evidence/reference context + the model's own generation
reservation + a safety margin -- must never exceed the configured
`--ctx-size` (8192 by default). Covers mcp_server/rag/token_budget.py,
mcp_server/rag/context_builder.py's max_tokens/authoritative-first behavior,
and mcp_server/generator_service.py's end-to-end trimming loop.
"""

import asyncio

import pytest

from mcp_server.generator_claims import GeneratedClaim
from mcp_server.generator_service import GeneratorClaimRequest, generate_claim
from mcp_server.llamacpp_config import LlamaCppConfig
from mcp_server.logging_utils import AuditLogger
from mcp_server.rag.chroma_client import ChromaCollections
from mcp_server.rag.config import CORPORATE_EVIDENCE, RagConfig
from mcp_server.rag.context_builder import approximate_token_count, build_rag_context
from mcp_server.rag.embeddings import get_embedding_backend
from mcp_server.rag.ingestion import ingest_evidence
from mcp_server.rag.schemas import RetrievalResult
from mcp_server.rag.token_budget import (
    SAFETY_MARGIN_TOKENS,
    TokenBudget,
    TokenBudgetExceeded,
    compute_budget,
)

pytestmark = pytest.mark.unit


def _fake_result(record_id, *, collection, score, content="x" * 400):
    return RetrievalResult(
        record_id=record_id, collection=collection, source_type=collection, content=content, metadata={},
        retrieval_method="vector", retrieval_score=score, authoritative=(collection == CORPORATE_EVIDENCE),
    )


# --- context_builder.build_rag_context ---------------------------------------

def test_normal_prompt_fits_within_a_generous_budget():
    results = [_fake_result("EVD-0001", collection=CORPORATE_EVIDENCE, score=1.0, content="short content")]
    config = RagConfig(max_context_tokens=5000)
    context, included = build_rag_context(results, config, max_tokens=5000)
    assert included == ["EVD-0001"]
    assert approximate_token_count(context) < 5000


def test_oversized_retrieval_is_reduced_to_fit_the_budget():
    results = [_fake_result(f"EVD-{i:04d}", collection=CORPORATE_EVIDENCE, score=1.0, content="x" * 2000) for i in range(20)]
    config = RagConfig(max_context_tokens=5000)
    context, included = build_rag_context(results, config, max_tokens=200)
    assert len(included) < len(results)
    assert approximate_token_count(context) <= 250  # 200 budget + small delimiter overhead


def test_authoritative_evidence_is_retained_before_reference_content_when_trimming():
    # Reference record appears FIRST in the input list (would normally be
    # processed first) but authoritative evidence must still win the budget.
    results = [
        _fake_result("CVE-2026-00001", collection="vulnerabilities", score=1.0, content="x" * 100),
        _fake_result("EVD-0001", collection=CORPORATE_EVIDENCE, score=0.5, content="x" * 100),
    ]
    config = RagConfig(max_context_tokens=5000)
    # Budget only large enough for ONE record's block (each renders to
    # roughly 60-70 tokens once its header + 100-char content is counted).
    _, included = build_rag_context(results, config, max_tokens=80)
    assert included == ["EVD-0001"]


def test_max_tokens_override_is_capped_by_the_smaller_of_the_two_ceilings():
    results = [_fake_result("EVD-0001", collection=CORPORATE_EVIDENCE, score=1.0, content="x" * 2000)]
    config = RagConfig(max_context_tokens=50)  # RAG ceiling smaller than max_tokens override
    _, included = build_rag_context(results, config, max_tokens=5000)
    assert included == []  # excluded: the smaller RAG_MAX_CONTEXT_TOKENS ceiling still applies


# --- token_budget.compute_budget / count_tokens ------------------------------

async def _fake_tokenize_none(config, text):
    return None  # forces the approximation fallback, deterministic and instant


def test_compute_budget_falls_back_to_approximation_when_tokenizer_unavailable():
    llamacpp_config = LlamaCppConfig(context_size=8192, max_output_tokens=1200)
    budget = asyncio.run(compute_budget(
        system_prompt="short system prompt", user_question_block="short question",
        llamacpp_config=llamacpp_config, tokenize_fn=_fake_tokenize_none,
    ))
    assert budget.exact is False
    assert budget.context_size == 8192
    assert budget.reserved_output_tokens == 1200
    assert budget.safety_margin_tokens == SAFETY_MARGIN_TOKENS
    assert budget.available_for_rag_context > 0


def test_compute_budget_uses_exact_tokenizer_when_available():
    async def _fake_tokenize(config, text):
        return [0] * 42  # fixed, deterministic "exact" count regardless of text

    llamacpp_config = LlamaCppConfig(context_size=8192, max_output_tokens=1200)
    budget = asyncio.run(compute_budget(
        system_prompt="anything", user_question_block="anything else",
        llamacpp_config=llamacpp_config, tokenize_fn=_fake_tokenize,
    ))
    assert budget.exact is True
    assert budget.fixed_overhead_tokens == 42


def test_output_token_reservation_is_preserved_in_the_available_budget():
    budget = TokenBudget(
        context_size=8192, reserved_output_tokens=1200, safety_margin_tokens=128,
        fixed_overhead_tokens=500, exact=True,
    )
    assert budget.available_for_rag_context == 8192 - 1200 - 128 - 500
    # The reservation is never eaten by RAG content: available_for_rag_context
    # excludes it entirely, by construction (a subtraction, not a shared pool).


def test_compute_budget_raises_when_fixed_overhead_alone_exceeds_the_context():
    llamacpp_config = LlamaCppConfig(context_size=100, max_output_tokens=50)  # tiny, unrealistic context on purpose

    async def _fake_tokenize(config, text):
        return [0] * 200  # bigger than the entire context window

    with pytest.raises(TokenBudgetExceeded):
        asyncio.run(compute_budget(
            system_prompt="x", user_question_block="y", llamacpp_config=llamacpp_config, tokenize_fn=_fake_tokenize,
        ))


# --- end-to-end: generator_service.generate_claim never exceeds context -----

async def _no_real_tokenizer(config, text, *, timeout_seconds=5.0):
    return None


def test_generate_claim_never_exceeds_the_configured_context_size(tmp_path, monkeypatch):
    monkeypatch.setattr("mcp_server.llm_roles.llamacpp_client.tokenize", _no_real_tokenizer)

    rag_config = RagConfig(chroma_persist_dir=str(tmp_path / "chroma"), min_score=0.0, max_context_tokens=5000)
    chroma = ChromaCollections(rag_config)
    embeddings = get_embedding_backend(rag_config, force_fake=True)
    audit = AuditLogger(journal_path=str(tmp_path / "journal.jsonl"))

    # A large number of big evidence records -- an oversized retrieval that
    # must be reduced, not sent whole into an 8192-token context.
    records = [
        {
            "id": f"EVD-{i:04d}", "case_id": "VUL-018", "ticket_id": "SEC-104", "asset_id": "SRV-ERP-01",
            "cve_ids": [], "source": "ITSM-FICTIF", "observed_at": "2026-07-22T09:00:00Z",
            "evidence_type": "vulnerability_scan", "classification": "CONFIDENTIAL",
            "content": f"Record {i}: " + ("Detailed scan finding text repeated for bulk. " * 80),
        }
        for i in range(30)
    ]
    ingest_evidence(records, chroma=chroma, embeddings=embeddings, config=rag_config, audit=audit,
                     session_id="SES-BUDGET", correlation_id="COR-BUDGET")

    llamacpp_config = LlamaCppConfig(
        base_url="http://mock-llama:8080/v1", context_size=8192, max_output_tokens=1200,
    )

    valid_response = (
        '{"status": "INSUFFICIENT_EVIDENCE", "claim": null, "evidence_ids": [], "reference_ids": [], '
        '"reasoning_summary": "Too much unrelated content to draw a conclusion.", '
        '"confidence": 0.1, "limitations": ["bulk_test_fixture"]}'
    )
    captured_prompts = []

    async def _fake_chat_completion(*, config, system_prompt, user_prompt):
        captured_prompts.append((system_prompt, user_prompt))
        return valid_response

    monkeypatch.setattr("mcp_server.generator_service.chat_completion", _fake_chat_completion)

    req = GeneratorClaimRequest(request_id="REQ-BUDGET", question="Summarize the scan findings.",
                                 case_id="VUL-018", ticket_id="SEC-104", asset_id="SRV-ERP-01")
    claim = asyncio.run(generate_claim(
        req, chroma=chroma, embeddings=embeddings, rag_config=rag_config, llamacpp_config=llamacpp_config,
    ))
    assert isinstance(claim, GeneratedClaim)

    system_prompt, user_prompt = captured_prompts[0]
    total_tokens = approximate_token_count(f"{system_prompt}\n{user_prompt}")
    hard_limit = llamacpp_config.context_size - llamacpp_config.max_output_tokens - SAFETY_MARGIN_TOKENS
    assert total_tokens <= hard_limit
