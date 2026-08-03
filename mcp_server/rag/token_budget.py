"""Deterministic token-budget accounting for the FULL llama.cpp prompt --
system prompt + user request + JSON output schema (embedded in the system
prompt text) + retrieved evidence/reference context + the model's own
generation reservation + a safety margin -- enforced against
LlamaCppConfig.context_size (spec: `--ctx-size 8192`).

Exact token counts are obtained from llama.cpp's `/tokenize` endpoint
(mcp_server.llm_roles.llamacpp_client.tokenize) when reachable; otherwise this
falls back to the conservative ~4-chars/token approximation already used by
mcp_server.rag.context_builder. Every TokenBudget records whether the count it
used was exact or approximated (`.exact`), so callers/logs never silently
present an approximation as a measured fact.

This module does NOT decide which retrieved records to keep -- that stays in
context_builder.build_rag_context(), which now accepts an explicit max_tokens
override (computed here) instead of always using RagConfig.max_context_tokens
alone. Two independent caps are enforced together: the RAG-specific ceiling
(RAG_MAX_CONTEXT_TOKENS) and whatever headroom is actually left in the model's
context window after the fixed overhead and the output reservation.
"""

from dataclasses import dataclass
from typing import Awaitable, Callable

from mcp_server.rag.context_builder import approximate_token_count

# Headroom for chat-template overhead that the raw message text does not
# capture: role markers, BOS/EOS tokens, and per-turn special tokens added by
# llama.cpp's chat template. Deliberately generous and documented rather than
# tuned to a specific template, since the exact template varies by model/build.
SAFETY_MARGIN_TOKENS = 128


class TokenBudgetExceeded(RuntimeError):
    """Raised when even an empty RAG context would not fit the configured
    context window -- i.e. the fixed overhead (system prompt + user question)
    plus the output reservation and safety margin alone exceed context_size.
    This must fail closed (spec: "no request exceeds the configured 8,192
    token context"), never silently send an oversized prompt."""


@dataclass(frozen=True)
class TokenBudget:
    context_size: int
    reserved_output_tokens: int
    safety_margin_tokens: int
    fixed_overhead_tokens: int
    exact: bool

    @property
    def available_for_rag_context(self) -> int:
        return self.context_size - self.reserved_output_tokens - self.safety_margin_tokens - self.fixed_overhead_tokens

    def validate(self) -> None:
        if self.available_for_rag_context < 0:
            raise TokenBudgetExceeded(
                f"fixed overhead ({self.fixed_overhead_tokens} tokens) + output reservation "
                f"({self.reserved_output_tokens}) + safety margin ({self.safety_margin_tokens}) already "
                f"exceeds context_size ({self.context_size}); no room remains for any RAG context"
            )


async def count_tokens(
    text: str, *, llamacpp_config, tokenize_fn: Callable[..., Awaitable[list[int] | None]] | None = None,
) -> tuple[int, bool]:
    """Returns (count, exact). Tries the real tokenizer first; falls back to
    the conservative approximation on any failure (unreachable server, tests
    with no live llama.cpp instance). `tokenize_fn` is injectable so tests can
    supply a deterministic fake without a network dependency; production
    callers omit it and get the real mcp_server.llm_roles.llamacpp_client.tokenize.
    """
    resolved_tokenize_fn = tokenize_fn
    if resolved_tokenize_fn is None:
        from mcp_server.llm_roles.llamacpp_client import tokenize as resolved_tokenize_fn
    assert resolved_tokenize_fn is not None  # narrows for the type checker; always true after the branch above
    tokens = await resolved_tokenize_fn(llamacpp_config, text)
    if tokens is not None:
        return len(tokens), True
    return approximate_token_count(text), False


async def compute_budget(
    *, system_prompt: str, user_question_block: str, llamacpp_config,
    tokenize_fn: Callable[..., Awaitable[list[int] | None]] | None = None,
) -> TokenBudget:
    """Computes the token budget available for RAG context, given the fixed
    (non-RAG) parts of the prompt: the system prompt (which embeds the
    required JSON output schema, see mcp_server/generator_prompts.py) and the
    user question wrapper (without the RAG context text, which is what we are
    solving for). Raises TokenBudgetExceeded if there is no room left even
    before any evidence is added.
    """
    fixed_text = f"{system_prompt}\n{user_question_block}"
    fixed_overhead_tokens, exact = await count_tokens(fixed_text, llamacpp_config=llamacpp_config, tokenize_fn=tokenize_fn)
    budget = TokenBudget(
        context_size=llamacpp_config.context_size,
        reserved_output_tokens=llamacpp_config.max_output_tokens,
        safety_margin_tokens=SAFETY_MARGIN_TOKENS,
        fixed_overhead_tokens=fixed_overhead_tokens,
        exact=exact,
    )
    budget.validate()
    return budget
