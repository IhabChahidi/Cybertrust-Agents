"""One-off diagnostic: reproduce generator_service.generate_claim()'s exact
retrieval + context-assembly steps for Scenario I, WITHOUT calling the LLM,
to see precisely what context Llama 3.1 actually received. Answers: did
EVD-0009 make it into the final prompt, or was it dropped before the model
ever saw it?

Run: PYTHONPATH=. python scripts/debug_scenario_i_context.py
"""

import asyncio

from mcp_server.generator_prompts import SYSTEM_PROMPT, build_user_prompt
from mcp_server.llamacpp_config import LlamaCppConfig
from mcp_server.rag import token_budget
from mcp_server.rag.chroma_client import ChromaCollections
from mcp_server.rag.config import CORPORATE_EVIDENCE, RagConfig
from mcp_server.rag.context_builder import build_rag_context
from mcp_server.rag.embeddings import get_embedding_backend
from mcp_server.rag.retrieval import retrieve

QUESTION = "What did the scan of app05.fictif.example.com (10.10.0.9) find?"
CASE_ID = "VUL-070"


async def main():
    rag_config = RagConfig()  # default persist dir -- same store the live API uses
    chroma = ChromaCollections(rag_config)
    embeddings = get_embedding_backend(rag_config)
    llamacpp_config = LlamaCppConfig()

    results, trace = retrieve(
        query=QUESTION, chroma=chroma, embeddings=embeddings, config=rag_config,
        case_id=CASE_ID, ticket_id=None, asset_id=None, allowed_classification=None,
    )
    print("=== retrieve() results ===")
    for r in results:
        print(f"  {r.record_id} | collection={r.collection} | method={r.retrieval_method} | "
              f"score={r.retrieval_score:.2f} | authoritative={r.authoritative}")

    user_question_block = build_user_prompt(question=QUESTION, rag_context_text="")
    budget = await token_budget.compute_budget(
        system_prompt=SYSTEM_PROMPT, user_question_block=user_question_block, llamacpp_config=llamacpp_config,
    )
    print(f"\n=== token budget ===\navailable_for_rag_context = {budget.available_for_rag_context}")

    context_text, included_ids = build_rag_context(results, rag_config, max_tokens=budget.available_for_rag_context)
    print(f"\n=== included_ids after budget ===\n{included_ids}")

    evidence_ids = {r.record_id for r in results if r.record_id in included_ids and r.collection == CORPORATE_EVIDENCE}
    print(f"\n=== corporate evidence_ids that would be passed to enforce_source_authority ===\n{evidence_ids}")

    user_prompt = build_user_prompt(question=QUESTION, rag_context_text=context_text)
    print("\n=== FULL user_prompt actually sent to the model ===")
    print(user_prompt)

    print(f"\n=== approx token count of full prompt ===")
    total_tokens, _ = await token_budget.count_tokens(f"{SYSTEM_PROMPT}\n{user_prompt}", llamacpp_config=llamacpp_config)
    print(f"total_tokens={total_tokens}, context_size={llamacpp_config.context_size}, "
          f"max_output_tokens={llamacpp_config.max_output_tokens}")


if __name__ == "__main__":
    asyncio.run(main())
