"""Verification (not a fix): are ML2/ML3's INSUFFICIENT_EVIDENCE outcomes
reproducible, or was the single run each got today just non-determinism?
Calls generate_claim() 3 times for each question, same evidence, same
temperature as production (0.1).

Run inside the generator-api container:
    docker exec <container> python /app/verify_ml2_ml3_reproducibility.py
"""

import asyncio
import json

from mcp_server.generator_claims import GeneratorOutputError
from mcp_server.generator_service import GeneratorClaimRequest, generate_claim
from mcp_server.llamacpp_config import LlamaCppConfig
from mcp_server.rag.chroma_client import ChromaCollections
from mcp_server.rag.config import RagConfig
from mcp_server.rag.embeddings import get_embedding_backend

SCENARIOS = [
    ("ML2", "Le ticket SEC-104 (dossier VUL-018) est-il remedie sur SRV-ERP-01 ?",
     {"case_id": "VUL-018", "ticket_id": "SEC-104", "asset_id": "SRV-ERP-01"}),
    ("ML3", "Is ticket SEC-500 (case VUL-080) remediated on SRV-FR-01?",
     {"case_id": "VUL-080", "ticket_id": "SEC-500", "asset_id": "SRV-FR-01"}),
]


async def run_once(sid, question, ctx, run_num, chroma, embeddings, rag_config, llamacpp_config):
    req = GeneratorClaimRequest(request_id=f"{sid}-repro-{run_num}", question=question, **ctx)
    try:
        claim = await generate_claim(req, chroma=chroma, embeddings=embeddings, rag_config=rag_config, llamacpp_config=llamacpp_config)
        return {"status": claim.status, "claim": claim.claim, "evidence_ids": claim.evidence_ids}
    except GeneratorOutputError as exc:
        return {"status": "ERROR", "detail": str(exc)[:200]}


async def main():
    rag_config = RagConfig()
    chroma = ChromaCollections(rag_config)
    embeddings = get_embedding_backend(rag_config)
    llamacpp_config = LlamaCppConfig()  # production default: temperature=0.1

    for sid, question, ctx in SCENARIOS:
        print(f"\n{'='*15} {sid} {'='*15}")
        for i in range(1, 4):
            result = await run_once(sid, question, ctx, i, chroma, embeddings, rag_config, llamacpp_config)
            print(f"  run {i}: {json.dumps(result, ensure_ascii=False)}")


if __name__ == "__main__":
    asyncio.run(main())
