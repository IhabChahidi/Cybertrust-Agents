"""Empirical test (NOT a production change): does lowering the Generator's
temperature from 0.1 (current default) to 0.0 actually reduce output
variance? Calls generate_claim() 3 times at each temperature for the same
scenario (C: "public_cve_information_only", the scenario that showed the
most run-to-run variance this session -- INSUFFICIENT_EVIDENCE, a citation
hallucination, or a successful claim, on different runs with identical input)
and prints every result side by side. No config file is touched -- this
overrides LlamaCppConfig.temperature only for this script's own calls.

Run inside the generator-api container:
    docker exec <container> python /app/test_temperature_variance.py
"""

import asyncio
import json

from mcp_server.generator_service import GeneratorClaimRequest, generate_claim
from mcp_server.generator_claims import GeneratorOutputError
from mcp_server.llamacpp_config import LlamaCppConfig
from mcp_server.rag.chroma_client import ChromaCollections
from mcp_server.rag.config import RagConfig
from mcp_server.rag.embeddings import get_embedding_backend

QUESTION = "What does CVE-2027-99999 affect, according to MITRE ATT&CK T1190? Is it remediated anywhere?"
CTX = {"case_id": "VUL-999"}


async def run_once(temperature, run_num, chroma, embeddings, rag_config):
    llamacpp_config = LlamaCppConfig(temperature=temperature)
    req = GeneratorClaimRequest(request_id=f"TEMP-{temperature}-{run_num}", question=QUESTION, **CTX)
    try:
        claim = await generate_claim(req, chroma=chroma, embeddings=embeddings, rag_config=rag_config, llamacpp_config=llamacpp_config)
        return {"status": claim.status, "claim": claim.claim, "evidence_ids": claim.evidence_ids, "reference_ids": claim.reference_ids}
    except GeneratorOutputError as exc:
        return {"status": "ERROR", "detail": str(exc)[:200]}


async def main():
    rag_config = RagConfig()
    chroma = ChromaCollections(rag_config)
    embeddings = get_embedding_backend(rag_config)

    for temperature in (0.1, 0.0):
        print(f"\n{'='*15} temperature={temperature} {'='*15}")
        for i in range(1, 4):
            result = await run_once(temperature, i, chroma, embeddings, rag_config)
            print(f"  run {i}: {json.dumps(result, ensure_ascii=False)}")


if __name__ == "__main__":
    asyncio.run(main())
