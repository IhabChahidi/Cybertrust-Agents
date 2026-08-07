"""Bridges the new llama.cpp/Foundation-Sec RAG Generator
(mcp_server/generator_service.py) into the existing synchronous
`Generator` interface (mcp_server/llm_roles/base.py) the MCP orchestrator
already calls -- so it is selectable at the exact same call site as
MockGenerator/LlamaGenerator/RealGenerator (mcp_server/llm_roles/factory.py),
gated behind MCPConfig.generator_backend == "foundation_sec_rag" (spec:
"Add a clean adapter... Add an environment-controlled feature flag").

Behavioral difference from the other Generators, by design, not a bug: this
backend performs its OWN ChromaDB retrieval from `request_statement` as a
free-text query, rather than being handed a pre-selected `evidence: list[dict]`
by the orchestrator's catalogue lookup. The `evidence` parameter is accepted
(interface compatibility) but not the source of truth for this backend --
retrieval scope (case_id/ticket_id/asset_id/allowed_classification) is not
threaded through the existing Generator.generate() signature at all yet,
so this bridge issues an UNSCOPED query. This is a known, documented
limitation of the bridge, not of the underlying Foundation-Sec pipeline
(which fully supports scoping via GeneratorClaimRequest when called through
its own API, see web/generator_api.py).

No automatic fallback to another backend ever happens here: any failure
(retrieval unavailable, model output rejected twice, timeout) is raised
explicitly, exactly once, for the orchestrator's existing retry/fail-closed
handling (_invoke_role in mcp_server/orchestrator.py) to deal with -- never
silently retried against a different Generator implementation.
"""

import asyncio
import uuid

from mcp_server.config import MCPConfig
from mcp_server.errors import EventCode, MCPTechnicalFailure
from mcp_server.generator_claims import GeneratorOutputError, to_mcp_claim
from mcp_server.generator_service import GeneratorClaimRequest, GeneratorRequestError, generate_claim
from mcp_server.llamacpp_config import DEFAULT_LLAMACPP_CONFIG
from mcp_server.llm_roles.base import Generator
from mcp_server.logging_utils import AuditLogger
from mcp_server.rag.chroma_client import ChromaCollections, ChromaUnavailable
from mcp_server.rag.config import DEFAULT_RAG_CONFIG
from mcp_server.rag.embeddings import EmbeddingBackendUnavailable, get_embedding_backend
from mcp_server.rag.retrieval import RagUnavailable


class FoundationSecRagGenerator(Generator):
    """Selected instead of MockGenerator/LlamaGenerator/RealGenerator when
    MCPConfig.generator_backend == "foundation_sec_rag" (see
    mcp_server/llm_roles/factory.py::build_generator). Constructs its own
    ChromaDB/embedding-backend handles lazily -- these are only ever touched
    when this backend is actually selected, so the default "ollama" backend
    pays zero cost for their existence.
    """

    def __init__(self, config: MCPConfig):
        self.config = config
        self._rag_config = DEFAULT_RAG_CONFIG
        self._llamacpp_config = DEFAULT_LLAMACPP_CONFIG
        self._chroma = ChromaCollections(self._rag_config)
        self._embeddings = get_embedding_backend(self._rag_config)
        self._audit = AuditLogger(journal_path=config.journal_path)

    def generate(self, *, request_statement: str, evidence: list[dict], claim_id: str,
                 session_id: str, correlation_id: str) -> dict:
        req = GeneratorClaimRequest(request_id=f"REQ-{uuid.uuid4().hex[:12].upper()}", question=request_statement or "")
        try:
            generated = asyncio.run(generate_claim(
                req, chroma=self._chroma, embeddings=self._embeddings,
                rag_config=self._rag_config, llamacpp_config=self._llamacpp_config,
            ))
        except (ChromaUnavailable, EmbeddingBackendUnavailable, RagUnavailable) as exc:
            raise MCPTechnicalFailure(EventCode.EVIDENCE_CATALOG_UNAVAILABLE, f"Foundation-Sec RAG retrieval unavailable: {exc}")
        except GeneratorRequestError as exc:
            raise MCPTechnicalFailure(EventCode.SCHEMA_ERROR, f"Foundation-Sec Generator request invalid: {exc}")
        except GeneratorOutputError as exc:
            from mcp_server.errors import LLMOutputContractViolation
            raise LLMOutputContractViolation(f"Foundation-Sec Generator output rejected: {exc}")

        if generated.status != "CLAIM_GENERATED":
            from mcp_server.errors import LLMOutputContractViolation
            raise LLMOutputContractViolation(
                f"Foundation-Sec Generator returned status={generated.status!r} (INSUFFICIENT_EVIDENCE is not "
                "adaptable into a Claim -- the MCP pipeline's Verifier must receive an explicit "
                "insufficient-evidence signal upstream of this bridge, not a fabricated Claim)"
            )

        try:
            return to_mcp_claim(
                generated, session_id=session_id, correlation_id=correlation_id, claim_id=claim_id, audit=self._audit,
            )
        except GeneratorOutputError as exc:
            from mcp_server.errors import LLMOutputContractViolation
            raise LLMOutputContractViolation(f"Foundation-Sec GeneratedClaim could not be adapted to CLAIM_SCHEMA: {exc}")
