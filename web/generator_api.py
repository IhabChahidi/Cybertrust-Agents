"""FastAPI router for the new llama.cpp/Foundation-Sec Generator API (spec
sections 6, 12, 13). Separate from web/backend.py's existing CISO dashboard
routes and session-cookie auth: this surface is machine-to-machine
(ingestion pipelines, retrieval callers, the Generator itself) and is
protected by a distinct `X-API-Key` header instead, per spec section 16
("API-key auth dependency, distinct from the existing CISO dashboard session
auth").

Mounted into the main app via web/backend.py:
    from web.generator_api import router as generator_router
    app.include_router(generator_router)

Ingestion endpoints return a job_id immediately (FastAPI BackgroundTasks) and
the caller polls GET /api/v1/ingestion/jobs/{job_id} — kept intentionally
simple (mcp_server/rag/jobs.py's in-memory JobService), documented there as
"replaceable by a queue later" rather than built out now.
"""

import asyncio
import os
import secrets
import uuid
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from mcp_server.config import MCPConfig, SUPPORTED_LLM_MODES
from mcp_server.generator_claims import GeneratedClaim, GeneratorOutputError, to_mcp_claim
from mcp_server.generator_service import GeneratorClaimRequest, GeneratorRequestError, generate_claim
from mcp_server.llamacpp_config import (
    DEFAULT_API_SECURITY,
    DEFAULT_LLAMACPP_CONFIG,
    ApiSecuritySettings,
    LlamaCppConfig,
)
from mcp_server.llm_roles.llamacpp_client import health_check, probe_structured_output_capability
from mcp_server.logging_utils import AuditLogger
from mcp_server.orchestrator import MCPServer
from mcp_server.rag.chroma_client import ChromaCollections, ChromaUnavailable
from mcp_server.rag.config import DEFAULT_RAG_CONFIG, RagConfig
from mcp_server.rag.embeddings import EmbeddingBackend, EmbeddingBackendUnavailable, get_embedding_backend
from mcp_server.rag.ingestion import ingest_cve, ingest_evidence, ingest_kev, ingest_mitre, ingest_runbooks
from mcp_server.rag.jobs import JOB_SERVICE, JobNotFoundError, JobService
from mcp_server.rag.retrieval import RagUnavailable, retrieve

router = APIRouter(prefix="/api/v1")

# Not under mcp_server/ -- that directory is Python source; a persistent
# Docker volume there would shadow the package files. See JOURNAL_DIR on
# generator-api's named volume in docker-compose.yml.
_JOURNAL_DIR = os.environ.get("JOURNAL_DIR", "audit_journal")
_JOURNAL_PATH = f"{_JOURNAL_DIR}/journal_generator_api.jsonl"

# Module-level singletons, overridable per-request via FastAPI dependency
# overrides in tests (see tests/test_generator_api.py) -- production code
# never needs to touch these directly.
_chroma = ChromaCollections(DEFAULT_RAG_CONFIG)
_embeddings = get_embedding_backend(DEFAULT_RAG_CONFIG)
_audit = AuditLogger(journal_path=_JOURNAL_PATH)


def get_rag_config() -> RagConfig:
    return DEFAULT_RAG_CONFIG


def get_llamacpp_config() -> LlamaCppConfig:
    return DEFAULT_LLAMACPP_CONFIG


def get_api_security() -> ApiSecuritySettings:
    return DEFAULT_API_SECURITY


def get_chroma() -> ChromaCollections:
    return _chroma


def get_embeddings() -> EmbeddingBackend:
    return _embeddings


def get_audit() -> AuditLogger:
    return _audit


def get_job_service() -> JobService:
    return JOB_SERVICE


# One long-lived MCPServer per llm_mode, mirroring web/backend.py's own
# _servers cache (kept separate rather than shared/imported to avoid a
# circular import -- web/backend.py imports this module's router). Each
# instance's Verifier/Validator are the SAME ones the classic Ollama-backed
# pipeline uses; only the Claim they receive here was produced by the
# Foundation-Sec/RAG Generator instead of this orchestrator's own Generator.
_mcp_servers: dict[str, MCPServer] = {}


def _get_mcp_server(llm_mode: str) -> MCPServer:
    if llm_mode not in SUPPORTED_LLM_MODES:
        raise HTTPException(400, f"Unsupported llm_mode: {llm_mode!r}. Must be one of {SUPPORTED_LLM_MODES}.")
    if llm_mode not in _mcp_servers:
        config = MCPConfig(
            llm_mode=llm_mode,
            journal_path=f"{_JOURNAL_DIR}/journal_verified_claims_{llm_mode}.jsonl",
            llm_timeout_seconds=90.0 if llm_mode == "llama" else 30.0,
        )
        _mcp_servers[llm_mode] = MCPServer(config, chroma=_chroma)
    return _mcp_servers[llm_mode]


@dataclass(frozen=True)
class ServiceAuthContext:
    """Typed result of successful service-to-service authentication (spec
    section 6: "introduce a typed service-authentication context where
    practical"). Distinct from web.auth.Session (the CISO dashboard's human
    session-cookie identity): this represents "some caller holding the
    shared API key", not a named principal.

    Known pilot limitation (documented, not accidental): the API key is a
    single shared secret across every machine caller (ingestion pipelines,
    retrieval callers, the Generator itself) -- there is no per-caller
    identity, scope, or role yet. This dataclass is the extension point: a
    future per-caller identity/claims/scopes model replaces `authenticated`
    with real fields without changing every endpoint's dependency wiring.
    """

    authenticated: bool = True


def require_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    security: ApiSecuritySettings = Depends(get_api_security),
) -> ServiceAuthContext:
    # secrets.compare_digest is constant-time: a plain `!=`/`==` comparison on
    # a shared static secret leaks timing information proportional to the
    # number of matching leading bytes, a real (if narrow) side channel here.
    if not x_api_key or not secrets.compare_digest(x_api_key, security.api_key):
        # Never include the submitted key (valid or not) in the error detail
        # or in any log -- this message is the only thing returned to the
        # caller, and it names neither the expected nor the received value.
        raise HTTPException(401, "Missing or invalid API key")
    return ServiceAuthContext(authenticated=True)


class IngestionResponse(BaseModel):
    job_id: str
    status: str


class JobResponse(BaseModel):
    job_id: str
    kind: str
    status: str
    result: dict | None = None
    error: str | None = None
    created_at: str
    updated_at: str


class RetrievalSearchRequest(BaseModel):
    query: str
    case_id: str | None = None
    ticket_id: str | None = None
    asset_id: str | None = None
    allowed_classification: str | None = None


class GeneratorClaimApiRequest(BaseModel):
    request_id: str = Field(min_length=1)
    question: str = Field(min_length=1)
    case_id: str | None = None
    ticket_id: str | None = None
    asset_id: str | None = None
    allowed_classification: str | None = None


class VerifiedClaimApiRequest(GeneratorClaimApiRequest):
    # Which Verifier/Validator implementation runs against the Foundation-Sec
    # Claim -- same three choices web/backend.py's ProcessRequest.llm_mode
    # exposes for the classic pipeline ("mock" for tests/dry-runs, "llama" for
    # a real local Ollama Verifier+deterministic Validator).
    llm_mode: str = "mock"


_INGESTORS = {
    "mitre": ingest_mitre,
    "cve": ingest_cve,
    "kev": ingest_kev,
    "runbooks": ingest_runbooks,
    "evidence": ingest_evidence,
}


def _run_ingestion_job(
    kind: str, records: list[dict[str, Any]], job_id: str, *,
    chroma: ChromaCollections, embeddings: EmbeddingBackend, config: RagConfig,
    audit: AuditLogger, jobs: JobService,
) -> None:
    jobs.mark_running(job_id)
    try:
        ingest_fn = _INGESTORS[kind]
        result = ingest_fn(
            records, chroma=chroma, embeddings=embeddings, config=config, audit=audit,
            session_id=f"SES-INGEST-{job_id}", correlation_id=job_id,
        )
        jobs.mark_succeeded(job_id, {
            "ingested": result.ingested, "updated": result.updated,
            "duplicates": result.duplicates, "skipped_suspicious": result.skipped_suspicious,
            "record_ids": result.record_ids,
        })
    except Exception as exc:  # noqa: BLE001 -- job failure must never crash the worker
        jobs.mark_failed(job_id, str(exc))


def _enqueue_ingestion(
    kind: str, records: list[dict[str, Any]], background_tasks: BackgroundTasks, *,
    chroma: ChromaCollections, embeddings: EmbeddingBackend, config: RagConfig,
    audit: AuditLogger, jobs: JobService,
) -> IngestionResponse:
    job = jobs.create(kind=f"ingestion:{kind}")
    background_tasks.add_task(
        _run_ingestion_job, kind, records, job.job_id,
        chroma=chroma, embeddings=embeddings, config=config, audit=audit, jobs=jobs,
    )
    return IngestionResponse(job_id=job.job_id, status=job.status)


@router.post("/ingestion/mitre", dependencies=[Depends(require_api_key)], response_model=IngestionResponse)
def ingest_mitre_endpoint(
    records: list[dict[str, Any]], background_tasks: BackgroundTasks,
    chroma: ChromaCollections = Depends(get_chroma), embeddings: EmbeddingBackend = Depends(get_embeddings),
    config: RagConfig = Depends(get_rag_config), audit: AuditLogger = Depends(get_audit),
    jobs: JobService = Depends(get_job_service),
):
    return _enqueue_ingestion("mitre", records, background_tasks, chroma=chroma, embeddings=embeddings,
                               config=config, audit=audit, jobs=jobs)


@router.post("/ingestion/cve", dependencies=[Depends(require_api_key)], response_model=IngestionResponse)
def ingest_cve_endpoint(
    records: list[dict[str, Any]], background_tasks: BackgroundTasks,
    chroma: ChromaCollections = Depends(get_chroma), embeddings: EmbeddingBackend = Depends(get_embeddings),
    config: RagConfig = Depends(get_rag_config), audit: AuditLogger = Depends(get_audit),
    jobs: JobService = Depends(get_job_service),
):
    return _enqueue_ingestion("cve", records, background_tasks, chroma=chroma, embeddings=embeddings,
                               config=config, audit=audit, jobs=jobs)


@router.post("/ingestion/kev", dependencies=[Depends(require_api_key)], response_model=IngestionResponse)
def ingest_kev_endpoint(
    records: list[dict[str, Any]], background_tasks: BackgroundTasks,
    chroma: ChromaCollections = Depends(get_chroma), embeddings: EmbeddingBackend = Depends(get_embeddings),
    config: RagConfig = Depends(get_rag_config), audit: AuditLogger = Depends(get_audit),
    jobs: JobService = Depends(get_job_service),
):
    return _enqueue_ingestion("kev", records, background_tasks, chroma=chroma, embeddings=embeddings,
                               config=config, audit=audit, jobs=jobs)


@router.post("/ingestion/runbooks", dependencies=[Depends(require_api_key)], response_model=IngestionResponse)
def ingest_runbooks_endpoint(
    records: list[dict[str, Any]], background_tasks: BackgroundTasks,
    chroma: ChromaCollections = Depends(get_chroma), embeddings: EmbeddingBackend = Depends(get_embeddings),
    config: RagConfig = Depends(get_rag_config), audit: AuditLogger = Depends(get_audit),
    jobs: JobService = Depends(get_job_service),
):
    return _enqueue_ingestion("runbooks", records, background_tasks, chroma=chroma, embeddings=embeddings,
                               config=config, audit=audit, jobs=jobs)


@router.post("/ingestion/evidence", dependencies=[Depends(require_api_key)], response_model=IngestionResponse)
def ingest_evidence_endpoint(
    records: list[dict[str, Any]], background_tasks: BackgroundTasks,
    chroma: ChromaCollections = Depends(get_chroma), embeddings: EmbeddingBackend = Depends(get_embeddings),
    config: RagConfig = Depends(get_rag_config), audit: AuditLogger = Depends(get_audit),
    jobs: JobService = Depends(get_job_service),
):
    return _enqueue_ingestion("evidence", records, background_tasks, chroma=chroma, embeddings=embeddings,
                               config=config, audit=audit, jobs=jobs)


@router.get("/ingestion/jobs/{job_id}", dependencies=[Depends(require_api_key)], response_model=JobResponse)
def get_ingestion_job(job_id: str, jobs: JobService = Depends(get_job_service)):
    try:
        job = jobs.get(job_id)
    except JobNotFoundError:
        raise HTTPException(404, f"job {job_id!r} not found")
    return JobResponse(
        job_id=job.job_id, kind=job.kind, status=job.status, result=job.result,
        error=job.error, created_at=job.created_at, updated_at=job.updated_at,
    )


@router.post("/retrieval/search", dependencies=[Depends(require_api_key)])
def retrieval_search(
    req: RetrievalSearchRequest, chroma: ChromaCollections = Depends(get_chroma),
    embeddings: EmbeddingBackend = Depends(get_embeddings), config: RagConfig = Depends(get_rag_config),
):
    if not req.query.strip():
        raise HTTPException(400, "query must not be empty")
    try:
        results, trace = retrieve(
            query=req.query, chroma=chroma, embeddings=embeddings, config=config,
            case_id=req.case_id, ticket_id=req.ticket_id, asset_id=req.asset_id,
            allowed_classification=req.allowed_classification,
        )
    except (ChromaUnavailable, EmbeddingBackendUnavailable, RagUnavailable) as exc:
        raise HTTPException(503, f"retrieval unavailable: {exc}")
    return {
        "results": [r.model_dump(mode="json") for r in results],
        "trace": trace.model_dump(mode="json"),
    }


@router.post("/generator/claims", dependencies=[Depends(require_api_key)], response_model=GeneratedClaim)
async def generator_claims(
    req: GeneratorClaimApiRequest, chroma: ChromaCollections = Depends(get_chroma),
    embeddings: EmbeddingBackend = Depends(get_embeddings), rag_config: RagConfig = Depends(get_rag_config),
    llamacpp_config: LlamaCppConfig = Depends(get_llamacpp_config),
):
    try:
        return await generate_claim(
            GeneratorClaimRequest(
                request_id=req.request_id, question=req.question, case_id=req.case_id,
                ticket_id=req.ticket_id, asset_id=req.asset_id, allowed_classification=req.allowed_classification,
            ),
            chroma=chroma, embeddings=embeddings, rag_config=rag_config, llamacpp_config=llamacpp_config,
        )
    except GeneratorRequestError as exc:
        raise HTTPException(400, str(exc))
    except (ChromaUnavailable, EmbeddingBackendUnavailable, RagUnavailable) as exc:
        raise HTTPException(503, f"retrieval unavailable: {exc}")
    except GeneratorOutputError as exc:
        raise HTTPException(502, f"generator produced unusable output: {exc}")
    except TimeoutError as exc:
        raise HTTPException(504, f"generator model timed out: {exc}")


@router.post("/generator/verified-claims", dependencies=[Depends(require_api_key)])
async def generator_verified_claims(
    req: VerifiedClaimApiRequest, chroma: ChromaCollections = Depends(get_chroma),
    embeddings: EmbeddingBackend = Depends(get_embeddings), rag_config: RagConfig = Depends(get_rag_config),
    llamacpp_config: LlamaCppConfig = Depends(get_llamacpp_config),
):
    """Composes the Foundation-Sec/RAG Generator with the existing MCP
    Verifier/Validator chain: Foundation-Sec owns generation end to end (its
    own scoped RAG retrieval, citation/source-authority enforcement -- see
    generate_claim()), and the resulting Claim is handed, unmodified, to
    mcp_server.orchestrator.MCPServer.process_claim() -- the SAME Verifier and
    deterministic Validator the classic Ollama-backed pipeline uses, which
    remain entirely unaware of which Generator produced the Claim.

    status == INSUFFICIENT_EVIDENCE is returned as-is, without ever reaching
    the Verifier: an inconclusive Foundation-Sec result is not something for
    the Verifier to adjudicate, per to_mcp_claim()'s own contract.

    Audit coverage (added after a real diagnostic gap found in this session:
    every stage before process_claim() -- Generator call, Generator output,
    contract adaptation -- used to be invisible in the audit journal on
    failure, forcing a one-off diagnostic script instead of just reading the
    journal). session_id/correlation_id are minted HERE, before anything can
    fail, and every stage below logs to server.audit (the SAME journal
    process_claim()'s own internal stages write to -- one coherent trace per
    session_id, not split across files) so a CISO or engineer can reconstruct
    exactly what happened, including WHY a request never reached the
    Verifier, without re-running anything.
    """
    server = _get_mcp_server(req.llm_mode)
    session_id = f"SES-{uuid.uuid4().hex[:12].upper()}"
    correlation_id = f"COR-{uuid.uuid4().hex[:12].upper()}"

    def _log(*, event_type: str, role: str, result: str, detail: str = "") -> None:
        server.audit.log(
            session_id=session_id, correlation_id=correlation_id, state="GENERATION",
            event_type=event_type, role=role, result=result, detail=detail,
        )

    _log(
        event_type="REQUEST_RECEIVED", role="MCP", result="OK",
        detail=(f"request_id={req.request_id} question={req.question!r} case_id={req.case_id} "
                f"ticket_id={req.ticket_id} asset_id={req.asset_id} llm_mode={req.llm_mode}"),
    )

    try:
        generated = await generate_claim(
            GeneratorClaimRequest(
                request_id=req.request_id, question=req.question, case_id=req.case_id,
                ticket_id=req.ticket_id, asset_id=req.asset_id, allowed_classification=req.allowed_classification,
            ),
            chroma=chroma, embeddings=embeddings, rag_config=rag_config, llamacpp_config=llamacpp_config,
        )
    except GeneratorRequestError as exc:
        _log(event_type="GENERATION_FAILED", role="MCP", result="REJECTED", detail=f"GeneratorRequestError: {exc}")
        raise HTTPException(400, str(exc))
    except (ChromaUnavailable, EmbeddingBackendUnavailable, RagUnavailable) as exc:
        _log(event_type="GENERATION_FAILED", role="MCP", result="TECHNICAL_FAILURE", detail=f"retrieval unavailable: {exc}")
        raise HTTPException(503, f"retrieval unavailable: {exc}")
    except GeneratorOutputError as exc:
        _log(event_type="GENERATION_FAILED", role="GENERATOR", result="OUTPUT_INVALID", detail=str(exc))
        raise HTTPException(502, f"generator produced unusable output: {exc}")
    except TimeoutError as exc:
        _log(event_type="GENERATION_FAILED", role="GENERATOR", result="TIMEOUT", detail=str(exc))
        raise HTTPException(504, f"generator model timed out: {exc}")

    # Logged regardless of status -- this is exactly the (status, claim,
    # evidence_ids, reference_ids) tuple that previously required a one-off
    # debug script (scripts/diagnose_failing_scenarios.py) to observe.
    _log(
        event_type="GENERATION_RESULT", role="GENERATOR", result=generated.status,
        detail=(f"claim={generated.claim!r} evidence_ids={generated.evidence_ids} "
                f"reference_ids={generated.reference_ids} reasoning_summary={generated.reasoning_summary!r}"),
    )

    if generated.status != "CLAIM_GENERATED":
        return {
            "mcp_state": "INSUFFICIENT_EVIDENCE",
            "status": generated.status,
            "reasoning_summary": generated.reasoning_summary,
            "limitations": generated.limitations,
        }

    claim_id = server._next_id("CLM")  # CLAIM_SCHEMA requires the ^CLM-[0-9]{4}$ shape this orchestrator's own Generator uses
    try:
        mcp_claim = to_mcp_claim(
            generated, session_id=session_id, correlation_id=correlation_id, claim_id=claim_id, audit=server.audit,
        )
    except GeneratorOutputError as exc:
        _log(event_type="ADAPTATION_FAILED", role="MCP", result="REJECTED", detail=str(exc))
        raise HTTPException(502, f"Foundation-Sec claim could not be adapted to the MCP contract: {exc}")

    # process_claim() is synchronous and, when llm_mode="llama", calls
    # LlamaVerifier -> ollama_client.call_ollama(), which blocks on
    # `requests.post()` for the Ollama response (tens of seconds under real
    # load). Calling it directly inside this async def route would block
    # uvicorn's single event loop for that entire duration -- starving every
    # other concurrent request, INCLUDING this same process's own /health/live
    # healthcheck, which is exactly what caused Swarm to kill the container as
    # "unhealthy" mid-request the first time llm_mode="llama" actually reached
    # this line (Foundation-Sec's frequent INSUFFICIENT_EVIDENCE responses had
    # masked this, never reaching process_claim() at all in earlier testing).
    # asyncio.to_thread offloads the blocking call to a worker thread so the
    # event loop stays free.
    return await asyncio.to_thread(server.process_claim, mcp_claim)


# Health endpoints are unprefixed (/health/live, /health/ready), not under
# /api/v1, so they live on their own router mounted separately in web/backend.py.
health_router = APIRouter()


@health_router.get("/health/live")
def health_live():
    return {"status": "ok"}


@health_router.get("/health/ready")
async def health_ready(
    chroma: ChromaCollections = Depends(get_chroma), embeddings: EmbeddingBackend = Depends(get_embeddings),
    llamacpp_config: LlamaCppConfig = Depends(get_llamacpp_config),
):
    """Reports per-component readiness (spec: "Improve readiness reporting").
    Never exposes model filesystem paths, API keys, full exception traces, or
    other internal credentials -- every value here is a fixed, safe status
    string ("ready"/"unavailable"/"unsupported"), never str(exc) or a config
    field. Component failure -> overall status "not_ready" and HTTP 503; the
    Generator/RAG pipeline degrades on each of these independently (Chroma,
    embeddings, llama.cpp unavailability are all explicit, non-fatal test
    cases elsewhere -- readiness reporting is what surfaces that state to an
    orchestrator/operator, not a crash).
    """
    components: dict[str, str] = {"generator_api": "ready"}

    components["chromadb"] = "ready" if chroma.is_available() else "unavailable"
    components["embedding_backend"] = "ready" if embeddings.is_available() else "unavailable"

    llama_ready = await health_check(llamacpp_config)
    components["llama_cpp"] = "ready" if llama_ready else "unavailable"

    # If the deployment REQUIRES schema-constrained output (GENERATOR_STRUCTURED_OUTPUT_MODE=json_schema),
    # readiness must fail when the configured server doesn't actually support
    # it (spec: "fail readiness if the configured server does not support
    # it") -- "auto"/"json_object"/"disabled" never gate readiness on this.
    if llamacpp_config.structured_output_mode == "json_schema":
        supported = await probe_structured_output_capability(llamacpp_config) if llama_ready else False
        components["structured_output"] = "ready" if supported else "unsupported"

    ready = all(status == "ready" for status in components.values())
    body = {"status": "ready" if ready else "not_ready", "components": components}
    if not ready:
        raise HTTPException(503, body)
    return body
