"""Direct, standalone execution of one function/module at a time from the
architecture table -- NOT pytest, real calls to the real code. Run one
section at a time:

    python scripts/execute_modules_directly.py prompts
    python scripts/execute_modules_directly.py claims
    python scripts/execute_modules_directly.py scoring
    python scripts/execute_modules_directly.py policy
    python scripts/execute_modules_directly.py policy_config
    python scripts/execute_modules_directly.py mock_roles
    python scripts/execute_modules_directly.py policy_validator
    python scripts/execute_modules_directly.py orchestrator
    python scripts/execute_modules_directly.py rag
    python scripts/execute_modules_directly.py llamacpp_client   # needs a real OpenAI-compatible endpoint (Ollama)
    python scripts/execute_modules_directly.py generator_service # needs Ollama + fresh local Chroma
    python scripts/execute_modules_directly.py legacy            # needs Ollama; imports from legacy/
"""
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def section_prompts():
    from mcp_server.generator_prompts import SYSTEM_PROMPT, build_user_prompt, build_repair_prompt
    print("SYSTEM_PROMPT (first 200 chars):", SYSTEM_PROMPT[:200], "...")
    prompt = build_user_prompt(question="Is CVE-2026-12345 remediated on SRV-ERP-01?",
                                rag_context_text="[EVD-0001] Ticket SEC-104 closed, vendor patch applied.")
    print("\nbuild_user_prompt() ->\n", prompt[:400], "...")
    repair = build_repair_prompt(original_output='{"claim": "..."}', error_detail="cites EVD-9999, not in retrieved context")
    print("\nbuild_repair_prompt() ->\n", repair[:300], "...")


def section_claims():
    from mcp_server.generator_claims import GeneratedClaim, enforce_source_authority, to_mcp_claim
    from mcp_server.rag.schemas import RetrievalResult

    claim = GeneratedClaim(
        claim_id="GCLM-0001", request_id="REQ-0001", status="CLAIM_GENERATED",
        claim="CVE-2026-12345 is remediated on SRV-ERP-01.",
        evidence_ids=["EVD-0001", "EVD-0002"], reference_ids=["CVE-2026-12345"],
        reasoning_summary="Ticket closed with vendor patch, rescan confirms absence.",
        confidence=0.9, limitations=[], generated_at=datetime.now(timezone.utc),
        model_name="demo-model", retrieval_trace_id="RAGTRC-DEMO",
    )
    included = [
        RetrievalResult(record_id="EVD-0001", collection="corporate_evidence", source_type="corporate_evidence",
                         content="Ticket SEC-104 closed, vendor patch applied.",
                         metadata={"evidence_type": "remediation_ticket", "case_id": "VUL-018"},
                         retrieval_method="vector", retrieval_score=0.9, authoritative=True),
        RetrievalResult(record_id="EVD-0002", collection="corporate_evidence", source_type="corporate_evidence",
                         content="Rescan confirms CVE-2026-12345 is no longer present.",
                         metadata={"evidence_type": "vulnerability_scan", "case_id": "VUL-018"},
                         retrieval_method="vector", retrieval_score=0.9, authoritative=True),
    ]
    enforce_source_authority(claim, included_results=included, case_id="VUL-018")
    print("enforce_source_authority() did not raise -> claim respects source-authority rules")

    mcp_claim = to_mcp_claim(claim, session_id="SES-DEMO00000001", correlation_id="COR-DEMO00000001", claim_id="CLM-0001")
    print("\nto_mcp_claim() ->", mcp_claim)


def section_scoring():
    from mcp_server.scoring import compute_mcp_score
    evidence = [{"id": "EVD-0001", "type": "ticket", "severity": "HIGH",
                 "content": {"summary": "s", "raw_data": "status=closed"}}]
    verification_result = {"id": "VER-DEMO0001", "status": "supported", "contradicting_evidence": []}
    score = compute_mcp_score(evidence=evidence, verification_result=verification_result,
                               score_id="MCP-SCORE-DEMO", session_id="SES-DEMO00000001", correlation_id="COR-DEMO00000001")
    print("compute_mcp_score() ->", score)


def section_policy():
    from mcp_server.policy import decide
    verification_result = {"id": "VER-DEMO0001", "status": "supported"}
    mcp_score = {"id": "MCP-SCORE-DEMO", "risk_level": "HIGH"}
    decision = decide(verification_result=verification_result, mcp_score=mcp_score,
                       decision_id="VAL-DEMO0001", session_id="SES-DEMO00000001", correlation_id="COR-DEMO00000001",
                       diagnostic_warnings=[])
    print("policy.decide() ->", decision)


def section_policy_config():
    from mcp_server.policy_config import load_policy_config, config_hash
    config = load_policy_config()
    print("load_policy_config() -> loaded", len(config.get("rules", [])), "rule(s)")
    print("config_hash() ->", config_hash(config))


def section_mock_roles():
    from mcp_server.llm_roles.mock_verifier import MockVerifier
    from mcp_server.llm_roles.mock_validator import MockValidator
    evidence = [{"id": "EVD-0001", "type": "ticket", "content": {"summary": "s", "raw_data": "status=closed"}}]
    v = MockVerifier()
    result = v.verify(claim={"id": "CLM-0001", "evidence_ids": ["EVD-0001"], "statement": "x"}, evidence=evidence,
                       verification_id="VER-DEMO0001", session_id="SES-DEMO00000001", correlation_id="COR-DEMO00000001")
    print("MockVerifier.verify() ->", result)

    val = MockValidator()
    decision = val.validate(verification_result=result, mcp_score={"id": "MCP-SCORE-DEMO", "risk_level": "LOW"}, diagnostic_warnings=[],
                             decision_id="VAL-DEMO0001", session_id="SES-DEMO00000001", correlation_id="COR-DEMO00000001")
    print("\nMockValidator.validate() ->", decision)


def section_policy_validator():
    from mcp_server.llm_roles.policy_validator import PolicyValidator
    from mcp_server.config import MCPConfig
    pv = PolicyValidator(MCPConfig(llm_mode="llama"))
    decision = pv.validate(verification_result={"id": "VER-DEMO0002", "status": "supported"}, mcp_score={"id": "MCP-SCORE-DEMO2", "risk_level": "CRITICAL"},
                            diagnostic_warnings=[], decision_id="VAL-DEMO0002",
                            session_id="SES-DEMO00000001", correlation_id="COR-DEMO00000001")
    print("PolicyValidator.validate() -> (this class is NOT exercised by any pytest test today)")
    print(decision)


def section_orchestrator():
    from mcp_server.orchestrator import MCPServer
    from mcp_server.config import MCPConfig
    mcp = MCPServer(MCPConfig(llm_mode="mock", journal_path="/tmp/execute_modules_journal.jsonl"))
    claim = {
        "schema_version": "1.0", "session_id": f"SES-{uuid.uuid4().hex[:12].upper()}",
        "correlation_id": f"COR-{uuid.uuid4().hex[:12].upper()}", "id": "CLM-0001",
        "evidence_ids": ["EVD-0001"], "statement": "CVE-2026-12345 is remediated on SRV-ERP-01.",
        "confidence": 0.9, "context": "demo", "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator_role": "GENERATOR", "reference_ids": ["CVE-2026-12345"], "limitations": [],
        "retrieval_trace_id": "RAGTRC-DEMO",
    }
    result = mcp.process_claim(claim)
    print("MCPServer.process_claim() -> mcp_state:", result.get("mcp_state"))
    print("transitions:", result.get("transitions") or (result.get("partial") or {}).get("transitions"))


def section_rag():
    import tempfile
    from mcp_server.rag.config import RagConfig
    from mcp_server.rag.chroma_client import ChromaCollections
    from mcp_server.rag.embeddings import get_embedding_backend
    from mcp_server.rag.ingestion import ingest_evidence
    from mcp_server.rag.retrieval import retrieve
    from mcp_server.logging_utils import AuditLogger

    tmp = tempfile.mkdtemp(prefix="direct_rag_")
    config = RagConfig(chroma_persist_dir=tmp)
    chroma = ChromaCollections(config)
    embeddings = get_embedding_backend(config)
    audit = AuditLogger(journal_path=str(Path(tmp) / "journal.jsonl"))

    result = ingest_evidence(
        [{"id": "EVD-0001", "case_id": "VUL-018", "source": "DEMO", "observed_at": "2026-07-31T00:00:00Z",
          "evidence_type": "remediation_ticket", "classification": "INTERNAL",
          "content": "Ticket closed, vendor patch applied."}],
        chroma=chroma, embeddings=embeddings, config=config, audit=audit,
        session_id="SES-DEMO00000001", correlation_id="COR-DEMO00000001",
    )
    print("ingest_evidence() ->", result)

    results, trace = retrieve(query="Is the ticket closed?", chroma=chroma, embeddings=embeddings, config=config,
                               case_id="VUL-018", ticket_id=None, asset_id=None, allowed_classification=None)
    print("\nretrieve() -> found", len(results), "result(s), trace_id:", trace.trace_id)


def section_llamacpp_client():
    from mcp_server.llamacpp_config import LlamaCppConfig
    from mcp_server.llm_roles.llamacpp_client import chat_completion
    config = LlamaCppConfig(base_url="http://localhost:11434/v1", model_name="llama3.1:latest")
    text = chat_completion(config=config, system_prompt="Reply with the single word PONG.",
                            user_prompt="ping", max_tokens=10)
    print("chat_completion() ->", text)


def section_generator_service():
    import tempfile
    from mcp_server.rag.config import RagConfig
    from mcp_server.rag.chroma_client import ChromaCollections
    from mcp_server.rag.embeddings import get_embedding_backend
    from mcp_server.rag.ingestion import ingest_evidence
    from mcp_server.llamacpp_config import LlamaCppConfig
    from mcp_server.logging_utils import AuditLogger
    from mcp_server.generator_service import generate_claim, GeneratorClaimRequest

    tmp = tempfile.mkdtemp(prefix="direct_genservice_")
    rag_config = RagConfig(chroma_persist_dir=tmp)
    chroma = ChromaCollections(rag_config)
    embeddings = get_embedding_backend(rag_config)
    audit = AuditLogger(journal_path=str(Path(tmp) / "journal.jsonl"))
    ingest_evidence(
        [{"id": "EVD-0001", "case_id": "VUL-018", "source": "DEMO", "observed_at": "2026-07-31T00:00:00Z",
          "evidence_type": "remediation_ticket", "classification": "INTERNAL",
          "content": "Ticket closed, vendor patch applied for CVE-2026-12345 on SRV-ERP-01."}],
        chroma=chroma, embeddings=embeddings, config=rag_config, audit=audit,
        session_id="SES-DEMO00000001", correlation_id="COR-DEMO00000001",
    )
    llamacpp_config = LlamaCppConfig(base_url="http://localhost:11434/v1", model_name="llama3.1:latest")
    import asyncio
    result = asyncio.run(generate_claim(
        GeneratorClaimRequest(request_id="REQ-DEMO0001", question="Is CVE-2026-12345 remediated on SRV-ERP-01?",
                               case_id="VUL-018"),
        chroma=chroma, embeddings=embeddings, rag_config=rag_config, llamacpp_config=llamacpp_config,
    ))
    print("generate_claim() -> status:", result.status)
    print(result)


def section_legacy():
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "legacy"))
    from legacy.mcp_server.llm_roles.llama_generator import LlamaGenerator
    from mcp_server.config import MCPConfig
    gen = LlamaGenerator(MCPConfig(llm_mode="llama", ollama_host="http://localhost:11434"))
    print("LlamaGenerator instantiated from legacy/ ->", gen)
    print("(archived: not deployed in docker-compose.yml; requires Ollama reachable at ollama_host)")


SECTIONS = {
    "prompts": section_prompts, "claims": section_claims, "scoring": section_scoring,
    "policy": section_policy, "policy_config": section_policy_config, "mock_roles": section_mock_roles,
    "policy_validator": section_policy_validator, "orchestrator": section_orchestrator, "rag": section_rag,
    "llamacpp_client": section_llamacpp_client, "generator_service": section_generator_service,
    "legacy": section_legacy,
}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in SECTIONS:
        print("Usage: python scripts/execute_modules_directly.py <" + "|".join(SECTIONS) + ">")
        sys.exit(1)
    SECTIONS[sys.argv[1]]()
