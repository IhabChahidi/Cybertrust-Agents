# Legacy Ollama pipeline (archived)

This directory holds the classic, Ollama-backed LLM pipeline that predates the
Foundation-Sec-8B + llama.cpp + RAG chain this project now runs in Docker
(`chromadb` + `llama-generator` + `generator-api`, see `docker-compose.yml`).

None of it is deployed anywhere: there is no Ollama service in
`docker-compose.yml`, and `MCPConfig.ollama_host` (`http://localhost:11434` by
default) is unreachable from inside the `generator-api` container's internal
network. It was archived rather than deleted so it can be restored quickly if
Ollama support is needed again.

## What's here

- `mcp_server/llm_roles/llama_generator.py` — Ollama-backed Generator.
- `mcp_server/llm_roles/llama_verifier.py` — Ollama-backed Verifier.
- `mcp_server/llm_roles/ollama_client.py` — `call_ollama()`, the HTTP client both of the above use.
- `mcp_server/llm_roles/real_stub.py` — unimplemented `llm_mode="real"` placeholders (`RealGenerator`/`RealVerifier`/`RealValidator`), never wired to any actual provider.
- `mcp_server/llm_roles/llama_validator.py` — deprecated re-export shim (`LlamaValidator = PolicyValidator`); had zero real importers even before archiving. `PolicyValidator` itself (pure deterministic, no Ollama dependency) stays in `mcp_server/llm_roles/policy_validator.py` — it was never part of this legacy group despite the confusing old name.
- `mcp_server/llm_roles/foundation_sec_generator.py` — adapter that let the classic `/api/process` endpoint optionally swap in the new RAG generator via `GENERATOR_BACKEND=foundation_sec_rag` (never set in `docker-compose.yml`).
- `mcp_server/rag/generator_integration.py` — RAG bridge (`augment_with_rag`) used only by `llama_generator.py`.
- `tests/test_ollama_integration.py`, `tests/test_llama_generator_validation.py`, `tests/test_rag_generator_integration.py`, `tests/test_rag_availability.py`, `tests/test_generator_backend_flag.py` — tests exercising the above.
- `tests/test_adversarial_llama_verifier.py` — the 7 `LlamaVerifier` malformed-output tests split out of `tests/test_adversarial.py` (that file's remaining 4 date/chronology tests are generic and stayed in place).

## How to restore

1. Move each file back to its original path (see the path implied by
   `legacy/<original path>` above).
2. In `mcp_server/llm_roles/factory.py`, restore the imports and the
   `llm_mode == "llama"` / `"real"` branches for `build_generator()` and
   `build_verifier()` (the git history for that file has the prior version).
3. Fold `tests/test_adversarial_llama_verifier.py`'s tests back into
   `tests/test_adversarial.py` if desired.
4. Add an `ollama` service to `docker-compose.yml` (or point `OLLAMA_HOST` at
   an existing instance) — nothing here works without a reachable Ollama
   server.

## What did NOT move

`mcp_server/llm_roles/policy_validator.py` (`PolicyValidator`) — despite being
selected under the old `llm_mode == "llama"` branch, it calls no LLM and has
no Ollama dependency. It's functionally identical to `MockValidator` (both
just call `mcp_server.policy.decide()`) and remains wired in
`factory.build_validator()`.
