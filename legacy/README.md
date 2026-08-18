# Legacy Ollama pipeline (partially archived)

This directory held the classic, Ollama-backed LLM pipeline that predates the
Foundation-Sec-8B + llama.cpp + RAG chain this project now runs in Docker
(`chromadb` + `llama-generator` + `generator-api`, see `docker-compose.yml`).

**Update (2026-08-07): the Verifier half was restored to production.**
`mcp_server/llm_roles/llama_verifier.py` and `ollama_client.py` moved back to
`mcp_server/llm_roles/`, and `factory.build_verifier()` wires `llm_mode="llama"`
to `LlamaVerifier`, configured for **Qwen 2.5:7b-instruct** (not Llama 3.1 --
see `factory.py`'s docstring for the benchmark reasoning). `generator-api` now
reaches the host's native Ollama via `host.docker.internal` (see
`docker-compose.yml`'s `OLLAMA_HOST`/`extra_hosts` on the `generator-api`
service). The Generator is unaffected: it is still always Foundation-Sec-8B
via `mcp_server.generator_service` on the live `/api/v1/generator/verified-claims`
path, which never uses this factory's `build_generator()`.

Everything else below is still archived and NOT deployed: the classic
Ollama-backed Generator, the "real" provider stubs, and the RAG bridge for the
old `/api/process` endpoint.

## What's still here

- `mcp_server/llm_roles/llama_generator.py` — Ollama-backed Generator (classic `/api/process` pipeline only; the live `/api/v1/generator/verified-claims` path always uses Foundation-Sec-8B instead).
- `mcp_server/llm_roles/real_stub.py` — unimplemented `llm_mode="real"` placeholders (`RealGenerator`/`RealVerifier`/`RealValidator`), never wired to any actual provider.
- `mcp_server/llm_roles/llama_validator.py` — deprecated re-export shim (`LlamaValidator = PolicyValidator`); had zero real importers even before archiving. `PolicyValidator` itself (pure deterministic, no Ollama dependency) stays in `mcp_server/llm_roles/policy_validator.py` — it was never part of this legacy group despite the confusing old name.
- `mcp_server/llm_roles/foundation_sec_generator.py` — adapter that let the classic `/api/process` endpoint optionally swap in the new RAG generator via `GENERATOR_BACKEND=foundation_sec_rag` (never set in `docker-compose.yml`).
- `mcp_server/rag/generator_integration.py` — RAG bridge (`augment_with_rag`) used only by `llama_generator.py`.
- `tests/test_ollama_integration.py`, `tests/test_llama_generator_validation.py`, `tests/test_rag_generator_integration.py`, `tests/test_rag_availability.py`, `tests/test_generator_backend_flag.py` — tests exercising the above (classic Generator pipeline only; `tests/test_adversarial_llama_verifier.py` for the Verifier moved back to `tests/`).

## How to restore the Generator half too (if ever needed)

1. Move each remaining file back to its original path (see the path implied
   by `legacy/<original path>` above).
2. In `mcp_server/llm_roles/factory.py`, restore the `llm_mode == "llama"` /
   `"real"` branches for `build_generator()` (mirror what was already done
   for `build_verifier()`).
3. `docker-compose.yml` already has `OLLAMA_HOST`/`extra_hosts` wired on
   `generator-api` from the Verifier restore above — nothing extra needed
   there for the Generator to reach the same host Ollama instance.

## What did NOT move

`mcp_server/llm_roles/policy_validator.py` (`PolicyValidator`) — despite being
selected under the old `llm_mode == "llama"` branch, it calls no LLM and has
no Ollama dependency. It's functionally identical to `MockValidator` (both
just call `mcp_server.policy.decide()`) and remains wired in
`factory.build_validator()`.
