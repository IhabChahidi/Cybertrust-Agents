"""Local, controlled Retrieval-Augmented Generation layer for the Generator role.

Scope note: the original request for this package described infrastructure this
repository does not actually have (a separate "app/" tree, existing ingestion
API endpoints, a Docker Compose stack, a distinct "Generator client"). This
package instead integrates directly into the real Generator
(mcp_server/llm_roles/llama_generator.py) and reuses the real MCP contracts
(mcp_server/schemas.py), config (mcp_server/config.py), and audit logger
(mcp_server/logging_utils.py) rather than duplicating them. See the session
report for the full list of scoping decisions.

Everything here is optional and off by default (MCPConfig.rag_enabled=False):
importing this package must never fail even if chromadb/sentence-transformers
are not installed, and the Generator must behave exactly as before when RAG is
disabled -- this is the backward-compatibility guarantee the request asked for.
"""
