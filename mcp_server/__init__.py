"""CyberTrust Agents — MCP server (Semaine 3).

Orchestrates the Evidence -> Claim -> VerificationResult -> MCPScore ->
ValidationDecision pipeline defined in Semaine 1 (L3 contracts, L4 routing,
L5 scoring). Runs today against mocked Generator/Verifier/Validator roles;
see mcp_server/llm_roles/real_stub.py for the swap-in point once Copilot
Studio and external LLM access are available.
"""
