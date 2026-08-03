"""FastAPI backend exposing the MCP server (mcp_server/) to the dashboard frontend.

Run with:
    python -m uvicorn web.backend:app --reload --port 8000
from the project root, then open http://localhost:8000/.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dotenv import load_dotenv

# Must run before `from web import auth` — auth.py seeds its dev user table
# from these env vars at import time. override=False (the default) so any
# variable already set in the real environment always wins over .env.
load_dotenv(REPO_ROOT / ".env")

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from mcp_server.config import ENDPOINT_WHITELIST, MCPConfig, SUPPORTED_LLM_MODES
from mcp_server.orchestrator import MCPServer
from web import auth
from web.generator_api import health_router
from web.generator_api import router as generator_router

app = FastAPI(title="CyberTrust Agents — MCP Dashboard")

# New Generator/RAG API surface (spec sections 6, 12, 13): X-API-Key auth,
# fully separate from the CISO dashboard's session-cookie auth above.
app.include_router(generator_router)
app.include_router(health_router)

# One long-lived MCPServer per LLM mode, so audit history and CISO decisions
# accumulate in-memory across requests instead of being recreated each time.
_servers: dict[str, MCPServer] = {}


def _get_server(llm_mode: str) -> MCPServer:
    if llm_mode not in SUPPORTED_LLM_MODES:
        raise HTTPException(400, f"Unsupported llm_mode: {llm_mode!r}. Must be one of {SUPPORTED_LLM_MODES}.")
    if llm_mode not in _servers:
        config = MCPConfig(
            llm_mode=llm_mode,
            journal_path=str(REPO_ROOT / "mcp_server" / f"journal_{llm_mode}.jsonl"),
            llm_timeout_seconds=90.0 if llm_mode == "llama" else 30.0,
        )
        _servers[llm_mode] = MCPServer(config)
    return _servers[llm_mode]


class ProcessRequest(BaseModel):
    statement: str = ""
    evidence_ids: list[str]
    llm_mode: str = "mock"
    endpoint: str = "GENERATOR_COPILOT_STUDIO"
    session_id: str | None = None
    correlation_id: str | None = None
    schema_version: str = "1.0"


class CisoDecisionRequest(BaseModel):
    session_id: str
    correlation_id: str
    llm_mode: str = "mock"
    decision: str


class LoginRequest(BaseModel):
    username: str
    password: str


def _session_payload(session: auth.Session) -> dict:
    return {
        "username": session.username,
        "role": session.role,
        "csrf_token": session.csrf_token,
        "expires_in_seconds": auth.SESSION_TTL_SECONDS,
        "dev_mode": True,
        "dev_notice": auth.DEV_AUTH_NOTICE,
    }


@app.get("/api/auth/mode")
def auth_mode():
    # Public on purpose: a UI hint only (boolean + static text), not sensitive,
    # so the login page can show the dev-mode notice before any credentials exist.
    return {"dev_mode": True, "notice": auth.DEV_AUTH_NOTICE}


@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request, response: Response):
    session = auth.authenticate(req.username, req.password)
    if session is None:
        # Generic message on purpose: never reveal whether the username exists.
        raise HTTPException(401, "Identifiants invalides")
    # Secure flag follows the actual request scheme: Secure over https, dropped
    # over plain http (browsers refuse Secure cookies on non-TLS connections).
    auth.set_session_cookie(response, session, secure=request.url.scheme == "https")
    return _session_payload(session)


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(auth.SESSION_COOKIE_NAME)
    session = auth.get_session(token)
    if session is not None:
        # A live session exists: require the matching CSRF token, same as any
        # other state-changing request, before destroying it.
        header_token = request.headers.get("x-csrf-token")
        if not header_token or header_token != session.csrf_token:
            raise HTTPException(403, "Jeton CSRF invalide ou absent")
    auth.destroy_session(token)
    auth.clear_session_cookie(response)
    return {"ok": True}


@app.get("/api/auth/me")
def me(session: auth.Session = Depends(auth.require_auth)):
    return _session_payload(session)


@app.get("/api/config")
def get_config(session: auth.Session = Depends(auth.require_auth)):
    return {"llm_modes": list(SUPPORTED_LLM_MODES), "endpoints": sorted(ENDPOINT_WHITELIST)}


@app.get("/api/evidence")
def list_evidence(session: auth.Session = Depends(auth.require_auth)):
    # The static Evidence catalogue is identical regardless of llm_mode.
    server = _get_server("mock")
    return [
        {
            "id": e["id"], "type": e["type"], "severity": e["severity"],
            "summary": e["content"]["summary"],
        }
        for e in sorted(server.evidence_catalogue.values(), key=lambda e: e["id"])
    ]


@app.get("/api/evidence/{evidence_id}")
def get_evidence(evidence_id: str, session: auth.Session = Depends(auth.require_auth)):
    server = _get_server("mock")
    item = server.evidence_catalogue.get(evidence_id)
    if item is None:
        raise HTTPException(404, f"Evidence {evidence_id!r} not found in static catalogue")
    return item


@app.post("/api/process")
def process(req: ProcessRequest, session: auth.Session = Depends(auth.require_csrf)):
    server = _get_server(req.llm_mode)
    request_dict = {
        "session_id": req.session_id,
        "correlation_id": req.correlation_id,
        "endpoint": req.endpoint,
        "statement": req.statement,
        "evidence_ids": req.evidence_ids,
        "schema_version": req.schema_version,
    }
    return server.process_request(request_dict)


@app.get("/api/journal/{session_id}")
def get_journal(session_id: str, session: auth.Session = Depends(auth.require_auth)):
    # Search every instantiated server — session_ids are unique across modes.
    for server in _servers.values():
        events = [e for e in server.audit.events if e["session_id"] == session_id]
        if events:
            return events
    return []


@app.post("/api/ciso-decision")
def ciso_decision(req: CisoDecisionRequest, session: auth.Session = Depends(auth.require_csrf)):
    # Recording a CISO decision is restricted to the authorized roles, even
    # though today both roles that can log in at all share this permission —
    # this is the enforcement point a future lower-privilege role would hit.
    if session.role not in auth.VALID_ROLES:
        raise HTTPException(403, f"Role {session.role!r} non autorise pour cette action")
    server = _get_server(req.llm_mode)
    try:
        return server.record_ciso_decision(req.session_id, req.correlation_id, req.decision)
    except ValueError as exc:
        raise HTTPException(400, str(exc))


app.mount("/", StaticFiles(directory=str(Path(__file__).parent / "static"), html=True), name="static")
