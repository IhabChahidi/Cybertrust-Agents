import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
import requests

from mcp_server.config import MCPConfig
from mcp_server.orchestrator import MCPServer

SESSION_ID = "SES-20260722-PILOT"
CORRELATION_ID = "COR-20260722-PILOT"


def _ollama_available() -> bool:
    """Used to auto-skip @pytest.mark.ollama tests: the normal suite must never
    depend on a running model (spec section 8 / acceptance criteria)."""
    try:
        requests.get("http://localhost:11434/api/tags", timeout=1.5)
        return True
    except requests.exceptions.RequestException:
        return False


def pytest_collection_modifyitems(config, items):
    if _ollama_available():
        return
    skip_ollama = pytest.mark.skip(reason="Ollama not reachable at http://localhost:11434 — normal suite does not require it")
    for item in items:
        if "ollama" in item.keywords:
            item.add_marker(skip_ollama)


@pytest.fixture()
def mcp(tmp_path):
    config = MCPConfig(journal_path=str(tmp_path / "journal.jsonl"))
    return MCPServer(config)


def make_request(evidence_ids, statement="Requete de test.", endpoint="GENERATOR_COPILOT_STUDIO", **overrides):
    request = {
        "session_id": SESSION_ID,
        "correlation_id": CORRELATION_ID,
        "endpoint": endpoint,
        "statement": statement,
        "evidence_ids": evidence_ids,
    }
    request.update(overrides)
    return request
