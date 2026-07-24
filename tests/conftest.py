import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from mcp_server.config import MCPConfig
from mcp_server.orchestrator import MCPServer

SESSION_ID = "SES-20260722-PILOT"
CORRELATION_ID = "COR-20260722-PILOT"


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
