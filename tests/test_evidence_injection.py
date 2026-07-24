"""TC-10/TC-11 via Evidence content (not the request statement).

catalogue/negative/EVD-N003.json embeds a prompt-injection payload in
content.raw_data. The MCP must block it during SELECTION_EVIDENCE, before the
Evidence ever reaches a Generator/Verifier prompt — a request statement scan
alone is not enough.
"""

import json
import shutil
from pathlib import Path

from mcp_server.config import MCPConfig
from mcp_server.errors import EventCode
from mcp_server.orchestrator import MCPServer
from tests.conftest import make_request

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_evidence_embedded_injection_blocked_before_generation(tmp_path):
    valid_dir = tmp_path / "valid"
    valid_dir.mkdir()
    shutil.copy(REPO_ROOT / "catalogue" / "negative" / "EVD-N003.json", valid_dir / "EVD-0099.json")

    config = MCPConfig(catalogue_valid_dir=str(valid_dir), journal_path=str(tmp_path / "journal.jsonl"))
    mcp = MCPServer(config)

    result = mcp.process_request(make_request(["EVD-0099"]))

    assert result["mcp_state"] == "BLOCKED"
    assert result["blocked_reason"] == EventCode.PROMPT_INJECTION.value
    assert "transitions" in result and "GENERATION_CLAIM" not in result["transitions"]
