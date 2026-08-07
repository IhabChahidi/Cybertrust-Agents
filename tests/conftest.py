import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Deterministic dev credentials for the dashboard auth tests
# (tests/test_web_auth.py, web/auth.py). MUST be set here, in conftest.py --
# pytest guarantees this module is imported before any test module in this
# directory, which is what makes this deterministic. web/auth.py seeds its
# in-memory user table from these env vars ONCE, at web.backend's import
# time; several other test files (test_generator_api.py,
# test_generator_verifier_validator_integration.py) also import web.backend
# and, alphabetically, collect before test_web_auth.py. Setting these only
# inside test_web_auth.py itself (as it used to) meant whichever of those
# other files happened to import web.backend first won the race: on a
# machine with a local .env already setting CISO_DEV_PASSWORD (never
# committed, gitignored), load_dotenv()'s default of not overriding existing
# env vars papered over the bug by coincidence; on a clean CI checkout with
# no .env, web.auth fell back to generating a random dev password before
# test_web_auth.py's own os.environ.setdefault() ever ran, and every login
# in that file failed with 401 -- a real bug, not a CI-specific quirk.
os.environ.setdefault("CISO_DEV_USERNAME", "ciso")
os.environ.setdefault("CISO_DEV_PASSWORD", "test-ciso-pass-001")
os.environ.setdefault("DELEGATE_DEV_USERNAME", "ciso.delegate")
os.environ.setdefault("DELEGATE_DEV_PASSWORD", "test-delegate-pass-002")

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
    skip_ollama = pytest.mark.skip(reason="Ollama not reachable at http://localhost:11434 — normal suite does not require it")
    ollama_up = _ollama_available()

    # real_model tests (tests/test_real_model_generator.py) hit a live
    # llama.cpp server hosting the actual Foundation-Sec GGUF -- never run in
    # normal CI/dev, opt-in only via RUN_REAL_MODEL_TESTS=true (spec section 8:
    # "Do not require the GGUF model in normal CI").
    run_real_model = os.environ.get("RUN_REAL_MODEL_TESTS", "").strip().lower() == "true"
    skip_real_model = pytest.mark.skip(
        reason="real_model tests are opt-in only; set RUN_REAL_MODEL_TESTS=true to run them against a live llama.cpp server"
    )

    for item in items:
        if "ollama" in item.keywords and not ollama_up:
            item.add_marker(skip_ollama)
        if "real_model" in item.keywords and not run_real_model:
            item.add_marker(skip_real_model)


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
