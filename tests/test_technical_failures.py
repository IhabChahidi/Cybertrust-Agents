"""TC-18 — LLM timeout, TC-19 — secrets never appear in clear in the journal."""

from mcp_server.errors import EventCode
from mcp_server.llm_roles.base import Generator
from mcp_server.logging_utils import redact
from tests.conftest import make_request


class TimeoutGenerator(Generator):
    def generate(self, **kwargs):
        raise TimeoutError("provider did not respond in time")


def test_tc18_llm_timeout_yields_technical_failure_not_block(mcp):
    """A provider timeout must land in TECHNICAL_FAILURE, never be logged as a security block."""
    mcp.generator = TimeoutGenerator()
    result = mcp.process_request(make_request(["EVD-0001"]))

    assert result["mcp_state"] == "TECHNICAL_FAILURE"
    assert result["failure_reason"] == EventCode.LLM_TIMEOUT.value


def test_tc19_secret_in_statement_is_redacted_in_journal(mcp):
    """A fictitious secret embedded in the request must never reach the journal in clear."""
    secret_statement = "Contexte: api_key=SUPERSECRET12345 doit etre ignore lors du traitement."
    mcp.process_request(make_request(["EVD-0001"], statement=secret_statement))

    # The orchestrator does not log the raw statement itself today, but any
    # future event detail containing it must come out redacted.
    for event in mcp.audit.events:
        assert "SUPERSECRET12345" not in str(event)


def test_redact_masks_common_secret_shapes():
    assert "SUPERSECRET12345" not in redact("api_key=SUPERSECRET12345")
    assert "[REDACTED]" in redact("api_key=SUPERSECRET12345")
    assert "[REDACTED]" in redact("Authorization: Bearer abc.def.ghi")
    assert "[REDACTED]" in redact("token: my-token-value")
