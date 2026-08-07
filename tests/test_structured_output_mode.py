"""Structured-output capability detection (spec: "Investigate constrained
JSON support"). Covers mcp_server/llamacpp_config.py's
GENERATOR_STRUCTURED_OUTPUT_MODE validation and
mcp_server/llm_roles/llamacpp_client.py's probe/resolve/payload-building
logic. Pydantic validation remains authoritative regardless of mode --
these tests only cover which `response_format` gets sent, never bypass
mcp_server/generator_claims.py's own checks.
"""

import asyncio

import pytest

from mcp_server.generator_prompts import GENERATED_CLAIM_JSON_SCHEMA
from mcp_server.llamacpp_config import STRUCTURED_OUTPUT_MODES, InvalidStructuredOutputMode, LlamaCppConfig
from mcp_server.llm_roles import llamacpp_client
from mcp_server.llm_roles.llamacpp_client import (
    _response_format_for_mode,
    resolve_structured_output_mode,
)

pytestmark = pytest.mark.unit


def test_all_four_modes_are_valid():
    for mode in ("auto", "json_schema", "json_object", "disabled"):
        assert mode in STRUCTURED_OUTPUT_MODES
        LlamaCppConfig(structured_output_mode=mode)  # must not raise


def test_invalid_mode_fails_at_construction():
    with pytest.raises(InvalidStructuredOutputMode):
        LlamaCppConfig(structured_output_mode="not_a_real_mode")


def test_json_schema_mode_resolves_to_the_generated_claim_schema():
    fmt = _response_format_for_mode("json_schema")
    assert fmt == {"type": "json_schema", "json_schema": GENERATED_CLAIM_JSON_SCHEMA}


def test_json_object_mode_preserves_existing_behavior():
    assert _response_format_for_mode("json_object") == {"type": "json_object"}


def test_disabled_mode_omits_response_format_entirely():
    assert _response_format_for_mode("disabled") is None


def test_pinned_modes_never_probe(monkeypatch):
    probed = {"called": False}

    async def _fake_probe(config, *, timeout_seconds=5.0):
        probed["called"] = True
        return True

    monkeypatch.setattr(llamacpp_client, "probe_structured_output_capability", _fake_probe)

    for mode in ("json_schema", "json_object", "disabled"):
        config = LlamaCppConfig(structured_output_mode=mode)
        resolved = asyncio.run(resolve_structured_output_mode(config))
        assert resolved == mode
    assert probed["called"] is False


def test_auto_mode_falls_back_to_json_object_when_probe_fails(monkeypatch):
    async def _unsupported(config, *, timeout_seconds=5.0):
        return False

    monkeypatch.setattr(llamacpp_client, "probe_structured_output_capability", _unsupported)
    llamacpp_client._capability_cache.clear()

    config = LlamaCppConfig(structured_output_mode="auto", base_url="http://probe-test-1:8080/v1")
    resolved = asyncio.run(resolve_structured_output_mode(config))
    assert resolved == "json_object"


def test_auto_mode_uses_json_schema_when_the_server_supports_it(monkeypatch):
    async def _supported(config, *, timeout_seconds=5.0):
        return True

    monkeypatch.setattr(llamacpp_client, "probe_structured_output_capability", _supported)
    llamacpp_client._capability_cache.clear()

    config = LlamaCppConfig(structured_output_mode="auto", base_url="http://probe-test-2:8080/v1")
    resolved = asyncio.run(resolve_structured_output_mode(config))
    assert resolved == "json_schema"


def test_auto_mode_caches_the_probe_result_per_base_url(monkeypatch):
    call_count = {"n": 0}

    async def _counting_probe(config, *, timeout_seconds=5.0):
        call_count["n"] += 1
        return True

    monkeypatch.setattr(llamacpp_client, "probe_structured_output_capability", _counting_probe)
    llamacpp_client._capability_cache.clear()

    config = LlamaCppConfig(structured_output_mode="auto", base_url="http://probe-test-3:8080/v1")
    asyncio.run(resolve_structured_output_mode(config))
    asyncio.run(resolve_structured_output_mode(config))
    assert call_count["n"] == 1


def test_probe_never_raises_when_server_unreachable():
    config = LlamaCppConfig(base_url="http://definitely-not-a-real-host-xyz:8080/v1")
    result = asyncio.run(llamacpp_client.probe_structured_output_capability(config, timeout_seconds=0.5))
    assert result is False
