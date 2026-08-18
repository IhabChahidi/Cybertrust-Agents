"""mcp_server/llm_roles/ollama_client.py::call_ollama -- payload construction,
notably keep_alive (asymmetric memory strategy added this session: the
Verifier's Ollama model should release memory promptly since the Generator's
llama.cpp process stays loaded continuously -- see the docstring on
call_ollama and MCPConfig.ollama_keep_alive)."""

import pytest

from mcp_server.llm_roles.ollama_client import call_ollama

pytestmark = pytest.mark.unit


class _FakeResponse:
    status_code = 200

    def json(self):
        return {"message": {"content": '{"ok": true}'}}


def test_keep_alive_defaults_to_immediate_unload(monkeypatch):
    captured = {}

    def fake_post(url, json, timeout):
        captured["payload"] = json
        return _FakeResponse()

    monkeypatch.setattr("mcp_server.llm_roles.ollama_client.requests.post", fake_post)
    call_ollama(host="http://x", model="m", system_prompt="s", user_prompt="u", json_schema={}, timeout_seconds=5)
    assert captured["payload"]["keep_alive"] == "0"


def test_keep_alive_is_configurable(monkeypatch):
    captured = {}

    def fake_post(url, json, timeout):
        captured["payload"] = json
        return _FakeResponse()

    monkeypatch.setattr("mcp_server.llm_roles.ollama_client.requests.post", fake_post)
    call_ollama(
        host="http://x", model="m", system_prompt="s", user_prompt="u", json_schema={}, timeout_seconds=5,
        keep_alive="30s",
    )
    assert captured["payload"]["keep_alive"] == "30s"
