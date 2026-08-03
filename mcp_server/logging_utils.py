"""Append-only JSONL audit journal (L4 section 7).

Every event carries event_id, session_id, correlation_id, a UTC timestamp, the
MCP state, the event type, the role involved, and the result. Secrets/tokens are
redacted before anything touches disk or memory-held history (TC-19).
"""

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Redact common secret shapes: API keys, bearer tokens, generic "token=" pairs.
_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)([^\s;,\"]+)"),
    re.compile(r"(?i)(bearer\s+)([A-Za-z0-9\-_.]+)"),
    re.compile(r"(?i)(token\s*[:=]\s*)([^\s;,\"]+)"),
    re.compile(r"(?i)(secret\s*[:=]\s*)([^\s;,\"]+)"),
]


def redact(text: str) -> str:
    """Replace anything that looks like a secret/token/API key with a fixed marker."""
    if not isinstance(text, str):
        return text
    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(lambda m: f"{m.group(1)}[REDACTED]", redacted)
    return redacted


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    return value


@dataclass
class AuditLogger:
    """In-memory + on-disk audit trail for a single MCP session."""

    journal_path: str
    events: list = field(default_factory=list)

    def log(self, *, session_id: str, correlation_id: str, state: str,
            event_type: str, role: str, result: str, detail: str = "") -> dict:
        event = {
            "event_id": f"EVT-{uuid.uuid4().hex[:12].upper()}",
            "session_id": session_id,
            "correlation_id": correlation_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "state": state,
            "event_type": event_type,
            "role": role,
            "result": result,
            "detail": _redact_value(detail),
        }
        self.events.append(event)
        self._append_to_disk(event)
        return event

    def _append_to_disk(self, event: dict) -> None:
        path = Path(self.journal_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    def transitions(self, session_id: str | None = None) -> list:
        """Ordered list of MCP states passed through.

        AuditLogger instances are long-lived (one per llm_mode, cached across
        every request -- see web/generator_api.py's _mcp_servers), so
        self.events accumulates every event ever logged by this instance, not
        just the current session's. Without session_id, this returns that
        entire cross-session history; callers building a single session's
        response MUST pass session_id to get only that session's transitions.
        """
        events = self.events if session_id is None else [e for e in self.events if e["session_id"] == session_id]
        return [e["state"] for e in events]
