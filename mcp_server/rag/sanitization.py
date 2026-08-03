"""Prompt-injection heuristics for retrieved/ingested text (spec sections 10).

Reuses the same philosophy already established in mcp_server/orchestrator.py's
_INJECTION_PATTERNS/_EXFILTRATION_PATTERNS (which scan the CISO's request
statement and Evidence content before the Generator/Verifier ever see them):
retrieved RAG chunks are just as untrusted as that Evidence content, so they go
through an equivalent scan before being placed in the context. This module does
NOT replace the orchestrator's own scan (which still runs on the actual
Evidence selected for the pipeline) — it covers the additional surface RAG
introduces: ingested reference documents and retrieved chunks that never pass
through the orchestrator's existing checks.

Documented limitation (spec section 10's own requirement): these are heuristics.
They reduce risk; they do not guarantee complete prompt-injection prevention.
"""

import re

_INJECTION_PATTERNS = [
    re.compile(r"ignore (all )?(previous|prior) instructions", re.IGNORECASE),
    re.compile(r"disregard (all )?(prior|previous) instructions", re.IGNORECASE),
    re.compile(r"reveal (the )?(system|hidden) prompt", re.IGNORECASE),
    re.compile(r"\byou are now\b", re.IGNORECASE),
    re.compile(r"\bsystem\s*:\s*", re.IGNORECASE),
    re.compile(r"\bassistant\s*:\s*", re.IGNORECASE),
    re.compile(r"verifier\s*:\s*return\s+\w+", re.IGNORECASE),
    re.compile(r"policy engine instruction", re.IGNORECASE),
]

_SCRIPT_PATTERNS = [
    re.compile(r"<script[\s>]", re.IGNORECASE),
    re.compile(r"<iframe[\s>]", re.IGNORECASE),
    re.compile(r"on\w+\s*=\s*[\"']", re.IGNORECASE),  # onerror=, onclick=, ...
    re.compile(r"javascript:", re.IGNORECASE),
]

MAX_CHUNK_CHARS = 2000  # cap on any single retrieved chunk before it enters the context


class InjectionScanResult:
    def __init__(self, matched_patterns: list[str], suspicious: bool):
        self.matched_patterns = matched_patterns
        self.suspicious = suspicious


def scan_for_injection(text: str) -> InjectionScanResult:
    """Never raises; never modifies the text. Callers decide whether to exclude
    a suspicious chunk from generation (spec: "optionally exclude suspicious
    chunks... retain excluded chunks for audit")."""
    text = text or ""
    matched = []
    for pattern in (*_INJECTION_PATTERNS, *_SCRIPT_PATTERNS):
        if pattern.search(text):
            matched.append(pattern.pattern)
    return InjectionScanResult(matched_patterns=matched, suspicious=bool(matched))


def cap_chunk(text: str, max_chars: int = MAX_CHUNK_CHARS) -> str:
    """Truncate a chunk defensively. Callers building context records must still
    apply this AFTER preserving identifiers/dates/authority classification in
    separate structured fields (spec section 4: never let truncation remove
    those) — this caps only the free-text `content` field.
    """
    text = text or ""
    return text if len(text) <= max_chars else text[:max_chars] + " …[truncated]"
