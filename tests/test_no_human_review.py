"""Repository-wide governance check (section 11 of the CISO-only routing spec).

The literal HUMAN_REVIEW value (and its predecessor APPROVED_FOR_CISO_REVIEW)
must never be PRODUCIBLE anywhere in this repository: no enum, no returned
string, no frontend option, no schema value. This test scans every .py/.js/.md
file under mcp_server/, web/, docs/, and tests/ for the value used as an actual
quoted string literal (`"HUMAN_REVIEW"` / `'HUMAN_REVIEW'`) — the shape it would
take if it were an enum member, a dict value, or a comparison target.

Plain-English mentions in comments/docs explaining that the value does NOT
exist (e.g. "there is no HUMAN_REVIEW status") are not flagged: they never
appear as a quoted literal, only as prose. That distinction is the point of
using a quoted-literal regex instead of a blind substring search.

Explicitly excluded (per the governance spec, "migration code and historical
migration tests may be explicitly excluded"):
  - mcp_server/policy.py: the documented, deprecated legacy-alias migration
    dict (_LEGACY_DECISION_ALIASES) intentionally maps the OLD value to a
    current one for reading historical data; it is never returned by decide().
  - tests/test_policy.py: tests of that migration path, and assertions proving
    the *absence* of the old value in live output.
  - docs/s3_llama_test_results.md: explicitly marked historical snapshot
    predating the CISO-only routing redesign (see the note at its top).
  - this file itself, which must name the strings to scan for them.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_ALLOWED_FILES = {
    REPO_ROOT / "tests" / "test_no_human_review.py",
    REPO_ROOT / "mcp_server" / "policy.py",
    REPO_ROOT / "tests" / "test_policy.py",
    # Proves a config rule NAMING HUMAN_REVIEW is rejected at load time -- an
    # adversarial-config test, not a producible value (see spec section 7.4).
    REPO_ROOT / "tests" / "test_policy_config.py",
    # Proves malformed/adversarial Verifier output never yields a legacy value
    # in the final result -- asserts the ABSENCE of these literals, doesn't
    # produce them.
    REPO_ROOT / "tests" / "test_adversarial.py",
    # Live-Ollama integration test asserting the ABSENCE of legacy values in
    # real-model output; skipped automatically when Ollama is unavailable.
    REPO_ROOT / "tests" / "test_ollama_integration.py",
    REPO_ROOT / "docs" / "s3_llama_test_results.md",
}

_SCAN_DIRS = ["mcp_server", "web", "docs", "tests"]
_SCAN_EXTENSIONS = {".py", ".js", ".md", ".html", ".css"}

_QUOTED_LITERAL_RE = {
    "HUMAN_REVIEW": re.compile(r"""["']HUMAN_REVIEW["']"""),
    "APPROVED_FOR_CISO_REVIEW": re.compile(r"""["']APPROVED_FOR_CISO_REVIEW["']"""),
}


def _iter_scanned_files():
    for dirname in _SCAN_DIRS:
        base = REPO_ROOT / dirname
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix in _SCAN_EXTENSIONS and "__pycache__" not in path.parts:
                yield path


def _find_offenders(pattern: re.Pattern) -> list[str]:
    offenders = []
    for path in _iter_scanned_files():
        if path in _ALLOWED_FILES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if pattern.search(text):
            offenders.append(str(path.relative_to(REPO_ROOT)))
    return offenders


def test_human_review_is_not_a_producible_literal_anywhere():
    offenders = _find_offenders(_QUOTED_LITERAL_RE["HUMAN_REVIEW"])
    assert not offenders, (
        f"'HUMAN_REVIEW' found as a quoted string literal (a producible value) "
        f"outside the allowed migration/historical files: {offenders}"
    )


def test_approved_for_ciso_review_is_not_a_producible_literal_anywhere():
    offenders = _find_offenders(_QUOTED_LITERAL_RE["APPROVED_FOR_CISO_REVIEW"])
    assert not offenders, (
        f"'APPROVED_FOR_CISO_REVIEW' found as a quoted string literal (a producible value) "
        f"outside the allowed migration/historical files: {offenders}"
    )


def test_validation_decision_schema_enum_has_no_legacy_values():
    from mcp_server.schemas import VALIDATION_DECISION_SCHEMA

    enum = VALIDATION_DECISION_SCHEMA["properties"]["decision"]["enum"]
    assert "HUMAN_REVIEW" not in enum
    assert "APPROVED_FOR_CISO_REVIEW" not in enum
    assert set(enum) == {
        "READY_FOR_CISO_DECISION", "READY_FOR_CISO_INFORMATION",
        "REJECTED", "INSUFFICIENT_EVIDENCE",
    }


def test_policy_engine_module_constants_have_no_legacy_values():
    from mcp_server.policy import VALID_DECISIONS

    assert "HUMAN_REVIEW" not in VALID_DECISIONS
    assert "APPROVED_FOR_CISO_REVIEW" not in VALID_DECISIONS
