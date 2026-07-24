"""Validate the Evidence catalogue against the Evidence JSON schema.

- catalogue/valid/   must ALL pass schema validation, hash verification and the
  prompt-injection guard. Any failure here is a real defect (exit code 1).
- catalogue/negative/ must ALL fail. A negative file that unexpectedly passes is
  itself a defect (exit code 1), because it means the validator missed a case it
  is supposed to catch.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

from jsonschema import Draft7Validator

ROOT = Path(__file__).resolve().parent.parent
VALID_DIR = ROOT / "catalogue" / "valid"
NEGATIVE_DIR = ROOT / "catalogue" / "negative"

EVIDENCE_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Evidence",
    "description": "Preuve SecOps fictive constituant la base factuelle obligatoire de tout Claim.",
    "type": "object",
    "required": [
        "schema_version", "session_id", "correlation_id", "id", "source",
        "date", "type", "content", "severity", "integrity_hash",
    ],
    "additionalProperties": False,
    "properties": {
        "schema_version": {"type": "string", "const": "1.0"},
        "session_id": {"type": "string", "pattern": "^SES-[A-Z0-9-]{8,50}$"},
        "correlation_id": {"type": "string", "pattern": "^COR-[A-Z0-9-]{8,50}$"},
        "id": {"type": "string", "pattern": "^EVD-[0-9]{4}$"},
        "source": {"type": "string", "maxLength": 100},
        "date": {"type": "string", "format": "date-time"},
        "type": {
            "type": "string",
            "enum": ["ticket", "report", "scan_result", "audit_record", "validation_record"],
        },
        "content": {
            "type": "object",
            "required": ["summary", "raw_data"],
            "additionalProperties": False,
            "properties": {
                "summary": {"type": "string", "minLength": 1, "maxLength": 500},
                "raw_data": {"type": "string", "maxLength": 5000},
                "affected_assets": {
                    "type": "array", "maxItems": 20, "uniqueItems": True,
                    "items": {"type": "string", "maxLength": 100},
                },
                "indicators": {
                    "type": "array", "maxItems": 20, "uniqueItems": True,
                    "items": {"type": "string", "maxLength": 100},
                },
            },
        },
        "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
        "integrity_hash": {"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"},
    },
}

VALIDATOR = Draft7Validator(EVIDENCE_SCHEMA)

# Minimal TC-10 / TC-11 guard: base prompt-injection / exfiltration phrasing.
INJECTION_PATTERNS = [
    re.compile(r"ignore (all )?previous instructions", re.IGNORECASE),
    re.compile(r"disregard (all )?(prior|previous) instructions", re.IGNORECASE),
    re.compile(r"return all (available )?evidence", re.IGNORECASE),
    re.compile(r"reveal (the )?(system|hidden) prompt", re.IGNORECASE),
]


def schema_errors(data: dict) -> list[str]:
    return [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
            for e in VALIDATOR.iter_errors(data)]


def hash_error(data: dict) -> str | None:
    content = data.get("content")
    declared = data.get("integrity_hash")
    if content is None or declared is None:
        return None  # already reported as a schema error
    canonical = json.dumps(content, sort_keys=True)
    expected = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if declared != expected:
        return f"integrity_hash mismatch: declared={declared} expected={expected}"
    return None


def injection_error(data: dict) -> str | None:
    content = data.get("content", {})
    for field in ("summary", "raw_data"):
        value = content.get(field, "")
        if not isinstance(value, str):
            continue
        for pattern in INJECTION_PATTERNS:
            if pattern.search(value):
                return f"prompt-injection pattern detected in content.{field}: {pattern.pattern!r}"
    return None


def validate_file(path: Path) -> tuple[bool, bool, list[str]]:
    """Return (schema_ok, hash_ok, errors). Injection errors are appended to errors."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return False, False, [f"invalid JSON: {exc}"]

    errors = schema_errors(data)
    schema_ok = not errors

    h_err = hash_error(data) if schema_ok else None
    hash_ok = h_err is None
    if h_err:
        errors.append(h_err)

    inj_err = injection_error(data)
    if inj_err:
        errors.append(inj_err)

    return schema_ok, hash_ok and not inj_err, errors


def print_table(rows: list[tuple[str, str, str, str, list[str]]]) -> None:
    print(f"{'ID':<12}{'Schema':<10}{'Hash':<10}{'Result':<8}")
    print("-" * 40)
    for evd_id, schema_col, hash_col, result, errors in rows:
        print(f"{evd_id:<12}{schema_col:<10}{hash_col:<10}{result:<8}")
        for err in errors:
            print(f"    - {err}")


def main() -> int:
    overall_ok = True

    print("== catalogue/valid ==")
    valid_files = sorted(VALID_DIR.glob("EVD-*.json"))
    rows = []
    pass_count = 0
    for path in valid_files:
        schema_ok, hash_ok, errors = validate_file(path)
        passed = schema_ok and hash_ok and not errors
        if passed:
            pass_count += 1
        else:
            overall_ok = False
        rows.append((
            path.stem,
            "PASS" if schema_ok else "FAIL",
            "PASS" if hash_ok else "FAIL",
            "PASS" if passed else "FAIL",
            errors,
        ))
    print_table(rows)
    print(f"\n{pass_count}/{len(valid_files)} valid Evidence files PASS\n")

    print("== catalogue/negative (expected to FAIL) ==")
    negative_files = sorted(NEGATIVE_DIR.glob("EVD-*.json"))
    rows = []
    expected_fail_count = 0
    for path in negative_files:
        schema_ok, hash_ok, errors = validate_file(path)
        passed = schema_ok and hash_ok and not errors
        if passed:
            overall_ok = False  # a negative file must NOT pass
        else:
            expected_fail_count += 1
        rows.append((
            path.stem,
            "PASS" if schema_ok else "FAIL",
            "PASS" if hash_ok else "FAIL",
            "PASS (unexpected!)" if passed else "FAIL (expected)",
            errors,
        ))
    print_table(rows)
    print(f"\n{expected_fail_count}/{len(negative_files)} negative Evidence files correctly FAIL\n")

    if len(negative_files) != 3:
        print(f"ERROR: expected exactly 3 negative Evidence files, found {len(negative_files)}")
        overall_ok = False

    if overall_ok:
        print("Conformance check PASSED.")
    else:
        print("Conformance check FAILED.")

    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
