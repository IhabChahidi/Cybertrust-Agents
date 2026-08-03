#!/usr/bin/env python
"""Final validation gate before connecting the Foundation-Sec/RAG Generator
to the Verifier (spec section 10). Aggregates every prerequisite this
hardening phase produced and returns a single, unambiguous verdict -- never
overridable by a manual boolean environment variable (spec: "Do not allow a
manual boolean environment variable to bypass these checks" -- this script
takes no --force/--skip-checks flag of any kind).

Usage:
    python scripts/check_generator_readiness.py

Exit codes:
    0 - READY_FOR_VERIFIER_INTEGRATION
    1 - NOT_READY_FOR_VERIFIER_INTEGRATION
    2 - configuration or execution error (a check itself could not run)
"""

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

REAL_MODEL_SUMMARY = REPO_ROOT / "artifacts" / "real_model" / "summary.json"
DOCKER_RESULT = REPO_ROOT / "artifacts" / "docker_validation" / "result.json"

# Test files that must pass for the gate to even consider passing (spec
# section 10: "unit and mocked integration test results", "exact identifier-
# routing tests"). Run together, excluding real_model/ollama (those are
# checked separately via their own artifacts, not by re-running them here).
REQUIRED_TEST_TARGETS = [
    "tests/",
]
PYTEST_MARKER_EXPR = "not ollama and not real_model"


class Check:
    def __init__(self, name: str, passed: bool, detail: str):
        self.name = name
        self.passed = passed
        self.detail = detail


def _run_pytest() -> Check:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-m", PYTEST_MARKER_EXPR, *REQUIRED_TEST_TARGETS],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    tail = "\n".join(result.stdout.strip().splitlines()[-5:])
    return Check("non_real_model_tests_pass", result.returncode == 0, tail)


def _check_config_validity() -> Check:
    try:
        from mcp_server.config import MCPConfig
        from mcp_server.llamacpp_config import LlamaCppConfig
        MCPConfig()
        LlamaCppConfig()
        return Check("configuration_valid", True, "MCPConfig/LlamaCppConfig construct cleanly from the current environment")
    except Exception as exc:  # noqa: BLE001 -- report as a failed check, not a crash
        return Check("configuration_valid", False, f"{type(exc).__name__}: {exc}")


def _check_real_model_evaluation() -> Check:
    if not REAL_MODEL_SUMMARY.exists():
        return Check(
            "real_model_evaluation_passed", False,
            f"{REAL_MODEL_SUMMARY} does not exist -- the real-model suite has never been run "
            "(RUN_REAL_MODEL_TESTS=true python -m pytest tests/test_real_model_generator.py -m real_model)",
        )
    try:
        summary = json.loads(REAL_MODEL_SUMMARY.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return Check("real_model_evaluation_passed", False, f"{REAL_MODEL_SUMMARY} is not valid JSON: {exc}")

    if summary.get("zero_tolerance_failures"):
        reasons = ", ".join(f"{f['scenario']}:{f['reason']}" for f in summary["zero_tolerance_failures"])
        return Check("real_model_evaluation_passed", False, f"zero-tolerance failures: {reasons}")

    passed = bool(summary.get("overall_passed"))
    return Check("real_model_evaluation_passed", passed, f"overall_passed={passed}, scenarios={summary.get('scenario_count')}")


def _check_docker_validation() -> Check:
    if not DOCKER_RESULT.exists():
        return Check(
            "docker_runtime_validated", False,
            f"{DOCKER_RESULT} does not exist -- scripts/validate_docker_runtime.py has never been run",
        )
    try:
        result = json.loads(DOCKER_RESULT.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return Check("docker_runtime_validated", False, f"{DOCKER_RESULT} is not valid JSON: {exc}")

    if not result.get("executed", False):
        return Check("docker_runtime_validated", False, "Docker CLI was not available when validate_docker_runtime.py last ran")
    passed = bool(result.get("passed"))
    return Check("docker_runtime_validated", passed, f"passed={passed}, checks={result.get('checks')}")


def run_all_checks() -> list[Check]:
    return [
        _check_config_validity(),
        _run_pytest(),
        _check_real_model_evaluation(),
        _check_docker_validation(),
    ]


def main() -> int:
    try:
        checks = run_all_checks()
    except Exception as exc:  # noqa: BLE001 -- a crash here is a configuration/execution error, not "not ready"
        print(f"CONFIGURATION_OR_EXECUTION_ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    print("=== Generator readiness checks ===")
    for check in checks:
        print(f"  [{'PASS' if check.passed else 'FAIL'}] {check.name}: {check.detail}")

    ready = all(check.passed for check in checks)
    verdict = "READY_FOR_VERIFIER_INTEGRATION" if ready else "NOT_READY_FOR_VERIFIER_INTEGRATION"
    print(f"\n{verdict}")
    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
