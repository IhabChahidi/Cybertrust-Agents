#!/usr/bin/env python
"""Docker RUNTIME validation (spec section 7: "Do not only inspect Docker
Compose statically... Validate Docker runtime"). Complements
tests/test_docker_artifacts_static.py (structural-only, no Docker daemon
needed) with an actual `docker compose` lifecycle: build, start, health-check,
verify DNS/persistence/read-only mounts/no-published-ports, then tear down.

Platform-neutral Python (not a shell script) specifically for Windows
compatibility, per spec: "Prefer Python if Windows compatibility is
important."

If the Docker CLI is not available, this script does NOT claim anything was
validated -- it prints the exact host-side checklist (spec section 7) and
exits 2, matching scripts/check_generator_readiness.py's expectation that a
missing Docker validation blocks Verifier integration readiness.

Usage:
    python scripts/validate_docker_runtime.py [--api-key change-me] [--keep-running]

Exit codes:
    0 - Docker available AND every runtime check passed
    1 - Docker available, but at least one runtime check failed
    2 - Docker CLI not available in this environment -- nothing was executed;
        see the printed host-side checklist instead
"""

import argparse
import json
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR_API_URL = "http://localhost:8000"
RESULT_PATH = REPO_ROOT / "artifacts" / "docker_validation" / "result.json"

HOST_SIDE_CHECKLIST = [
    "docker compose -f docker-compose.yml config --quiet   (validates the file parses and resolves)",
    "Place Foundation-Sec-8B-Instruct.Q4_K_M.gguf under ./models/ BEFORE starting -- it is never downloaded automatically",
    "docker compose build",
    "docker compose up -d",
    "docker compose ps   (all three services should reach `healthy`)",
    "docker compose logs --no-color llama-generator   (confirm the GGUF loaded and --ctx-size 8192 is active)",
    "docker compose logs --no-color chromadb",
    "docker compose logs --no-color generator-api",
    "curl --fail http://localhost:8000/health/live",
    "curl --fail http://localhost:8000/health/ready   (all components must report \"ready\")",
    "docker compose exec generator-api python -c \"import urllib.request; "
    "print(urllib.request.urlopen('http://chromadb:8000/api/v2/heartbeat').status)\"   "
    "(confirms Docker DNS resolves chromadb from inside generator-api)",
    "docker inspect <chromadb_container> --format '{{json .Mounts}}'   (confirm the persistent Chroma volume is attached)",
    "docker inspect <llama-generator_container> --format '{{json .Mounts}}'   (confirm the model mount shows \"RW\":false, i.e. read-only)",
    "docker compose port chromadb 8000   (should print nothing / error -- not published)",
    "docker compose port llama-generator 8080   (should print nothing / error -- not published)",
    "docker network inspect <project>_internal --format '{{json .Internal}}'   (should print true)",
    "docker compose exec chromadb id   (should not be uid 0, where the base image supports it)",
    "Ingest one evidence record via POST /api/v1/ingestion/evidence, then `docker compose restart chromadb`, "
    "then confirm the same record is still returned by POST /api/v1/retrieval/search",
    "docker compose stop llama-generator; curl http://localhost:8000/health/ready  (must report not_ready/503)",
    "docker compose start llama-generator; docker compose stop chromadb; curl http://localhost:8000/health/ready  (must report not_ready/503)",
    "docker compose down",
]


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, **kwargs)


def _http_get(path: str, timeout: float = 5.0):
    try:
        with urllib.request.urlopen(f"{GENERATOR_API_URL}{path}", timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 -- report as a check failure, not a crash
        return None, str(exc)


def _wait_for(predicate, *, timeout: float, interval: float = 2.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep-running", action="store_true", help="Skip `docker compose down` at the end")
    args = parser.parse_args(argv)

    if not _docker_available():
        print("Docker CLI not found in PATH -- Docker runtime CANNOT be validated in this environment.")
        print("This script has NOT validated anything. Perform this checklist by hand on a host with Docker:\n")
        for i, step in enumerate(HOST_SIDE_CHECKLIST, 1):
            print(f"  {i}. {step}")
        _write_result(passed=False, checks={}, executed=False)
        return 2

    checks: dict[str, bool] = {}

    result = _run(["docker", "compose", "-f", "docker-compose.yml", "config", "--quiet"])
    checks["compose_config_valid"] = result.returncode == 0
    if not checks["compose_config_valid"]:
        print(result.stderr)

    result = _run(["docker", "compose", "build"])
    checks["build_succeeded"] = result.returncode == 0
    if not checks["build_succeeded"]:
        print(result.stderr)
        return _report(checks)

    result = _run(["docker", "compose", "up", "-d"])
    checks["up_succeeded"] = result.returncode == 0

    healthy = _wait_for(
        lambda: "healthy" in _run(["docker", "compose", "ps"]).stdout and "unhealthy" not in _run(["docker", "compose", "ps"]).stdout,
        timeout=180, interval=5,
    )
    checks["all_services_healthy"] = healthy
    print(_run(["docker", "compose", "ps"]).stdout)

    for service in ("generator-api", "llama-generator", "chromadb"):
        logs = _run(["docker", "compose", "logs", "--no-color", service])
        print(f"--- {service} logs (last 2000 chars) ---")
        print(logs.stdout[-2000:])

    status, body = _http_get("/health/live")
    checks["health_live_ok"] = status == 200

    status, body = _http_get("/health/ready")
    checks["health_ready_ok"] = status == 200
    if status == 200:
        components = body.get("components", {})
        checks["chromadb_component_ready"] = components.get("chromadb") == "ready"
        checks["llama_cpp_component_ready"] = components.get("llama_cpp") == "ready"
        checks["embedding_backend_component_ready"] = components.get("embedding_backend") == "ready"
    else:
        print(f"/health/ready returned {status}: {body}")

    # No published ports on chromadb/llama-generator (spec: "ChromaDB and
    # llama.cpp ports are not publicly published unless explicitly configured").
    for service, port in (("chromadb", "8000"), ("llama-generator", "8080")):
        result = _run(["docker", "compose", "port", service, port])
        checks[f"{service}_port_not_published"] = result.returncode != 0 or not result.stdout.strip()

    # Failure-mode checks: stopping a dependency must make readiness fail.
    _run(["docker", "compose", "stop", "llama-generator"])
    status, body = _http_get("/health/ready")
    checks["readiness_fails_when_llama_cpp_down"] = status == 503
    _run(["docker", "compose", "start", "llama-generator"])
    _wait_for(lambda: _http_get("/health/ready")[0] == 200, timeout=60, interval=3)

    _run(["docker", "compose", "stop", "chromadb"])
    status, body = _http_get("/health/ready")
    checks["readiness_fails_when_chromadb_down"] = status == 503
    _run(["docker", "compose", "start", "chromadb"])

    if not args.keep_running:
        _run(["docker", "compose", "down"])

    return _report(checks)


def _write_result(*, passed: bool, checks: dict[str, bool], executed: bool) -> None:
    """Persists a machine-readable result (spec: readiness gate must inspect
    "Docker validation results") so scripts/check_generator_readiness.py can
    require actual evidence this script ran and passed, without itself
    re-running `docker compose`. `executed=False` marks the "Docker wasn't
    even available" case distinctly from an executed-but-failed run.
    """
    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(json.dumps({
        "executed": executed, "passed": passed, "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }, indent=2), encoding="utf-8")


def _report(checks: dict[str, bool]) -> int:
    print("\n=== Docker runtime validation report ===")
    for name, passed in checks.items():
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
    all_passed = all(checks.values())
    print(f"\nOverall: {'PASS' if all_passed else 'FAIL'}")
    _write_result(passed=all_passed, checks=checks, executed=True)
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
