"""Runs the 13-scenario fixture set against the LIVE production API
(http://localhost:8000) with llm_mode="llama" -- Llama 3.1 8B Instruct
(Generator, via llama.cpp+RAG) + Qwen 2.5:7b-instruct (Verifier, LlamaVerifier)
+ PolicyValidator (Validator, deterministic) -- and saves the FULL per-stage
output for each scenario: Claim, VerificationResult, MCPScore (with its full
factor breakdown), ValidationDecision (with diagnostic_warnings and
diagnostic_details), ciso_routing, and the state transition list.

Unlike scripts/prod_run_13_scenarios.py (which this supersedes for reporting
purposes), this script does not discard any part of the API response -- the
single POST /api/v1/generator/verified-claims call already returns every
stage's output in one JSON body, so there is nothing to fetch separately;
this script's only job is to not throw any of it away before writing it to
disk.

Not a pytest test: a one-off tool producing the raw JSON this session's
Llama-3.1+Qwen-2.5 production report is built from. No fabricated data --
every field in the output JSON is exactly what the live API returned.

Run: python scripts/prod_run_13_scenarios_full.py --out artifacts/production_run/llama31_qwen25_13_scenarios_full.json
"""

import argparse
import json
import time
from pathlib import Path

import httpx

from scripts.benchmark_harness import CVES, EVIDENCE, MITRE, RUNBOOKS, SCENARIOS

BASE_URL = "http://localhost:8000"
API_KEY = "change-me"
HEADERS = {"X-API-Key": API_KEY}
REQUEST_TIMEOUT = 400.0  # observed smoke test: ~2m17s for one Llama 3.1 + Qwen 2.5 round trip


def _wait_job(client, job_id, timeout=60.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = client.get(f"{BASE_URL}/api/v1/ingestion/jobs/{job_id}", headers=HEADERS)
        body = resp.json()
        if body["status"] in ("SUCCEEDED", "FAILED"):
            return body
        time.sleep(0.3)
    raise RuntimeError(f"job {job_id} did not finish within {timeout}s")


def _ingest(client, kind, records):
    resp = client.post(f"{BASE_URL}/api/v1/ingestion/{kind}", json=records, headers=HEADERS, timeout=60.0)
    resp.raise_for_status()
    job = _wait_job(client, resp.json()["job_id"])
    if job["status"] != "SUCCEEDED":
        raise RuntimeError(f"ingestion of {kind} failed: {job}")
    return job["result"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
        print("=== INGESTION ===", flush=True)
        print("evidence:", _ingest(client, "evidence", EVIDENCE), flush=True)
        print("cve:", _ingest(client, "cve", CVES), flush=True)
        print("mitre:", _ingest(client, "mitre", MITRE), flush=True)
        print("runbooks:", _ingest(client, "runbooks", RUNBOOKS), flush=True)

        results = []
        for i, (sid, name, question, ctx) in enumerate(SCENARIOS, 1):
            print(f"=== [{i}/{len(SCENARIOS)}] Scenario {sid}: {name} ===", flush=True)
            req = {"request_id": f"FULL-{sid}", "question": question, "llm_mode": "llama", **ctx}
            started = time.monotonic()
            entry = {
                "scenario_id": sid,
                "scenario_name": name,
                "question": question,
                "request": req,
                "http_status": None,
                "latency_seconds": None,
                # Full, unmodified stage outputs -- nothing summarized or dropped.
                "response": None,
                "error": None,
            }
            try:
                resp = client.post(f"{BASE_URL}/api/v1/generator/verified-claims", json=req, headers=HEADERS)
                entry["http_status"] = resp.status_code
                entry["response"] = resp.json() if resp.status_code == 200 else None
                if resp.status_code != 200:
                    entry["error"] = resp.text
                print(f"  -> HTTP {resp.status_code} in {time.monotonic()-started:.1f}s", flush=True)
                if entry["response"]:
                    r = entry["response"]
                    print(f"     mcp_state={r.get('mcp_state')} ciso_routing={r.get('ciso_routing')}", flush=True)
            except Exception as exc:  # noqa: BLE001
                entry["error"] = str(exc)
                print(f"  -> ERROR: {exc}", flush=True)
            entry["latency_seconds"] = round(time.monotonic() - started, 1)
            results.append(entry)

            # Flush incrementally so a crash/timeout on a later scenario never
            # loses the results already collected -- this run is long (13
            # scenarios x ~1-3min real-model latency each).
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")

        print(f"=== DONE: wrote {args.out} ===")


if __name__ == "__main__":
    main()
