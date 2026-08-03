#!/usr/bin/env python
"""Standalone CLI: evaluates artifacts/real_model/results.json against the
acceptance thresholds (spec section 4) and exits non-zero if any
zero-tolerance gate fails. This is the same computation
tests/test_real_model_generator.py's final step already runs and asserts on
-- exposed here as an independent command so it can be run without pytest
(e.g. from scripts/check_generator_readiness.py, or by hand after a real-model
run), reading whatever the harness already wrote to disk.

Usage:
    python scripts/evaluate_real_model_results.py [--results-dir artifacts/real_model]

Exit codes:
    0 - all scenarios recorded and every acceptance gate passed
    1 - results.json exists but at least one gate failed (see printed report)
    2 - results.json does not exist / could not be read (configuration error,
        not a gate failure -- see scripts/check_generator_readiness.py, which
        treats a missing real-model result as NOT_READY_FOR_VERIFIER_INTEGRATION)
"""

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.real_model_lib import write_summary_files  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", default="artifacts/real_model")
    args = parser.parse_args(argv)

    results_path = Path(args.results_dir) / "results.json"
    if not results_path.exists():
        print(f"ERROR: {results_path} does not exist -- run tests/test_real_model_generator.py "
              "with RUN_REAL_MODEL_TESTS=true first.", file=sys.stderr)
        return 2

    try:
        results = json.loads(results_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"ERROR: {results_path} is not valid JSON: {exc}", file=sys.stderr)
        return 2

    evaluation = write_summary_files(results, Path(args.results_dir))

    print(f"Scenarios: {evaluation['scenario_count']}")
    for name, metric in evaluation["metrics"].items():
        rate_str = "n/a" if metric["rate"] is None else f"{metric['rate']:.1%}"
        status = "PASS" if metric["passed"] else "FAIL"
        print(f"  [{status}] {name}: {rate_str} (threshold {metric['threshold']:.0%}, "
              f"{metric['applicable_scenarios']} applicable)")

    if evaluation["zero_tolerance_failures"]:
        print("\nZero-tolerance failures:")
        for failure in evaluation["zero_tolerance_failures"]:
            print(f"  - {failure['scenario']}: {failure['reason']}")

    if evaluation["overall_passed"]:
        print("\nOverall: PASS")
        return 0
    print("\nOverall: FAIL")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
