#!/usr/bin/env python3
"""Validate detection metadata and exercise it against synthetic fixtures."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from detection_engine import ROOT, evaluate, load_detections, load_fixtures, validate_catalog


RESULTS_PATH = ROOT / "evidence" / "results.json"


def serialized(results: dict[str, object]) -> str:
    return json.dumps(results, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-results", action="store_true")
    parser.add_argument("--check-results", action="store_true")
    args = parser.parse_args()

    detections = load_detections()
    fixtures = load_fixtures()
    errors = validate_catalog(detections, fixtures)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    results = evaluate(detections, fixtures)
    if not results["validation"]["passed"]:
        print(serialized(results), end="")
        return 1

    rendered = serialized(results)
    if args.write_results:
        RESULTS_PATH.write_text(rendered)
    if args.check_results:
        if not RESULTS_PATH.exists() or RESULTS_PATH.read_text() != rendered:
            print("ERROR: evidence/results.json is stale; run with --write-results")
            return 1

    catalog = results["catalog"]
    print(
        "Validated "
        f"{catalog['detection_count']} detections against "
        f"{catalog['fixture_count']} synthetic fixtures."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
