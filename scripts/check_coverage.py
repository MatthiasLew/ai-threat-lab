"""Enforce independent coverage thresholds using the unrounded counters."""

import json
import sys
from pathlib import Path


def main(path):
    totals = json.loads(Path(path).read_text(encoding="utf-8"))["totals"]
    branches = totals["covered_branches"], totals["num_branches"]
    combined = totals["covered_lines"] + branches[0], totals["num_statements"] + branches[1]
    passed = True
    for name, (covered, total) in (("Combined", combined), ("Branches", branches)):
        if total <= 0 or not 0 <= covered <= total:
            print(f"{name}: invalid coverage counters", file=sys.stderr)
            passed = False
            continue
        print(f"{name} covered: {covered / total:.2%} ({covered}/{total})")
        if covered * 100 < total * 90:
            print(f"{name} coverage is below 90%", file=sys.stderr)
            passed = False
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
