"""Score pre-labelled, pinned Flaskr source as text; never import the sample."""

import argparse
import hashlib
import json
import platform
import subprocess
from pathlib import Path
from time import perf_counter

from ai_threat_lab.code_review import review_source

REVISION = "2c1b30d0503cfb064f1cb252e6614a06915a362a"
SOURCE = f"https://github.com/pallets/flask/blob/{REVISION}/examples/tutorial"
CASES = (
    (
        "flaskr-auth-bound-sql", "flaskr/auth.py",
        "a5ed5eaa05c6f6ee3e5bdb07b9e657a6e9320a115a68fd74b1cb4ac646680167",
        False, "Request values use SQL parameter binding (auth.py lines 66–69 and 92–94).",
    ),
    (
        "flaskr-blog-bound-sql", "flaskr/blog.py",
        "c49c5f6e3db32d74bfac13633fd328ec904cb7159d76ca78f6956432076c1fd7",
        False, "Request values use SQL parameter binding (blog.py lines 76–79 and 104–107).",
    ),
    (
        "flaskr-build-metadata", "pyproject.toml",
        "8ea666f85481f44bc7a5cef54e39ab939f92f5f2cb576f9a6b959866a3fac0aa",
        None, "Project metadata does not contain Python data flow; excluded from PY014 scoring.",
    ),
)


def measure(corpus):
    counts = dict(tp=0, fp=0, tn=0, fn=0, unsupported=0, errors=0)
    observations = []
    for sample, path, checksum, expected, evidence in CASES:
        started = perf_counter()
        status = "errors"
        observed = None
        try:
            raw = (corpus / Path(path).name).read_bytes()
            if hashlib.sha256(raw).hexdigest() != checksum:
                raise ValueError("Source does not match the pinned revision")
            if expected is None:
                status = "unsupported"
            else:
                findings = review_source(raw.decode("utf-8"), filename=path).findings
                observed = any(row.rule_id == "PY014" for row in findings)
                status = ("tp" if observed else "fn") if expected else ("fp" if observed else "tn")
        except (OSError, ValueError) as error:
            evidence += f" Input or analysis failed: {type(error).__name__}."
        counts[status] += 1
        observations.append({
            "id": sample, "source": f"{SOURCE}/{path}", "revision": REVISION,
            "license": "BSD-3-Clause", "sha256": checksum, "rule": "PY014",
            "expected": expected, "in_scope": expected is not None, "label_evidence": evidence,
            "observed": observed, "status": status, "seconds": perf_counter() - started,
        })
    tp, fp, tn, fn = (counts[key] for key in ("tp", "fp", "tn", "fn"))
    return {
        "scanner_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "system": platform.platform(), "python": platform.python_version(),
        "corpus": "Flaskr 3.1.2: selected files, negative controls for PY014",
        "counts": counts,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "observations": observations,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path, help="Directory containing the three source files")
    args = parser.parse_args()
    report = measure(args.corpus)
    print(json.dumps(report, indent=2))
    raise SystemExit(bool(report["counts"]["errors"]))
