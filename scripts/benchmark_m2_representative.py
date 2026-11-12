"""Score pinned upstream inputs as data using the existing local scan pipeline."""

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

from benchmark_m2_flaskr import measure

from ai_threat_lab.local_inventory import local_inventory

NEURO_REV = "b84b0c441e954fe1125529d9c8d7847a8aa395e9"
NEURO_HASH = "5bc66003d6fbe980c3a98f6f5638ddcd9b16658fd467ab7fa32905cf3128d4d9"
RULE = "container_explicit_root"


def representative(flaskr, dockerfile):
    result = measure(flaskr)
    result["corpus"] = "Flaskr 3.1.2 and Neurodesktop pinned configuration"
    if result["counts"]["errors"]:
        raise ValueError("Flaskr inputs must match the pinned hashes")
    raw = dockerfile.read_bytes()
    if hashlib.sha256(raw).hexdigest() != NEURO_HASH:
        raise ValueError("Dockerfile must match the pinned hash")
    with TemporaryDirectory(prefix="atl-representative-") as directory:
        root = Path(directory)
        project = root / "flaskr"
        project.mkdir()
        for name in ("auth.py", "blog.py", "pyproject.toml"):
            shutil.copyfile(flaskr / name, project / name)
        started = perf_counter()
        combined = local_inventory(str(project))
        result["multi_file"] = {
            "inputs": ["auth.py", "blog.py", "pyproject.toml"],
            "seconds": perf_counter() - started,
            "candidate_checks": sorted({finding.check for finding in combined.findings}),
            "limitations": combined.not_checked,
        }
        config = root / "neurodesktop"
        config.mkdir()
        (config / "Dockerfile").write_bytes(raw)
        started = perf_counter()
        scan = local_inventory(str(config))
        seconds = perf_counter() - started
    evidence = [finding.evidence for finding in scan.findings if finding.check == RULE]
    final_user_observed = any(item.startswith("Dockerfile:1850:") for item in evidence)
    status = "tp" if final_user_observed else "fn"
    result["observations"].append({
        "id": "neurodesktop-final-user",
        "source": f"https://github.com/neurodesk/neurodesktop/blob/{NEURO_REV}/Dockerfile",
        "revision": NEURO_REV, "license": "MIT", "sha256": NEURO_HASH, "rule": RULE,
        "expected": True, "in_scope": True, "observed": final_user_observed, "status": status,
        "label_evidence": "Final USER root at line 1850. The preceding comments describe "
        "root bootstrap and a subsequent privilege drop in the entry point.",
        "observed_evidence": evidence,
        "limitations": "Literal configuration observation. The image and entry point were "
        "not built or run, and effective runtime privileges were not evaluated.",
        "seconds": seconds,
    })
    result["counts"][status] += 1
    counts = result["counts"]
    result["precision"] = counts["tp"] / (counts["tp"] + counts["fp"]) if counts["tp"] else None
    result["recall"] = counts["tp"] / (counts["tp"] + counts["fn"])
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("flaskr", type=Path)
    parser.add_argument("dockerfile", type=Path)
    args = parser.parse_args()
    print(json.dumps(representative(args.flaskr, args.dockerfile), indent=2))
