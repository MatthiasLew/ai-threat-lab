"""Measure independently labelled, inert detector observations per rule."""

import json
import platform
import runpy
import subprocess
import tracemalloc
from pathlib import Path
from time import perf_counter

from ai_threat_lab.code_review import review_source
from ai_threat_lab.config_review import inspect_configuration
from ai_threat_lab.dependencies import inventory_sources
from ai_threat_lab.local_inventory import inspect_text

ROOT = Path(__file__).resolve().parents[1]
FLOW = (
    "from flask import Flask, request\nimport os\napp = Flask(__name__)\n"
    "@app.route('/fixture')\ndef handler():\n    value = request.args.get('value')\n"
)


def cases():
    fixtures = runpy.run_path(str(ROOT / "tests/test_analyzer_quality_benchmark.py"))
    positives = {rule: source for _, source, rule in fixtures["PYTHON_VULNERABLE_SAMPLES"]}
    positives.update({
        "PY010": "import jinja2\njinja2.Environment(autoescape=False)",
        "PY011": "import markupsafe\nmarkupsafe.Markup(value)",
        "PY012": "import jwt\njwt.decode(value, options={'verify_signature': False})",
        "PY013": FLOW + "    os.system(value)\n",
    })
    safe = {name: source for name, source in fixtures["PYTHON_SAFE_SYNTACTICALLY_SIMILAR_SAMPLES"]}
    negatives = dict(zip(
        (f"PY{i:03}" for i in range(1, 15)),
        [safe["literal_eval"], safe["subprocess_list"], safe["json_loads"],
         safe["requests_verified"], safe["subprocess_list"], safe["tempfile_mkstemp"],
         safe["default_ssl"], safe["safe_yaml"], safe["sha256_digest"],
         "import jinja2\njinja2.Environment(autoescape=True)",
         "import markupsafe\nmarkupsafe.escape(value)",
         "import jwt\njwt.decode(value, key=key, algorithms=['HS256'])",
         FLOW + "    return value\n", safe["flask_parameterized_sql"]], strict=True,
    ))
    for rule, source in sorted(positives.items()):
        yield rule, "positive", source, True
        yield rule, "negative", negatives[rule], False
        # Whitespace/Unicode comments should not affect the reference observation.
        yield rule, "format_boundary", "# fixture: próba\n\n" + source, True
        # Runtime source generated outside the file is outside the static corpus contract.
        yield rule, "unsupported", "source = external_source_provider()\n", None

    yield "container_explicit_root", "positive", "FROM scratch\nUSER root\n", True
    yield "container_explicit_root", "negative", "FROM scratch\nUSER 10001\n", False
    yield "possible_secret", "positive", "# -----BEGIN PRIVATE KEY-----\n", True
    yield "possible_secret", "negative", "# No credential material\n", False
    yield "dependency_exact_version", "positive", "fixture-package==1.2.3\n", True
    yield "dependency_exact_version", "negative", "fixture-package>=1.2.3\n", False


def observe(rule, source, label):
    if rule == "container_explicit_root":
        return {finding.check for finding in inspect_configuration("Dockerfile", source)}, []
    if rule == "possible_secret":
        return {finding.check for finding in inspect_text("fixture.txt", source)}, []
    if rule == "dependency_exact_version":
        result = inventory_sources("fixture", [("requirements.txt", source.encode())])
        exact = any(p.name == "fixture-package" and p.version == "1.2.3" for p in result.packages)
        return {rule} if exact else set(), list(result.not_checked)
    result = review_source(source, filename=f"{rule}-{label}.py")
    return {finding.rule_id for finding in result.findings}, list(result.limitations)


def measure():
    metrics, observations = {}, []
    for rule, label, source, expected in cases():
        counts = metrics.setdefault(rule, dict(tp=0, fp=0, tn=0, fn=0, unsupported=0, errors=0))
        if expected is None:
            counts["unsupported"] += 1
            observations.append({"rule": rule, "case": label, "status": "unsupported"})
            continue
        tracemalloc.start()
        started = perf_counter()
        try:
            observed, limitations = observe(rule, source, label)
            hit = rule in observed
            outcome = ("tp" if hit else "fn") if expected else ("fp" if hit else "tn")
        except (ValueError, RuntimeError):
            observed, outcome = set(), "errors"
            limitations = []
        elapsed = perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        counts[outcome] += 1
        observations.append({
            "rule": rule, "case": label, "expected": expected, "observed": sorted(observed),
            "status": outcome, "seconds": elapsed, "python_peak_bytes": peak,
            "limitations": limitations,
        })

    def ratio(numerator, denominator):
        return numerator / denominator if denominator else None

    categories = {}
    for rule, counts in metrics.items():
        category = {
            "container_explicit_root": "configuration",
            "possible_secret": "secret markers",
            "dependency_exact_version": "manifest extraction",
            "PY013": "Python data flow",
            "PY014": "Python data flow",
        }.get(rule, "Python syntax and API observations")
        grouped = categories.setdefault(category, dict.fromkeys(counts, 0))
        for name, value in counts.items():
            grouped[name] += value
    for counts in (*metrics.values(), *categories.values()):
        tp, fp, tn, fn = (counts[key] for key in ("tp", "fp", "tn", "fn"))
        counts.update(precision=ratio(tp, tp + fp), recall=ratio(tp, tp + fn),
                      false_positive_rate=ratio(fp, fp + tn))
    return {
        "schema_version": 1, "corpus": "m2-inert-detector-observations-v2",
        "scanner_commit": subprocess.check_output(["git", "rev-parse", "HEAD"],
                                                  cwd=ROOT, text=True).strip(),
        "python": platform.python_version(), "system": platform.platform(),
        "configuration": "Default detector options, one independently labelled input per case",
        "per_rule": metrics, "per_category": categories, "cases": observations,
    }


if __name__ == "__main__":
    print(json.dumps(measure(), indent=2, ensure_ascii=True))
