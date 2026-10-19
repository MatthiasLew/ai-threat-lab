"""New AST rules across standalone, assessment, scan, GitHub and installed boundaries."""

import json
from dataclasses import asdict

import pytest
from test_cli_process import run_cli
from test_remote_audit import QueueHTTP, blob, repository

from ai_threat_lab.assessment import AssessmentService
from ai_threat_lab.audit_report import merge_reports
from ai_threat_lab.cli import main
from ai_threat_lab.code_review import render_code_review, review_source
from ai_threat_lab.local_inventory import local_inventory
from ai_threat_lab.remote_audit import GithubAudit
from ai_threat_lab.scan_bundle import compare_bundles, publish_bundle, read_bundle, scope_digest
from ai_threat_lab.scan_cli import assessor
from ai_threat_lab.scan_engine import ScanOptions, ScanService

SAMPLE = """import os
import tempfile
import ssl
import yaml
import hashlib
os.system(command)
tempfile.mktemp()
ssl._create_unverified_context()
yaml.load(payload, Loader=yaml.UnsafeLoader)
hashlib.md5(payload)
"""


@pytest.mark.parametrize(
    "source,rule",
    [
        ("import os\nos.system(command)", "PY005"),
        ("import os as operating\noperating.popen(command)", "PY005"),
        ("from os import system as shell\nshell(command)", "PY005"),
        ("from tempfile import mktemp as name\nname()", "PY006"),
        ("import tempfile as t\nt.mktemp(prefix=private_value)", "PY006"),
        ("import ssl\nssl._create_unverified_context()", "PY007"),
        ("from ssl import _create_unverified_context as context\ncontext()", "PY007"),
        ("import yaml\nyaml.unsafe_load(document)", "PY008"),
        ("from yaml import unsafe_load_all as load\nload(document)", "PY008"),
        ("import yaml\nyaml.load(document, Loader=yaml.Loader)", "PY008"),
        ("import yaml as y\ny.load(document, Loader=y.CLoader)", "PY008"),
        ("import yaml\nyaml.load_all(document, yaml.UnsafeLoader)", "PY008"),
        ("from yaml import load, CUnsafeLoader as L\nload(document, L)", "PY008"),
        ("import hashlib as h\nh.md5(data)", "PY009"),
        ("from hashlib import sha1 as digest\ndigest(data)", "PY009"),
        ('import hashlib\nhashlib.new("md5", data)', "PY009"),
        ('import hashlib\nhashlib.new(name="SHA1", data=data)', "PY009"),
        ('from hashlib import new\nnew("sha-1", data)', "PY009"),
        ("import hashlib\nhashlib.sha1(data, usedforsecurity=policy)", "PY009"),
        ("import hashlib\nhashlib.sha1(data, usedforsecurity=True)", "PY009"),
    ],
)
def test_explicit_patterns_and_import_aliases(source, rule):
    result = review_source(source)
    assert [f.rule_id for f in result.findings] == [rule]
    assert result.findings[0].line == 2 and result.findings[0].column == 1
    assert result.engine == "python-ast-1.8"
    assert result.findings[0].rationale and result.findings[0].recommendation


@pytest.mark.parametrize(
    "source",
    [
        'text="os.system(command)"\n# tempfile.mktemp()',
        "import os\nos.path.join(a,b)",
        "import tempfile\ntempfile.mkstemp()",
        "import tempfile as t\nt.NamedTemporaryFile()",
        "import ssl\nssl.create_default_context()",
        "import ssl\nssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)",
        "import yaml\nyaml.safe_load(data)",
        "import yaml\nyaml.safe_load_all(data)",
        "import yaml\nyaml.load(data, Loader=yaml.SafeLoader)",
        "import yaml\nyaml.load(data, yaml.CSafeLoader)",
        "import yaml\nyaml.load(data, Loader=yaml.FullLoader)",
        "import yaml\nyaml.load(data)",
        "import yaml\nyaml.load(data, Loader=custom_loader)",
        "import yaml\nyaml.load(data, **options)",
        "import hashlib\nhashlib.sha256(data)",
        'import hashlib\nhashlib.new("sha256", data)',
        "import hashlib\nhashlib.new(algorithm, data)",
        "import hashlib\nhashlib.new()",
        "import hashlib\nhashlib.md5(data, usedforsecurity=False)",
        "import hashlib\nhashlib.sha1(data, usedforsecurity=False)",
        'import hashlib\nhashlib.new("md5", data, usedforsecurity=False)',
        "from hashlib import sha1 as digest\ndigest(data, usedforsecurity=False)",
        "import unrelated\nunrelated.unsafe_load(data)",
    ],
)
def test_narrow_scope_and_explicit_non_security_digest_exemption(source):
    assert not review_source(source).findings


def test_loader_and_digest_dispatch_does_not_execute_source(tmp_path, monkeypatch):
    import os
    import socket
    import tempfile

    def forbidden(*args, **kwargs):
        pytest.fail("AST analysis executed a target API")

    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(tempfile, "mktemp", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    result = review_source(SAMPLE)
    assert [f.rule_id for f in result.findings] == [f"PY00{i}" for i in range(5, 10)]
    assert [f.line for f in result.findings] == [6, 7, 8, 9, 10]


def test_all_new_rules_omit_private_values_in_text_and_json():
    source = SAMPLE.replace("command", '"PRIVATE_COMMAND"').replace("payload", 'b"PRIVATE_DATA"')
    result = review_source(source, "review.py")
    for format in ("txt", "json"):
        report = render_code_review(result, format)
        assert "PRIVATE_COMMAND" not in report and "PRIVATE_DATA" not in report
        assert "review.py" in report


def test_local_routes_and_combined_review_priority(tmp_path):
    path = tmp_path / "code.py"
    path.write_text(SAMPLE, encoding="utf-8")
    for result in (AssessmentService().assess(str(path)), local_inventory(str(path))):
        assert {f.check for f in result.findings} == {f"PY00{i}" for i in range(5, 10)}
        assert all(f.status == "candidate" for f in result.findings)
        document = json.loads(json.dumps(asdict(result)))
        report = merge_reports([document])
        assert all(f["triage_priority"] == "P2" for f in report["findings"])
    ScanService(assessor).run(ScanOptions(str(path)), tmp_path / "run")
    assert (
        read_bundle(tmp_path / "run")["documents"]["report.json"]["summary"]["unique_findings"] == 5
    )


def test_verified_github_source_uses_same_new_rules():
    item, data = blob(SAMPLE)
    http = QueueHTTP(*repository(item), data)
    result = GithubAudit(http).assess("https://github.com/owner/repo")
    assert {f.check for f in result.findings} == {f"PY00{i}" for i in range(5, 10)}
    assert len(http.calls) == 4
    assert "a" * 40 in http.calls[2][0]


def test_helper_warning_does_not_claim_effective_context_validation():
    result = review_source(
        "import ssl\nssl._create_unverified_context(cert_reqs=ssl.CERT_REQUIRED)"
    )
    assert result.findings[0].rule_id == "PY007"
    assert "overrides and later changes" in result.findings[0].rationale


def test_cli_exit_policy_json_and_existing_output(tmp_path, capsys):
    path = tmp_path / "source.py"
    path.write_text(SAMPLE, encoding="utf-8")
    assert main(["review-code", str(path), "--format", "json", "--fail-on-findings"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert len(report["review"]["findings"]) == 5
    saved = tmp_path / "result.json"
    assert main(["review-code", str(path), "--format", "json", "--output", str(saved)]) == 0
    original = saved.read_bytes()
    assert main(["review-code", str(path), "--output", str(saved)]) == 2
    assert saved.read_bytes() == original


def test_real_cli_new_patterns_and_negative_exemption(tmp_path):
    path = tmp_path / "review próbny.py"
    path.write_text(SAMPLE, encoding="utf-8")
    result = run_cli("review-code", path, "--format", "json", "--fail-on-findings")
    assert result.returncode == 1, result.stderr
    assert len(json.loads(result.stdout)["review"]["findings"]) == 5
    result = run_cli("scan", path, "--output-dir", tmp_path / "bundle")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["unique_findings"] == 5
    path.write_text("import hashlib\nhashlib.md5(data, usedforsecurity=False)", encoding="utf-8")
    result = run_cli("review-code", path, "--fail-on-findings")
    assert result.returncode == 0, result.stderr


def test_engine_five_bundle_is_readable_and_cross_engine_deltas_disabled(tmp_path):
    path = tmp_path / "source.py"
    path.write_text(SAMPLE, encoding="utf-8")
    ScanService(assessor).run(ScanOptions(str(path)), tmp_path / "new")
    current = read_bundle(tmp_path / "new")
    metadata = dict(current["manifest"])
    metadata["scope"] = {**metadata["scope"], "engine": "read-only-pipeline-5"}
    metadata["scope_digest"] = scope_digest(metadata["scope"])
    artifacts = {name: (tmp_path / "new" / name).read_bytes() for name in metadata["files"]}
    publish_bundle(tmp_path / "legacy", artifacts, metadata)
    assert not compare_bundles(read_bundle(tmp_path / "legacy"), current)["comparable"]
