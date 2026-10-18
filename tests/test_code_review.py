import json

import pytest

from ai_threat_lab import ValidationError, review_file, review_source
from ai_threat_lab.cli import main
from ai_threat_lab.code_review import MAX_SOURCE_BYTES, render_code_review


@pytest.mark.parametrize(
    "source,rule_id",
    [
        ("eval(user_input)", "PY001"),
        ("exec(user_input)", "PY001"),
        ("import subprocess as sp\nsp.run(command, shell=True)", "PY002"),
        ("from subprocess import Popen as start\nstart(command, shell=True)", "PY002"),
        ("import pickle as p\np.loads(data)", "PY003"),
        ("from pickle import load\nload(stream)", "PY003"),
        ("import requests as r\nr.get(url, verify=False)", "PY004"),
    ],
)
def test_risky_patterns_and_import_aliases(source, rule_id):
    result = review_source(source)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == rule_id
    assert finding.line >= 1 and finding.column >= 1
    assert finding.recommendation and finding.rationale


@pytest.mark.parametrize(
    "source",
    [
        'text = "eval(user_input)"\n# exec(code)',
        'import subprocess\nsubprocess.run(["echo", "hello"], shell=False)',
        "import requests\nrequests.get(url, verify=True)",
        "import json\njson.loads(data)",
        # Conservative checks do not guess computed kwargs or perform data flow.
        "import subprocess\nsubprocess.run(command, **options)",
    ],
)
def test_nonmatching_and_safer_examples(source):
    assert not review_source(source).findings


def test_review_never_executes_source_or_imports(tmp_path):
    marker = tmp_path / "must-not-exist"
    source = f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\neval(data)"
    assert review_source(source).findings
    assert not marker.exists()


def test_locations_are_stable_and_source_not_in_report():
    source = "import pickle\n\neval(private_customer_text)\npickle.loads(secret_payload)"
    result = review_source(source, "example.py")
    assert [f.line for f in result.findings] == [3, 4]
    for format in ("txt", "json"):
        report = render_code_review(result, format)
        assert "private_customer_text" not in report
        assert "secret_payload" not in report
        assert "example.py" in report
    assert json.loads(render_code_review(result, "json"))["schema_version"] == 1


def test_invalid_large_and_non_python_inputs(tmp_path):
    with pytest.raises(ValidationError, match="Cannot parse"):
        review_source("private_secret = (")
    with pytest.raises(ValidationError, match="limit"):
        review_source("#" * (MAX_SOURCE_BYTES + 1))
    bad = tmp_path / "large.py"
    bad.write_bytes(b"#" * (MAX_SOURCE_BYTES + 1))
    with pytest.raises(ValidationError, match="limit"):
        review_file(bad)
    with pytest.raises(ValidationError, match=".py"):
        review_file(tmp_path / "source.js")
    with pytest.raises(ValidationError):
        render_code_review(review_source(""), "pdf")


def test_python_declared_encoding(tmp_path):
    path = tmp_path / "source.py"
    path.write_bytes(b"# coding: latin-1\nname = '\xe9'\neval(data)\n")
    assert review_file(path).findings[0].line == 3


def test_cli_json_exit_codes_and_no_overwrite(tmp_path, capsys):
    source = tmp_path / "source.py"
    source.write_text("eval(data)\n")
    report = tmp_path / "review.json"
    assert main(["review-code", str(source), "--format", "json"]) == 0
    assert len(json.loads(capsys.readouterr().out)["review"]["findings"]) == 1
    assert main(["review-code", str(source), "--fail-on-findings"]) == 1
    capsys.readouterr()
    assert main(["review-code", str(source), "--format", "json", "--output", str(report)]) == 0
    original = report.read_bytes()
    assert main(["review-code", str(source), "--output", str(report)]) == 2
    assert report.read_bytes() == original
    assert "Error:" in capsys.readouterr().err
    source.write_text("broken = (")
    assert main(["review-code", str(source)]) == 2
    assert "broken" not in capsys.readouterr().err


def test_cli_clean_result_has_no_security_guarantee(tmp_path, capsys):
    path = tmp_path / "clean.py"
    path.write_text("value = 1\n")
    assert main(["review-code", str(path), "--fail-on-findings"]) == 0
    assert "does not establish" in capsys.readouterr().out
