"""Source-free SARIF paths, rule identity, Unicode locations and real CLI behavior."""

import json
from urllib.parse import unquote, urlsplit

import pytest
from test_cli_process import run_cli

from ai_threat_lab import ValidationError, review_file, review_source
from ai_threat_lab.cli import main
from ai_threat_lab.code_review import render_code_review
from ai_threat_lab.sarif import render_sarif

ALL_RULES = """import subprocess, pickle, requests, os, tempfile, ssl, yaml, hashlib
eval(private_argument)
subprocess.run(private_command, shell=True)
pickle.loads(private_pickle)
requests.get(private_url, verify=False)
os.system(private_command)
tempfile.mktemp()
ssl._create_unverified_context()
yaml.unsafe_load(private_yaml)
hashlib.sha1(private_data)
eval(another_private_argument)
"""


def run_document(source=ALL_RULES, filename="app.py", **options):
    return json.loads(render_sarif(review_source(source, filename), **options))["runs"][0]


def test_all_rules_repeated_observations_and_candidate_semantics():
    run = run_document()
    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == [f"PY00{i}" for i in range(1, 10)]
    assert len(run["results"]) == 10
    for item, line in zip(run["results"], range(2, 12), strict=True):
        assert rules[item["ruleIndex"]]["id"] == item["ruleId"]
        assert item["locations"][0]["physicalLocation"]["region"] == {"startLine": line}
        assert item["level"] == "warning" and item["properties"]["candidateOnly"] is True
        assert item["properties"]["patternSeverity"] in ("High", "Medium")
        assert "Recommendation:" in item["message"]["text"]
    assert run["properties"]["candidateOnly"] is True
    assert any("not validated" in item for item in run["properties"]["limitations"])


def test_empty_review_is_a_valid_empty_run_without_security_guarantee():
    payload = json.loads(render_code_review(review_source("value = 1"), "sarif"))
    assert payload["version"] == "2.1.0" and payload["$schema"].endswith(".json")
    run = payload["runs"][0]
    assert run["results"] == [] and run["tool"]["driver"]["rules"] == []
    assert any("does not establish" in value for value in run["properties"]["limitations"])


@pytest.mark.parametrize(
    "filename", ["space name.py", "żółć.py", "a#b?.py", "a%20b.py", "name:part.py"]
)
def test_basename_paths_are_uri_encoded_and_no_absolute_location_is_exposed(tmp_path, filename):
    # Colon and question-mark examples are logical editor filenames, not files on Windows.
    source = str(tmp_path / "private-client" / filename)
    run = run_document(filename=source)
    uri = run["artifacts"][0]["location"]["uri"]
    assert unquote(uri) == filename
    assert not urlsplit(uri).scheme and not urlsplit(uri).query and not urlsplit(uri).fragment
    assert "private-client" not in json.dumps(run)
    assert str(tmp_path) not in json.dumps(run)
    assert all(
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == uri
        for r in run["results"]
    )


def test_root_relative_export_uses_portable_path_and_no_root_disclosure(tmp_path):
    folder = tmp_path / "src folder"
    folder.mkdir()
    source = folder / "żółć.py"
    source.write_text("eval(private_input)", encoding="utf-8")
    result = review_file(source)
    payload = render_code_review(result, "sarif", source_root=tmp_path)
    uri = json.loads(payload)["runs"][0]["artifacts"][0]["location"]["uri"]
    assert unquote(uri) == "src folder/żółć.py" and "\\" not in uri
    assert str(tmp_path) not in payload and "private_input" not in payload


def test_outside_root_is_rejected_even_with_parent_traversal(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    source = tmp_path / "outside.py"
    source.write_text("eval(data)")
    result = review_file(root / ".." / "outside.py")
    with pytest.raises(ValidationError, match="inside"):
        render_sarif(result, source_root=root)


def test_resolved_symlink_escape_is_rejected(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    source = tmp_path / "outside.py"
    source.write_text("eval(data)")
    link = root / "linked.py"
    try:
        link.symlink_to(source)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is unavailable")
    with pytest.raises(ValidationError, match="inside"):
        render_sarif(review_file(link), source_root=root)


def test_root_must_exist_and_be_a_directory(tmp_path):
    result = review_source("eval(data)", str(tmp_path / "source.py"))
    with pytest.raises(OSError):
        render_sarif(result, source_root=tmp_path / "missing")
    root_file = tmp_path / "not-directory"
    root_file.write_text("")
    with pytest.raises(ValidationError, match="directory"):
        render_sarif(result, source_root=root_file)
    with pytest.raises(ValidationError, match="filename"):
        render_sarif(review_source("", ""))


def test_source_is_not_reopened_for_default_export_and_arguments_are_absent(tmp_path):
    source = tmp_path / "private" / "app.py"
    result = review_source(ALL_RULES, str(source))
    payload = render_sarif(result)
    assert not source.exists()
    assert "private_" not in payload and "another_private_argument" not in payload
    assert "snippet" not in payload and "contents" not in payload
    assert "invocations" not in payload and "environmentVariables" not in payload
    assert payload == render_sarif(result)


def test_unicode_byte_columns_are_not_misrepresented_as_character_columns():
    result = review_source('name = "ż😀"; eval(data)', "editor.py")
    item = json.loads(render_sarif(result))["runs"][0]["results"][0]
    assert item["properties"]["pythonUtf8ByteColumn"] > len('name = "ż😀"; ') + 1
    assert item["locations"][0]["physicalLocation"]["region"] == {"startLine": 1}


@pytest.mark.parametrize("format", ["txt", "json"])
def test_root_option_rejected_for_other_formats(format, tmp_path):
    with pytest.raises(ValidationError, match="only supported"):
        render_code_review(review_source(""), format, source_root=tmp_path)


def test_cli_sarif_output_exit_codes_and_no_overwrite(tmp_path, capsys):
    source = tmp_path / "app.py"
    source.write_text("eval(private_input)")
    report = tmp_path / "review.sarif"
    args = ["review-code", str(source), "--format", "sarif", "--source-root", str(tmp_path)]
    assert main(args + ["--output", str(report), "--fail-on-findings"]) == 1
    assert json.loads(report.read_text())["runs"][0]["results"][0]["ruleId"] == "PY001"
    original = report.read_bytes()
    assert main(args + ["--output", str(report)]) == 2
    assert report.read_bytes() == original
    assert "Error:" in capsys.readouterr().err
    assert main(["review-code", str(source), "--source-root", str(tmp_path)]) == 2
    assert "only supported" in capsys.readouterr().err
    source.write_text("value = 1")
    assert main(args + ["--fail-on-findings"]) == 0
    assert json.loads(capsys.readouterr().out)["runs"][0]["results"] == []


def test_cli_invalid_root_does_not_create_report(tmp_path, capsys):
    source = tmp_path / "app.py"
    source.write_text("eval(data)")
    destination = tmp_path / "absent.sarif"
    assert (
        main(
            [
                "review-code",
                str(source),
                "--format",
                "sarif",
                "--source-root",
                str(tmp_path / "missing"),
                "--output",
                str(destination),
            ]
        )
        == 2
    )
    assert not destination.exists()
    assert "Error:" in capsys.readouterr().err


def test_real_process_relative_paths_unicode_and_syntax_failure(tmp_path):
    source = tmp_path / "żółć.py"
    source.write_text('name="😀"; eval(private_data)', encoding="utf-8")
    completed = run_cli(
        "review-code",
        source.name,
        "--format",
        "sarif",
        "--source-root",
        ".",
        "--fail-on-findings",
        cwd=tmp_path,
    )
    assert completed.returncode == 1 and not completed.stderr
    run = json.loads(completed.stdout)["runs"][0]
    assert unquote(run["artifacts"][0]["location"]["uri"]) == source.name
    source.write_text("private_syntax_error = (")
    failed = run_cli("review-code", source, "--format", "sarif")
    assert failed.returncode == 2 and not failed.stdout
    assert "private_syntax_error" not in failed.stderr and "Traceback" not in failed.stderr
