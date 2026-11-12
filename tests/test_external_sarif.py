"""Pinned producer interoperability and untrusted-data regressions."""

import json
from pathlib import Path

import pytest

from ai_threat_lab import import_sarif
from ai_threat_lab.cli import main
from ai_threat_lab.models import ValidationError
from ai_threat_lab.sarif_review import review_sarif

FIXTURES = Path(__file__).parent / "fixtures" / "external_sarif"


def bandit():
    return json.loads((FIXTURES / "bandit.sarif").read_bytes())


def save(tmp_path, data):
    path = tmp_path / "external.sarif"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.mark.parametrize("name,version,count", [
    ("bandit", "1.7.8", 1), ("semgrep", None, 1), ("semgrep-trace", None, 2),
    ("trivy", "dev", 4), ("gitleaks", "v8.0.0", 1),
])
def test_upstream_reports(name, version, count):
    report, failures = import_sarif(FIXTURES / f"{name}.sarif")
    assert not failures
    assert report["schema_version"] == 1
    assert report["runs"][0]["producer_version"] == version
    assert len(report["observations"]) == count
    row = report["observations"][0]
    assert row["status"] == "unverified" and row["rule_id"]
    assert row["producer"].casefold().startswith(name.split("-")[0])
    if name == "bandit":
        assert (row["rule_id"], row["severity"], row["confidence"]) == ("B101", "LOW", "HIGH")
    if name == "trivy":
        assert report["runs"][0]["target_kind"] == "image"
        assert row["locations"][0]["kind"] == "target"
        assert row["locations"][0]["package"] == "libcrypto1.1"
        assert row["locations"][0]["package_version"] == "1.1.1c-r0"
        assert row["severity"] == "MEDIUM" and row["category"] == "vulnerability"
    if name == "gitleaks":
        assert row["locations"][0]["label"] is None
        assert row["message"] == "[secret scanner message withheld]"


def test_bandit_variants_page_and_exact_deduplication(tmp_path):
    document = bandit()
    run = document["runs"][0]
    row = run["results"][0]
    second = {
        **row, "ruleId": "B999",
        "properties": {"issue_severity": "HIGH", "issue_confidence": "LOW"},
        "suppressions": [{"kind": "external", "status": "accepted"}],
        "baselineState": "new",
    }
    del second["ruleIndex"]
    run["results"] = [row, row, second]
    run["invocations"][0]["executionSuccessful"] = False
    del run["tool"]["driver"]["version"], run["tool"]["driver"]["semanticVersion"]
    path = save(tmp_path, document)
    report, failures = import_sarif(path)
    assert failures == 1 and report["runs"][0]["duplicates"] == 1
    first, last = report["observations"]
    assert first["provenance"]["result_ordinals"] == [1, 2]
    assert first["producer_version"] is None and first["producer_succeeded"] is False
    assert (last["rule_id"], last["severity"], last["confidence"]) == ("B999", "HIGH", "LOW")
    assert last["suppressions"] == [{"kind": "external", "status": "accepted"}]
    assert last["baseline_state"] == "new"
    page, _ = import_sarif(path, start=2, max_entries=1)
    assert page["observations"][0]["provenance"]["result_ordinals"] == [2]
    assert page["runs"][0]["outside_page"] == 2
    legacy, _ = review_sarif(path)
    assert len(legacy["findings"]) == 3
    run["results"] = []
    run.pop("invocations")
    empty, failures = import_sarif(save(tmp_path, document))
    assert not empty["observations"] and not failures
    assert empty["runs"][0]["producer_succeeded"] is None


@pytest.mark.parametrize("uri,expected", [
    ("src\\żółć.py", "src/żółć.py"),
    ("C:\\Users\\PRIVATE\\app.py", None),
    ("\\\\host\\share\\app.py", None),
    ("%2E%2E/PRIVATE", None),
    ("https://PRIVATE@example.invalid/token", None),
    ("src/%ff", None),
])
def test_unsafe_locations_and_redacted_messages(tmp_path, uri, expected):
    document = bandit()
    row = document["runs"][0]["results"][0]
    row["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = uri
    row["message"]["text"] = "token=CANARY-SENSITIVE \x1b[31m \u202e"
    path = save(tmp_path, document)
    report, failures = import_sarif(path)
    if uri == "src/%ff":
        assert failures == 1 and not report["observations"]
    else:
        assert not failures and report["observations"][0]["locations"][0]["label"] == expected
    legacy, _ = review_sarif(path)
    for output in (report, legacy):
        serialized = json.dumps(output, ensure_ascii=False)
        assert all(value not in serialized for value in ("CANARY-SENSITIVE", "PRIVATE", "\u202e"))


def test_local_message_catalog_and_extension_component(tmp_path):
    data = bandit()
    run = data["runs"][0]
    row = run["results"][0]
    run["tool"]["extensions"] = [{
        "name": "Local extension", "version": "2",
        "rules": [{"id": "B101", "messageStrings": {"key": {"text": "Review {0}"}}}],
    }]
    row["rule"] = {"id": "B101", "index": 0, "toolComponent": {"index": 0}}
    row["message"] = {"id": "key", "arguments": ["local label"]}
    row["codeFlows"] = [{"description": {"text": "PRIVATE"}}]
    report, failures = import_sarif(save(tmp_path, data))
    assert not failures
    item = report["observations"][0]
    assert item["component_version"] == "2" and item["message"] == "Review local label"
    assert item["code_flows_omitted"] == 1 and "PRIVATE" not in json.dumps(report)
    row["rule"]["id"] = "B999"
    broken, failures = import_sarif(save(tmp_path, data))
    assert failures and broken["runs"][0]["unsupported"] == 1


def test_depth_limit_and_cli_export(tmp_path):
    data = bandit()
    path = save(tmp_path, data)
    output = tmp_path / "observations.json"
    args = ["review-sarif", str(path), "--structured", "--output", str(output)]
    assert main(args + ["--fail-on-findings"]) == 1
    assert json.loads(output.read_bytes())["observations"][0]["rule_id"] == "B101"
    assert main(args) == 2
    value = []
    for _ in range(50):
        value = [value]
    data["properties"] = value
    with pytest.raises(ValidationError, match="nesting"):
        import_sarif(save(tmp_path, data))


def test_secret_scanner_withholds_arbitrary_text_and_metadata(tmp_path):
    data = json.loads((FIXTURES / "gitleaks.sarif").read_bytes())
    run = data["runs"][0]
    run["properties"] = {"limitations": ["SECRET-CANARY"]}
    row = run["results"][0]
    row["message"] = {"text": "SECRET-CANARY"}
    row["partialFingerprints"] = {"commitMessage": "SECRET-CANARY"}
    row["locations"][0]["physicalLocation"]["region"]["snippet"] = {"text": "SECRET-CANARY"}
    row["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "private/SECRET-CANARY"
    path = save(tmp_path, data)
    for importer in (import_sarif, review_sarif):
        report, failures = importer(path)
        assert not failures and "SECRET-CANARY" not in json.dumps(report)


def test_legacy_projection_ignores_unprojected_producer_metadata(tmp_path):
    data = bandit()
    row = data["runs"][0]["results"][0]
    row["properties"]["issue_severity"] = 5
    path = save(tmp_path, data)
    legacy, failures = review_sarif(path)
    assert not failures and len(legacy["findings"]) == 1
    structured, failures = import_sarif(path)
    assert failures == 1 and structured["runs"][0]["unsupported"] == 1


@pytest.mark.parametrize("name", ["Git-Leaks CLI", "TRIVY scanner", "Unknown scanner"])
def test_secret_shape_is_withheld_independently_of_producer_name(tmp_path, capsys, name):
    data = bandit()
    run = data["runs"][0]
    run["tool"]["driver"]["name"] = name
    run["results"][0]["message"] = {"text": "Match : OPAQUE-CANARY"}
    if name != "Unknown scanner":
        run["properties"]["limitations"] = ["OPAQUE-CANARY"]
    path = save(tmp_path, data)
    for options in ([], ["--structured"]):
        assert main(["review-sarif", str(path), *options]) == 0
        captured = capsys.readouterr()
        assert "OPAQUE-CANARY" not in captured.out + captured.err


def test_resolved_catalog_secret_match_is_also_withheld(tmp_path):
    data = bandit()
    run = data["runs"][0]
    run["tool"]["driver"]["name"] = "Unknown scanner"
    run["tool"]["driver"]["globalMessageStrings"] = {
        "private": {"text": "Synthetic\n\tMatch: {0}"},
    }
    run["results"][0]["message"] = {"id": "private", "arguments": ["OPAQUE-CANARY"]}
    for importer in (import_sarif, review_sarif):
        report, failures = importer(save(tmp_path, data))
        assert not failures and "OPAQUE-CANARY" not in json.dumps(report)


@pytest.mark.parametrize("tags", [[], ["secret", "security"]])
def test_trivy_secret_messages_and_paths_are_withheld(tmp_path, tags):
    data = json.loads((FIXTURES / "trivy.sarif").read_bytes())
    run = data["runs"][0]
    row = run["results"][0]
    run["results"] = [row]
    run["tool"]["driver"]["rules"][row["ruleIndex"]]["properties"]["tags"] = tags
    row["message"] = {"text": "Secret fixture\nSeverity: HIGH\nMatch: OPAQUE-CANARY"}
    physical = row["locations"][0]["physicalLocation"]
    physical["artifactLocation"]["uri"] = "project/OPAQUE-CANARY"
    row["locations"][0]["message"] = {"text": "project/OPAQUE-CANARY: OPAQUE-CANARY@1"}
    row["properties"] = {"confidence": "OPAQUE-CANARY"}
    path = save(tmp_path, data)
    for importer in (import_sarif, review_sarif):
        report, failures = importer(path)
        assert not failures and "OPAQUE-CANARY" not in json.dumps(report)
