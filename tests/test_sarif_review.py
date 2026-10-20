"""External scanner evidence stays unverified, bounded and independent of source access."""

import copy
import json
import socket

import pytest

from ai_threat_lab.code_review import review_source
from ai_threat_lab.evidence import load_evidence
from ai_threat_lab.models import ValidationError
from ai_threat_lab.sarif import render_sarif
from ai_threat_lab.sarif_review import review_sarif


def result(message="Review fixture"):
    return {
        "ruleId": "EXT001", "level": "warning", "message": {"text": message},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "src/app.js"}, "region": {"startLine": 12},
        }}],
    }


def payload():
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Fixture scanner", "rules": [{"id": "EXT001"}]}},
        "results": [result()],
        "invocations": [{"executionSuccessful": True,
                         "environmentVariables": {"SECRET": "PRIVATE"},
                         "commandLine": "PRIVATE"}],
    }]}


def save(tmp_path, value):
    path = tmp_path / "input.sarif"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_bounded_interchange_without_network_or_source_reads(tmp_path, monkeypatch):
    monkeypatch.setattr(socket, "create_connection", lambda *a, **kw: pytest.fail("network"))
    path = save(tmp_path, payload())
    report, failures = review_sarif(path)
    assert not failures and len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["status"] == "unverified" and finding["check"] == "external_sarif_result"
    assert '"src/app.js":12' in finding["evidence"]
    assert "EXT001" in finding["evidence"] and "PRIVATE" not in json.dumps(report)
    output = tmp_path / "report.json"
    output.write_text(json.dumps(report), encoding="utf-8")
    path.unlink()
    assert load_evidence(output)["report"]["findings"]


def test_own_export_roundtrip_preserves_rules_as_external_claims(tmp_path):
    source = review_source("eval(user_input)\n", filename="source.py")
    path = tmp_path / "export.sarif"
    path.write_text(render_sarif(source), encoding="utf-8")
    report, failures = review_sarif(path)
    assert not failures and len(report["findings"]) == 1
    assert "PY001" in report["findings"][0]["evidence"]
    assert "invocation outcome supplied=False" in json.dumps(report)


@pytest.mark.parametrize("field,value", [
    ("baselineState", "absent"), ("kind", "pass"), ("level", "none"),
    ("suppressions", [{"kind": "inSource", "status": "accepted"}]),
])
def test_non_active_classifications_are_retained(tmp_path, field, value):
    data = payload()
    data["runs"][0]["results"][0][field] = value
    report, failures = review_sarif(save(tmp_path, data))
    assert not failures
    evidence = report["findings"][0]["evidence"]
    assert ("accepted" if field == "suppressions" else value) in evidence
    assert report["findings"][0]["status"] == "unverified"


@pytest.mark.parametrize("change", ["failed", "notification", "external"])
def test_partial_producer_preserves_results_and_returns_failure(tmp_path, change):
    data = payload()
    run = data["runs"][0]
    if change == "failed":
        run["invocations"][0]["executionSuccessful"] = False
    elif change == "notification":
        run["invocations"][0]["toolExecutionNotifications"] = [
            {"level": "error", "message": {"text": "PRIVATE"}},
        ]
    else:
        run["externalPropertyFileReferences"] = {"results": [{"location": {"uri": "PRIVATE"}}]}
    report, failures = review_sarif(save(tmp_path, data))
    assert failures == 1 and report["findings"]
    assert "PRIVATE" not in json.dumps(report)


def test_global_paging_and_malformed_run_offsets(tmp_path):
    data = payload()
    bad = copy.deepcopy(data["runs"][0])
    bad["tool"] = None
    data["runs"].insert(0, bad)
    report, failures = review_sarif(save(tmp_path, data), start=2, max_entries=1)
    assert failures == 1 and len(report["findings"]) == 1
    assert report["findings"][0]["target"] == "SARIF run 0002"
    with pytest.raises(ValidationError, match="beyond"):
        review_sarif(save(tmp_path, data), start=3)


@pytest.mark.parametrize("item", [
    {}, None, {"message": {"id": "external-catalog-entry"}},
    {**result(), "ruleIndex": True}, {**result(), "ruleIndex": 1},
    {**result(), "ruleIndex": 0, "ruleId": "CONTRADICTORY"},
    {**result(), "rule": {"toolComponent": {"index": 0}}},
    {**result(), "message": {"text": "x" * 2001}},
    {**result(), "baselineState": "unknown"},
    {**result(), "suppressions": [{"status": "bad"}]},
    {**result(), "locations": [{"physicalLocation": {
        "artifactLocation": {"index": -1},
    }}]},
])
def test_malformed_result_does_not_erase_other_evidence(tmp_path, item):
    data = payload()
    data["runs"][0]["results"] = [item, result()]
    report, failures = review_sarif(save(tmp_path, data))
    assert failures == 1 and len(report["findings"]) == 1
    assert "selected unsupported results: 1" in json.dumps(report)


def test_index_only_rule_and_artifact_references(tmp_path):
    data = payload()
    run = data["runs"][0]
    item = run["results"][0]
    del item["ruleId"]
    item["ruleIndex"] = 0
    item["locations"][0]["physicalLocation"]["artifactLocation"] = {"index": 0}
    run["artifacts"] = [{"location": {"uri": "file.js", "uriBaseId": "SRCROOT"},
                         "contents": {"text": "PRIVATE"}}]
    report, failures = review_sarif(save(tmp_path, data))
    assert not failures
    evidence = report["findings"][0]["evidence"]
    assert "EXT001" in evidence and "file.js" in evidence and "unresolved base" in evidence
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("options", [
    {"start": 0}, {"start": True}, {"max_entries": 0}, {"max_entries": 201},
    {"max_entries": True},
])
def test_invalid_paging(tmp_path, options):
    with pytest.raises(ValidationError):
        review_sarif(save(tmp_path, payload()), **options)


@pytest.mark.parametrize("value", [
    {"version": "2.0.0", "runs": []}, {"version": "2.1.0", "runs": []},
    {"version": "2.1.0", "runs": None}, {"version": "2.1.0", "runs": [{}] * 21},
])
def test_invalid_document_not_clean(tmp_path, value):
    with pytest.raises(ValidationError):
        review_sarif(save(tmp_path, value))


@pytest.mark.parametrize("invocations", [
    None, [{}], [{"executionSuccessful": 1}],
    [{"executionSuccessful": True, "toolExecutionNotifications": [{"level": "bad"}]}],
])
def test_malformed_execution_metadata_retains_results(tmp_path, invocations):
    data = payload()
    data["runs"][0]["invocations"] = invocations
    report, failures = review_sarif(save(tmp_path, data))
    assert failures == 1 and report["findings"]
    assert "malformed invocation" in json.dumps(report)


def test_producer_limitations_survive_and_invalid_limits_are_not_silent(tmp_path):
    data = payload()
    data["runs"][0]["properties"] = {"limitations": ["Selected fixture scope only."]}
    report, failures = review_sarif(save(tmp_path, data))
    assert not failures and "Selected fixture scope only." in json.dumps(report)
    data["runs"][0]["properties"]["limitations"] = "PRIVATE"
    report, failures = review_sarif(save(tmp_path, data))
    assert failures and report["findings"] and "PRIVATE" not in json.dumps(report)


def test_paging_does_not_deduplicate_identical_external_claims(tmp_path):
    data = payload()
    data["runs"][0]["results"] = [result()] * 3
    report, failures = review_sarif(save(tmp_path, data), start=2, max_entries=1)
    assert not failures and len(report["findings"]) == 1
    assert "Result 2;" in report["findings"][0]["evidence"]
    assert "outside selected global page: 2" in json.dumps(report)
    full, _ = review_sarif(save(tmp_path, data))
    assert len(full["findings"]) == 3


def test_source_locations_are_bounded_and_never_dereferenced(tmp_path):
    data = payload()
    location = data["runs"][0]["results"][0]["locations"][0]
    location["physicalLocation"]["artifactLocation"]["uri"] = "https://never-open.invalid/file.js"
    data["runs"][0]["results"][0]["locations"] = [location] * 4
    report, failures = review_sarif(save(tmp_path, data))
    assert not failures and "locations_omitted=1" in report["findings"][0]["evidence"]
    location["physicalLocation"]["region"]["startLine"] = True
    report, failures = review_sarif(save(tmp_path, data))
    assert failures == 1 and not report["findings"]


def test_contradictory_artifact_identity_not_assigned_to_wrong_source(tmp_path):
    data = payload()
    run = data["runs"][0]
    run["artifacts"] = [{"location": {"uri": "different.js"}}]
    run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["index"] = 0
    report, failures = review_sarif(save(tmp_path, data))
    assert failures and not report["findings"]


def test_cli_failure_saved_with_good_result_and_no_overwrite(tmp_path, capsys):
    from ai_threat_lab.cli import main

    data = payload()
    data["runs"][0]["invocations"][0]["executionSuccessful"] = False
    source, output = save(tmp_path, data), tmp_path / "report.json"
    args = ["review-sarif", str(source), "--output", str(output), "--fail-on-findings"]
    assert main(args) == 2
    assert load_evidence(output)["report"]["findings"]
    original = output.read_bytes()
    assert main(args) == 2
    assert output.read_bytes() == original
    assert "PRIVATE" not in capsys.readouterr().err
