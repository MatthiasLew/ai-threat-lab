"""Independent boundaries for the collector -> saved evidence -> interpretation journey."""

import copy
import json
from dataclasses import asdict

import pytest

from ai_threat_lab.ai_costs import AIConfig, compact_evidence
from ai_threat_lab.assessment import AssessmentFinding, AssessmentResult
from ai_threat_lab.audit_report import merge_reports
from ai_threat_lab.cli import main
from ai_threat_lab.contracts import write_document
from ai_threat_lab.evidence import (
    brief,
    interpretation_evidence,
    load_evidence,
    validate_combined,
)
from ai_threat_lab.models import ValidationError
from ai_threat_lab.scan_engine import ScanOptions, ScanService
from ai_threat_lab.workbench_cli import prepare_evidence


def assessment(target="private-target", *, finding=True):
    return {"target": target, "target_kind": "python_source", "status": "partial",
            "findings": [{"check": "PY001", "status": "candidate", "evidence": "line 1",
                          "recommendation": "Review input validation"}] if finding else [],
            "not_checked": ["No runtime execution"]}


def config():
    return AIConfig("fixture-model", "2", "8")


def save(tmp_path, value, name="evidence.json"):
    path = tmp_path / name
    write_document(value, path)
    return path


def test_combined_to_model_preserves_different_targets_and_limitations(tmp_path):
    report = merge_reports([assessment("private-one"), assessment("private-two")])
    path = save(tmp_path, report)
    value = prepare_evidence(path, config())
    prompt = value["input_text"]
    assert "private-one" not in prompt and "private-two" not in prompt
    assert value["finding_count"] == 2
    assert value["input"]["not_checked"] == [
        "[T001] No runtime execution", "[T002] No runtime execution"]
    assert [f["evidence_id"] for f in value["input"]["findings"]] == [
        f["id"] for f in report["findings"]]
    assert value["network_called"] is False
    assert value["ledger_written"] is False
    assert value["credentials_inspected"] is False
    assert value["input_bytes"] == len(prompt.encode())
    assert value["origin"] == "unverified_combined_report"


def test_duplicate_source_observations_preserve_original_count(tmp_path):
    source = assessment()
    source["findings"] *= 2
    report = merge_reports([source, assessment()])
    assert validate_combined(report) == report
    prepared = prepare_evidence(save(tmp_path, report), config())
    assert prepared["finding_count"] == 1


@pytest.mark.parametrize("mutation", [
    lambda r: r.update(schema_version=True),
    lambda r: r["summary"].update(unique_findings=True),
    lambda r: r["summary"].update(unique_findings=10),
    lambda r: r["findings"][0].update(id="0" * 64),
    lambda r: r["findings"][0].update(sources=[True]),
    lambda r: r["findings"][0].update(sources=[1, 1]),
    lambda r: r["findings"][0].update(sources=[2]),
    lambda r: r["findings"][0].update(target="different"),
    lambda r: r["findings"][0].update(triage_priority="P1"),
    lambda r: r["not_checked"][0].update(source=False),
    lambda r: r["not_checked"][0].update(target="different"),
    lambda r: r["assessments"][0].update(finding_count=0),
    lambda r: r["assessments"][0].update(finding_count=True),
    lambda r: r["assessments"][0].update(source=2),
    lambda r: r.update(notice="Everything is secure"),
])
def test_tampered_combined_report_rejected(mutation):
    report = merge_reports([assessment()])
    mutation(report)
    with pytest.raises(ValidationError):
        validate_combined(report)


def test_empty_report_stays_partial_and_makes_no_reservation(tmp_path):
    path = save(tmp_path, merge_reports([assessment(finding=False)]))
    value = prepare_evidence(path, config())
    assert value["status"] == "skipped_no_findings"
    assert value["reserved_usd"] == "0.000000000"
    assert value["input"]["not_checked"]
    text = brief(load_evidence(path))
    assert "does not establish" in text


def test_single_assessment_retains_existing_prompt_contract(tmp_path):
    source = assessment()
    value = load_evidence(save(tmp_path, source))
    assert compact_evidence(value["ai_document"], 12000) == compact_evidence(source, 12000)


def test_reference_prevents_cross_target_deduplication():
    source = assessment()
    source["findings"] *= 2
    source["findings"] = [copy.deepcopy(row) for row in source["findings"]]
    source["findings"][0]["evidence_id"] = "a" * 64
    source["findings"][1]["evidence_id"] = "b" * 64
    assert len(json.loads(compact_evidence(source, 12000))["findings"]) == 2
    source["findings"][0]["evidence_id"] = "not-a-reference"
    with pytest.raises(ValidationError):
        compact_evidence(source, 12000)


def test_verified_bundle_and_tampered_bundle(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text("pass")
    service = ScanService(lambda options: AssessmentResult(
        options.target, "python_source", "partial",
        (AssessmentFinding("PY001", "candidate", "line 1", "Review"),), ("Partial",)))
    output = tmp_path / "run"
    service.run(ScanOptions(str(target)), output)
    target.unlink()  # Summary and model preparation must not rescan the original target.
    assert load_evidence(output)["origin"] == "verified_scan"
    assert prepare_evidence(output, config())["finding_count"] == 1
    (output / "assessment.json").write_text("{}")
    with pytest.raises(ValidationError):
        load_evidence(output)


def test_failed_scan_remains_visible_in_preview(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text("pass")
    def failing(options):
        raise RuntimeError("not collected")
    output = tmp_path / "run"
    ScanService(failing).run(ScanOptions(str(target)), output)
    value = prepare_evidence(output, config())
    assert value["failed_components"] == ["target_assessment"]
    assert value["status"] == "skipped_no_findings"
    assert "failed" in " ".join(value["input"]["not_checked"])


def test_cli_summary_prepare_and_existing_ai_dry_run(tmp_path, capsys):
    source = save(tmp_path, merge_reports([assessment()]))
    settings = save(tmp_path, {"schema_version": 1, **asdict(config())}, "config.json")
    assert main(["brief", str(source)]) == 0
    assert "Review input validation" in capsys.readouterr().out
    assert main(["ai-prepare", str(source), "--ai-config", str(settings)]) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["finding_count"] == 1
    assert main(["ai-explain", str(source), "--ai-config", str(settings), "--ledger",
                 str(tmp_path / "cost.sqlite"), "--dry-run"]) == 0
    estimate = json.loads(capsys.readouterr().out)
    assert estimate["reserved_usd"] == preview["reserved_usd"]


def test_brief_escapes_terminal_controls(tmp_path):
    source = assessment()
    source["findings"][0]["evidence"] = "\x1b[2J deceptive"
    text = brief(load_evidence(save(tmp_path, source)))
    assert "\x1b" not in text and "\\u001b" in text


def test_output_not_overwritten(tmp_path):
    source = save(tmp_path, assessment())
    output = tmp_path / "summary.txt"
    assert main(["brief", str(source), "--output", str(output)]) == 0
    before = output.read_bytes()
    assert main(["brief", str(source), "--output", str(output)]) == 2
    assert output.read_bytes() == before


def test_invalid_oversize_and_duplicate_json_are_rejected(tmp_path):
    path = tmp_path / "bad.json"
    for raw in (b'{"a":1,"a":2}', b"[]", b"x" * (8 * 1024 * 1024 + 1)):
        path.write_bytes(raw)
        with pytest.raises(ValidationError):
            load_evidence(path)


def test_large_evidence_never_silently_truncated(tmp_path):
    source = assessment()
    source["findings"][0]["evidence"] = "x" * 13000
    with pytest.raises(ValidationError, match="split"):
        prepare_evidence(save(tmp_path, source), config())


def test_projection_does_not_change_report():
    report = merge_reports([assessment()])
    original = copy.deepcopy(report)
    interpretation_evidence(report)
    assert report == original
