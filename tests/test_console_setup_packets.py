"""End-to-end navigation, lossless packet boundaries and truthful setup reports."""

import json
from dataclasses import asdict, replace

import pytest

from ai_threat_lab.ai_costs import AIConfig, compact_evidence
from ai_threat_lab.ai_review import review_result
from ai_threat_lab.audit_report import merge_reports
from ai_threat_lab.batch_scan import run_batch
from ai_threat_lab.cli import main
from ai_threat_lab.console import run_console
from ai_threat_lab.contracts import write_document
from ai_threat_lab.models import ValidationError
from ai_threat_lab.review_packets import review_packets, select_packet
from ai_threat_lab.setup_check import setup_check
from ai_threat_lab.workbench_cli import prepare_evidence


def report(count=7):
    return merge_reports([{
        "target": "fixture", "target_kind": "python_source", "status": "partial",
        "findings": [{"check": "PY001", "status": "candidate", "evidence": f"line {n}",
                      "recommendation": "Review inputs"} for n in range(count)],
        "not_checked": ["No execution", "No complete language coverage"],
    }])


def config():
    return AIConfig("test-selected-model", "2", "8")


def test_packets_partition_all_findings_preserving_every_limitation():
    source = report()
    packets = review_packets(source, 12000)
    assert [len(p["findings"]) for p in packets] == [3, 3, 1]
    ids = [f["evidence_id"] for p in packets for f in p["findings"]]
    assert ids == [f["id"] for f in source["findings"]]
    assert len(set(ids)) == 7
    for packet in packets:
        assert packet["not_checked"] == [
            "[T001] No execution", "[T001] No complete language coverage"]
        assert len(compact_evidence(packet, 12000).encode()) <= 12000


def test_byte_limit_also_splits_packets():
    packets = review_packets(report(4), 500, group_size=20)
    assert len(packets) == 4
    assert all(len(compact_evidence(p, 500).encode()) <= 500 for p in packets)


def test_packets_reject_oversized_single_observation_or_limitations():
    source = report(1)
    source["findings"][0]["evidence"] = "x" * 1000
    with pytest.raises(ValidationError):
        review_packets(source, 500)
    source = report(1)
    source["not_checked"][0]["notice"] = "x" * 1000
    with pytest.raises(ValidationError):
        review_packets(source, 500)


@pytest.mark.parametrize("size", [0, 21, True, "3"])
def test_group_bounds(size):
    with pytest.raises(ValidationError):
        review_packets(report(), 12000, group_size=size)


def test_packet_limit_and_index_bounds():
    with pytest.raises(ValidationError, match="100"):
        review_packets(report(101), 12000, group_size=1)
    with pytest.raises(ValidationError, match="3 packets"):
        select_packet(report(), 12000)
    for index in (0, 4, True, "1"):
        with pytest.raises(ValidationError):
            select_packet(report(), 12000, packet_index=index)
    selected, index, total = select_packet(report(), 12000, packet_index=3)
    assert len(selected["findings"]) == 1 and (index, total) == (3, 3)


def test_split_preview_matches_each_dry_run_and_aggregate_cost(tmp_path):
    source = report()
    path = tmp_path / "report.json"
    write_document(source, path)
    preview = prepare_evidence(path, config(), structured=True, split=True)
    assert preview["packet_count"] == 3 and preview["total_finding_count"] == 7
    for packet in preview["packets"]:
        index = packet["packet_index"]
        estimate = review_result(config(), None, None, source, dry_run=True, packet_index=index)
        assert estimate["reserved_usd"] == packet["reserved_usd"]
        assert estimate["evidence_sha256"] == packet["evidence_sha256"]
        single = prepare_evidence(path, config(), structured=True, packet_index=index)
        assert single == packet
    total = sum(int(p["reserved_usd"].replace(".", "")) for p in preview["packets"])
    assert int(preview["maximum_reserved_usd"].replace(".", "")) == total


def test_packet_options_require_structured_and_exclusive_selection(tmp_path):
    path = tmp_path / "report.json"
    write_document(report(), path)
    for kwargs in ({"split": True}, {"packet_index": 1}, {"group_size": 2},
                   {"structured": True, "split": True, "packet_index": 1}):
        with pytest.raises(ValidationError):
            prepare_evidence(path, config(), **kwargs)


def test_empty_packet_never_calls_model():
    result = review_result(config(), None, None, report(0))
    assert result["status"] == "skipped_no_findings"
    assert result["packet_count"] == 1 and result["total_finding_count"] == 0


def test_setup_distinguishes_syntax_configuration_and_live_validation(tmp_path):
    assert setup_check()["status"] == "configuration_needed"
    path = tmp_path / "config.json"
    write_document({"schema_version": 1, **asdict(config())}, path)
    result = setup_check(path)
    assert result["status"] == "local_configuration_valid"
    assert result["live_ready"] is False and result["credentials_inspected"] is False
    assert result["network_called"] is False and len(result["remaining_live_checks"]) == 4
    path.unlink()
    write_document({"schema_version": 1, **asdict(replace(config(), model="REPLACE_MODEL"))}, path)
    assert setup_check(path)["status"] == "configuration_needed"


def test_setup_does_not_hide_inconsistent_installation(monkeypatch):
    import ai_threat_lab.setup_check as module
    monkeypatch.setattr(module, "installation_report", lambda: {"status": "inconsistent"})
    assert setup_check()["status"] == "installation_inconsistent"


def test_batch_can_be_prepared_after_original_targets_are_deleted(tmp_path):
    first, second = tmp_path / "first.py", tmp_path / "second.py"
    first.write_text("eval(input())\n")
    second.write_text("eval(input())\n")
    output = tmp_path / "batch"
    run_batch([str(first), str(second)], output)
    first.unlink()
    second.unlink()
    value = prepare_evidence(output, config(), structured=True, split=True)
    assert value["total_finding_count"] == 2
    assert value["packets"][0]["origin"] == "verified_batch"
    ids = [row["evidence_id"] for packet in value["packets"]
           for row in packet["input"]["findings"]]
    assert len(set(ids)) == 2


def answers(monkeypatch, values):
    iterator = iter(values)
    monkeypatch.setattr("builtins.input", lambda _: next(iterator))


def test_console_plan_does_not_run_without_final_confirmation(tmp_path, monkeypatch, capsys):
    target = tmp_path / "test.py"
    target.write_text("pass")
    calls = []
    answers(monkeypatch, ["1", str(target), str(tmp_path / "run"), "n", "0"])
    assert run_console(lambda args: calls.append(args)) == 0
    assert calls == [] and "cancelled" in capsys.readouterr().out


def test_console_network_requires_separate_scope_and_run_approval(monkeypatch):
    calls = []
    answers(monkeypatch, ["1", "https://example.invalid", "n", "1",
                          "https://example.invalid", "y", "run", "y", "0"])
    assert run_console(lambda args: calls.append(args) or 0) == 0
    assert calls == [["inspect", "https://example.invalid", "--network", "--allow-host",
                      "example.invalid", "--output-dir", "run"]]


def test_console_other_flows_and_invalid_selection(monkeypatch, capsys):
    calls = []
    answers(monkeypatch, ["9", "2", "saved", "3", "saved", "config", "preview",
                          "4", "5", "", "5", "config", "6", "0"])
    assert run_console(lambda args: calls.append(args) or 0) == 0
    assert calls == [["brief", "saved"], ["ai-prepare", "saved", "--ai-config", "config",
                     "--structured", "--split", "--output", "preview"], ["interactive"],
                     ["setup-check"], ["setup-check", "--ai-config", "config"], ["readiness"]]
    assert "Choose a number" in capsys.readouterr().out


def test_console_failure_bad_input_and_end_of_input(monkeypatch, capsys):
    answers(monkeypatch, ["", "\x1b", "2", "saved", "0"])
    assert run_console(lambda args: 2) == 0
    text = capsys.readouterr().out
    assert "Input problem" in text and "status 2" in text
    def eof(_):
        raise EOFError
    monkeypatch.setattr("builtins.input", eof)
    assert main(["console"]) == 0


def test_setup_and_split_preview_cli(tmp_path, capsys):
    assert main(["setup-check"]) == 0
    assert json.loads(capsys.readouterr().out)["live_ready"] is False
    path, settings = tmp_path / "report.json", tmp_path / "config.json"
    write_document(report(), path)
    write_document({"schema_version": 1, **asdict(config())}, settings)
    assert main(["ai-prepare", str(path), "--ai-config", str(settings),
                 "--structured", "--split"]) == 0
    assert json.loads(capsys.readouterr().out)["packet_count"] == 3
