"""Independent privacy, provenance and paid-consent regression controls."""

import copy
import hashlib
import json
import socket

import pytest

from ai_threat_lab.ai_costs import AIConfig, CostLedger, compact_evidence
from ai_threat_lab.code_snippet import extract_code_snippet
from ai_threat_lab.evidence import evidence_digest, interpretation_evidence, load_saved_run
from ai_threat_lab.gemini_adapter import gemini_review_result
from ai_threat_lab.gui_api import run_audit
from ai_threat_lab.models import ValidationError
from ai_threat_lab.pdf_report import generate_pdf_report, validate_ai_review_binding


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Regression controls must not open sockets")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def scanned(tmp_path, source):
    project = tmp_path / "project"
    project.mkdir()
    path = project / "app.py"
    path.write_text(source, encoding="utf-8")
    run = tmp_path / "run"
    run_audit(project, run)
    return project, path, run, load_saved_run(run)["report"]


def advisory(report, ids=None):
    evidence = interpretation_evidence(report)
    ids = ids or {row["evidence_id"] for row in evidence["findings"]}
    evidence["findings"] = [row for row in evidence["findings"] if row["evidence_id"] in ids]
    return {
        "evidence_sha256": evidence_digest(json.loads(compact_evidence(evidence, 100000))),
        "interpretation": {
            "summary": "Synthetic advice", "uncertainty": "No live validation",
            "observations": [
                {"evidence_id": row["evidence_id"], "explanation": "Candidate",
                 "what_to_review": "Inspect context", "suggested_remediation": "Review input"}
                for row in evidence["findings"]
            ],
        },
    }


def test_pdf_does_not_reintroduce_detected_secret(tmp_path):
    token = "ghp_" + "Z" * 36
    root, _, _, report = scanned(tmp_path, f'GITHUB_PAT = "{token}"\n')
    assert report["findings"][0]["check"] == "possible_secret"
    assert token not in json.dumps(report)
    assert token.encode() not in generate_pdf_report(report, source_root=root)


@pytest.mark.parametrize("line,marker", [
    ('password = "' + "A" * 180 + '"', "A" * 30),
    ('password = "synthetic secret with spaces!"', "synthetic secret"),
    ('value = "ghp_' + "Z" * 36 + '"', "ghp_"),
    ('value = "AKIA' + "Z" * 16 + '"', "AKIA"),
])
def test_context_redacts_before_truncation(tmp_path, line, marker):
    path = tmp_path / "source.py"
    path.write_text(line + "\neval(input())\n", encoding="utf-8")
    snippet = extract_code_snippet(path, 2, source_root=tmp_path)
    assert marker not in snippet.format_text()
    assert "eval(input())" in snippet.format_text()
    assert snippet.status == "unverified_current"


def test_multiline_private_key_redaction_preserves_line_numbers(tmp_path):
    path = tmp_path / "key.py"
    path.write_text("-----BEGIN PRIVATE KEY-----\nSYNTHETIC_KEY_DATA\n"
                    "-----END PRIVATE KEY-----\neval(input())\n")
    snippet = extract_code_snippet(path, 4)
    assert "SYNTHETIC_KEY_DATA" not in snippet.format_text()
    assert any(row.line_number == 4 and row.text == "eval(input())" for row in snippet.lines)


def test_context_cannot_escape_root_or_use_cwd_fallback(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("SYNTHETIC_OUTSIDE\n")
    monkeypatch.chdir(tmp_path)
    for target in (outside, "../outside.py", "outside.py"):
        snippet = extract_code_snippet(target, 1, source_root=root)
        assert not snippet.lines


def test_context_snapshot_mismatch_is_not_displayed(tmp_path):
    path = tmp_path / "source.py"
    raw = b"old_source\n"
    path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    assert extract_code_snippet(path, 1, expected_hash=digest).status == "exact"
    path.write_bytes(b"new_source\n")
    snippet = extract_code_snippet(path, 1, expected_hash=digest)
    assert snippet.status == "diverged" and not snippet.lines


def test_saved_pdf_does_not_read_sources_and_live_context_is_labeled(tmp_path, monkeypatch):
    root, path, _, report = scanned(tmp_path, "eval(input()) # BEFORE_SCAN\n")
    path.write_text("eval(input()) # CHANGED_AFTER_SCAN\n")
    live = generate_pdf_report(report, source_root=root)
    assert b"CHANGED_AFTER_SCAN" in live
    assert b"not verified against the scan snapshot" in live
    def forbidden(*args, **kwargs):
        pytest.fail("Saved PDF implicitly reopened source")
    monkeypatch.setattr("ai_threat_lab.pdf_report.extract_code_snippet", forbidden)
    assert b"CHANGED_AFTER_SCAN" not in generate_pdf_report(report)


@pytest.mark.parametrize("mutation", ["digest", "duplicate", "malformed", "stale_notice"])
def test_ai_pdf_rejects_invalid_binding(tmp_path, mutation):
    _, _, _, report = scanned(tmp_path, "eval(input())\n")
    value = advisory(report)
    if mutation == "digest":
        value["evidence_sha256"] = "0" * 64
    elif mutation == "duplicate":
        value["interpretation"]["observations"] *= 2
    elif mutation == "malformed":
        value["interpretation"]["observations"].append({})
    else:
        report = copy.deepcopy(report)
        report["not_checked"][0]["notice"] += " Modified scope."
    with pytest.raises(ValidationError):
        generate_pdf_report(report, ai_review=value)


def test_partial_ai_packet_is_bound_and_labeled(tmp_path):
    _, _, _, report = scanned(tmp_path, "eval(input())\nimport pickle\npickle.loads(data)\n")
    first = report["findings"][0]["id"]
    value = advisory(report, {first})
    validate_ai_review_binding(report, value)
    pdf = generate_pdf_report(report, ai_review=value)
    assert b"AI coverage: 1/2 findings." in pdf


def test_changed_evidence_is_rejected_before_paid_call(tmp_path):
    _, _, _, report = scanned(tmp_path, "eval(input())\n")
    config = AIConfig("gemini-test", "0.50", "1.50")
    class Forbidden:
        def request(self, *args, **kwargs):
            pytest.fail("Unexpected paid request")
    with pytest.raises(ValidationError, match="changed after preview"):
        gemini_review_result(config, CostLedger(tmp_path / "costs.sqlite"), Forbidden(),
                             report, expected_evidence_sha256="0" * 64)


def test_menu_uses_confirmed_config_packet_and_shared_ledger(tmp_path, monkeypatch):
    from ai_threat_lab import interactive_menu as menu

    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("eval(input())\n" * 5)
    config_path = tmp_path / "ai.json"
    config_path.write_text(json.dumps({
        "schema_version": 1, "model": "gemini-test",
        "input_usd_per_million": "1.23", "output_usd_per_million": "4.56",
        "daily_budget_usd": "0.20", "max_calls_per_day": 2,
    }))
    config_dir = tmp_path / "settings"
    monkeypatch.setattr(menu, "get_default_reports_dir", lambda: tmp_path / "reports")
    monkeypatch.setattr(menu, "get_user_config_file", lambda: config_dir / "settings.json")
    monkeypatch.setenv("GEMINI_API_KEY", "synthetic-only")
    prepared, calls = [], []
    real_prepare = menu.prepare_ai_packets
    def prepare(*args, **kwargs):
        result = real_prepare(*args, **kwargs)
        prepared.append((kwargs["config"], result))
        return result
    monkeypatch.setattr(menu, "prepare_ai_packets", prepare)
    def review(config, ledger, client, report, **kwargs):
        assert config is prepared[-1][0]
        selected = prepared[-1][1]["packets"][1]
        assert kwargs["packet_index"] == 2
        assert kwargs["expected_evidence_sha256"] == selected["evidence_sha256"]
        assert ledger.path == config_dir / "ai-costs.sqlite"
        calls.append(ledger.path)
        evidence = interpretation_evidence(report)
        ids = {row["evidence_id"] for row in evidence["findings"][3:]}
        return advisory(report, ids)
    monkeypatch.setattr("ai_threat_lab.gemini_adapter.gemini_review_result", review)
    printed = []
    for _ in range(2):
        replies = iter(["1", str(project), "2", "y", "1", "y", str(config_path), "2", "y"])
        menu.run_new_audit_workflow("en", input_fn=lambda _: next(replies),
                                   print_fn=lambda *x: printed.append(" ".join(map(str, x))))
    assert len(calls) == 2 and calls[0] == calls[1]
    assert "1.23" in "\n".join(printed)
    assert "4.56" in "\n".join(printed)
