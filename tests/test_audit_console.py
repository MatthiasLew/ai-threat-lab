import json

import pytest

from ai_threat_lab.audit_console import browse_history, display_diagnostics, display_event
from ai_threat_lab.gui_api import run_audit
from ai_threat_lab.interactive_menu import run_interactive_entrypoint
from ai_threat_lab.scan_lifecycle import ScanEvent


@pytest.mark.parametrize("language", ["pl", "en"])
def test_history_summary_detail_compare_and_corrupt_run(tmp_path, language):
    target, history = tmp_path / "app.py", tmp_path / "history"
    target.write_text("eval(input())\n", encoding="utf-8")
    run_audit(target, history / "a")
    target.write_text("value = 1\n", encoding="utf-8")
    run_audit(target, history / "b")
    (history / "c").mkdir()
    (history / "c" / "manifest.json").write_text("{}", encoding="utf-8")
    # View a finding, then compare the two verified runs; reject corrupt entry.
    answers = iter([str(history), "1", "1", "1", "0", "2", "1", "2", "1", "3", "0"])
    output = []
    browse_history(language, input_fn=lambda _: next(answers), print_fn=output.append)
    text = "\n".join(output)
    assert "[invalid]" in text
    assert '"evidence"' in text
    assert '"no_longer_observed"' in text and '"comparable": true' in text
    assert "invalid; cannot display" in text


@pytest.mark.parametrize("language", ["pl", "en"])
def test_empty_history_and_invalid_choices(tmp_path, language):
    output = []
    browse_history(language, input_fn=lambda _: str(tmp_path), print_fn=output.append)
    assert any("Brak audytów" in line or "No saved" in line for line in output)
    answers = iter(["0"])
    browse_history(language, input_fn=lambda _: next(answers), print_fn=output.append)
    browse_history(language, input_fn=lambda _: str(tmp_path / "missing"), print_fn=output.append)
    assert any("error" in line.lower() or "Błąd" in line for line in output)


@pytest.mark.parametrize("language", ["pl", "en"])
def test_menu_history_and_diagnostic_routes(tmp_path, language):
    answers = iter(["2", str(tmp_path), "", "6", "", "0"])
    output = []
    assert run_interactive_entrypoint(
        override_language=language, input_fn=lambda _: next(answers),
        print_fn=lambda *v: output.append(
            " ".join(map(str, v))),
    ) == 0
    text = "\n".join(output)
    assert "capabilities" in text and "installation" in text
    assert "Brak audytów" in text or "No saved audits" in text


def test_event_adapter_reports_stage_without_percentage():
    output = []
    display_event(ScanEvent(1, "id", 1, "module_failed", "target_assessment", "failed"),
                  "en", output.append)
    assert output == ["[1] Analyzer failed: target_assessment (failed)"]
    output.clear()
    display_diagnostics("en", output.append)
    assert "pdf" in json.loads(output[-1])["capabilities"]["export_formats"]


def test_history_names_and_saved_strings_cannot_emit_terminal_controls(monkeypatch):
    import ai_threat_lab.audit_console as console

    monkeypatch.setattr(console, "get_audit_history", lambda _: {
        "runs": [{"directory": "untrusted\x1b]52;payload\x07", "verification": "invalid"}],
        "notice": "data\x1b[2J",
    })
    answers, output = iter(["history", "0"]), []
    browse_history("en", input_fn=lambda _: next(answers), print_fn=output.append)
    assert "\x1b" not in "\n".join(output)
    assert "\\u001b" in "\n".join(output)
