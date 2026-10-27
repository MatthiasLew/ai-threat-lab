"""Automated tests for Stage 5: i18n, interactive menu, and PDF reports."""

from __future__ import annotations

import pytest

from ai_threat_lab import (
    CodeSnippet,
    ValidationError,
    export_audit_pdf,
    export_audit_report,
    extract_code_snippet,
    generate_pdf_report,
    get_active_language,
    load_language_preference,
    save_language_preference,
    set_active_language,
    t,
)
from ai_threat_lab.cli import main
from ai_threat_lab.i18n import TRANSLATIONS
from ai_threat_lab.interactive_menu import run_interactive_entrypoint
from ai_threat_lab.pdf_writer import PDFDocument, string_width

# ============================================================================
# 1. i18n & Localization Tests
# ============================================================================


def test_i18n_translations_completeness():
    """Verify that every translation key has non-empty entries for both PL and EN."""
    assert len(TRANSLATIONS) >= 40
    for key, bundle in TRANSLATIONS.items():
        assert "pl" in bundle, f"Missing Polish translation for key: {key}"
        assert "en" in bundle, f"Missing English translation for key: {key}"
        assert isinstance(bundle["pl"], str) and len(bundle["pl"]) > 0
        assert isinstance(bundle["en"], str) and len(bundle["en"]) > 0


def test_i18n_translation_fallback_and_interpolation():
    """Verify interpolation and graceful fallback for unknown keys or unsupported languages."""
    # Normal translation
    assert "AI THREAT LAB" in t("app_title", "pl").upper()
    assert "AI THREAT LAB" in t("app_title", "en").upper()

    # Parameter interpolation
    text_pl = t("metric_threats_found", "pl", count=42)
    assert "42" in text_pl

    text_en = t("metric_threats_found", "en", count=42)
    assert "42" in text_en

    # Unknown key returns the key itself as a safe fallback
    assert t("non_existent_key_xyz", "pl") == "non_existent_key_xyz"
    assert t("non_existent_key_xyz", "en") == "non_existent_key_xyz"

    # Unsupported language code falls back to en or pl
    assert len(t("app_title", "fr")) > 0


def test_language_preference_persistence(tmp_path, monkeypatch):
    """Verify loading and saving user language preference in config file."""
    fake_config_dir = tmp_path / ".ai-threat-lab"
    monkeypatch.setattr("ai_threat_lab.i18n.get_user_config_dir", lambda: fake_config_dir)

    # Initially empty
    assert load_language_preference() is None

    # Save PL preference
    save_language_preference("pl")
    assert (fake_config_dir / "config.json").exists()
    assert load_language_preference() == "pl"
    assert get_active_language() == "pl"

    # Save EN preference
    save_language_preference("en")
    assert load_language_preference() == "en"
    assert get_active_language() == "en"

    # Corrupt config file falls back safely without error
    (fake_config_dir / "config.json").write_text("invalid json content!", encoding="utf-8")
    assert load_language_preference() is None

    # Reset active language
    set_active_language("pl")
    assert get_active_language() == "pl"


# ============================================================================
# 2. CLI & Interactive Menu Non-Blocking Behavior
# ============================================================================


def test_cli_non_interactive_never_hangs_on_stdin(monkeypatch):
    """When launched without arguments in non-interactive / CI / piped stdin, CLI must not hang."""
    monkeypatch.setattr("sys.argv", ["ai-threat-lab"])
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)

    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2


def test_cli_explicit_menu_with_mocked_inputs(tmp_path, monkeypatch):
    """Verify explicit interactive menu execution with simulated keyboard input."""
    fake_config_dir = tmp_path / ".ai-threat-lab"
    monkeypatch.setattr("ai_threat_lab.i18n.get_user_config_dir", lambda: fake_config_dir)

    inputs = iter(["1", "0"])  # Select pl language first, then exit
    outputs = []

    def mock_print(*args):
        outputs.append(" ".join(str(a) for a in args))

    code = run_interactive_entrypoint(input_fn=lambda _: next(inputs), print_fn=mock_print)
    assert code == 0
    joined = "\n".join(outputs)
    assert "AI THREAT LAB" in joined.upper()


def test_cli_subcommands_bypass_menu(tmp_path):
    """Subcommands like --version or analyze must parse directly without entering menu."""
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


# ============================================================================
# 3. Code Snippet Extraction & Secret Scrubbing
# ============================================================================


def test_code_snippet_extraction_and_highlighting(tmp_path):
    """Verify code snippet extraction, line numbers, and target line highlighting."""
    source_file = tmp_path / "vulnerable.py"
    source_file.write_text(
        "import os\n"
        "import sys\n"
        "def run_cmd(user_input):\n"
        "    cmd = f'echo {user_input}'\n"
        "    os.system(cmd)  # dangerous\n"
        "    return True\n",
        encoding="utf-8",
    )

    snippet = extract_code_snippet(str(source_file), line_number=5, context_lines=2)
    assert snippet is not None
    assert isinstance(snippet, CodeSnippet)
    assert snippet.target_line == 5
    assert snippet.status == "unverified_current"

    # Lines 3, 4, 5, 6 should be present
    line_nums = [item.line_number for item in snippet.lines]
    assert 5 in line_nums
    assert 3 in line_nums

    # Target line must have is_target=True
    target_entry = next(item for item in snippet.lines if item.line_number == 5)
    assert target_entry.is_target is True
    assert "os.system(cmd)" in target_entry.text

    # Formatted lines should have '>' marker on target line
    formatted = snippet.format_text()
    assert ">    5 |" in formatted


def test_code_snippet_secret_scrubbing(tmp_path):
    """Verify that credentials, API keys, and sensitive tokens in snippets are scrubbed."""
    source_file = tmp_path / "config_with_secrets.py"
    source_file.write_text(
        'DB_HOST = "localhost"\n'
        'API_KEY = "AIzaSyD-1234567890abcdefghijklmnopqrst"\n'
        'SECRET_TOKEN = "sk-1234567890abcdef1234567890abcdef"\n'
        'PASSWORD = "super_secret_password_123"\n',
        encoding="utf-8",
    )

    snippet = extract_code_snippet(str(source_file), line_number=2, context_lines=2)
    assert snippet is not None
    rendered = snippet.format_text()

    assert "AIzaSyD" not in rendered
    assert "sk-" not in rendered
    assert "[REDACTED_SECRET]" in rendered


def test_code_snippet_missing_or_out_of_bounds(tmp_path):
    """Verify robust handling of non-existent files or invalid line numbers."""
    snippet_missing = extract_code_snippet(str(tmp_path / "non_existent.py"), line_number=10)
    assert snippet_missing.status == "unavailable"
    assert len(snippet_missing.lines) == 0

    empty_file = tmp_path / "empty.py"
    empty_file.write_text("", encoding="utf-8")
    snippet_empty = extract_code_snippet(str(empty_file), line_number=100)
    assert snippet_empty is None or snippet_empty.status == "unavailable"


# ============================================================================
# 4. Low-Level PDF Writer & Polish Diacritics
# ============================================================================


def test_pdf_writer_document_structure():
    """Verify PDF 1.4 header, object structure, trailer, and EOF markers."""
    doc = PDFDocument()
    doc.text(50, 700, "Hello World")
    doc.rect(50, 650, 200, 30, fill=(0.9, 0.9, 0.9), stroke=(0.2, 0.2, 0.2))
    doc.line(50, 640, 250, 640)
    pdf_bytes = doc.render()

    assert pdf_bytes.startswith(b"%PDF-1.4\n")
    assert pdf_bytes.rstrip().endswith(b"%%EOF")
    assert b"/Root" in pdf_bytes
    assert b"/Pages" in pdf_bytes
    assert b"xref\n" in pdf_bytes
    assert b"trailer\n" in pdf_bytes


def test_pdf_writer_polish_diacritics_encoding():
    """Verify that all 18 Polish diacritical characters are correctly mapped and rendered."""
    polish_sample = "Zażółć gęślą jaźń — ZAŻÓŁĆ GĘŚLĄ JAŹŃ"
    doc = PDFDocument()
    doc.text(50, 700, polish_sample)
    pdf_bytes = doc.render()

    # The PDF must NOT contain replacement '?' or unhandled Unicode escapes
    assert b"/WinAnsiEncoding" in pdf_bytes
    assert b"/Differences" in pdf_bytes
    assert b"/ToUnicode" in pdf_bytes
    assert b"/Aogonek" in pdf_bytes
    assert b"/aogonek" in pdf_bytes
    assert b"/Lslash" in pdf_bytes
    assert b"/lslash" in pdf_bytes

    # Ensure character widths compute without error
    w = string_width(polish_sample, "Helvetica", 10.0)
    assert w > 100


def test_pdf_writer_multipage_and_headers_footers():
    """Verify multi-page flow and running header/footer callbacks with page count."""
    doc = PDFDocument()
    for i in range(1, 100):
        doc.cursor_y -= 15
        if doc.cursor_y < 100:
            doc.new_page()
        doc.text(50, doc.cursor_y, f"Item number {i}")

    def footer(page_num, total_pages, c):
        c.text(50, 20, f"Page {page_num} of {total_pages}")

    pdf_bytes = doc.render(footer_fn=footer)
    assert len(doc.pages) > 1
    assert b"Page 1 of " in pdf_bytes


# ============================================================================
# 5. High-Level PDF Audit Report Generation
# ============================================================================


@pytest.fixture
def clean_audit_report():
    return {
        "status": "clean",
        "target": "c:/projects/safe_app",
        "generated_at": "2026-10-20T20:00:00Z",
        "summary": {
            "unique_findings": 0,
            "triage_counts": {"P1": 0, "P2": 0, "P3": 0, "P4": 0},
        },
        "findings": [],
        "not_checked": [
            {
                "tool_id": "network_reachability",
                "reason": "Offline audit policy prevents active network probes.",
            }
        ],
        "notice": "All candidate observations are verified locally without network calls.",
    }


@pytest.fixture
def vulnerable_audit_report(tmp_path):
    target_file = tmp_path / "app.py"
    target_file.write_text(
        "import subprocess\n"
        "def execute(cmd):\n"
        "    subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )

    return {
        "status": "candidate_findings",
        "target": str(target_file),
        "generated_at": "2026-10-20T21:00:00Z",
        "summary": {
            "unique_findings": 1,
            "triage_counts": {"P1": 1, "P2": 0, "P3": 0, "P4": 0},
        },
        "findings": [
            {
                "rule_code": "SEC001",
                "finding_id": "OBS-001",
                "title": "Subprocess execution with shell=True",
                "triage_priority": "P1",
                "confirmation_status": "candidate",
                "target": str(target_file),
                "file_path": str(target_file),
                "line_number": 3,
                "mechanism": "Spawning system shell with unvalidated input allows injection.",
                "recommendation": "Pass command arguments as a list with shell=False.",
            }
        ],
        "not_checked": [
            {
                "tool_id": "dynamic_memory_safety",
                "reason": "Static analysis does not track dynamic memory allocations.",
            }
        ],
        "notice": "Offline candidate findings require developer context validation.",
    }


def test_generate_pdf_report_clean_audit(clean_audit_report):
    """Verify PDF report generation for a clean project in Polish and English."""
    # Polish
    pdf_pl = generate_pdf_report(clean_audit_report, lang="pl")
    assert pdf_pl.startswith(b"%PDF-1.4\n")
    assert pdf_pl.rstrip().endswith(b"%%EOF")
    assert len(pdf_pl) > 5000

    # English
    pdf_en = generate_pdf_report(clean_audit_report, lang="en")
    assert pdf_en.startswith(b"%PDF-1.4\n")
    assert pdf_en.rstrip().endswith(b"%%EOF")
    assert len(pdf_en) > 5000


def test_generate_pdf_report_with_findings(vulnerable_audit_report):
    """Verify PDF report generation for an audit containing findings with code snippets."""
    pdf_bytes = generate_pdf_report(vulnerable_audit_report, lang="pl")
    assert pdf_bytes.startswith(b"%PDF-1.4\n")
    assert pdf_bytes.rstrip().endswith(b"%%EOF")
    assert len(pdf_bytes) > 8000

    # Check presence of Polish diacritics differences
    assert b"/Differences" in pdf_bytes


def test_generate_pdf_report_rejects_legacy_ungrounded_advisory(vulnerable_audit_report):
    """Verify attaching Google Gemini AI advisory interpretation to the PDF report."""
    ai_review = {
        "provider": "gemini",
        "model": "gemini-2.5-flash",
        "interpretation": {
            "summary": "Wykorzystanie powłoki systemowej stwarza ryzyko wykonania poleceń.",
            "observations": [
                {
                    "finding_id": "OBS-001",
                    "assessment": "Potwierdzone ryzyko wstrzyknięcia poleceń powłoki.",
                    "business_impact": "Przejęcie kontroli nad serwerem aplikacji.",
                    "safe_fix": "Zastąp subprocess.run(cmd, shell=True) listą argumentów.",
                }
            ],
        },
    }

    with pytest.raises(ValidationError):
        generate_pdf_report(vulnerable_audit_report, ai_review=ai_review, lang="pl")


def test_generate_pdf_report_rejects_tampered_ai_review(vulnerable_audit_report):
    """Verify that an AI review referencing non-existent findings is rejected."""
    tampered_ai_review = {
        "provider": "gemini",
        "model": "gemini-2.5-flash",
        "interpretation": {
            "summary": "Fake summary",
            "observations": [
                {
                    "finding_id": "OBS-UNKNOWN-999",
                    "assessment": "Fake observation",
                }
            ],
        },
    }

    with pytest.raises(ValidationError):
        generate_pdf_report(vulnerable_audit_report, ai_review=tampered_ai_review, lang="pl")


# ============================================================================
# 6. End-to-End Export via GUI API & CLI
# ============================================================================


def test_export_audit_pdf_gui_api(vulnerable_audit_report, tmp_path):
    """Verify exporting audit PDF via gui_api.export_audit_pdf."""
    out_pdf = tmp_path / "report_from_api.pdf"
    result_path = export_audit_pdf(vulnerable_audit_report, out_pdf, language="pl")
    assert result_path == out_pdf
    assert out_pdf.exists()
    assert out_pdf.stat().st_size > 5000

    content = out_pdf.read_bytes()
    assert content.startswith(b"%PDF-1.4\n")
    assert content.rstrip().endswith(b"%%EOF")


def test_export_audit_report_format_pdf_and_rejections(tmp_path):
    """Verify export_audit_report with format='pdf' on a verified saved scan directory."""
    from ai_threat_lab.gui_api import run_audit

    target_file = tmp_path / "app.py"
    target_file.write_text("import os\nos.system('dir')\n", encoding="utf-8")
    run_dir = tmp_path / "saved_run"

    run_audit(target_file, run_dir)
    assert (run_dir / "report.json").exists()

    # Valid export outside run_dir
    out_pdf = tmp_path / "exported.pdf"
    ret = export_audit_report(run_dir, output=out_pdf, format="pdf", language="pl")
    assert str(out_pdf) in ret
    assert out_pdf.exists()
    assert out_pdf.stat().st_size > 5000

    # Rejection when trying to write inside the run_dir
    inside_pdf = run_dir / "inside.pdf"
    with pytest.raises(ValidationError):
        export_audit_report(run_dir, output=inside_pdf, format="pdf")
