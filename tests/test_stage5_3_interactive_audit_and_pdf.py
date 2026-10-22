"""Tests for Stage 5.3: Expanded interactive audit, scan profiles, and PDF reports."""

from __future__ import annotations

from pathlib import Path

import pytest

from ai_threat_lab.gui_api import (
    create_audit_options,
    get_scan_profile,
    get_scan_profiles,
)
from ai_threat_lab.interactive_menu import (
    confirm_network_consent,
    run_new_audit_workflow,
    select_scan_profile,
)
from ai_threat_lab.local_inventory import local_inventory
from ai_threat_lab.models import ValidationError
from ai_threat_lab.pdf_report import (
    extract_scope_details,
    generate_pdf_report,
    parse_not_checked_items,
)
from ai_threat_lab.scan_bundle import read_bundle


def test_scan_profiles_definitions_and_lookup() -> None:
    """Verify that scan profiles (Fast, Standard, Extended, Custom) are available and valid."""
    profiles = get_scan_profiles()
    assert "fast" in profiles
    assert "standard" in profiles
    assert "extended" in profiles
    assert "custom" in profiles

    assert profiles["fast"]["max_files"] == 100
    assert profiles["standard"]["max_files"] == 1000
    assert profiles["extended"]["max_files"] == 5000
    assert profiles["custom"]["max_files"] is None

    p_fast = get_scan_profile("fast")
    assert p_fast["max_files"] == 100

    p_ext = get_scan_profile("EXTENDED")
    assert p_ext["max_files"] == 5000

    with pytest.raises(ValidationError, match="Unknown scan profile"):
        get_scan_profile("ultra_unsupported")


def test_create_audit_options_with_profiles_and_large_bounds(tmp_path: Path) -> None:
    """Verify ScanOptions bounds allow up to 10,000 files and respect profiles."""
    opts_fast = create_audit_options(tmp_path, profile="fast")
    assert opts_fast.max_files == 100

    opts_std = create_audit_options(tmp_path, profile="standard")
    assert opts_std.max_files == 1000

    opts_ext = create_audit_options(tmp_path, profile="extended")
    assert opts_ext.max_files == 5000

    opts_max = create_audit_options(tmp_path, max_files=10000)
    assert opts_max.max_files == 10000

    with pytest.raises(ValidationError, match="limit"):
        create_audit_options(tmp_path, max_files=10001)

    with pytest.raises(ValidationError, match="limit"):
        create_audit_options(tmp_path, max_files=0)


def test_select_scan_profile_interactive_helper() -> None:
    """Test interactive profile selection prompt in Polish and English."""
    printed: list[str] = []

    def mock_print(*args: object) -> None:
        printed.append(" ".join(str(a) for a in args))

    # Test 1: Fast
    assert select_scan_profile("pl", input_fn=lambda _: "1", print_fn=mock_print) == 100
    # Test 2: Standard (default)
    assert select_scan_profile("en", input_fn=lambda _: "", print_fn=mock_print) == 1000
    # Test 3: Extended
    assert select_scan_profile("pl", input_fn=lambda _: "3", print_fn=mock_print) == 5000
    # Test 4: Custom valid
    inputs_custom = iter(["4", "2500"])
    assert (
        select_scan_profile("en", input_fn=lambda _: next(inputs_custom), print_fn=mock_print)
        == 2500
    )
    # Test 5: Custom invalid fallback
    inputs_bad = iter(["4", "invalid_num"])
    assert (
        select_scan_profile("pl", input_fn=lambda _: next(inputs_bad), print_fn=mock_print) == 1000
    )


def test_confirm_network_consent_granted_vs_denied() -> None:
    """Verify explicit consent gate allows requests when granted and stops when denied."""
    printed: list[str] = []

    def mock_print(*args: object) -> None:
        printed.append(" ".join(str(a) for a in args))

    # Denied by default or 'n'
    assert not confirm_network_consent(
        "github.com", "GitHub API tree fetch", "pl", input_fn=lambda _: "n", print_fn=mock_print
    )
    assert any("Odmówiono" in p for p in printed)

    # Granted with 't'
    assert confirm_network_consent(
        "github.com", "GitHub API tree fetch", "pl", input_fn=lambda _: "t", print_fn=mock_print
    )
    # Granted with 'yes'
    assert confirm_network_consent(
        "example.com", "HTTPS check", "en", input_fn=lambda _: "yes", print_fn=mock_print
    )


def test_interactive_target_menu_option_0_returns_cleanly() -> None:
    """Option 0 immediately returns to menu without running scan."""
    printed: list[str] = []

    def mock_print(*args: object) -> None:
        printed.append(" ".join(str(a) for a in args))

    run_new_audit_workflow("pl", input_fn=lambda _: "0", print_fn=mock_print)
    out_text = "\n".join(printed)
    assert "WYBÓR RODZAJU CELU AUDYTU" in out_text
    assert "Anulowano audyt." in out_text


def test_interactive_target_menu_option_1_local_project(tmp_path: Path) -> None:
    """Option 1 runs local project audit with profile selection."""
    proj = tmp_path / "my_project"
    proj.mkdir()
    (proj / "main.py").write_text("import subprocess\nsubprocess.run(['ls'])\n", encoding="utf-8")
    (proj / "go.mod").write_text("module example.com/app\n", encoding="utf-8")
    (proj / "config.json").write_text('{"env": "prod"}\n', encoding="utf-8")

    out_dir = tmp_path / "out_proj"
    printed: list[str] = []

    def mock_print(*args: object) -> None:
        printed.append(" ".join(str(a) for a in args))

    # Inputs:
    # 1. Target menu: "1" (Local project)
    # 2. Project path: str(proj)
    # 3. Profile: "2" (Standard)
    # 4. Confirm scan: "t"
    # 5. Output dir: str(out_dir)
    # 6. Confirm dest: "t"
    # 7. AI enrich: "n"
    inputs = iter(["1", str(proj), "2", "t", "2", str(out_dir), "n", "n"])
    run_new_audit_workflow("pl", input_fn=lambda _: next(inputs), print_fn=mock_print)

    out_text = "\n".join(printed)
    assert "PODSUMOWANIE AUDYTU BEZPIECZEŃSTWA" in out_text or "ANALIZA ZAKOŃCZONA" in out_text
    assert (out_dir / "report.json").is_file()

    assert (out_dir / "exports" / "audit_pl.pdf").is_file()

    # Bundle integrity check must pass with derived exports
    bundle = read_bundle(out_dir)
    assert bundle["documents"]["report.json"]["status"] in ("complete", "partial")


def test_interactive_target_menu_option_2_single_file(tmp_path: Path) -> None:
    """Option 2 runs single file audit."""
    script = tmp_path / "script.py"
    script.write_text("import os\nprint('hello')\n", encoding="utf-8")
    out_dir = tmp_path / "out_single"

    printed: list[str] = []

    def mock_print(*args: object) -> None:
        printed.append(" ".join(str(a) for a in args))

    inputs = iter(["2", str(script), "t", "2", str(out_dir), "n", "n"])
    run_new_audit_workflow("en", input_fn=lambda _: next(inputs), print_fn=mock_print)

    out_text = "\n".join(printed)
    assert "SECURITY AUDIT SUMMARY" in out_text or "ANALYSIS COMPLETED" in out_text
    assert (out_dir / "report.json").is_file()
    assert (out_dir / "exports" / "audit_en.pdf").is_file()


def test_interactive_target_menu_option_3_github_consent_denied(tmp_path: Path) -> None:
    """Option 3 (GitHub) refuses execution when network consent is denied."""
    printed: list[str] = []

    def mock_print(*args: object) -> None:
        printed.append(" ".join(str(a) for a in args))

    # User picks 3, inputs repo, then denies network consent with 'n'
    inputs = iter(["3", "owner/sample-repo", "n"])
    run_new_audit_workflow("pl", input_fn=lambda _: next(inputs), print_fn=mock_print)

    out_text = "\n".join(printed)
    assert "ZGODA NA POŁĄCZENIE SIECIOWE" in out_text
    assert "Odmówiono zgody na połączenie sieciowe." in out_text


def test_interactive_target_menu_option_7_gmail_guide_and_cancelled() -> None:
    """Option 7 (Gmail) displays setup guide and allows clean cancellation."""
    printed: list[str] = []

    def mock_print(*args: object) -> None:
        printed.append(" ".join(str(a) for a in args))

    # User picks 7, sees guide, cancels at prompt with empty input / 0
    inputs = iter(["7", "0"])
    run_new_audit_workflow("pl", input_fn=lambda _: next(inputs), print_fn=mock_print)

    out_text = "\n".join(printed)
    assert "INSTRUKCJA KONFIGURACJI AUDYTU GMAIL" in out_text
    assert "https://www.googleapis.com/auth/gmail.readonly" in out_text


def test_local_inventory_multi_technology_and_scope_metric(tmp_path: Path) -> None:
    """Verify local inventory recognizes multi-language projects and adds structured scope."""
    (tmp_path / "app.py").write_text("print('python')\n", encoding="utf-8")
    (tmp_path / "main.go").write_text("package main\n", encoding="utf-8")
    (tmp_path / "lib.rs").write_text("fn test() {}\n", encoding="utf-8")
    (tmp_path / "Service.java").write_text("class Service {}\n", encoding="utf-8")
    (tmp_path / "script.sh").write_text("#!/bin/bash\n", encoding="utf-8")
    (tmp_path / "index.html").write_text("<html></html>\n", encoding="utf-8")
    (tmp_path / "schema.sql").write_text("CREATE TABLE x (id INT);\n", encoding="utf-8")

    result = local_inventory(str(tmp_path), max_files=100)
    not_checked_texts = [
        item if isinstance(item, str) else item.get("notice", "") for item in result.not_checked
    ]

    # Verify structured scope entry was added
    scope_entry = [t for t in not_checked_texts if t.startswith("Scope technologies:")]
    assert len(scope_entry) == 1
    assert "Python" in scope_entry[0]
    assert "Go" in scope_entry[0]
    assert "Rust" in scope_entry[0]
    assert "Java" in scope_entry[0]
    assert "Shell" in scope_entry[0]
    assert "HTML" in scope_entry[0]
    assert "SQL" in scope_entry[0]


def test_pdf_report_scope_and_next_steps_rendering(tmp_path: Path) -> None:
    """Verify PDF report contains Scope & Methodology, grouped limitations, and Next Steps."""
    rep = {
        "summary": {
            "unique_findings": 1,
            "triage_counts": {"P1": 1, "P2": 0, "P3": 0, "P4": 0},
            "finding_count": 1,
        },
        "findings": [
            {
                "id": "1",
                "check": "python_review",
                "status": "candidate",
                "evidence": "app.py: subprocess.run with shell=True",
                "recommendation": "Use arguments sequence without shell=True",
                "triage_priority": "P1",
                "confirmation_status": "candidate",
                "title": "Subprocess Shell Execution",
                "what_was_detected": "Unsafe subprocess call with shell=True",
                "mechanism": "Arbitrary command execution via shell argument.",
                "consequences": "Remote code execution if attacker controls input.",
                "how_to_verify": "Check if user-controlled input reaches shell.",
                "how_to_fix": "Pass list of arguments and set shell=False.",
                "file_path": "app.py",
                "line_number": 2,
            }
        ],
        "not_checked": [
            "Scope technologies: Python, Config. Files inspected: 15 / 15.",
            "Flow coverage: candidate data-flow checks apply only to selected Python modules",
            "Flow coverage: candidate data-flow checks apply only to selected Python modules",
            (
                "Inventory traversal stopped at the file/directory limit "
                "(100 files / 1000 directories). Scope is incomplete."
            ),
            "Excluded 5 temporary/cache/environment directories: .venv, __pycache__, tmp.",
            "Root-only dependency inventory: packages were read only from root manifests",
            "No packages were installed or executed: dependency audit is static only",
            "Only selected Python AST patterns were checked",
        ],
        "status": "partial",
        "notice": "Analysis was partial.",
        "project_name": "TestLabrys",
    }

    # Test extract_scope_details helper
    details = extract_scope_details(rep)
    assert "Python" in details["technologies"]
    assert "Config" in details["technologies"]
    assert details["files_inspected"] == "15 / 15"

    # Test parse_not_checked_items grouping
    categories = parse_not_checked_items(rep["not_checked"], "pl")
    cat_titles = [c["title"] for c in categories]
    # Data flow should be grouped into 1 category (not 2!)
    assert any("przepływu danych" in t for t in cat_titles)
    # Traversal limit should be present
    assert any("limit przeglądania" in t for t in cat_titles)
    # Scope technologies should not be in limitations
    assert not any("Scope technologies" in t for t in cat_titles)

    # Generate Polish PDF
    pdf_bytes_pl = generate_pdf_report(rep, language="pl", project_name="TestLabrys")
    assert isinstance(pdf_bytes_pl, bytes)
    assert len(pdf_bytes_pl) > 5000
    assert b"%PDF-1.4" in pdf_bytes_pl

    # Generate English PDF
    pdf_bytes_en = generate_pdf_report(rep, language="en", project_name="TestLabrys")
    assert isinstance(pdf_bytes_en, bytes)
    assert len(pdf_bytes_en) > 5000
    assert b"%PDF-1.4" in pdf_bytes_en
