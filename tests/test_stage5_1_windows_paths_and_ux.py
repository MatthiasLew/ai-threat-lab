"""Tests for Stage 5.1: Windows path normalization, pre-audit validation, and UX enhancements."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_threat_lab import clean_user_path
from ai_threat_lab.interactive_menu import (
    describe_planned_scope,
    format_target_kind,
    run_export_workflow,
    run_interactive_entrypoint,
    run_language_selection,
    run_new_audit_workflow,
    run_settings_workflow,
    suggest_output_dir,
    validate_output_directory,
    validate_target_path,
)
from ai_threat_lab.path_utils import clean_user_path as pu_clean_user_path


def test_clean_user_path_variations() -> None:
    """Test clean_user_path across all supported quoting and formatting styles."""
    assert clean_user_path(None) == ""
    assert clean_user_path("") == ""
    assert clean_user_path("   ") == ""

    # Normal unquoted paths
    assert clean_user_path(r"C:\Users\Praca\Desktop\Labrys") == r"C:\Users\Praca\Desktop\Labrys"
    assert clean_user_path("/home/user/project") == "/home/user/project"

    # Double-quoted paths (Windows Explorer "Copy as path")
    expected = r"C:\Users\Praca\Desktop\raport_labrys"
    assert clean_user_path(r'"C:\Users\Praca\Desktop\raport_labrys"') == expected
    assert clean_user_path(r'  "C:\Users\Praca\Desktop\raport_labrys"  ') == expected
    assert clean_user_path(r'"  C:\Users\Praca\Desktop\raport_labrys  "') == expected

    # Single-quoted paths
    assert clean_user_path(r"'C:\Users\Praca\Desktop\raport_labrys'") == expected
    assert clean_user_path(r"  'C:\Users\Praca\Desktop\raport_labrys'  ") == expected

    # Paths with spaces
    assert clean_user_path(r'"C:\Program Files\My App\scan"') == r"C:\Program Files\My App\scan"
    assert clean_user_path(r"'C:\My Documents\Projects'") == r"C:\My Documents\Projects"

    # UNC paths
    assert clean_user_path(r"\\server\share\folder") == r"\\server\share\folder"
    assert clean_user_path(r'"\\server\share\folder"') == r"\\server\share\folder"

    # Shell prefixes
    assert clean_user_path(r'& "C:\Users\foo"') == r"C:\Users\foo"
    assert clean_user_path(r'@"C:\Users\foo"') == r"C:\Users\foo"

    # Multiple quotes wrapper
    assert clean_user_path(r'""C:\Users\foo""') == r"C:\Users\foo"

    # Internal quotes are preserved
    assert clean_user_path(r'path"with"internal') == r'path"with"internal'

    # NUL byte cleanup
    assert clean_user_path("C:\\Users\\foo\0\\bar") == "C:\\Users\\foo\\bar"

    # Both imports identical
    assert pu_clean_user_path(r'"C:\test"') == r"C:\test"


def test_suggest_output_dir(tmp_path: Path) -> None:
    """Test auto-incrementing output directory proposal."""
    base_dir = tmp_path / "reports"
    base_dir.mkdir(parents=True)

    # First suggestion
    s1 = suggest_output_dir("my_target", base_dir=str(base_dir))
    assert s1.endswith("my_target")

    # Create the first suggestion directory
    (base_dir / "my_target").mkdir()
    s2 = suggest_output_dir("my_target", base_dir=str(base_dir))
    assert s2.endswith("my_target_1")

    # Create the second
    (base_dir / "my_target_1").mkdir()
    s3 = suggest_output_dir("my_target", base_dir=str(base_dir))
    assert s3.endswith("my_target_2")


def test_validate_target_path(tmp_path: Path) -> None:
    """Test target path validation logic."""
    # Empty
    valid, p, err = validate_target_path("", language="pl")
    assert not valid and p is None
    assert "nie może być pusta" in (err or "")

    # Non-existent
    valid, p, err = validate_target_path(r'"C:\non_existent_folder_xyz_123"', language="pl")
    assert not valid and p is None
    assert "nie istnieje" in (err or "")

    # Valid folder (quoted)
    target_dir = tmp_path / "test_target"
    target_dir.mkdir()
    valid, p, err = validate_target_path(f'"{target_dir}"', language="pl")
    assert valid and p is not None and err is None
    assert p.resolve() == target_dir.resolve()


def test_validate_output_directory(tmp_path: Path) -> None:
    """Test output destination validation logic."""
    target_dir = tmp_path / "target_app"
    target_dir.mkdir()

    # Empty
    valid, p, err = validate_output_directory("", target_dir, language="pl")
    assert not valid and p is None
    assert "nie może być pusta" in (err or "")

    # Already existing directory
    existing_out = tmp_path / "existing_dir"
    existing_out.mkdir()
    valid, p, err = validate_output_directory(f'"{existing_out}"', target_dir, language="pl")
    assert not valid and p is None
    assert "już istnieje" in (err or "")

    # Output directory same as target
    valid, p, err = validate_output_directory(f'"{target_dir}"', target_dir, language="pl")
    assert not valid and p is None
    assert "nie może być tożsamy" in (err or "")

    # Output directory inside target
    inside_dir = target_dir / "reports" / "run1"
    valid, p, err = validate_output_directory(f'"{inside_dir}"', target_dir, language="pl")
    assert not valid and p is None
    assert "nie może znajdować się wewnątrz" in (err or "")

    # Valid non-existing new directory
    valid_out = tmp_path / "new_report"
    valid, p, err = validate_output_directory(f'"{valid_out}"', target_dir, language="pl")
    assert valid and p is not None and err is None


def test_format_target_kind_and_planned_scope(tmp_path: Path) -> None:
    """Test target kind formatting and planned scope descriptions."""
    assert format_target_kind("local_project", "pl") == "Katalog projektu lokalnego"
    assert format_target_kind("local_project", "en") == "Local project directory"
    assert format_target_kind("custom_kind", "pl") == "custom_kind"

    # Local project plan
    plan_local = {
        "target_kind": "local_project",
        "tools": [
            {"id": "local_inventory", "purpose": "source and secrets"},
            {"id": "dependency_inventory", "purpose": "manifests"},
            {"id": "verified_report_bundle", "purpose": "bundle"},
        ],
    }
    scope_pl = describe_planned_scope(tmp_path, plan_local, "pl")
    assert len(scope_pl) == 3
    assert any("subprocess" in item for item in scope_pl)
    assert any("Skaner sekretów" in item for item in scope_pl)
    assert any("zależności" in item for item in scope_pl)

    scope_en = describe_planned_scope(tmp_path, plan_local, "en")
    assert len(scope_en) == 3
    assert any("subprocess" in item for item in scope_en)
    assert any("Secrets" in item for item in scope_en)

    # Empty plan
    scope_empty = describe_planned_scope(tmp_path, {}, "pl")
    assert scope_empty == []


def test_language_selection_first_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test first-run language selection screen appearance and persistence."""
    config_dir = tmp_path / "config"
    monkeypatch.setenv("AI_THREAT_LAB_CONFIG_DIR", str(config_dir))

    printed: list[str] = []

    def mock_print(*args: object) -> None:
        printed.append(" ".join(str(a) for a in args))

    inputs = iter(["1"])  # User picks Polski

    lang = run_language_selection(input_fn=lambda _: next(inputs), print_fn=mock_print)
    assert lang == "pl"

    output_text = "\n".join(printed)
    assert "AI THREAT LAB — WYBÓR JĘZYKA / LANGUAGE SELECTION" in output_text
    assert "1. Polski (Polish)" in output_text
    assert "2. English (Angielski)" in output_text
    assert "Zmieniono język na: Polski" in output_text

    # Verify persisted config file
    cfg_file = config_dir / "config.json"
    assert cfg_file.is_file()
    data = json.loads(cfg_file.read_text(encoding="utf-8"))
    assert data.get("language") == "pl"


def test_interactive_entrypoint_auto_load_vs_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test auto-loading preference on subsequent runs vs CLI override flags."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    cfg_file = config_dir / "config.json"
    cfg_file.write_text(json.dumps({"language": "en"}), encoding="utf-8")
    monkeypatch.setenv("AI_THREAT_LAB_CONFIG_DIR", str(config_dir))

    printed: list[str] = []

    def mock_print(*args: object) -> None:
        printed.append(" ".join(str(a) for a in args))

    # Auto-load should use 'en' directly and not show language selection prompt
    inputs = iter(["0"])  # Exit menu
    code = run_interactive_entrypoint(input_fn=lambda _: next(inputs), print_fn=mock_print)
    assert code == 0
    all_out = "\n".join(printed)
    assert "WYBÓR JĘZYKA" not in all_out
    assert "Goodbye!" in all_out

    # Force selection flag should prompt even when config exists
    printed.clear()
    inputs_force = iter(["1", "0"])  # Pick Polish, then exit
    code = run_interactive_entrypoint(
        input_fn=lambda _: next(inputs_force),
        print_fn=mock_print,
        force_language_selection=True,
    )
    assert code == 0
    all_out = "\n".join(printed)
    assert "WYBÓR JĘZYKA" in all_out
    assert "Do widzenia!" in all_out

    # Override language flag should set language directly without prompt
    printed.clear()
    inputs_override = iter(["0"])  # Exit
    code = run_interactive_entrypoint(
        input_fn=lambda _: next(inputs_override),
        print_fn=mock_print,
        override_language="pl",
    )
    assert code == 0
    all_out = "\n".join(printed)
    assert "WYBÓR JĘZYKA" not in all_out
    assert "Do widzenia!" in all_out


def test_interactive_audit_workflow_with_quoted_windows_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end regression test: user inputs Windows paths with Explorer quotes."""
    target_project = tmp_path / "Labrys_project"
    target_project.mkdir()
    code = "import subprocess\nsubprocess.run(['ls'])\n"
    (target_project / "app.py").write_text(code, encoding="utf-8")

    out_destination = tmp_path / "raport_labrys"

    printed: list[str] = []

    def mock_print(*args: object) -> None:
        printed.append(" ".join(str(a) for a in args))

    # Simulate user inputs:
    # 1. Target with outer quotes: '"C:\...\Labrys_project"'
    # 2. Confirm scan: 't'
    # 3. Output directory with outer quotes: '"C:\...\raport_labrys"'
    # 4. Confirm destination: 't'
    # 5. Skip AI enrichment: 'n'
    user_inputs = [
        f'"{target_project}"',
        "t",
        f'"{out_destination}"',
        "t",
        "n",
    ]
    inputs_iter = iter(user_inputs)

    run_new_audit_workflow(
        language="pl",
        input_fn=lambda _: next(inputs_iter),
        print_fn=mock_print,
    )

    all_out = "\n".join(printed)
    # Check that planned analyzers are displayed (not empty!)
    assert "Dostępne analizatory lokalne:" in all_out
    assert "Analizator statyczny kodu Python" in all_out
    assert "Skaner sekretów" in all_out

    # Check that destination screen was shown with explanation block
    assert "LOKALIZACJA RAPORTU I WYNIKÓW AUDYTU" in all_out
    assert "Raport wykonawczy w formacie PDF" in all_out
    assert "Pełny raport techniczny w formacie JSON" in all_out

    # Check that audit completed cleanly
    assert "ANALIZA ZAKOŃCZONA" in all_out
    assert "audit.pdf" in all_out
    assert "report.json" in all_out

    # Verify files exist on disk
    assert (out_destination / "report.json").is_file()
    assert (out_destination / "audit.pdf").is_file()


def test_interactive_audit_reprompting_on_invalid_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test that invalid paths trigger helpful error messages and re-prompt without crashing."""
    valid_target = tmp_path / "valid_target"
    valid_target.mkdir()
    (valid_target / "main.py").write_text("print('clean')\n", encoding="utf-8")

    valid_out = tmp_path / "valid_report"

    # Pre-create an existing dir to test collision
    collision_dir = tmp_path / "already_exists"
    collision_dir.mkdir()

    printed: list[str] = []

    def mock_print(*args: object) -> None:
        printed.append(" ".join(str(a) for a in args))

    user_inputs = [
        r'"C:\non_existent_folder_xyz"',  # Invalid target
        f'"{valid_target}"',  # Valid target
        "t",  # Confirm scan
        f'"{collision_dir}"',  # Invalid out: already exists
        f'"{valid_out}"',  # Valid out
        "t",  # Confirm destination
    ]
    inputs_iter = iter(user_inputs)

    run_new_audit_workflow(
        language="pl",
        input_fn=lambda _: next(inputs_iter),
        print_fn=mock_print,
    )

    all_out = "\n".join(printed)
    assert "nie istnieje" in all_out
    assert "już istnieje" in all_out
    assert "ANALIZA ZAKOŃCZONA" in all_out
    assert (valid_out / "audit.pdf").is_file()


def test_run_export_workflow_with_quoted_paths(tmp_path: Path) -> None:
    """Test exporting a saved report using quoted paths."""
    from ai_threat_lab.gui_api import run_audit

    dummy_target = tmp_path / "dummy_project"
    dummy_target.mkdir()
    (dummy_target / "clean.py").write_text("x = 1\n", encoding="utf-8")

    run_dir = tmp_path / "saved_run"
    run_audit(dummy_target, run_dir, language="pl")

    out_file = tmp_path / "my_export.pdf"

    printed: list[str] = []

    def mock_print(*args: object) -> None:
        printed.append(" ".join(str(a) for a in args))

    user_inputs = [
        f'"{run_dir}"',  # Quoted directory
        "1",  # PDF
        f'"{out_file}"',  # Quoted destination
    ]
    inputs_iter = iter(user_inputs)

    run_export_workflow(
        language="pl",
        input_fn=lambda _: next(inputs_iter),
        print_fn=mock_print,
    )

    all_out = "\n".join(printed)
    assert "Pomyślnie wyeksportowano raport" in all_out
    assert out_file.is_file()


def test_settings_workflow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test settings workflow for viewing and changing language."""
    config_dir = tmp_path / "config"
    monkeypatch.setenv("AI_THREAT_LAB_CONFIG_DIR", str(config_dir))

    printed: list[str] = []

    def mock_print(*args: object) -> None:
        printed.append(" ".join(str(a) for a in args))

    user_inputs = [
        "1",  # Change language
        "2",  # English
    ]
    inputs_iter = iter(user_inputs)

    new_lang = run_settings_workflow(
        language="pl",
        input_fn=lambda _: next(inputs_iter),
        print_fn=mock_print,
    )
    assert new_lang == "en"
    all_out = "\n".join(printed)
    assert "USTAWIENIA" in all_out
    assert "Language changed to: English" in all_out
