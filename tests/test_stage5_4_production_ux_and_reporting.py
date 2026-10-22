"""Acceptance tests for Stage 5.4: Production-Ready Audit UX & Reporting.

Covers:
- Report destination selection (default, custom, collision handling, subfolder naming)
- Fix for false-positive inside-target check on remote targets
- Symlink and junction security rejections
- Multiple exports overwrite without FileExistsError
- Elimination of duplicate audit.pdf, canonical exports/audit_<lang>.pdf
- Target-kind-aware PDF report (cover, metrics, methodology, finding explanations, next steps)
- Dedicated explanation for html_external_script_without_integrity (SRI, CDN, CSP)
- Full Polish translation for not_checked notices (no English fallbacks)
- Terminal summary format matching Section 9
"""

from __future__ import annotations

import datetime
from pathlib import Path

from ai_threat_lab.finding_details import describe_finding
from ai_threat_lab.gui_api import export_audit_report, run_audit
from ai_threat_lab.html_review import review_html_file
from ai_threat_lab.i18n import (
    load_reports_directory_preference,
    save_reports_directory_preference,
)
from ai_threat_lab.interactive_menu import (
    run_new_audit_workflow,
    validate_output_directory,
)
from ai_threat_lab.path_utils import (
    generate_audit_subfolder_name,
    get_safe_target_display_name,
    get_unique_audit_directory,
)
from ai_threat_lab.pdf_report import (
    generate_pdf_report,
    parse_not_checked_items,
)
from ai_threat_lab.scan_engine import ScanOptions


def extract_text_from_pdf(pdf_bytes: bytes) -> str:
    """Extract plain text from generated PDF document bytes."""
    return pdf_bytes.decode("cp1250", errors="ignore")


def test_safe_target_display_name_and_subfolder_generation() -> None:
    """Verify target name normalization preserves dots in domains and creates clean timestamps."""
    assert get_safe_target_display_name("https://archeolabrys.pl/") == "archeolabrys.pl"
    sub_url = "https://sub.domain.co.uk/path/index.html"
    assert get_safe_target_display_name(sub_url) == "sub.domain.co.uk"
    assert get_safe_target_display_name("mailbox:user@example.com") == "user@example.com"
    gh_url = "git@github.com:MatthiasLew/ai-threat-lab.git"
    assert get_safe_target_display_name(gh_url) == "ai-threat-lab"
    assert get_safe_target_display_name("C:\\Projects\\Labrys") == "Labrys"

    fixed_dt = datetime.datetime(2026, 10, 22, 9, 45)
    subfolder_pl = generate_audit_subfolder_name(
        "https://archeolabrys.pl/", language="pl", dt=fixed_dt
    )
    assert subfolder_pl == "Audyt_archeolabrys.pl_2026-10-22_0945"

    subfolder_en = generate_audit_subfolder_name(
        "https://archeolabrys.pl/", language="en", dt=fixed_dt
    )
    assert subfolder_en == "Audit_archeolabrys.pl_2026-10-22_0945"


def test_unique_audit_directory_collision_avoidance(tmp_path: Path) -> None:
    """Verify collision avoidance creates suffix _1, _2 when subfolder already exists."""
    fixed_dt = datetime.datetime(2026, 10, 22, 9, 45)
    dir1 = get_unique_audit_directory(tmp_path, "archeolabrys.pl", language="pl", dt=fixed_dt)
    assert dir1.name == "Audyt_archeolabrys.pl_2026-10-22_0945"
    dir1.mkdir(parents=True)

    dir2 = get_unique_audit_directory(tmp_path, "archeolabrys.pl", language="pl", dt=fixed_dt)
    assert dir2.name == "Audyt_archeolabrys.pl_2026-10-22_0945_1"
    dir2.mkdir(parents=True)

    dir3 = get_unique_audit_directory(tmp_path, "archeolabrys.pl", language="pl", dt=fixed_dt)
    assert dir3.name == "Audyt_archeolabrys.pl_2026-10-22_0945_2"


def test_remote_target_inside_project_not_blocked(tmp_path: Path) -> None:
    """Verify remote targets (website, github, mail) do NOT trigger inside-target rejection."""
    reports_cand = tmp_path / "reports" / "archeolabrys_pl"
    valid, res, err = validate_output_directory(
        str(reports_cand),
        target_path=None,
        language="pl",
        target_kind="website",
        allow_existing=True,
    )
    assert valid is True
    assert res is not None
    assert err is None


def test_local_project_inside_target_is_blocked(tmp_path: Path) -> None:
    """Local project audit MUST block output directory if placed inside scanned project."""
    proj_dir = tmp_path / "scanned_project"
    proj_dir.mkdir()
    inside_dir = proj_dir / "reports" / "audit_run"

    valid, res, err = validate_output_directory(
        str(inside_dir),
        target_path=proj_dir,
        language="pl",
        target_kind="local_project",
        allow_existing=True,
    )
    assert valid is False
    assert res is None
    assert "wewnątrz skanowanego projektu" in (err or "")


def test_symlink_and_junction_destination_rejected(tmp_path: Path) -> None:
    """Symlink destination directories must be rejected for security."""
    target_real = tmp_path / "real_dir"
    target_real.mkdir()
    link_dir = tmp_path / "link_dir"
    try:
        link_dir.symlink_to(target_real, target_is_directory=True)
    except OSError:
        # Symlink creation may require privilege on Windows, skip if OS denies
        return

    valid, res, err = validate_output_directory(
        str(link_dir),
        target_path=None,
        language="pl",
        target_kind="website",
    )
    assert valid is False
    assert "dowiązaniem symbolicznym" in (err or "")


def test_reports_directory_preference_persistence(tmp_path: Path, monkeypatch) -> None:
    """Verify loading and saving user preferred reports directory."""
    fake_config = tmp_path / "config.json"
    monkeypatch.setattr("ai_threat_lab.i18n.get_user_config_file", lambda: fake_config)

    assert load_reports_directory_preference() is None

    my_custom = tmp_path / "CustomReports"
    save_reports_directory_preference(my_custom)

    loaded = load_reports_directory_preference()
    assert loaded == my_custom.resolve()


def test_multiple_exports_overwrite_without_file_exists_error(tmp_path: Path) -> None:
    """Verify that export_audit_report can be called multiple times without FileExistsError."""
    proj = tmp_path / "code"
    proj.mkdir()
    (proj / "app.py").write_text("x = 1\n", encoding="utf-8")

    out_audit = tmp_path / "audit_output"
    run_audit(ScanOptions(target=str(proj), network=False), out_audit, language="pl")

    # Export PDF once
    pdf_dest = out_audit / "exports" / "audit_pl.pdf"
    pdf_path1 = export_audit_report(out_audit, pdf_dest, format="pdf", language="pl")
    assert Path(pdf_path1).is_file()
    assert Path(pdf_path1).name == "audit_pl.pdf"

    # Export PDF a second time (must overwrite safely without FileExistsError)
    pdf_path2 = export_audit_report(out_audit, pdf_dest, format="pdf", language="pl")
    assert Path(pdf_path2).is_file()

    # Export PDF in English as well
    pdf_dest_en = out_audit / "exports" / "audit_en.pdf"
    pdf_path_en = export_audit_report(out_audit, pdf_dest_en, format="pdf", language="en")
    assert Path(pdf_path_en).is_file()
    assert Path(pdf_path_en).name == "audit_en.pdf"


def test_html_external_script_without_integrity_sanitized_snippet(tmp_path: Path) -> None:
    """Verify HTML review produces sanitized snippet for external script without SRI."""
    html_content = (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        '    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>\n'
        "</head>\n"
        "<body>\n"
        "    <h1>ArcheoLabrys</h1>\n"
        "</body>\n"
        "</html>\n"
    )
    doc_path = tmp_path / "index.html"
    doc_path.write_text(html_content, encoding="utf-8")

    res = review_html_file(doc_path, document_url="https://archeolabrys.pl")

    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.check == "html_external_script_without_integrity"
    assert f.status == "candidate"
    assert f.evidence is not None
    assert "<script src=" in f.evidence
    assert "https://cdn.jsdelivr.net" in f.evidence


def test_dedicated_finding_details_for_sri_and_forms() -> None:
    """Verify html_external_script_without_integrity has dedicated explanation without forms."""
    f_dict = {"rule_code": "html_external_script_without_integrity"}
    desc_pl = describe_finding(f_dict, language="pl")
    assert desc_pl.threat_category == "html_external_script"
    assert "(SRI)" in desc_pl.title
    assert "CDN" in desc_pl.consequences or "Content Security Policy" in desc_pl.consequences
    assert "formularz" not in desc_pl.consequences.lower()
    assert "hasło" not in desc_pl.consequences.lower()
    assert "GET" not in desc_pl.consequences

    desc_en = describe_finding(f_dict, language="en")
    assert desc_en.threat_category == "html_external_script"
    assert "Subresource Integrity (SRI)" in desc_en.title
    assert "password" not in desc_en.consequences.lower()
    assert "form" not in desc_en.consequences.lower()


def test_pdf_report_target_kind_aware_for_website(tmp_path: Path) -> None:
    """E2E Test: Generate PDF for website audit and verify target-kind-aware contents."""
    manifest = {
        "target": "https://archeolabrys.pl/",
        "target_kind": "website",
        "scope": {
            "target": "https://archeolabrys.pl/",
            "target_kind": "website",
            "network": True,
            "allowed_hosts": ["archeolabrys.pl"],
            "inspected_pages": 1,
            "transport": "HTTPS / TLS",
        },
    }
    report = {
        "status": "partial",
        "target_kind": "website",
        "findings": [
            {
                "rule_code": "html_external_script_without_integrity",
                "priority": "P3",
                "file": "index.html",
                "line": 17,
                "title": "External script without SRI",
                "evidence": '> 17 | <script src="https://cdn.jsdelivr.net/npm/bootstrap.js"></script>',
                "message": "HTML document loads external script without integrity attribute.",
            }
        ],
        "not_checked": [
            (
                "Passive single main-page inspection; multi-page crawling, authentication, "
                "forms, and dynamic JS execution were not performed."
            ),
            "Duplicate attributes leave the affected element unchecked.",
            "Plaintext remainder unchecked as markup.",
        ],
    }

    pdf_bytes = generate_pdf_report(
        report,
        language="pl",
        manifest=manifest,
        scope=manifest["scope"],
    )
    assert len(pdf_bytes) > 1000

    extracted_text = extract_text_from_pdf(pdf_bytes)

    # Verify Target Identity
    assert "strony WWW" in extracted_text or "archeolabrys.pl" in extracted_text
    assert "archeolabrys.pl" in extracted_text

    # Verify Metric Cards: HTTPS instead of FILE LIMIT
    assert "HTTPS" in extracted_text
    assert "LIMIT PLIKÓW" not in extracted_text
    assert "FILE LIMIT" not in extracted_text

    # Verify Methodology: Mentions HTTPS and passive parsing
    assert (
        "Pasywna analiza nagłówków HTTP" in extracted_text
        or "Pasywna analiza strony WWW" in extracted_text
    )

    # Verify Finding section explains SRI, CDN, CSP
    assert "Subresource Integrity" in extracted_text
    assert "CDN" in extracted_text

    # Verify Evidence snippet has line number and script tag
    assert "<script" in extracted_text
    assert "cdn.jsdelivr.net" in extracted_text
    assert "17" in extracted_text

    # Verify NO password form mentions
    assert "formularz hasła" not in extracted_text.lower()
    assert "metodą get" not in extracted_text.lower()

    # Verify not_checked items are translated into Polish (no raw English paragraphs)
    assert "Pasywna analiza pojedynczej strony" in extracted_text
    assert "Passive single main-page inspection" not in extracted_text
    assert "Duplicate attributes leave the affected element unchecked" not in extracted_text


def test_pdf_report_target_kind_aware_for_mail_domain(tmp_path: Path) -> None:
    """Verify target-kind-aware PDF for mail domain (SPF, DMARC, DKIM)."""
    manifest = {
        "target": "example.com",
        "target_kind": "mail_domain",
        "scope": {
            "target": "example.com",
            "target_kind": "mail_domain",
            "network": True,
            "allowed_hosts": ["example.com"],
        },
    }
    report = {
        "status": "complete",
        "target_kind": "mail_domain",
        "findings": [],
        "not_checked": [],
    }

    pdf_bytes = generate_pdf_report(
        report, language="pl", manifest=manifest, scope=manifest["scope"]
    )
    extracted_text = extract_text_from_pdf(pdf_bytes)

    assert "domeny pocztowej" in extracted_text
    assert "example.com" in extracted_text
    assert "REKORDY DNS" in extracted_text
    assert "DMARC" in extracted_text


def test_notice_translations_pl_all_keys_mapped() -> None:
    """Verify all standard engine not_checked strings have Polish translations."""
    sample_notices = [
        (
            "Network communication was disabled for this run; "
            "remote services and live endpoints were not checked."
        ),
        (
            "Traversed file count reached the configured limit; "
            "additional project files were not checked."
        ),
        "Response is not unambiguously declared text/html; body unchecked.",
        "HTML body exceeded the size limit; body unchecked.",
        "Nested forms unchecked; HTML tree repair was not simulated.",
        (
            "Passive single main-page inspection; multi-page crawling, authentication, "
            "forms, and dynamic JS execution were not performed."
        ),
    ]
    parsed = parse_not_checked_items(sample_notices, language="pl")
    for item in parsed:
        # None of them should contain raw English phrases
        assert "was disabled" not in item
        assert "were not checked" not in item
        assert "body unchecked" not in item
        assert "not simulated" not in item


def test_interactive_workflow_default_destination_option_1(tmp_path: Path, monkeypatch) -> None:
    """Test interactive workflow with Option 1: creates subfolder inside default dir."""
    mock_default = tmp_path / "MyReports"
    mock_default.mkdir(parents=True)
    monkeypatch.setattr(
        "ai_threat_lab.interactive_menu.get_default_reports_dir",
        lambda: mock_default,
    )

    proj = tmp_path / "sample_code"
    proj.mkdir()
    (proj / "app.py").write_text("print('test')\n", encoding="utf-8")

    printed: list[str] = []

    def mock_print(*args: object) -> None:
        printed.append(" ".join(str(a) for a in args))

    # Inputs:
    # 1. Target menu: "1" (Local project)
    # 2. Path: str(proj)
    # 3. Profile: "2" (Standard)
    # 4. Confirm scan: "t"
    # 5. Destination menu: "1" (Default location)
    # 6. Skip AI: "n"
    inputs = iter(["1", str(proj), "2", "t", "1", "n"])
    run_new_audit_workflow("pl", input_fn=lambda _: next(inputs), print_fn=mock_print)

    out_text = "\n".join(printed)
    assert "PODSUMOWANIE AUDYTU BEZPIECZEŃSTWA" in out_text
    assert "Raport PDF:" in out_text
    assert "audit_pl.pdf" in out_text

    # Verify a dedicated subfolder was created inside mock_default
    subfolders = list(mock_default.iterdir())
    assert len(subfolders) == 1
    audit_sub = subfolders[0]
    assert audit_sub.name.startswith("Audyt_sample_code_")
    assert (audit_sub / "report.json").is_file()
    assert (audit_sub / "exports" / "audit_pl.pdf").is_file()
    # Confirm NO duplicate audit.pdf in root
    assert not (audit_sub / "audit.pdf").exists()
