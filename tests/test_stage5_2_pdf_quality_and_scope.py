"""Stage 5.2 acceptance test suite: PDF generator quality, Unicode fidelity,
not_checked parsing, partial audit credibility, and scan scope limits.
"""

from __future__ import annotations

from pathlib import Path

import pytest

try:
    from PySide6.QtCore import QSize
    from PySide6.QtPdf import QPdfDocument
    HAS_PYSIDE6 = True
except ImportError:
    HAS_PYSIDE6 = False

from ai_threat_lab.local_inventory import local_inventory
from ai_threat_lab.pdf_report import (
    extract_project_identity,
    generate_pdf_report,
    parse_not_checked_items,
)
from ai_threat_lab.pdf_writer import PDFDocument, string_width


def test_pdf_writer_unicode_special_chars_no_question_marks(tmp_path: Path) -> None:
    """Verify that Polish diacritics, dashes, typographic quotes, bullets, and symbols
    are properly encoded and do not become literal '?'."""
    doc = PDFDocument()
    doc.new_page()

    sample_text = (
        "Zażółć gęślą jaźń — raport audytu – wersja „2.0” “final” • test & < > € …"
    )
    doc.text(50, 750, sample_text, font="Helvetica", size=12)

    raw_pdf = doc.render()
    assert b"%PDF-1.4" in raw_pdf
    assert b"/ToUnicode" in raw_pdf
    assert b"/Differences" in raw_pdf

    # Ensure unmapped question mark fallback was not used
    assert b"?" not in raw_pdf

    if HAS_PYSIDE6:
        pdf_file = tmp_path / "unicode_test.pdf"
        pdf_file.write_bytes(raw_pdf)

        # Open with QtPdf to verify text extraction and ToUnicode CMap
        qdoc = QPdfDocument()
        load_status = qdoc.load(str(pdf_file))
        assert load_status == QPdfDocument.Error.None_

        page_text = qdoc.getAllText(0).text()

        assert "?" not in page_text
        assert "Zażółć" in page_text
        assert "gęślą" in page_text
        assert "jaźń" in page_text
        assert "—" in page_text  # em-dash
        assert "–" in page_text  # en-dash
        assert "•" in page_text  # bullet
        assert "„" in page_text  # Polish opening quote
        assert "”" in page_text  # Polish closing quote


@pytest.mark.skipif(not HAS_PYSIDE6, reason="PySide6 QtPdf required for raster page rendering")
def test_pdf_writer_page_rendering_to_image(tmp_path: Path) -> None:
    """Verify that the generated PDF pages can be visually rendered by QtPdf without error."""
    doc = PDFDocument()
    doc.new_page()
    doc.text(50, 800, "AI Threat Lab — Visual Acceptance Test", font="Helvetica-Bold", size=16)
    doc.text(50, 700, "Strona testowa z polskimi znakami: ĄĆĘŁŃÓŚŹŻ", font="Helvetica", size=10)
    doc.badge(
        50,
        670,
        "AUDYT CZĘŚCIOWY",
        bg_color=(0.95, 0.90, 0.80),
        text_color=(0.7, 0.4, 0.1),
    )

    raw_pdf = doc.render()

    pdf_file = tmp_path / "render_test.pdf"
    pdf_file.write_bytes(raw_pdf)

    qdoc = QPdfDocument()
    assert qdoc.load(str(pdf_file)) == QPdfDocument.Error.None_
    assert qdoc.pageCount() == 1

    # Render page to QImage
    image = qdoc.render(0, QSize(595, 842))
    assert not image.isNull()
    assert image.width() == 595
    assert image.height() == 842


def test_pdf_writer_long_words_wrapping_prevents_overflow() -> None:
    """Verify that very long unbroken strings (e.g. paths, URLs) are wrapped cleanly."""
    doc = PDFDocument()
    long_path = (
        "C:\\Users\\Praca\\fork\\MatthiasLew\\Labrys\\some\\very\\deep\\nested\\directory\\"
        "structure\\with\\an_extremely_long_filename_that_should_not_overflow_margins.py"
    )
    max_w = 200.0
    lines = doc.wrap_text(long_path, max_width=max_w, font="Helvetica", size=9)

    assert len(lines) > 1
    for line in lines:
        assert string_width(line, "Helvetica", 9) <= max_w + 10.0  # within margin tolerance


def test_extract_project_identity_resolution() -> None:
    """Verify that extract_project_identity resolves target from various report shapes."""
    # From explicit project_name override
    assert extract_project_identity({}, project_name="Labrys") == ("Labrys", "Labrys")

    # From target path in assessments
    report_with_assessments = {
        "assessments": [
            {"target": "C:\\Users\\Praca\\fork\\MatthiasLew\\Labrys"}
        ]
    }
    assert extract_project_identity(report_with_assessments) == (
        "Labrys",
        "C:\\Users\\Praca\\fork\\MatthiasLew\\Labrys",
    )

    # From Unix path in scope
    report_with_scope = {
        "manifest": {
            "scope": {
                "target": "/home/user/projects/SecureGateway"
            }
        }
    }
    assert extract_project_identity(report_with_scope) == (
        "SecureGateway",
        "/home/user/projects/SecureGateway",
    )

    # Fallback default
    assert extract_project_identity({}) == ("Projekt", "Nieznana lokalizacja")


def test_parse_not_checked_items_removes_raw_dicts() -> None:
    """Verify raw dict representations like {'source': ...} are parsed into human categories."""
    raw_not_checked = [
        {
            "source": "local_inventory",
            "target": "C:\\Users\\Praca\\fork\\MatthiasLew\\Labrys",
            "notice": (
                "Inventory traversal stopped at the file/directory limit "
                "(100 files / 1000 directories). Scope is incomplete."
            ),
        },
        {
            "source": "dependencies",
            "target": "dependencies",
            "notice": "OSV lockfile scanner is not configured for this project target.",
        },
        {
            "source": "inventory",
            "target": "Labrys/.ai/tmp/huge_file.dat",
            "notice": "File skipped because it exceeds 2 MiB limit.",
        },
        {
            "source": "inventory",
            "target": "Labrys/.venv",
            "notice": "Directory excluded from audit scope.",
        },
        {
            "source": "python_ast",
            "target": "Labrys/invalid.py",
            "notice": "SyntaxError in source file prevented AST inspection.",
        },
        # String representation fallback
        "Legacy unstructured warning string",
    ]

    cards = parse_not_checked_items(raw_not_checked, language="pl")
    assert len(cards) >= 4

    # Verify formatting strings do not have raw python dict syntax: "{'source':"
    for card in cards:
        assert "{'source':" not in card["description"]
        assert "{'target':" not in card["description"]
        assert card["title"]
        assert card["badge"]


def test_partial_audit_with_zero_findings_warning_in_pdf(tmp_path: Path) -> None:
    """Verify that when status is partial and findings are 0, the PDF clearly warns
    that zero findings applies strictly to inspected scope."""
    mock_report = {
        "status": "partial",
        "findings": [],
        "assessments": [
            {
                "analyzer": "local_security_audit",
                "status": "partial",
                "target": "C:\\Users\\Praca\\fork\\MatthiasLew\\Labrys",
                "findings": [],
            }
        ],
        "not_checked": [
            {
                "source": "local_inventory",
                "target": "C:\\Users\\Praca\\fork\\MatthiasLew\\Labrys",
                "notice": (
                    "Inventory traversal stopped at the file/directory limit "
                    "(100 files / 1000 directories). Scope is incomplete."
                ),
            }
        ],
        "inventory": {
            "total_files": 100,
            "total_directories": 45,
            "traversal_stopped_at_limit": True,
        },
    }

    pdf_bytes_pl = generate_pdf_report(mock_report, lang="pl", project_name="Labrys")
    assert b"%PDF-1.4" in pdf_bytes_pl
    assert b"Labrys" in pdf_bytes_pl
    assert b"LIMIT" in pdf_bytes_pl
    assert b"{'source':" not in pdf_bytes_pl

    if HAS_PYSIDE6:
        pdf_file = tmp_path / "partial_labrys.pdf"
        pdf_file.write_bytes(pdf_bytes_pl)

        qdoc = QPdfDocument()
        assert qdoc.load(str(pdf_file)) == QPdfDocument.Error.None_

        full_text = ""
        for i in range(qdoc.pageCount()):
            full_text += qdoc.getAllText(i).text() + "\n"

        assert "Labrys" in full_text
        assert "CZĘŚCIOWY" in full_text
        assert "LIMIT" in full_text
        assert "wyłącznie zbadanego fragmentu kodu" in full_text
        assert "nie stanowi gwarancji bezpieczeństwa" in full_text
        assert "{'source':" not in full_text


def test_full_clean_audit_displays_clean_status(tmp_path: Path) -> None:
    """Verify that a genuine full clean audit displays standard passed status."""
    mock_report = {
        "status": "completed",
        "findings": [],
        "assessments": [
            {
                "analyzer": "local_security_audit",
                "status": "completed",
                "target": "CleanProject",
                "findings": [],
            }
        ],
        "not_checked": [],
        "inventory": {
            "total_files": 12,
            "total_directories": 2,
            "traversal_stopped_at_limit": False,
        },
    }

    pdf_bytes_pl = generate_pdf_report(mock_report, lang="pl", project_name="CleanProject")
    assert b"%PDF-1.4" in pdf_bytes_pl
    assert b"CleanProject" in pdf_bytes_pl
    assert b"W NORMIE" in pdf_bytes_pl

    if HAS_PYSIDE6:
        pdf_file = tmp_path / "clean_project.pdf"
        pdf_file.write_bytes(pdf_bytes_pl)

        qdoc = QPdfDocument()
        assert qdoc.load(str(pdf_file)) == QPdfDocument.Error.None_

        full_text = qdoc.getAllText(0).text()
        assert "CleanProject" in full_text
        assert "nie wykryto znanych wzorców podatności" in full_text
        assert "W NORMIE" in full_text


def test_local_inventory_excludes_temporary_and_cache_dirs(tmp_path: Path) -> None:
    """Verify that local_inventory skips .ai, tmp, temp, .venv, etc."""
    project_dir = tmp_path / "MyProject"
    project_dir.mkdir()

    # Valid files
    (project_dir / "main.py").write_text("print('hello')", encoding="utf-8")
    (project_dir / "config.yaml").write_text("env: test", encoding="utf-8")

    # Excluded directories
    for ex_dir in [".ai", "tmp", "temp", ".venv", ".cache", "build"]:
        d = project_dir / ex_dir
        d.mkdir()
        (d / "ignored.py").write_text("print('ignored')", encoding="utf-8")

    result = local_inventory(str(project_dir))

    # Verify excluded directories are recorded in not_checked
    ex_notices = [n for n in result.not_checked if "Excluded" in str(n)]
    assert len(ex_notices) >= 1
    assert any("temporary/cache/environment directories" in str(n) for n in ex_notices)


def test_local_inventory_multi_technology_secret_detection(tmp_path: Path) -> None:
    """Verify that multi-technology projects (Go, Rust, Shell, Java) are scanned for secrets."""
    repo = tmp_path / "MultiTechRepo"
    repo.mkdir()

    # Go file with AWS access key
    go_file = repo / "main.go"
    go_file.write_text(
        'package main\nconst token = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8"
    )

    # Rust file with GitHub token
    rs_file = repo / "lib.rs"
    rs_file.write_text(
        'let secret = "ghp_123456789012345678901234567890123456";\n', encoding="utf-8"
    )

    # Shell script with private key
    sh_file = repo / "deploy.sh"
    sh_file.write_text(
        'export SECRET="-----BEGIN RSA PRIVATE KEY-----\\nfake\\n-----END RSA PRIVATE KEY-----"\n',
        encoding="utf-8",
    )

    result = local_inventory(str(repo))

    findings = result.findings
    finding_evidences = [f.evidence for f in findings]
    assert any("deploy.sh" in e and "credential pattern" in e for e in finding_evidences)
    assert any("lib.rs" in e and "credential pattern" in e for e in finding_evidences)
    assert any("main.go" in e and "credential pattern" in e for e in finding_evidences)
