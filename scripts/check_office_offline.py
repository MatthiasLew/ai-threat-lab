"""Installed local Office review acceptance; no live network or active document content."""

import io
import json
import socket
import tempfile
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from ai_threat_lab.cli import main


def forbidden(*args, **kwargs):
    raise AssertionError("Office review attempted a live request")


def run(*args, expected=0):
    output, errors = io.StringIO(), io.StringIO()
    with redirect_stdout(output), redirect_stderr(errors):
        code = main(list(map(str, args)))
    assert code == expected, (args[0], code, errors.getvalue())
    return output.getvalue()


def check():
    socket.socket = socket.create_connection = socket.getaddrinfo = forbidden
    with tempfile.TemporaryDirectory(prefix="office acceptance ") as folder:
        root = Path(folder)
        source, report = root / "inert.docm", root / "report.json"
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("[Content_Types].xml", (
                '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                '<Override PartName="/word/PRIVATE.bin" '
                'ContentType="application/vnd.ms-office.vbaProject"/></Types>'))
            archive.writestr("word/_rels/document.xml.rels", (
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="r1" Type="https://schemas.invalid/linked-image" '
                'TargetMode="External" Target="https://PRIVATE.invalid/token"/>'
                '</Relationships>'))
            archive.writestr("word/PRIVATE.bin", b"inert fixture, not executable")
        run("review-office", source, "--output", report, "--fail-on-findings", expected=1)
        saved = report.read_bytes()
        assert b"PRIVATE" not in saved
        run("review-office", source, "--output", report, expected=2)
        assert report.read_bytes() == saved
        source.unlink()
        text = run("brief", report)
        assert "office_macro_declarations" in text and "office_external_relationships" in text
        config = root / "budget.json"
        config.write_text(json.dumps({
            "schema_version": 1, "model": "fixture-model", "input_usd_per_million": "2",
            "output_usd_per_million": "8", "max_output_tokens": 1000,
            "daily_budget_usd": "2", "cache_ttl_seconds": 3600,
        }), encoding="utf-8")
        preview = json.loads(run("ai-prepare", report, "--ai-config", config,
                                 "--structured", "--split"))
        assert preview and "PRIVATE" not in json.dumps(preview)
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("[Content_Types].xml", "<!DOCTYPE x><x/>")
        partial = json.loads(run("review-office", source, expected=2))
        assert any(row["check"] == "zip_metadata" for row in partial["findings"])
        assert len(list(root.iterdir())) == 3  # Input, report and budget; nothing extracted.
    print(json.dumps({"status": "passed", "live_requests": 0,
                      "source_independent_summary": True, "active_content_opened": False}))


if __name__ == "__main__":
    check()
