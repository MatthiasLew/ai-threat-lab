"""Office declarations are inspected locally; embedded content is never opened."""

import io
import zipfile
from dataclasses import asdict

import pytest

from ai_threat_lab.models import ValidationError
from ai_threat_lab.office_review import CONTENT_NS, REL_NS, inspect_office


def package(parts=None, compression=zipfile.ZIP_STORED):
    data = io.BytesIO()
    values = {
        "[Content_Types].xml": f'<Types xmlns="{CONTENT_NS}"><Override '
        'PartName="/word/document.xml" ContentType="application/test"/></Types>'
    }
    values.update(parts or {})
    with zipfile.ZipFile(data, "w", compression=compression) as archive:
        for name, content in values.items():
            archive.writestr(name, content)
    return data.getvalue()


def relationships(mode="External", kind="hyperlink"):
    return (
        f'<Relationships xmlns="{REL_NS}"><Relationship Id="r1" '
        f'Type="https://schemas.invalid/{kind}" TargetMode="{mode}" '
        'Target="https://PRIVATE.invalid/token?secret=PRIVATE"/></Relationships>'
    )


def checks(result):
    return {item.check: item for item in result.findings}


def test_package_external_declarations_redact_content_and_urls(monkeypatch):
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("No networking allowed")

    monkeypatch.setattr(socket, "socket", forbidden)
    result = inspect_office(
        package(
            {
                "word/_rels/document.xml.rels": relationships(),
                "word/document.xml": "PRIVATE document content",
            }
        )
    )
    found = checks(result)
    assert found["office_external_relationships"].status == "candidate"
    assert found["office_external_hyperlinks"].status == "candidate"
    assert "PRIVATE" not in str(asdict(result))
    assert "word/document.xml" not in str(asdict(result))


def test_macros_and_activex_are_declarations_not_payload_analysis(monkeypatch):
    original = zipfile.ZipFile.open
    opened = []

    def observed(archive, name, *args, **kwargs):
        opened.append(name.filename)
        assert name.filename.endswith((".xml", ".rels"))
        return original(archive, name, *args, **kwargs)

    manifest = (
        f'<Types xmlns="{CONTENT_NS}"><Override PartName="/PRIVATE.bin" '
        'ContentType="application/vnd.ms-office.vbaProject"/>'
        '<Override PartName="/PRIVATE2.bin" '
        'ContentType="application/vnd.ms-office.activeX"/></Types>'
    )
    raw = package({"[Content_Types].xml": manifest, "PRIVATE.bin": b"inert macro marker"})
    monkeypatch.setattr(zipfile.ZipFile, "open", observed)
    result = inspect_office(raw)
    assert "office_macro_declarations" in checks(result)
    assert "office_activex_declarations" in checks(result)
    assert opened == ["[Content_Types].xml"]
    assert "PRIVATE" not in str(asdict(result))


@pytest.mark.parametrize(
    "xml",
    [
        '<!DOCTYPE x [<!ENTITY x "PRIVATE">]><x>&x;</x>',
        "<Relationships>",
        '<Relationships xmlns="wrong"/>',
        b"\xff\xfe<\x00x\x00/\x00>\x00",
        '<?xml version="1.0" encoding="iso-8859-1"?><x/>',
        relationships().replace('TargetMode="External"', 'TargetMode="bad"'),
    ],
)
def test_unsupported_xml_retains_other_metadata(xml):
    result = inspect_office(package({"word/_rels/document.xml.rels": xml}))
    assert "zip_metadata" in checks(result)
    assert any("part 0002" in gap for gap in result.not_checked)
    assert "office_external_relationships" not in checks(result)
    assert "PRIVATE" not in str(asdict(result))


def test_malformed_late_relationship_discards_that_parts_partial_counts():
    xml = relationships().replace("</Relationships>", "<Relationship/></Relationships>")
    result = inspect_office(package({"word/_rels/document.xml.rels": xml}))
    assert "office_external_relationships" not in checks(result)


def test_stored_and_deflated_packages_work():
    for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        result = inspect_office(package({"_rels/.rels": relationships()}, compression=method))
        assert "office_external_relationships" in checks(result)


@pytest.mark.parametrize("name", ["../x", "/x", "word/../x", "word\\x"])
def test_ambiguous_names_block_xml_processing(name):
    with pytest.raises(ValidationError, match="Ambiguous"):
        inspect_office(package({name.replace("\\", "/"): "private"}).replace(
            b"word/x", name.encode()) if "\\" in name else package({name: "private"}))


def test_non_zip_and_missing_manifest_rejected():
    with pytest.raises(ValidationError):
        inspect_office(b"not a package")
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("word/document.xml", "inert")
    with pytest.raises(ValidationError, match="manifest"):
        inspect_office(data.getvalue())


def test_oversized_metadata_is_not_decompressed(monkeypatch):
    original = zipfile.ZipFile.open
    opened = []

    def observed(archive, name, *args, **kwargs):
        opened.append(name.filename)
        return original(archive, name, *args, **kwargs)

    raw = package({"_rels/.rels": "x" * (128 * 1024 + 1)})
    monkeypatch.setattr(zipfile.ZipFile, "open", observed)
    result = inspect_office(raw)
    assert opened == ["[Content_Types].xml"]
    assert any("part 0002" in gap for gap in result.not_checked)


def test_part_limit_caps_decompression(monkeypatch):
    raw = package({f"_rels/part{i}.rels": relationships() for i in range(100)})
    original, opened = zipfile.ZipFile.open, []

    def observed(archive, name, *args, **kwargs):
        opened.append(name.filename)
        return original(archive, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "open", observed)
    result = inspect_office(raw)
    assert len(opened) == 64
    assert any("capped at 64" in gap for gap in result.not_checked)


def test_malformed_parts_still_consume_total_budget(monkeypatch):
    raw = package({f"_rels/part{i}.rels": "x" * (128 * 1024) for i in range(20)})
    original, sizes = zipfile.ZipFile.open, []

    def observed(archive, name, *args, **kwargs):
        sizes.append(name.file_size)
        return original(archive, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "open", observed)
    result = inspect_office(raw)
    assert sum(sizes) <= 1024 * 1024 and len(sizes) == 8
    assert len([gap for gap in result.not_checked if "could not be fully reviewed" in gap]) == 20


def test_high_expansion_ratio_prevents_xml_open(monkeypatch):
    raw = package({"_rels/.rels": " " * 100000}, compression=zipfile.ZIP_DEFLATED)
    original, opened = zipfile.ZipFile.open, []

    def observed(archive, name, *args, **kwargs):
        opened.append(name.filename)
        return original(archive, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "open", observed)
    result = inspect_office(raw)
    assert opened == ["[Content_Types].xml"]
    assert any("part 0002" in gap for gap in result.not_checked)


def test_duplicate_member_names_are_rejected():
    raw = io.BytesIO(package())
    with pytest.warns(UserWarning, match="Duplicate name"):
        with zipfile.ZipFile(raw, "a") as archive:
            archive.writestr("[Content_Types].xml", "<wrong/>")
    with pytest.raises(ValidationError, match="Ambiguous"):
        inspect_office(raw.getvalue())


def test_xml_crc_failure_returns_partial_evidence():
    raw = package({"_rels/.rels": relationships()})
    raw = raw.replace(b'TargetMode="External"', b'TargetMode="Internal"', 1)
    result = inspect_office(raw)
    assert "office_external_relationships" not in checks(result)
    assert "zip_metadata" in checks(result)
    assert any("part 0002" in gap for gap in result.not_checked)


def test_office_menu_routes_local_paths_without_network_flags(monkeypatch):
    from ai_threat_lab.console import run_console

    replies = iter(["18", "source.docm", "report.json", "0"])
    calls, prompts = [], []

    def answer(prompt):
        prompts.append(prompt)
        return next(replies)

    monkeypatch.setattr("builtins.input", answer)
    assert run_console(lambda args: calls.append(args) or 0) == 0
    assert calls == [["review-office", "source.docm", "--output", "report.json"]]
    assert prompts[0] == "Choose 0–18: "
