"""Exercise offline policy and evidence failure paths."""

import json
import stat
from types import SimpleNamespace

import pytest

from ai_threat_lab import agent_protocol, i18n, scanner_sandbox
from ai_threat_lab.evidence import _strip_target_prefix
from ai_threat_lab.models import ValidationError
from ai_threat_lab.pdf_report import extract_project_identity, extract_scope_details
from ai_threat_lab.pdf_writer import char_width, escape_pdf_string
from ai_threat_lab.sarif_review import finding, location, message_text, resolve_rule
from ai_threat_lab.scanner_plan import plan_bandit


@pytest.mark.parametrize("mode,uid,executable", [
    (None, 0, False), (stat.S_IFDIR | 0o755, 0, True),
    (stat.S_IFREG | 0o755, 1000, True), (stat.S_IFREG | 0o4755, 0, True),
    (stat.S_IFREG | 0o775, 0, True), (stat.S_IFREG | 0o644, 0, False),
    (stat.S_IFREG | 0o755, 0, True),
])
def test_bubblewrap_candidate_checks(monkeypatch, mode, uid, executable):
    monkeypatch.setattr(scanner_sandbox, "sys", SimpleNamespace(platform="linux"))

    class Candidate:
        def __init__(self, path):
            self.path = path

        def stat(self):
            if mode is None:
                raise FileNotFoundError
            return SimpleNamespace(st_mode=mode, st_uid=uid)

        def is_file(self):
            return False

    monkeypatch.setattr(scanner_sandbox, "Path", Candidate)
    monkeypatch.setattr(scanner_sandbox.os, "access", lambda *args: executable)
    diagnostic = scanner_sandbox.sandbox_diagnostic()
    assert diagnostic.availability == (
        "detected" if mode == stat.S_IFREG | 0o755 and uid == 0 and executable else "not_detected"
    )
    assert diagnostic.execution == "blocked"
    assert diagnostic.configuration == diagnostic.permissions == "not_checked"


@pytest.mark.parametrize("failure", [None, AttributeError, OSError])
def test_windows_diagnostic_reports_missing_prerequisite(monkeypatch, failure):
    monkeypatch.setattr(scanner_sandbox, "sys", SimpleNamespace(platform="win32"))

    def load_dll(name, *, winmode):
        assert winmode == 0x800
        if name == "userenv.dll":
            if failure is OSError:
                raise OSError("injected unavailable DLL")
            if failure is AttributeError:
                return SimpleNamespace()
            return SimpleNamespace(CreateAppContainerProfile=object())
        return SimpleNamespace(CreateJobObjectW=object())

    monkeypatch.setattr(scanner_sandbox.ctypes, "WinDLL", load_dll, raising=False)
    result = scanner_sandbox.sandbox_diagnostic()
    assert result.availability == ("missing" if failure else "detected")
    assert result.validation == "not_validated" and result.verified_controls == ()


def test_unsupported_host_and_late_path_rejection(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner_sandbox, "sys", SimpleNamespace(platform="other"))
    assert scanner_sandbox.sandbox_diagnostic().availability == "unsupported"
    monkeypatch.setattr("ai_threat_lab.scanner_plan.os.path.abspath", lambda _: "//fixture/share")
    with pytest.raises(ValidationError, match="Network"):
        plan_bandit(
            "project", executable=tmp_path / "fixture", expected_sha256="0" * 64,
            declared_version="1.7.8",
        )


@pytest.mark.parametrize("operation,args,message", [
    ("plan", {"target": 7}, "Invalid text"),
    ("plan", {"target": ""}, "Invalid text"),
    ("plan", {"target": "line\nbreak"}, "Invalid text"),
    ("findings", {"run": ".", "priority": "P9"}, "Invalid selection"),
    ("finding", {"run": ".", "id": "z" * 64}, "Invalid reference"),
])
def test_worker_schema_rejects_invalid_requests(operation, args, message):
    with pytest.raises(ValidationError, match=message):
        agent_protocol.validate_args(operation, args)


@pytest.mark.parametrize("payload,expected", [
    ({"status": "partial"}, "partial"),
    ({"status": "error", "error": {"code": "invalid_bundle", "message": "bad input"}}, "error"),
    ({"status": "error", "error": {"code": "invalid_bundle", "message": 1}}, "worker_error"),
    ({"status": "error", "error": []}, "worker_error"),
])
def test_worker_validates_return_contract(monkeypatch, tmp_path, payload, expected):
    response = {"tool": "ai-threat-lab", "schema_version": "1.0", "operation": "report", **payload}
    raw_response = json.dumps(response).encode()
    monkeypatch.setattr(agent_protocol, "_run_worker", lambda raw: (0, raw_response))
    result = agent_protocol.execute(tmp_path, "report", {})
    if expected == "worker_error":
        assert result["error"]["code"] == "worker_error"
    else:
        assert result["status"] == expected


def test_sarif_extension_and_message_references():
    descriptor = {"id": "X", "messageStrings": {"message": {"text": "Check {0} {1}"}}}
    extension = {"name": "extension", "rules": [descriptor]}
    tool = {"driver": {}, "extensions": [extension]}
    result = {"rule": {"index": 0, "toolComponent": {"index": 0, "name": "extension"}}}
    identifier, rule, component = resolve_rule(result, tool)
    assert (identifier, rule, component) == ("X", descriptor, extension)
    assert message_text(
        {"id": "message", "arguments": ["safe"]}, rule, component,
    ) == "Check safe {1}"
    with pytest.raises(ValidationError, match="component"):
        resolve_rule({"rule": {"toolComponent": {"index": 0, "name": "other"}}}, tool)
    with pytest.raises(ValidationError, match="rule index"):
        resolve_rule({"ruleIndex": True}, tool)
    with pytest.raises(ValidationError, match="template"):
        message_text({"id": "invalid"}, {"messageStrings": {"invalid": {"text": 42}}}, {})
    with pytest.raises(ValidationError, match="reference"):
        message_text({"id": "absent"}, {}, {})


@pytest.mark.parametrize("change,message", [
    ({"index": True}, "artifact index"),
    ({"index": 0, "uri": "mismatch.py"}, "artifact identity"),
    ({"index": 0, "uriBaseId": "other"}, "base identity"),
])
def test_sarif_conflicting_artifact_identity(change, message):
    value = {"physicalLocation": {"artifactLocation": change}}
    run = {"artifacts": [{"location": {"uri": "fixture.py", "uriBaseId": "root"}}]}
    with pytest.raises(ValidationError, match=message):
        location(value, run)


def test_sarif_untrusted_metadata_validation():
    run = {"tool": {"driver": {"name": "scanner"}}}
    base = {"message": {"text": "safe"}}
    for change, message in (
        ({"suppressions": [{"status": "bad"}]}, "suppression status"),
        ({"suppressions": [{"kind": "bad"}]}, "suppression kind"),
        ({"properties": []}, "result properties"),
        ({"locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "fixture.py"}, "region": {"startLine": 0},
        }}]}, "source line"),
    ):
        with pytest.raises(ValidationError, match=message):
            finding(base | change, run, 0, structured=True)


@pytest.mark.parametrize("text,target,expected", [
    ("Skipped C:\\sample\\project\\private.py", "C:\\sample\\project", "Skipped private.py"),
    ("Skipped C:\\sample\\project: inaccessible", "C:\\sample\\project",
     "Skipped project: inaccessible"),
    ("Skipped project: inaccessible", "project", "Skipped target: inaccessible"),
    ("project: inaccessible", "project", "inaccessible"),
    ("unchanged", "/", "unchanged"),
])
def test_evidence_omits_private_root(text, target, expected):
    assert _strip_target_prefix(text, target) == expected


@pytest.mark.parametrize("target,kind,network", [
    ("https://example.invalid/", "website", True),
    ("mail-domain:example.invalid", "mail_domain", True),
    ("mailbox:example@example.invalid", "mailbox_account", True),
    ("local.eml", "eml_message", False),
    ("./local", "local_project", False),
])
def test_pdf_reports_distinguish_saved_scope_types(target, kind, network):
    report = {"target": target, "not_checked": [
        42, "Scope technologies: Python, . Other detail. Files inspected: 7.",
    ]}
    details = extract_scope_details(report)
    assert details["target_kind"] == kind and details["network_enabled"] is network
    assert details["target"] == target
    if kind == "local_project":
        assert details["files_inspected"] == "7" and details["technologies"] == ["Python"]


def test_pdf_project_identity_reads_saved_metadata():
    assert extract_project_identity({}, scope={"target": "fixture.example"}) == (
        "fixture.example", "fixture.example",
    )
    assert extract_project_identity({"not_checked": [{"target": "fallback"}]}) == (
        "fallback", "fallback",
    )
    assert extract_project_identity({}, project_name="fixture") == ("fixture", "fixture")


def test_pdf_glyph_estimates_and_pdf_string_delimiters():
    assert char_width("—", "Helvetica", 100) == 95
    assert char_width("•", "Helvetica", 100) == 40
    assert char_width("„", "Helvetica", 100) == 35
    assert escape_pdf_string("(x)\\ 🐍﹙") == b"\\(x\\)\\\\ ?\\("


@pytest.mark.parametrize("config,expected", [
    ("[]", None), ("{}", None), ('{"language":"invalid"}', None),
    ('{"language":"PL"}', "pl"), ("{", None),
])
def test_offline_locale_preferences(monkeypatch, tmp_path, config, expected):
    monkeypatch.delenv("AI_THREAT_LAB_LANG", raising=False)
    monkeypatch.setenv("AI_THREAT_LAB_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(i18n, "_ACTIVE_LANGUAGE", None)
    config_file = tmp_path / "config.json"
    config_file.write_text(config, encoding="utf-8")
    assert i18n.load_language_preference() == expected
    assert i18n.get_active_language() == (expected or i18n.DEFAULT_LANGUAGE)
    i18n.save_language_preference("en")
    assert json.loads(config_file.read_text(encoding="utf-8"))["language"] == "en"


def test_reports_location_handles_corrupt_configuration(monkeypatch, tmp_path):
    monkeypatch.delenv("AI_THREAT_LAB_CONFIG_DIR", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    config = tmp_path / "ai-threat-lab" / "config.json"
    config.parent.mkdir()
    config.write_text("{", encoding="utf-8")
    assert i18n.get_user_config_file() == config
    assert i18n.load_reports_directory_preference() is None
    assert i18n.save_reports_directory_preference(tmp_path / "reports")
    assert i18n.load_reports_directory_preference() == tmp_path / "reports"

def test_pdf_reports_warn_and_bound_offline_limitations():
    from ai_threat_lab.pdf_report import parse_not_checked_items

    notices = [
        "HTTPS response was inspected", "File/directory limit reached",
        "Could not enumerate directory: restricted", "Flow coverage: incomplete",
        "Scope technologies: Python", "", 42, {"source": 5}, {"target": "fixture"},
    ]
    notices.extend(f"Excluded directory: folder{i}" for i in range(5))
    notices.extend(f"Skipped oversized file: path{i}.txt" for i in range(7))
    for language, overflow in (("en", "+2 more"), ("pl", "+2 więcej")):
        categories = parse_not_checked_items(notices, language)
        assert sum(row["is_warning"] for row in categories) >= 2
        assert any("HTTPS response" in row["description"] for row in categories)
        assert any("Data Flow" in row["title"] for row in categories)
        excluded = next(row for row in categories if row["count"] == 5)
        oversized = next(row for row in categories if row["count"] == 7)
        assert overflow in excluded["description"] and "folder4" not in excluded["description"]
        assert "path6.txt" not in oversized["description"]


def test_report_bytes_shared_across_nested_verification(tmp_path):
    from ai_threat_lab.report_io import ReportReadLimit, read_regular, report_read_budget

    artifact = tmp_path / "saved.json"
    artifact.write_bytes(b"abcdef")
    with report_read_budget(10):
        with report_read_budget(6):
            assert read_regular(artifact, 8) == b"abcdef"
        with pytest.raises(ReportReadLimit, match="aggregate"):
            read_regular(artifact, 8)
    assert read_regular(artifact, 8) == b"abcdef"


def test_report_rejects_non_regular_file(tmp_path):
    from ai_threat_lab.report_io import read_regular

    with pytest.raises(ValidationError, match="regular"):
        read_regular(tmp_path, 10)


def test_scanner_discovery_ignores_relative_and_remote_path_entries(monkeypatch):
    from ai_threat_lab.scanner_plan import bandit_availability

    monkeypatch.setattr(
        "ai_threat_lab.scanner_plan.os.get_exec_path", lambda: [".", "//remote.invalid/share"],
    )
    monkeypatch.setattr(
        "ai_threat_lab.scanner_plan.shutil.which", lambda *a, **kw: pytest.fail("unsafe PATH"),
    )
    assert bandit_availability()["candidate_present"] is False

def test_pinned_scope_rejects_replaced_directory(tmp_path):
    from ai_threat_lab.agent_fs import pinned_read_scope

    approved = tmp_path / "approved"
    approved.mkdir()
    identity = approved.stat()
    approved.rename(tmp_path / "original")
    approved.mkdir()
    with pytest.raises(ValidationError, match="changed since selection"):
        with pinned_read_scope(approved, expected=identity):
            pytest.fail("replacement entered approved scope")


@pytest.mark.parametrize("phase", ["create", "limits", "assign"])
def test_worker_job_api_failure_cannot_open_execution_gate(monkeypatch, phase):
    import ctypes

    from ai_threat_lab import agent_resources

    class NativeCall:
        def __init__(self, value):
            self.value = value
            self.calls = []

        def __call__(self, *args):
            self.calls.append(args)
            return self.value

    native = SimpleNamespace(
        CreateJobObjectW=NativeCall(0 if phase == "create" else 42),
        SetInformationJobObject=NativeCall(phase != "limits"),
        AssignProcessToJobObject=NativeCall(phase != "assign"),
        CloseHandle=NativeCall(True),
    )
    monkeypatch.setattr(agent_resources, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kw: native, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    monkeypatch.setattr(ctypes, "WinError", lambda code: OSError(code, "Denied"), raising=False)
    with pytest.raises(OSError):
        with agent_resources.supervise_windows(SimpleNamespace(_handle=100)):
            pytest.fail("failed job configuration opened the worker gate")
    assert native.CloseHandle.calls == ([] if phase == "create" else [(42,)])
    assert bool(native.AssignProcessToJobObject.calls) == (phase == "assign")


def test_scoped_snapshot_counts_skipped_entries(tmp_path, monkeypatch):
    from ai_threat_lab import agent_fs

    source = tmp_path / "src"
    source.mkdir()
    (source / ".ai-threat-lab").mkdir()
    (source / "too-large").write_bytes(b"12345")
    (source / "accepted").write_bytes(b"123")
    (source / "subdir").mkdir()
    (source / "subdir" / "nested").mkdir()
    monkeypatch.setattr(agent_fs, "MAX_FILE", 4)
    monkeypatch.setattr(agent_fs, "MAX_DEPTH", 1)
    copied, counters = agent_fs.snapshot(source, tmp_path / "copy")
    assert counters == {"files": 1, "bytes": 3, "skipped": 3, "entries": 5}
    assert (copied / "accepted").read_bytes() == b"123"
    assert not (copied / "too-large").exists()
    assert not (copied / "subdir" / "nested").exists()


def test_scan_snapshot_rejects_entry_limit(tmp_path, monkeypatch):
    from ai_threat_lab import agent_fs

    source = tmp_path / "source"
    source.mkdir()
    (source / "one").touch()
    (source / "two").touch()
    monkeypatch.setattr(agent_fs, "MAX_ENTRIES", 1)
    with pytest.raises(ValidationError, match="entry limit"):
        agent_fs.snapshot(source, tmp_path / "copy")
    assert list((tmp_path / "copy").iterdir()) == []
