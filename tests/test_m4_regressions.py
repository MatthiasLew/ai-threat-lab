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
