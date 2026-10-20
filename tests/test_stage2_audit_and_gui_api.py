"""Stage 2 end-to-end tests: 8 reference projects, detailed findings, offline reports,
multilingual AI contracts, and stable GUI Python API."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest

from ai_threat_lab import (
    DetailedFinding,
    ValidationError,
    attach_ai_interpretation,
    build_multilingual_ai_packet,
    create_audit_options,
    describe_finding,
    detailed_findings,
    export_audit_report,
    get_audit_history,
    get_audit_results,
    get_audit_status,
    get_capabilities,
    list_analyzers,
    plan_audit,
    prepare_ai_packets,
    run_audit,
)
from ai_threat_lab.ai_review import review_instructions
from ai_threat_lab.cli import main


def _build_reference_projects(base: Path) -> dict[str, Path]:
    projects: dict[str, Path] = {}

    # 1. Safe Python project
    safe_dir = base / "01_safe_python_project"
    safe_dir.mkdir(parents=True)
    (safe_dir / "calculator.py").write_text(
        "def add(a: int, b: int) -> int:\n"
        "    return a + b\n\n"
        "def greet(name: str) -> str:\n"
        "    cleaned = name.strip()\n"
        "    return f'Hello, {cleaned}'\n",
        encoding="utf-8",
    )
    (safe_dir / "requirements.txt").write_text(
        "pytest==8.3.3\npackaging==24.1\n",
        encoding="utf-8",
    )
    projects["safe"] = safe_dir

    # 2. Multi-vulnerability project
    vuln_dir = base / "02_multi_vulnerability_project"
    vuln_dir.mkdir(parents=True)
    (vuln_dir / "vuln_app.py").write_text(
        "import os\n"
        "import pickle\n"
        "import sqlite3\n"
        "import subprocess\n"
        "from flask import request\n\n"
        "def eval_expr(expr: str): return eval(expr)\n\n"
        "def run_cmd(user_cmd: str) -> None:\n"
        "    subprocess.run(user_cmd, shell=True, check=False)\n\n"
        "def load_state(blob: bytes):\n"
        "    return pickle.loads(blob)\n\n"
        "def find_user():\n"
        "    with sqlite3.connect(':memory:') as conn:\n"
        "        query = f\"SELECT * FROM users WHERE username = '{request.args['username']}'\"\n"
        "        return conn.execute(query).fetchall()\n",
        encoding="utf-8",
    )
    projects["multi_vuln"] = vuln_dir

    # 3. Misconfigured project (Dockerfile + Kubernetes + GitHub Actions)
    misconfig_dir = base / "03_misconfigured_project"
    (misconfig_dir / ".github" / "workflows").mkdir(parents=True)
    (misconfig_dir / "Dockerfile").write_text(
        "FROM python:latest\nUSER root\nRUN curl -fsSL https://example.com/install.sh | sh\n",
        encoding="utf-8",
    )
    (misconfig_dir / ".github" / "workflows" / "ci.yml").write_text(
        "name: CI\n"
        "on: [pull_request_target]\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@main\n"
        "      - run: echo ${{ github.event.pull_request.title }}\n",
        encoding="utf-8",
    )
    (misconfig_dir / "deployment.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: risky-api\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      hostNetwork: true\n"
        "      containers:\n"
        "        - name: app\n"
        "          image: app:latest\n"
        "          securityContext:\n"
        "            privileged: true\n"
        "            runAsNonRoot: false\n",
        encoding="utf-8",
    )
    projects["misconfigured"] = misconfig_dir

    # 4. Vulnerable/unpinned dependency project
    dep_dir = base / "04_dependency_project"
    dep_dir.mkdir(parents=True)
    (dep_dir / "requirements.txt").write_text(
        "--extra-index-url http://insecure.example.com/simple\n"
        "flask>=2.0\n"
        "requests\n"
        "urllib3==1.26.4\n",
        encoding="utf-8",
    )
    (dep_dir / "package.json").write_text(
        json.dumps({
            "name": "sample-web",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "^4.17.15",
                "express": "*",
            },
        }),
        encoding="utf-8",
    )
    projects["dependencies"] = dep_dir

    # 5. Multi-module Python project (cross-file taint flow)
    multi_mod_dir = base / "05_multi_module_project"
    pkg_dir = multi_mod_dir / "webapp"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "__init__.py").write_text("", encoding="utf-8")
    (pkg_dir / "shell_runner.py").write_text(
        "import subprocess\n\n"
        "def execute_unsafe(cmd: str) -> None:\n"
        "    subprocess.Popen(cmd, shell=True)\n",
        encoding="utf-8",
    )
    (pkg_dir / "routes.py").write_text(
        "from .shell_runner import execute_unsafe\n\n"
        "def handle_request(request):\n"
        "    command = request.args.get('cmd')\n"
        "    execute_unsafe(command)\n",
        encoding="utf-8",
    )
    projects["multi_module"] = multi_mod_dir

    # 6. Project with unsupported files
    unsupported_dir = base / "06_unsupported_files_project"
    unsupported_dir.mkdir(parents=True)
    (unsupported_dir / "app.py").write_text(
        "def ok(x: int) -> int:\n    return x * 2\n",
        encoding="utf-8",
    )
    (unsupported_dir / "native.rs").write_text(
        'fn main() { println!("hello"); }\n',
        encoding="utf-8",
    )
    (unsupported_dir / "notes.unknown_ext").write_text(
        "some arbitrary notes\n",
        encoding="utf-8",
    )
    projects["unsupported"] = unsupported_dir

    # 7. Project with corrupted file (syntax error in Python & invalid JSON manifest)
    corrupted_dir = base / "07_corrupted_file_project"
    corrupted_dir.mkdir(parents=True)
    (corrupted_dir / "broken.py").write_text(
        "def broken_func(:\n    return 42\n",
        encoding="utf-8",
    )
    (corrupted_dir / "valid.py").write_text(
        "import os\ndef run(cmd: str):\n    os.system(cmd)\n",
        encoding="utf-8",
    )
    (corrupted_dir / "package.json").write_text(
        "{ invalid json ",
        encoding="utf-8",
    )
    projects["corrupted"] = corrupted_dir

    # 8. Project partially inaccessible due to permissions (simulated via monkeypatch in test)
    perm_dir = base / "08_permission_restricted_project"
    perm_dir.mkdir(parents=True)
    (perm_dir / "accessible.py").write_text(
        "import subprocess\ndef run(x: str):\n    subprocess.call(x, shell=True)\n",
        encoding="utf-8",
    )
    locked_sub = perm_dir / "restricted_subdir"
    locked_sub.mkdir()
    (locked_sub / "secret.py").write_text("x = 1\n", encoding="utf-8")
    projects["permissions"] = perm_dir

    return projects


def test_eight_reference_projects_pipeline_and_quality_metrics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    projects = _build_reference_projects(tmp_path / "projects")
    out_root = tmp_path / "results"

    # 1. Safe project: 0 findings (FP == 0)
    safe_out = out_root / "safe"
    rc = main(["inspect", str(projects["safe"]), "--output-dir", str(safe_out), "--language", "pl"])
    assert rc == 0
    captured = capsys.readouterr().out
    assert "AI Threat Lab" in captured
    assert "Final JSON report:" in captured
    assert "Final HTML report:" in captured
    safe_results = get_audit_results(safe_out, language="pl")
    assert safe_results["summary"]["finding_count"] == 0
    assert safe_results["detailed_findings"] == []

    # 2. Multi-vulnerability project: detects secret, command exec, pickle, SQLi with exact
    # line numbers
    vuln_out = out_root / "multi_vuln"
    summary_vuln = run_audit(projects["multi_vuln"], output_dir=vuln_out, language="pl")
    assert summary_vuln["unique_findings"] >= 4
    vuln_results = get_audit_results(vuln_out, language="pl")
    vuln_details = vuln_results["detailed_findings"]
    rules_by_line = {(d["rule_code"], d["line_number"]) for d in vuln_details}
    # Line 6: AWS_SECRET, Line 9: subprocess.run(..., shell=True), Line 12: pickle.loads, Line
    # 16/17: SQLi
    assert any(line == 7 for _, line in rules_by_line)
    assert any(line == 10 for _, line in rules_by_line)
    assert any(line == 13 for _, line in rules_by_line)
    assert any(line in (16, 17, 18) for _, line in rules_by_line)
    for d in vuln_details:
        assert d["file_path"] is not None and d["file_path"].endswith("vuln_app.py")
        assert d["line_range"] is not None
        assert d["confirmation_status"] in ("candidate", "unverified")
        assert d["mechanism"]
        assert d["consequences"]
        assert d["recommendation"]
        assert d["verification_steps"]
        assert d["analysis_limitations"]

    # 3. Misconfigured project: detects Dockerfile and GitHub Actions workflow issues
    mis_out = out_root / "misconfigured"
    run_audit(projects["misconfigured"], output_dir=mis_out, language="en")
    mis_results = get_audit_results(mis_out, language="en")
    mis_files = {
        Path(d["file_path"]).name for d in mis_results["detailed_findings"] if d["file_path"]
    }
    assert "Dockerfile" in mis_files
    assert "ci.yml" in mis_files

    # 4. Dependency project: detects unpinned / insecure index / wildcard dependencies
    dep_out = out_root / "dependencies"
    run_audit(projects["dependencies"], output_dir=dep_out, language="pl")
    dep_results = get_audit_results(dep_out, language="pl")
    assert dep_results["summary"]["finding_count"] >= 1
    dep_categories = {d["threat_category"] for d in dep_results["detailed_findings"]}
    assert any("dependency" in cat or "supply_chain" in cat for cat in dep_categories)

    # 5. Multi-module Python project: detects cross-module taint flow from routes.py to
    # shell_runner.py
    mm_out = out_root / "multi_module"
    run_audit(projects["multi_module"], output_dir=mm_out, language="en")
    mm_results = get_audit_results(mm_out, language="en")
    assert mm_results["summary"]["finding_count"] >= 1
    mm_files = {
        Path(d["file_path"]).name for d in mm_results["detailed_findings"] if d["file_path"]
    }
    assert "routes.py" in mm_files or "shell_runner.py" in mm_files

    # 6. Unsupported files project: cleanly records unsupported extensions in not_checked
    # without crashing
    unsup_out = out_root / "unsupported"
    run_audit(projects["unsupported"], output_dir=unsup_out, language="pl")
    unsup_results = get_audit_results(unsup_out, language="pl")
    assert unsup_results["summary"]["finding_count"] == 0
    not_checked_text = " ".join(item["notice"] for item in unsup_results["report"]["not_checked"])
    assert "Only selected Python AST patterns were checked" in not_checked_text

    # 7. Corrupted file project: records syntax error & broken package.json and still scans valid.py
    corr_out = out_root / "corrupted"
    run_audit(projects["corrupted"], output_dir=corr_out, language="pl")
    corr_results = get_audit_results(corr_out, language="pl")
    assert corr_results["summary"]["finding_count"] >= 1
    corr_files = {
        Path(d["file_path"]).name for d in corr_results["detailed_findings"] if d["file_path"]
    }
    assert "valid.py" in corr_files
    corr_not_checked = " ".join(item["notice"] for item in corr_results["report"]["not_checked"])
    assert "broken.py" in corr_not_checked
    assert "package.json" in corr_not_checked or any(
        d["rule_code"] == "invalid_manifest" for d in corr_results["detailed_findings"]
    )

    # 8. Permission-restricted project: records permission error in not_checked while scanning
    # accessible.py
    real_walk = os.walk

    def restricted_walk(top, *args, **kwargs):
        onerror = kwargs.get("onerror")
        for root, dirs, files in real_walk(top, *args, **kwargs):
            if "restricted_subdir" in dirs:
                dirs.remove("restricted_subdir")
                if onerror is not None:
                    err = PermissionError(
                        13, "Permission denied", str(Path(root) / "restricted_subdir")
                    )
                    onerror(err)
            yield root, dirs, files

    monkeypatch.setattr(os, "walk", restricted_walk)
    perm_out = out_root / "permissions"
    run_audit(projects["permissions"], output_dir=perm_out, language="pl")
    perm_results = get_audit_results(perm_out, language="pl")
    assert perm_results["summary"]["finding_count"] >= 1
    perm_not_checked = " ".join(item["notice"] for item in perm_results["report"]["not_checked"])
    assert "restricted_subdir" in perm_not_checked


def test_detailed_finding_contract_never_invents_lines_or_overclaims_confirmation() -> None:
    finding_without_line = {
        "id": "hdr-1",
        "module": "header_review",
        "title": "Missing Content-Security-Policy header",
        "severity": "medium",
        "confidence": "high",
        "status": "candidate",
        "target": "https://example.test",
        "evidence": ["Strict-Transport-Security present; Content-Security-Policy missing"],
        "remediation": "Configure a strict Content-Security-Policy response header.",
    }
    detail_en = describe_finding(finding_without_line, language="en")
    assert isinstance(detail_en, DetailedFinding)
    assert detail_en.line_number is None
    assert detail_en.line_range is None
    assert detail_en.file_path is None
    assert detail_en.confirmation_status == "candidate"

    detail_pl = describe_finding(finding_without_line, language="pl")
    assert detail_pl.line_number is None
    assert detail_pl.line_range is None
    assert detail_pl.confirmation_status == "candidate"
    assert "weryfikacji" in detail_pl.analysis_limitations

    with pytest.raises(ValidationError):
        describe_finding(finding_without_line, language="de")


def test_offline_html_and_brief_reports_answer_six_developer_questions(tmp_path: Path) -> None:
    proj = tmp_path / "app"
    proj.mkdir()
    (proj / "service.py").write_text(
        "import subprocess\ndef run_task(cmd: str):\n    subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "out"
    run_audit(proj, output_dir=out_dir, language="pl")
    res_pl = get_audit_results(out_dir, language="pl")

    text_pl = res_pl["brief_text"]
    for question in (
        "Co wykryto?",
        "Dlaczego jest to potencjalnie niebezpieczne?",
        "Do czego może doprowadzić?",
        "Jak to naprawić?",
        "Jak sprawdzić poprawkę?",
        "Czego analizator nie ustalił?",
    ):
        assert question in text_pl
        assert question in res_pl["html"]

    res_en = get_audit_results(out_dir, language="en")
    for question_en in (
        "What was detected?",
        "Why is it potentially dangerous?",
        "What could it lead to?",
        "How to fix it?",
        "How to verify the fix?",
        "What did the analyzer not establish?",
    ):
        assert question_en in res_en["html"]
    assert "What was detected?" in res_en["brief_text"]
    assert "Why dangerous?" in res_en["brief_text"]
    assert "Potential consequences?" in res_en["brief_text"]
    assert "Verification" in res_en["brief_text"]
    assert "Limitations" in res_en["brief_text"]


def test_multilingual_ai_contract_immutability_and_guardrails(tmp_path: Path) -> None:
    proj = tmp_path / "app"
    proj.mkdir()
    (proj / "db.py").write_text(
        "import subprocess\ndef run_query(cmd: str):\n    return subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "out"
    run_audit(proj, output_dir=out_dir, language="pl")
    results = get_audit_results(out_dir, language="pl")
    original_report = copy.deepcopy(results["report"])

    # Prepare multilingual packet
    packet = build_multilingual_ai_packet(results["report"], language="pl")
    assert packet["report_language"] == "pl"
    assert packet["authoritative_constraints"]["cannot_invent_locations"] is True
    assert packet["authoritative_constraints"]["cannot_change_status"] is True
    assert packet["authoritative_constraints"]["cannot_execute_tools"] is True
    assert packet["tools_permitted"] is False
    assert "Polish (pl)" in review_instructions("pl")
    assert results["report"] == original_report

    evidence_ids = [item["evidence_id"] for item in packet["input"]["findings"]]
    assert evidence_ids

    # Valid AI response attaches cleanly without mutating technical findings
    valid_ai_raw = json.dumps({
        "summary": "Wykryto potencjalne wstrzyknięcie poleceń powłoki (shell=True).",
        "observations": [
            {
                "evidence_id": eid,
                "explanation": (
                    "Polecenie przekazywane jest do powłoki systemowej "
                    "przez shell=True."
                ),
                "what_to_review": "Sprawdź wywołanie subprocess.run w db.py.",
                "suggested_remediation": "Przekaż listę argumentów przy shell=False.",
            }
            for eid in evidence_ids
        ],
        "uncertainty": "Analiza statyczna nie zweryfikowała źródła zmiennej cmd.",
    })
    merged = attach_ai_interpretation(
        results["report"], valid_ai_raw, expected_ids=set(evidence_ids), language="pl"
    )
    assert merged["technical_report"]["findings"] == original_report["findings"]
    assert merged["ai_advisory"]["valid"] is True
    assert merged["ai_advisory"]["report_language"] == "pl"
    assert len(merged["ai_advisory"]["observations"]) == len(evidence_ids)
    for obs in merged["ai_advisory"]["observations"]:
        assert obs["authoritative_status"] in ("candidate", "unverified")

    # Invalid AI responses (hallucinated ID, invented location, status mutation, tool call,
    # malformed JSON)
    # must NEVER corrupt the local report when preserve_on_error=True
    bad_payloads = [
        "{not valid json",
        json.dumps({
            "summary": "Hallucinated ID",
            "observations": [
                {
                    "evidence_id": "non-existent-id",
                    "explanation": "x",
                    "what_to_review": "y",
                    "suggested_remediation": "z",
                }
            ],
            "uncertainty": "limit",
        }),
        json.dumps({
            "summary": "Invented location",
            "invented_locations": ["src/phantom.py:999"],
            "observations": [],
            "uncertainty": "limit",
        }),
        json.dumps({
            "summary": "Attempted status override",
            "status_override": "confirmed",
            "observations": [],
            "uncertainty": "limit",
        }),
        json.dumps({
            "summary": "Attempted tool execution",
            "tool_calls": [{"name": "rm", "args": ["-rf", "/"]}],
            "observations": [],
            "uncertainty": "limit",
        }),
    ]
    for bad_raw in bad_payloads:
        preserved = attach_ai_interpretation(
            results["report"],
            bad_raw,
            expected_ids=set(evidence_ids),
            language="pl",
            preserve_on_error=True,
        )
        assert preserved["technical_report"]["findings"] == original_report["findings"]
        assert preserved["ai_advisory"]["valid"] is False
        assert preserved["ai_advisory"]["status"] == "rejected_invalid_ai_output"
        assert preserved["ai_advisory"]["error"]
        with pytest.raises(ValidationError):
            attach_ai_interpretation(
                results["report"],
                bad_raw,
                expected_ids=set(evidence_ids),
                language="pl",
                preserve_on_error=False,
            )


def test_gui_python_api_end_to_end_and_typed_errors(tmp_path: Path) -> None:
    analyzers = list_analyzers()
    assert any(a["target_kind"] == "local_project" for a in analyzers)
    assert any(a["target_kind"] == "python_source" for a in analyzers)

    caps = get_capabilities()
    assert set(caps["supported_languages"]) == {"en", "pl"}
    assert "json" in caps["export_formats"]
    assert "sarif" in caps["export_formats"]

    opts = create_audit_options(language="pl", max_files=80)
    assert opts.max_files == 80

    with pytest.raises(ValidationError):
        create_audit_options(language="pl", max_files=200)

    with pytest.raises(ValidationError):
        create_audit_options(language="fr")

    proj = tmp_path / "gui_proj"
    proj.mkdir()
    (proj / "main.py").write_text(
        "import pickle\ndef load_item(data: bytes):\n    return pickle.loads(data)\n",
        encoding="utf-8",
    )

    plan = plan_audit(proj, language="pl")
    assert plan["target_kind"] == "local_project"
    assert plan["report_language"] == "pl"

    out_dir = tmp_path / "gui_out"
    with pytest.raises(ValidationError):
        get_audit_status(out_dir)

    run_summary = run_audit(proj, output_dir=out_dir, options=opts, language="pl")
    assert run_summary["status"] in ("partial", "completed")
    assert run_summary["unique_findings"] >= 1

    # Re-running into non-empty output_dir without overwrite raises ValidationError
    with pytest.raises((ValidationError, FileExistsError)):
        run_audit(proj, output_dir=out_dir, options=opts, language="pl")

    status_after = get_audit_status(out_dir)
    assert status_after["state"] in ("partial", "completed")
    assert status_after["integrity_verified"] is True

    results = get_audit_results(out_dir, language="pl")
    assert results["language"] == "pl"
    assert len(results["detailed_findings"]) >= 1

    # Export in HTML, JSON, SARIF
    exported_sarif = tmp_path / "exported.sarif"
    sarif_str = export_audit_report(out_dir, exported_sarif, format="sarif", language="pl")
    assert '"version": "2.1.0"' in sarif_str
    assert exported_sarif.is_file()

    exported_html = tmp_path / "exported_pl.html"
    html_str = export_audit_report(out_dir, exported_html, format="html", language="pl")
    assert "Co wykryto?" in html_str
    assert "Co wykryto?" in exported_html.read_text(encoding="utf-8")

    history = get_audit_history(tmp_path)
    assert history["verified_runs"] >= 1
    assert any(item["directory"] == "gui_out" for item in history["runs"])

    packets = prepare_ai_packets(out_dir, language="pl")
    assert packets["report_language"] == "pl"
    assert packets["packet_count"] >= 1

    # Additional GUI API error boundaries
    with pytest.raises(ValidationError):
        run_audit(12345, output_dir=tmp_path / "bad")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        run_audit(proj, output_dir=tmp_path / "bad2", options="not_options")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        export_audit_report(out_dir, out_dir / "inside.html", format="html", language="pl")
    with pytest.raises(ValidationError):
        prepare_ai_packets(out_dir, config="bad_config")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        build_multilingual_ai_packet(results["report"], config="bad_config")  # type: ignore[arg-type]


def test_finding_details_all_categories_and_sources() -> None:
    from ai_threat_lab.assessment import AssessmentFinding, AssessmentResult
    from ai_threat_lab.code_review import review_source
    from ai_threat_lab.finding_details import _RULE_CATALOG

    # Review source -> CodeReviewResult -> detailed_findings
    code_res = review_source("import os\nos.system('ls')\n", "script.py")
    details_code_en = detailed_findings(code_res, language="en")
    details_code_pl = detailed_findings(code_res, language="pl")
    assert len(details_code_en) == 1
    assert details_code_en[0].line_number == 2
    assert details_code_pl[0].language == "pl"

    # AssessmentResult -> detailed_findings
    assess_res = AssessmentResult(
        target="app.py",
        target_kind="python_source",
        status="partial",
        findings=(
            AssessmentFinding("PY001", "candidate", "app.py:4:0 — eval", "Avoid eval"),
            AssessmentFinding(
                "k8s_privileged_container",
                "candidate",
                "pod.json: line 12 privileged",
                "Disable privileged",
            ),
            AssessmentFinding(
                "html_password_form_http", "candidate", "login.html: line 8 form", "Use HTTPS"
            ),
            AssessmentFinding("missing_csp_header", "candidate", "https://example.test", "Add CSP"),
            AssessmentFinding(
                "message_suspicious_link", "candidate", "mail.eml: link", "Verify sender"
            ),
            AssessmentFinding("pe_missing_aslr", "candidate", "bin.exe: header", "Enable ASLR"),
            AssessmentFinding(
                "auth_repeated_failures", "candidate", "auth.jsonl: 10 failures", "Check logs"
            ),
            AssessmentFinding(
                "ssh_root_login", "candidate", "sshd.jsonl: root", "Disable root SSH"
            ),
            AssessmentFinding("har_cleartext_auth", "candidate", "trace.har: entry 3", "Use HTTPS"),
            AssessmentFinding(
                "sarif_external_finding", "candidate", "uri=src/a.py; start_line=22", "Fix issue"
            ),
            AssessmentFinding(
                "unpinned_dependencies", "candidate", "requirements.txt: flask", "Pin version"
            ),
            AssessmentFinding(
                "custom_unknown_check", "unverified", "some evidence", "Review context"
            ),
        ),
        not_checked=("limit",),
    )
    for lang in ("en", "pl"):
        items = detailed_findings(assess_res, language=lang)
        assert len(items) == len(assess_res.findings)
        for item in items:
            assert item.id
            assert item.what_was_detected
            assert item.mechanism
            assert item.consequences
            assert item.recommendation
            assert item.verification_steps
            assert item.analysis_limitations
            assert item.confirmation_status in ("candidate", "unverified")

    # Verify all catalog rules render in both languages
    for rule_code in _RULE_CATALOG:
        for lang in ("en", "pl"):
            df = describe_finding(
                {
                    "check": rule_code,
                    "status": "candidate",
                    "target": "src/example.py",
                    "evidence": "src/example.py:10:4 — matched",
                    "recommendation": "Review and remediate.",
                },
                language=lang,
            )
            assert df.rule_code == rule_code
            assert df.line_number == 10
            assert df.file_path == "src/example.py"

    with pytest.raises(ValidationError):
        describe_finding(12345)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        detailed_findings(12345)  # type: ignore[arg-type]
