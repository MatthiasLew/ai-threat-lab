"""Offline acceptance demonstration and explicit capability inventory."""

import html
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .acceptance_samples import (
    synthetic_auth_log,
    synthetic_cargo_lock,
    synthetic_go_sum,
    synthetic_header_capture,
    synthetic_html,
    synthetic_kubernetes_manifest,
    synthetic_message,
    synthetic_python_control_flow,
    synthetic_python_flow,
    synthetic_python_importlib,
    synthetic_python_local_calls,
    synthetic_python_package,
    synthetic_python_package_shadowing,
    synthetic_python_project,
    synthetic_python_sqlite_context,
    synthetic_zip,
)
from .audit_report import merge_reports, render_html
from .batch_scan import check_batch, run_batch
from .binary_samples import synthetic_binary_samples
from .campaigns import CampaignScope, CampaignService, ContentApproval
from .contracts import (
    approval_from_document,
    approval_to_document,
    plan_from_document,
    plan_to_document,
    read_document,
    write_document,
)
from .exercise_export import claim_directory, export_exercise, json_bytes
from .header_review import audit_header_capture
from .html_review import review_html_file
from .models import ValidationError
from .readiness import readiness
from .scan_bundle import read_bundle
from .scan_cli import assessor
from .scan_engine import ScanOptions, ScanService
from .training_lab import LabAction, TrainingLab, render_training_html

COMMANDS = {"readiness", "exercise-export", "offline-demo"}


def add_commands(commands):
    ready = commands.add_parser("readiness", help="Static implementation inventory; no API probes")
    ready.add_argument("--output", type=Path)
    export = commands.add_parser(
        "exercise-export", help="Export an approved inert local email/script/storyboard pack"
    )
    export.add_argument("plan", type=Path)
    export.add_argument("--approval", type=Path, required=True)
    export.add_argument("--output-dir", type=Path, required=True)
    demo = commands.add_parser(
        "offline-demo", help="Run synthetic scan/training acceptance workflow without APIs"
    )
    demo.add_argument("--output-dir", type=Path, required=True)


def offline_demo(output, *, now=None):
    current = now if now is not None else datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValidationError("Demo time must be timezone-aware")
    root = claim_directory(output)
    # Fixture source is read as text/AST only. Never imported or executed.
    project = root / "synthetic-project"
    project.mkdir()
    (project / "app.py").write_text("eval(user_value)\n", encoding="utf-8")
    (project / "requirements.txt").write_text("fixture-package==1.2.3\n", encoding="utf-8")
    (project / "Cargo.lock").write_text(synthetic_cargo_lock(), encoding="utf-8")
    (project / "go.sum").write_text(synthetic_go_sum(), encoding="utf-8")
    docker = project / "Dockerfile"
    docker.write_text("FROM python:latest\nUSER root\n", encoding="utf-8")
    nested = project / "services" / "api"
    nested.mkdir(parents=True)
    (nested / "requirements.txt").write_text("fixture-package==1.2.3\n", encoding="utf-8")
    options = ScanOptions(str(project), recursive_dependencies=True)
    engine = ScanService(assessor, clock=lambda: current)
    before = engine.run(options, root / "scan-before")
    (project / "app.py").write_text("value = 'synthetic fixture'\n", encoding="utf-8")
    docker.write_text("FROM python@sha256:" + "a" * 64 + "\nUSER app\n", encoding="utf-8")
    after = engine.run(options, root / "scan-after", baseline=root / "scan-before")
    if (
        before["failed_modules"]
        or after["failed_modules"]
        or not before["unique_findings"]
        or after["unique_findings"]
        or not after["comparison"]["comparable"]
    ):
        raise ValidationError("Synthetic scan acceptance failed; demo is incomplete")
    # Reading verifies both artifact indexes and report derivation.
    before_bundle = read_bundle(root / "scan-before")
    read_bundle(root / "scan-after")
    ecosystems = sorted(
        {
            item["ecosystem"]
            for item in before_bundle["documents"]["dependency-inventory.json"]["packages"]
        }
    )
    if ecosystems != ["Go", "PyPI", "crates.io"]:
        raise ValidationError("Synthetic dependency acceptance failed; demo is incomplete")
    mail_source = root / "synthetic-message.eml"
    mail_source.write_bytes(synthetic_message())
    mail = engine.run(ScanOptions(str(mail_source)), root / "mail-observations")
    if mail["failed_modules"] or mail["unique_findings"] != 5:
        raise ValidationError("Synthetic mail acceptance failed; demo is incomplete")
    read_bundle(root / "mail-observations")
    batch = run_batch(
        [str(project), str(mail_source)],
        root / "local-batch",
        recursive_dependencies=True,
        service=engine,
    )
    check_batch(root / "local-batch")
    if batch["failed_runs"] or batch["target_count"] != 2 or batch["unique_findings"] != 5:
        raise ValidationError("Synthetic batch acceptance failed; demo is incomplete")
    header_source = root / "response-headers.json"
    header_source.write_bytes(json_bytes(synthetic_header_capture()))
    header_assessment = audit_header_capture(header_source)
    header_document = asdict(header_assessment)
    header_document["findings"] = list(header_document["findings"])
    if len(header_assessment.findings) != 6:
        raise ValidationError("Synthetic header acceptance failed; demo is incomplete")
    (root / "headers-review.json").write_bytes(json_bytes(header_document))
    (root / "headers-review.html").write_text(
        render_html(merge_reports([header_document])),
        encoding="utf-8",
    )
    # HTML and ZIP are parsed only: no rendering, member reads or target requests.
    html_source = root / "saved-page.html"
    html_source.write_text(synthetic_html(), encoding="utf-8")
    html_review = review_html_file(
        html_source, document_url="https://website.example.invalid/login"
    )
    expected_html = {
        "html_password_form_get",
        "html_password_form_http",
        "html_password_form_cross_origin",
        "html_mixed_active_content",
        "html_external_script_without_integrity",
    }
    if {f.check for f in html_review.findings} != expected_html:
        raise ValidationError("Synthetic HTML acceptance failed; demo is incomplete")
    html_document = asdict(html_review)
    html_document["findings"] = list(html_document["findings"])
    (root / "html-review.json").write_bytes(json_bytes(html_document))
    (root / "html-review.html").write_text(
        render_html(merge_reports([html_document])), encoding="utf-8"
    )
    safer_html = root / "safer-page.html"
    safer_html.write_text(synthetic_html(safer=True), encoding="utf-8")
    if review_html_file(safer_html, document_url="https://website.example.invalid/login").findings:
        raise ValidationError("Synthetic HTML negative control failed; demo is incomplete")
    html_scan = engine.run(ScanOptions(str(html_source)), root / "html-observations")
    read_bundle(root / "html-observations")
    if html_scan["failed_modules"] or html_scan["unique_findings"] != 2:
        raise ValidationError("Synthetic HTML scan acceptance failed; demo is incomplete")
    form_mail = root / "saved-form.eml"
    form_mail.write_bytes(
        b"From: sender@example.invalid\r\nTo: recipient@example.invalid\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n" + synthetic_html().encode("utf-8")
    )
    form_mail_scan = engine.run(ScanOptions(str(form_mail)), root / "html-mail-observations")
    form_mail_bundle = read_bundle(root / "html-mail-observations")
    if form_mail_scan["failed_modules"] or {
        f["check"] for f in form_mail_bundle["documents"]["assessment.json"]["findings"]
    } != {"message_html_password_form_get", "message_html_password_form_http"}:
        raise ValidationError("Synthetic HTML mail acceptance failed; demo is incomplete")
    archive_source = root / "metadata.zip"
    archive_source.write_bytes(synthetic_zip())
    archive_scan = engine.run(ScanOptions(str(archive_source)), root / "zip-observations")
    archive_bundle = read_bundle(root / "zip-observations")
    zip_checks = {
        f["check"]
        for f in archive_bundle["documents"]["assessment.json"]["findings"]
        if f["status"] == "candidate"
    }
    if archive_scan["failed_modules"] or zip_checks != {
        "zip_path_escape",
        "zip_platform_ambiguous_path",
    }:
        raise ValidationError("Synthetic ZIP acceptance failed; demo is incomplete")
    auth_source = root / "logins.auth.jsonl"
    auth_source.write_text(synthetic_auth_log(), encoding="utf-8")
    auth_scan = engine.run(ScanOptions(str(auth_source)), root / "authentication-observations")
    auth_bundle = read_bundle(root / "authentication-observations")
    auth_checks = {f["check"] for f in auth_bundle["documents"]["assessment.json"]["findings"]}
    if auth_scan["failed_modules"] or auth_checks != {
        "auth_repeated_failures",
        "auth_success_after_failures",
        "auth_password_spray_pattern",
        "auth_distributed_failures",
    }:
        raise ValidationError("Synthetic authentication acceptance failed; demo is incomplete")
    negative_auth_source = root / "separated-logins.auth.jsonl"
    negative_auth_source.write_text(synthetic_auth_log(negative=True), encoding="utf-8")
    negative_auth = engine.run(
        ScanOptions(str(negative_auth_source)), root / "authentication-negative-control"
    )
    read_bundle(root / "authentication-negative-control")
    if negative_auth["failed_modules"] or negative_auth["unique_findings"]:
        raise ValidationError(
            "Synthetic authentication negative control failed; demo is incomplete"
        )
    kube_project = root / "kubernetes-fixture"
    kube_project.mkdir()
    (kube_project / "workload.json").write_bytes(json_bytes(synthetic_kubernetes_manifest()))
    kubernetes = engine.run(ScanOptions(str(kube_project)), root / "kubernetes-observations")
    read_bundle(root / "kubernetes-observations")
    if kubernetes["failed_modules"] or kubernetes["unique_findings"] != 10:
        raise ValidationError("Synthetic Kubernetes acceptance failed; demo is incomplete")
    binary_results = {}
    for name, raw in synthetic_binary_samples().items():
        target = root / name
        target.write_bytes(raw)
        key = name.removesuffix(".bin")
        result = engine.run(ScanOptions(str(target)), root / key)
        if result["failed_modules"]:
            raise ValidationError("Synthetic binary acceptance failed; demo is incomplete")
        verified = read_bundle(root / key)
        if any(
            f["check"] == "binary_structure_unavailable"
            for f in verified["documents"]["assessment.json"]["findings"]
        ):
            raise ValidationError("Synthetic binary structure failed; demo is incomplete")
        binary_results[key] = result["unique_findings"]
    # Inert source fixture: parsed only, never imported or executed (PyYAML is not required).
    pattern_source = root / "python-patterns.py"
    pattern_source.write_text(
        "import os, tempfile, ssl, yaml, hashlib, jinja2, markupsafe, jwt\n"
        "os.system(command)\ntempfile.mktemp()\nssl._create_unverified_context()\n"
        "yaml.load(payload, Loader=yaml.UnsafeLoader)\nhashlib.md5(payload)\n"
        "jinja2.Environment(autoescape=False)\nmarkupsafe.Markup(content)\n"
        'jwt.decode(token, options={"verify_signature": False})\n',
        encoding="utf-8",
    )
    patterns = engine.run(ScanOptions(str(pattern_source)), root / "python-patterns")
    if patterns["failed_modules"] or patterns["unique_findings"] != 8:
        raise ValidationError("Synthetic Python pattern acceptance failed; demo is incomplete")
    flow_source = root / "python-flow.py"
    flow_source.write_text(synthetic_python_flow(), encoding="utf-8")
    flows = engine.run(ScanOptions(str(flow_source)), root / "python-flow")
    flow_bundle = read_bundle(root / "python-flow")
    flow_rules = {f["check"] for f in flow_bundle["documents"]["assessment.json"]["findings"]}
    if (
        flows["failed_modules"]
        or flows["unique_findings"] != 3
        or flow_rules != {"PY005", "PY013", "PY014"}
    ):
        raise ValidationError("Synthetic Python flow acceptance failed; demo is incomplete")
    control_source = root / "python-control-flow.py"
    control_source.write_text(synthetic_python_control_flow(), encoding="utf-8")
    control = engine.run(ScanOptions(str(control_source)), root / "python-control-flow")
    control_bundle = read_bundle(root / "python-control-flow")
    control_rules = {f["check"] for f in control_bundle["documents"]["assessment.json"]["findings"]}
    if (
        control["failed_modules"]
        or control["unique_findings"] != 3
        or control_rules != {"PY005", "PY013", "PY014"}
    ):
        raise ValidationError("Synthetic Python control-flow acceptance failed; demo is incomplete")
    context_source = root / "python-sqlite-context.py"
    context_source.write_text(synthetic_python_sqlite_context(), encoding="utf-8")
    context = engine.run(ScanOptions(str(context_source)), root / "python-sqlite-context")
    context_bundle = read_bundle(root / "python-sqlite-context")
    context_rules = {f["check"] for f in context_bundle["documents"]["assessment.json"]["findings"]}
    if (
        context["failed_modules"]
        or context["unique_findings"] != 3
        or context_rules != {"PY005", "PY013", "PY014"}
    ):
        raise ValidationError(
            "Synthetic Python SQLite-context acceptance failed; demo is incomplete"
        )
    calls_source = root / "python-local-calls.py"
    calls_source.write_text(synthetic_python_local_calls(), encoding="utf-8")
    calls = engine.run(ScanOptions(str(calls_source)), root / "python-local-calls")
    calls_bundle = read_bundle(root / "python-local-calls")
    calls_findings = calls_bundle["documents"]["assessment.json"]["findings"]
    if (
        calls["failed_modules"]
        or calls["unique_findings"] != 3
        or {f["check"] for f in calls_findings} != {"PY005", "PY013", "PY014"}
        or not all(
            "Local call-site line(s):" in f["evidence"]
            for f in calls_findings
            if f["check"] in ("PY013", "PY014")
        )
    ):
        raise ValidationError("Synthetic Python local-call acceptance failed; demo is incomplete")
    project_source = root / "python-project-fixture"
    project_source.mkdir()
    for name, source in synthetic_python_project().items():
        (project_source / name).write_text(source, encoding="utf-8")
    project_flow = engine.run(ScanOptions(str(project_source)), root / "python-project-flow")
    project_bundle = read_bundle(root / "python-project-flow")
    project_findings = project_bundle["documents"]["assessment.json"]["findings"]
    if (
        project_flow["failed_modules"]
        or project_flow["unique_findings"] != 3
        or {f["check"] for f in project_findings} != {"PY005", "PY013", "PY014"}
        or not all(
            "cross-file candidate" in f["evidence"]
            for f in project_findings
            if f["check"] in ("PY013", "PY014")
        )
    ):
        raise ValidationError("Synthetic Python project-flow acceptance failed; demo is incomplete")
    package_source = root / "python-package-fixture"
    package_source.mkdir()
    for name, source in synthetic_python_package().items():
        path = package_source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    package_flow = engine.run(ScanOptions(str(package_source)), root / "python-package-flow")
    package_bundle = read_bundle(root / "python-package-flow")
    package_findings = package_bundle["documents"]["assessment.json"]["findings"]
    if (
        package_flow["failed_modules"]
        or package_flow["unique_findings"] != 3
        or {f["check"] for f in package_findings} != {"PY005", "PY013", "PY014"}
        or not all(
            "cross-file candidate" in f["evidence"]
            for f in package_findings
            if f["check"] in ("PY013", "PY014")
        )
    ):
        raise ValidationError("Synthetic Python package-flow acceptance failed; demo is incomplete")
    importlib_source = root / "python-importlib-fixture"
    importlib_source.mkdir()
    for name, source in synthetic_python_importlib().items():
        path = importlib_source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    importlib_flow = engine.run(ScanOptions(str(importlib_source)), root / "python-importlib-flow")
    importlib_bundle = read_bundle(root / "python-importlib-flow")
    importlib_findings = importlib_bundle["documents"]["assessment.json"]["findings"]
    if (
        importlib_flow["failed_modules"]
        or importlib_flow["unique_findings"] != 3
        or {f["check"] for f in importlib_findings} != {"PY005", "PY013", "PY014"}
        or not all(
            "cross-file candidate" in f["evidence"]
            for f in importlib_findings
            if f["check"] in ("PY013", "PY014")
        )
    ):
        raise ValidationError(
            "Synthetic Python importlib-flow acceptance failed; demo is incomplete"
        )
    namespace_counts = {}
    for label, shadowed in (("control", False), ("shadowed", True)):
        fixture = root / ("python-namespace-" + label + "-fixture")
        fixture.mkdir()
        for name, source in synthetic_python_package_shadowing(shadowed=shadowed).items():
            path = fixture / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8")
        output = root / ("python-namespace-" + label)
        namespace = engine.run(ScanOptions(str(fixture)), output)
        assessment = read_bundle(output)["documents"]["assessment.json"]
        expected = {"PY005"} if shadowed else {"PY005", "PY013", "PY014"}
        if (
            namespace["failed_modules"]
            or namespace["unique_findings"] != len(expected)
            or {finding["check"] for finding in assessment["findings"]} != expected
            or (shadowed and not any("package attribute" in n for n in assessment["not_checked"]))
        ):
            raise ValidationError(
                "Synthetic package namespace acceptance failed; demo is incomplete"
            )
        namespace_counts[label] = namespace["unique_findings"]
    lab = TrainingLab(root / "training.sqlite", clock=lambda: current)
    session_ids = []
    for channel, action in (
        ("email", LabAction.REPORT),
        ("voice", LabAction.REQUEST_VERIFICATION),
        ("video", LabAction.DECLINE),
    ):
        recipient = "+12025550100" if channel == "voice" else "participant@example.invalid"
        scope = CampaignScope(
            "synthetic-demo-" + channel,
            "Synthetic demo owner",
            (recipient,),
            current + timedelta(hours=1),
            identity_reference="fictional:training-coordinator",
        )
        plan = CampaignService().prepare(
            channel + "_training",
            scope,
            (recipient,),
            ("TRAINING-ALPHA is invented.",),
            now=current,
        )
        approval = ContentApproval(plan.digest, "Synthetic demo reviewer", current)
        # This approval applies only to the generated fictional demo, never user-supplied plans.
        (root / f"{channel}-plan.json").write_bytes(json_bytes(plan_to_document(plan)))
        (root / f"{channel}-approval.json").write_bytes(json_bytes(approval_to_document(approval)))
        export_exercise(plan, approval, root / (channel + "-pack"), now=current)
        state = lab.start(plan, approval, "demo-" + channel)
        session_ids.append(state["session_id"])
        lab.record(state["session_id"], action, "demo-selection")
    training = lab.report()
    (root / "training-report.json").write_bytes(json_bytes(training))
    (root / "training-report.html").write_text(render_training_html(training), encoding="utf-8")
    ready = readiness()
    (root / "readiness.json").write_bytes(json_bytes(ready))
    summary = {
        "schema_version": 1,
        "mode": "synthetic_offline_acceptance",
        "network_called": False,
        "ai_calls": 0,
        "output_directory": str(root.resolve()),
        "python_pattern_observations": patterns["unique_findings"],
        "python_flow_observations": flows["unique_findings"],
        "python_control_flow_observations": control["unique_findings"],
        "python_sqlite_context_observations": context["unique_findings"],
        "python_local_call_observations": calls["unique_findings"],
        "python_project_flow_observations": project_flow["unique_findings"],
        "python_package_flow_observations": package_flow["unique_findings"],
        "python_package_namespace_observations": namespace_counts,
        "python_importlib_flow_observations": importlib_flow["unique_findings"],
        "mail_observations": mail["unique_findings"],
        "batch_targets": batch["target_count"],
        "header_observations": len(header_assessment.findings),
        "authentication_checks": sorted(auth_checks),
        "authentication_negative_findings": negative_auth["unique_findings"],
        "html_observations": len(html_review.findings),
        "html_scan_observations": html_scan["unique_findings"],
        "html_mail_observations": form_mail_scan["unique_findings"],
        "zip_candidate_checks": sorted(zip_checks),
        "kubernetes_observations": kubernetes["unique_findings"],
        "dependency_ecosystems": ecosystems,
        "binary_fixture_observations": binary_results,
        "before_findings": before["unique_findings"],
        "after_findings": after["unique_findings"],
        "comparison": after["comparison"],
        "training_sessions": session_ids,
        "training_channels": ["email", "voice", "video"],
        "notice": "Generated synthetic fixtures only. Selected outcomes are scripted, "
        "not observed participant behavior. Not evidence of real-target or API readiness.",
    }
    links = (
        ("Login event patterns", "authentication-observations/report.html"),
        ("Login event negative control", "authentication-negative-control/report.html"),
        ("Saved HTML review", "html-review.html"),
        ("ZIP metadata review", "zip-observations/report.html"),
        ("Before scan", "scan-before/report.html"),
        ("After scan", "scan-after/report.html"),
        ("Selected training outcomes", "training-report.html"),
        *(
            (channel + " rehearsal", channel + "-pack/preview.html")
            for channel in ("email", "voice", "video")
        ),
        ("Python pattern observations", "python-patterns/report.html"),
        ("Python flow observations", "python-flow/report.html"),
        ("Python branch/loop observations", "python-control-flow/report.html"),
        ("Python SQLite context observations", "python-sqlite-context/report.html"),
        ("Python local-call observations", "python-local-calls/report.html"),
        ("Python cross-file observations", "python-project-flow/report.html"),
        ("Python package observations", "python-package-flow/report.html"),
        ("Package namespace positive control", "python-namespace-control/report.html"),
        ("Assigned package attribute control", "python-namespace-shadowed/report.html"),
        ("Python literal importlib observations", "python-importlib-flow/report.html"),
        ("Synthetic email observations", "mail-observations/report.html"),
        ("Combined local batch", "local-batch/report.html"),
        ("Synthetic HTTP header observations", "headers-review.html"),
        ("Synthetic Kubernetes observations", "kubernetes-observations/report.html"),
        ("Synthetic PE observations", "synthetic-pe/report.html"),
        ("Synthetic ELF observations", "synthetic-elf/report.html"),
        ("Capability inventory", "readiness.json"),
    )
    page = (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" '
        'content="default-src &#39;none&#39;; base-uri &#39;none&#39;; '
        'form-action &#39;none&#39;">'
        "<title>Synthetic offline demo</title><body><h1>Synthetic offline demo</h1>"
        f"<p>{html.escape(summary['notice'])}</p><ul>"
        + "".join(f'<li><a href="{url}">{html.escape(title)}</a></li>' for title, url in links)
        + "</ul><p>Zero API calls. Exported source fixture now contains the after-scan version; "
        "the before bundle preserves observations, not a copy of earlier source."
        "</p></body></html>"
    )
    (root / "index.html").write_text(page, encoding="utf-8")
    # Completion marker written last; failed demos leave a folder without this file.
    (root / "demo-result.json").write_bytes(json_bytes(summary))
    return summary


def run_command(args):
    if args.command == "readiness":
        payload = readiness()
        text = write_document(payload, args.output)
        print(
            f"Report saved: {args.output}" if args.output else text, end="\n" if args.output else ""
        )
        return 0
    if args.command == "exercise-export":
        payload = export_exercise(
            plan_from_document(read_document(args.plan)),
            approval_from_document(read_document(args.approval)),
            args.output_dir,
        )
    else:
        payload = offline_demo(args.output_dir)
    print(write_document(payload), end="")
    return 0
