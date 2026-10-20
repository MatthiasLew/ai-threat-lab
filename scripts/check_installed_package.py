"""Validate the built wheel in a clean venv and working directory containing spaces."""

import json
import os
import runpy
import subprocess
import tarfile
import tempfile
import venv
import zipfile
from email.parser import Parser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]



def check_distribution_archives(wheel: Path, sdist: Path, version: str) -> None:
    """Check both release artifacts without extracting or running archived content."""
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        metadata_path = f"ai_threat_lab-{version}.dist-info/METADATA"
        metadata = Parser().parsestr(archive.read(metadata_path).decode("utf-8"))
        assert metadata["Name"] == "ai-threat-lab"
        assert metadata["Version"] == version
        assert metadata["Requires-Python"] == ">=3.12"
        assert all('extra == "dev"' in item for item in metadata.get_all("Requires-Dist", []))
        entrypoints = archive.read(
            f"ai_threat_lab-{version}.dist-info/entry_points.txt"
        ).decode("utf-8")
        assert "ai-threat-lab = ai_threat_lab.cli:entrypoint" in entrypoints
        assert not any(name.startswith(("tests/", "scripts/")) for name in names)
        catalog = archive.read("ai_threat_lab/data/catalog.json")
        identity = archive.read("ai_threat_lab/_version.py")
    with tarfile.open(sdist, "r:gz") as archive:
        prefix = f"ai_threat_lab-{version}/"
        for relative in (
            "docs/CONSOLE_WORKFLOW.md", "docs/CLI_INSTALLATION.md", "CHANGELOG.md",
            "examples/ai-budget.json", "examples/providers.json", "scripts/verify.py",
            "scripts/check_console_offline.py", ".ai-dev-tools.toml",
        ):
            member = archive.extractfile(prefix + relative)
            assert member is not None, f"Source archive is missing {relative}"
            with member:
                assert member.read() == (ROOT / relative).read_bytes()
        assert not any(
            name.endswith((".sqlite", ".key", "/.env")) or "/.venv/" in name
            for name in archive.getnames()
        )
        for relative, expected in (
            ("src/ai_threat_lab/data/catalog.json", catalog),
            ("src/ai_threat_lab/_version.py", identity),
        ):
            member = archive.extractfile(prefix + relative)
            assert member is not None
            with member:
                assert member.read() == expected
        member = archive.extractfile(prefix + "PKG-INFO")
        assert member is not None
        with member:
            metadata = Parser().parsestr(member.read().decode("utf-8"))
        assert metadata["Version"] == version

def main() -> None:
    version = runpy.run_path(ROOT / "src/ai_threat_lab/_version.py")["__version__"]
    wheel = ROOT / "dist" / f"ai_threat_lab-{version}-py3-none-any.whl"
    if not wheel.is_file():
        raise SystemExit("Build the wheel first with python -m build")
    sdist = ROOT / "dist" / f"ai_threat_lab-{version}.tar.gz"
    check_distribution_archives(wheel, sdist, version)
    with tempfile.TemporaryDirectory(prefix="ai threat installed ") as folder:
        work = Path(folder)
        environment = work / "isolated venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        binary = environment / ("Scripts" if os.name == "nt" else "bin")
        python = binary / ("python.exe" if os.name == "nt" else "python")
        executable = binary / ("ai-threat-lab.exe" if os.name == "nt" else "ai-threat-lab")
        env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
        env.update(PYTHONNOUSERSITE="1", PYTHONIOENCODING="utf-8", PYTHONUTF8="1")

        def run(*args, expected=0):
            result = subprocess.run(
                list(map(str, args)),
                cwd=work,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=90,
            )
            if result.returncode != expected:
                raise RuntimeError(
                    f"Installed command failed ({result.returncode}): {result.stderr}"
                )
            return result.stdout

        run(python, "-m", "pip", "install", "--no-index", "--no-deps", wheel)
        expected_version = f"AI Threat Lab {version}"
        assert run(executable, "--version").strip() == expected_version
        assert run(python, "-m", "ai_threat_lab", "--version").strip() == expected_version
        installation = json.loads(run(executable, "doctor", "--installation"))
        assert installation["status"] == "ready"
        assert installation["mode"] == "installed_distribution"
        assert installation["distribution_version"] == installation["runtime_version"] == version
        assert all(installation["checks"].values())
        assert installation["network_checked"] is installation["credentials_checked"] is False
        command_names = json.loads(run(
            python, "-c",
            "import argparse,json;from ai_threat_lab.cli import build_parser;"
            "p=build_parser();print(json.dumps(sorted(next(a.choices for a in p._actions "
            "if isinstance(a,argparse._SubParsersAction)))))",
        ))
        assert command_names
        for name in command_names:
            assert "usage:" in run(executable, name, "--help")
        run(executable, "--ver", expected=2)
        run(executable, "doctor", "--instal", expected=2)
        env.update(PYTHONIOENCODING="ascii", PYTHONUTF8="0")
        unicode_report = json.loads(run(
            executable, "analyze", "ai_phishing", "--organization", "Łódź Żółw", "--format", "json"
        ))
        assert "Łódź Żółw" in json.dumps(unicode_report, ensure_ascii=False)
        env.update(PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        pipe = subprocess.Popen(
            [str(executable), "--help"], cwd=work, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        assert pipe.stdout is not None and pipe.stderr is not None
        pipe.stdout.close()
        try:
            assert pipe.wait(timeout=15) == 141
            assert pipe.stderr.read() == b""
        finally:
            pipe.stderr.close()
            if pipe.poll() is None:
                pipe.kill()
                pipe.wait()

        website_receipt = json.loads(run(python, ROOT / "scripts/check_website_offline.py"))
        assert website_receipt == {
            "status": "passed", "synthetic_requests": 6, "scope_rejections": 3,
            "live_requests": 0, "ai_calls": 0,
        }
        github_receipt = json.loads(run(python, ROOT / "scripts/check_github_offline.py"))
        assert github_receipt == {
            "status": "passed", "positive_requests": 5, "negative_controls": 7,
            "live_requests": 0, "ai_calls": 0,
        }
        mail_receipt = json.loads(run(python, ROOT / "scripts/check_mail_domain_offline.py"))
        assert mail_receipt == {
            "status": "passed", "positive_requests": 5, "scope_rejections": 3,
            "negative_controls": 6, "live_requests": 0, "ai_calls": 0,
        }
        gmail_receipt = json.loads(run(python, ROOT / "scripts/check_gmail_offline.py"))
        assert gmail_receipt == {
            "status": "passed", "positive_requests": 6, "scope_rejections": 3,
            "negative_controls": 8, "live_requests": 0, "ai_calls": 0,
        }
        dependency_receipt = json.loads(run(python, ROOT / "scripts/check_dependencies_offline.py"))
        assert dependency_receipt == {
            "status": "passed", "positive_requests": 2, "negative_controls": 4,
            "cached_workflows": 2, "live_requests": 0, "ai_calls": 0,
        }
        run(python, ROOT / "scripts/check_ai_offline.py")
        console_receipt = json.loads(run(python, ROOT / "scripts/check_console_offline.py"))
        assert console_receipt == {
            "status": "passed", "synthetic_ai_requests": 2, "live_requests": 0,
            "source_independent_summary": True, "invalid_advice_rejected": True,
        }
        ai_report = json.loads((work / "installed-ai-costs-result.json").read_text())
        assert ai_report["days"][0]["calls"] == 3 and not ai_report["unconfirmed"]
        assert (
            json.loads(run(executable, "api-costs", "--ledger", "installed AI costs.sqlite"))
            == ai_report
        )
        assert (
            json.loads(
                run(executable, "api-cache-prune", "--ledger", "installed AI costs.sqlite", "--all")
            )["accounting_rows_deleted"]
            == 0
        )
        assert json.loads(run(executable, "doctor"))["status"] == "ready_offline"
        for scenario in ("email_training", "voice_training"):
            run(executable, "campaign-example", scenario, "--output", "request.json")
            run(executable, "campaign-prepare", "request.json", "--output", "plan.json")
            run(
                executable,
                "campaign-approve",
                "plan.json",
                "--reviewer",
                "Wheel reviewer",
                "--output",
                "approval.json",
            )
            result = json.loads(
                run(
                    executable,
                    "campaign-simulate",
                    "plan.json",
                    "--approval",
                    "approval.json",
                    "--ledger",
                    "attempts.sqlite",
                )
            )
            assert result["receipts"][0]["status"] == "simulated"
            run(
                executable,
                "campaign-simulate",
                "plan.json",
                "--approval",
                "approval.json",
                "--ledger",
                "attempts.sqlite",
                expected=2,
            )
            for name in ("request.json", "plan.json", "approval.json", "attempts.sqlite"):
                (work / name).unlink()
        result = json.loads(
            run(
                executable,
                "analyze",
                "voice_deepfake",
                "--proposed",
                "callback",
                "--proposed",
                "independent_approval",
                "--format",
                "json",
            )
        )
        assert result["analysis"]["residual"]["score"] == 10
        source = work / "source.py"
        source.write_text("eval(data)\n")
        result = json.loads(run(executable, "review-code", source, "--format", "json"))
        assert result["review"]["findings"][0]["rule_id"] == "PY001"
        sarif = json.loads(
            run(
                executable,
                "review-code",
                source,
                "--format",
                "sarif",
                "--source-root",
                work,
                "--fail-on-findings",
                expected=1,
            )
        )
        assert sarif["version"] == "2.1.0"
        sarif_run = sarif["runs"][0]
        assert sarif_run["artifacts"][0]["location"]["uri"] == "source.py"
        assert sarif_run["results"][0]["ruleId"] == "PY001"
        assert sarif_run["properties"]["candidateOnly"] is True
        assert (
            json.loads(run(executable, "assess", "https://example.invalid"))["status"]
            == "not_configured"
        )
        run(executable, "audit", source, "--output", "audit.json")
        configuration = work / "ai-config.json"
        configuration.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "model": "fixture-model",
                    "input_usd_per_million": "2",
                    "output_usd_per_million": "8",
                }
            ),
            encoding="utf-8",
        )
        estimate = json.loads(
            run(
                executable,
                "ai-explain",
                "audit.json",
                "--ai-config",
                configuration,
                "--ledger",
                "costs.sqlite",
                "--dry-run",
            )
        )
        assert estimate["network_called"] is False
        assert json.loads(run(executable, "api-costs", "--ledger", "costs.sqlite"))["days"] == []
        assert (
            json.loads(run(executable, "api-cache-prune", "--ledger", "costs.sqlite"))[
                "cleared_responses"
            ]
            == 0
        )
        assert (
            json.loads(run(executable, "api-cache-prune", "--ledger", "costs.sqlite", "--all"))[
                "accounting_rows_deleted"
            ]
            == 0
        )
        run(executable, "api-costs", "--ledger", "missing-costs.sqlite", expected=2)
        run(executable, "api-cache-prune", "--ledger", "missing-costs.sqlite", expected=2)
        assert not (work / "missing-costs.sqlite").exists()
        run(
            executable,
            "ai-explain",
            "audit.json",
            "--ai-config",
            configuration,
            "--ledger",
            "costs.sqlite",
            "--dry-run",
            "--output",
            "estimate.json",
        )
        run(
            executable,
            "ai-explain",
            "audit.json",
            "--ai-config",
            configuration,
            "--ledger",
            "costs.sqlite",
            "--dry-run",
            "--output",
            "estimate.json",
            expected=2,
        )
        run(executable, "audit", "https://example.invalid", expected=2)
        requirements = work / "requirements.txt"
        requirements.write_text("fixture-package==1.2.3\n", encoding="utf-8")
        inventory = json.loads(run(executable, "audit-deps", requirements))
        assert inventory["packages"][0]["version"] == "1.2.3"
        merged = json.loads(run(executable, "audit-report", "audit.json", "audit.json"))
        assert merged["summary"]["unique_findings"] == 1
        run(executable, "audit-report", "audit.json", "--format", "html", "--output", "report.html")
        assert "<!doctype html>" in (work / "report.html").read_text(encoding="utf-8")
        run(executable, "campaign-example", "voice_training", "--output", "training-request.json")
        run(
            executable,
            "campaign-prepare",
            "training-request.json",
            "--output",
            "training-plan.json",
        )
        run(
            executable,
            "campaign-approve",
            "training-plan.json",
            "--reviewer",
            "Fixture reviewer",
            "--output",
            "training-approval.json",
        )
        session = json.loads(
            run(
                executable,
                "training-start",
                "training-plan.json",
                "--approval",
                "training-approval.json",
                "--participant-id",
                "fixture-01",
                "--ledger",
                "training.sqlite",
            )
        )
        identifier = session["session_id"]
        selected = json.loads(
            run(
                executable,
                "training-step",
                identifier,
                "--action",
                "request_verification",
                "--action-id",
                "fixture-step-01",
                "--ledger",
                "training.sqlite",
            )
        )
        assert selected["session"]["outcome"] == "verification_selected"
        assert (
            json.loads(
                run(executable, "training-status", identifier, "--ledger", "training.sqlite")
            )["turns"]
            == 1
        )
        run(
            executable,
            "training-report",
            "--ledger",
            "training.sqlite",
            "--format",
            "html",
            "--output",
            "training-report.html",
        )
        assert "Local text rehearsal" in (work / "training-report.html").read_text(encoding="utf-8")
        revoked = json.loads(
            run(
                executable,
                "training-cancel",
                "--plan-digest",
                session["plan_digest"],
                "--ledger",
                "training.sqlite",
            )
        )
        assert revoked["cancelled_sessions"] == 0
        scan_project = work / "scan project"
        scan_project.mkdir()
        (scan_project / "app.py").write_text("eval(data)\n", encoding="utf-8")
        (scan_project / "requirements.txt").write_text("fixture-package==1.2.3\n", encoding="utf-8")
        scan = json.loads(run(executable, "scan", scan_project, "--output-dir", "scan first"))
        assert scan["unique_findings"] == 1 and scan["ai_calls"] == 0
        assert scan["modules"]["dependency_inventory"]["status"] == "collected"
        assert (
            json.loads(run(executable, "scan-check", "scan first"))["status"]
            == "integrity_verified"
        )
        run(
            executable,
            "scan",
            scan_project,
            "--output-dir",
            "scan second",
            "--baseline",
            "scan first",
        )
        comparison = json.loads(run(executable, "scan-compare", "scan first", "scan second"))
        assert comparison["comparable"] and comparison["counts"]["still_observed"] == 1
        readiness = json.loads(run(executable, "readiness"))
        assert not readiness["api_key_alone_sufficient"]
        demo = json.loads(run(executable, "offline-demo", "--output-dir", "offline demo"))
        assert demo["before_findings"] == 3 and demo["after_findings"] == 0
        assert demo["local_report_history"] == {
            "verified_runs": 3,
            "invalid_runs": 0,
            "exported_reports": 2,
            "source_removed": True,
        }
        catalog = json.loads(run(executable, "history-list", "offline demo/local-history"))
        assert catalog["verified_runs"] == 3 and catalog["invalid_runs"] == 0
        run(
            executable,
            "history-list",
            "offline demo/local-history",
            "--format",
            "html",
            "--output",
            "installed-history.html",
        )
        run(
            executable,
            "history-list",
            "offline demo/local-history",
            "--output",
            "installed-history.html",
            expected=2,
        )
        run(
            executable,
            "report-export",
            "offline demo/local-history/before",
            "--output",
            "installed-report.json",
        )
        run(
            executable,
            "report-export",
            "offline demo/local-history/batch",
            "--format",
            "html",
            "--output",
            "installed-batch-report.html",
        )
        run(
            executable,
            "report-export",
            "offline demo/local-history/before",
            "--output",
            "installed-report.json",
            expected=2,
        )
        run(
            executable,
            "report-export",
            "offline demo/local-history/before",
            "--output",
            "offline demo/local-history/before/extra.json",
            expected=2,
        )
        assert (
            json.loads((work / "installed-report.json").read_text())["summary"]["unique_findings"]
            == 1
        )
        assert not (work / "offline demo/history-fixture.py").exists()
        assert demo["training_channels"] == ["email", "voice", "video"]
        assert demo["python_project_flow_observations"] == 3
        project_assessment = json.loads(
            run(executable, "audit", "offline demo/python-project-fixture")
        )
        assert {f["check"] for f in project_assessment["findings"]} == {"PY005", "PY013", "PY014"}
        assert all(
            "cross-file candidate" in f["evidence"]
            for f in project_assessment["findings"]
            if f["check"] != "PY005"
        )
        run(executable, "scan-check", "offline demo/python-project-flow")
        assert demo["python_package_namespace_observations"] == {"control": 3, "shadowed": 1}
        for label, expected in (("control", {"PY005", "PY013", "PY014"}), ("shadowed", {"PY005"})):
            namespace = json.loads(
                run(executable, "audit", "offline demo/python-namespace-" + label + "-fixture")
            )
            assert {f["check"] for f in namespace["findings"]} == expected
            if label == "shadowed":
                assert any("package attribute" in n for n in namespace["not_checked"])
            run(executable, "scan-check", "offline demo/python-namespace-" + label)
        assert demo["python_package_flow_observations"] == 3
        package_assessment = json.loads(
            run(executable, "audit", "offline demo/python-package-fixture")
        )
        assert {f["check"] for f in package_assessment["findings"]} == {"PY005", "PY013", "PY014"}
        assert all(
            "cross-file candidate" in f["evidence"]
            for f in package_assessment["findings"]
            if f["check"] != "PY005"
        )
        assert all(
            "cross-file candidate" in f["evidence"] and "src/example/" in f["evidence"]
            for f in package_assessment["findings"]
            if f["check"] != "PY005"
        )
        run(executable, "scan-check", "offline demo/python-package-flow")
        assert demo["python_importlib_flow_observations"] == 3
        importlib_assessment = json.loads(
            run(executable, "audit", "offline demo/python-importlib-fixture")
        )
        assert {f["check"] for f in importlib_assessment["findings"]} == {"PY005", "PY013", "PY014"}
        assert all(
            "cross-file candidate" in f["evidence"]
            for f in importlib_assessment["findings"]
            if f["check"] != "PY005"
        )
        assert all(
            "cross-file candidate" in f["evidence"] and "src/example/" in f["evidence"]
            for f in importlib_assessment["findings"]
            if f["check"] != "PY005"
        )
        run(executable, "scan-check", "offline demo/python-importlib-flow")
        assert demo["python_local_call_observations"] == 3
        calls_review = json.loads(
            run(executable, "review-code", "offline demo/python-local-calls.py", "--format", "json")
        )
        assert {f["rule_id"] for f in calls_review["review"]["findings"]} == {
            "PY005",
            "PY013",
            "PY014",
        }
        assert all(
            "Local call-site line(s):" in f["rationale"]
            for f in calls_review["review"]["findings"]
            if f["rule_id"] != "PY005"
        )
        run(executable, "scan-check", "offline demo/python-local-calls")
        assert demo["python_control_flow_observations"] == 3
        control_review = json.loads(
            run(
                executable, "review-code", "offline demo/python-control-flow.py", "--format", "json"
            )
        )
        assert {f["rule_id"] for f in control_review["review"]["findings"]} == {
            "PY005",
            "PY013",
            "PY014",
        }
        assert any("loop-carried" in n for n in control_review["review"]["limitations"])
        run(executable, "scan-check", "offline demo/python-control-flow")
        assert demo["python_sqlite_context_observations"] == 3
        context_review = json.loads(
            run(
                executable,
                "review-code",
                "offline demo/python-sqlite-context.py",
                "--format",
                "json",
            )
        )
        assert {f["rule_id"] for f in context_review["review"]["findings"]} == {
            "PY005",
            "PY013",
            "PY014",
        }
        assert any("selected SQLite contexts" in n for n in context_review["review"]["limitations"])
        run(executable, "scan-check", "offline demo/python-sqlite-context")
        assert demo["python_flow_observations"] == 3
        flow_review = json.loads(
            run(executable, "review-code", "offline demo/python-flow.py", "--format", "json")
        )
        assert {f["rule_id"] for f in flow_review["review"]["findings"]} == {
            "PY005",
            "PY013",
            "PY014",
        }
        run(executable, "scan-check", "offline demo/python-flow")
        assert demo["python_pattern_observations"] == 8
        patterns = json.loads(
            run(
                executable,
                "review-code",
                "offline demo/python-patterns.py",
                "--format",
                "json",
                "--fail-on-findings",
                expected=1,
            )
        )
        assert {f["rule_id"] for f in patterns["review"]["findings"]} == {
            "PY005",
            "PY006",
            "PY007",
            "PY008",
            "PY009",
            "PY010",
            "PY011",
            "PY012",
        }
        assert set(demo["binary_fixture_observations"]) == {"synthetic-pe", "synthetic-elf"}
        binary = json.loads(run(executable, "audit", "offline demo/synthetic-pe.bin"))
        assert "pe_header" in {f["check"] for f in binary["findings"]}
        assert all(f["status"] != "confirmed" for f in binary["findings"])
        run(executable, "scan-check", "offline demo/synthetic-elf")
        assert (work / "offline demo" / "email-pack" / "preview.eml").is_file()
        assert (work / "offline demo" / "index.html").is_file()
        nested_inventory = json.loads(
            run(
                executable,
                "audit-deps",
                "offline demo/synthetic-project",
                "--recursive-dependencies",
            )
        )
        assert next(p for p in nested_inventory["packages"] if p["ecosystem"] == "PyPI")[
            "sources"
        ] == [
            "requirements.txt:1",
            "services/api/requirements.txt:1",
        ]
        scan_inventory = json.loads(
            (work / "offline demo" / "scan-after" / "dependency-inventory.json").read_text(
                encoding="utf-8"
            )
        )
        assert (
            len(next(p for p in scan_inventory["packages"] if p["ecosystem"] == "PyPI")["sources"])
            == 2
        )
        assert demo["dependency_ecosystems"] == ["Go", "PyPI", "crates.io"]
        assert {p["ecosystem"] for p in scan_inventory["packages"]} == {"Go", "PyPI", "crates.io"}
        assert demo["mail_observations"] == 5
        mail = json.loads(run(executable, "audit", "offline demo/synthetic-message.eml"))
        assert {f["check"] for f in mail["findings"]} == {
            "message_link_cleartext",
            "message_link_ip_address",
            "message_link_display_mismatch",
            "message_attachment_active_type",
            "message_attachment_double_extension",
        }
        run(executable, "scan-check", "offline demo/mail-observations")
        assert demo["batch_targets"] == 2
        assert set(demo["signed_event_fixtures"]) == {"email", "voice", "video"}
        for channel, checks in demo["signed_event_fixtures"].items():
            assert checks["simulation_actions"] == checks["automated_excluded"] == 1
            assert checks["duplicate_rejected"] and checks["altered_signature_rejected"]
            assert checks["cancelled_plan_rejected"]
        event_plan = json.loads((work / "offline demo/email-plan.json").read_text())
        event_digest = event_plan["plan_digest"]
        run(executable, "training-event-keygen", "--key-file", "installed-signing.key")
        run(
            executable,
            "training-events-register",
            "offline demo/email-plan.json",
            "--approval",
            "offline demo/email-approval.json",
            "--bindings",
            "offline demo/email-event-bindings.json",
            "--issuer",
            "installed-fixture",
            "--key-file",
            "installed-signing.key",
            "--ledger",
            "installed-events.sqlite",
        )
        # This adapter fixture uses only the installed wheel and private temporary key.
        run(
            python,
            "-c",
            "from datetime import datetime,timezone; import json; "
            "from pathlib import Path; "
            "from ai_threat_lab.training_events import read_key,sign_envelope; "
            "now=datetime.now(timezone.utc).isoformat(); "
            "plan=json.loads(Path('offline demo/email-plan.json').read_text()); "
            "body=dict(schema_version=1,issuer='installed-fixture',plan_digest=plan['plan_digest'],"
            "channel='email',provenance='simulation',event_id='fixture',participant_id='demo-email',"
            "type='reported',automated=False,occurred_at=now,sent_at=now); "
            "Path('installed-event.json').write_text(json.dumps(sign_envelope(body,"
            "read_key('installed-signing.key'))))",
        )
        import_args = [
            executable,
            "training-events-import",
            "installed-event.json",
            "--key-file",
            "installed-signing.key",
            "--ledger",
            "installed-events.sqlite",
        ]
        assert json.loads(run(*import_args))["accepted"]
        assert json.loads(run(*import_args))["duplicate"]
        report_args = [
            executable,
            "training-events-report",
            "--ledger",
            "installed-events.sqlite",
            "--plan-digest",
            event_digest,
        ]
        claims = json.loads(run(*report_args))
        assert claims["groups"]["simulation"]["nonautomated_events_by_type"] == {"reported": 1}
        assert not claims["participant_behavior_verified"]
        run(*report_args, "--format", "html", "--output", "installed-claims.html")
        run(*report_args, "--output", "installed-claims.html", expected=2)
        assert demo["combined_local_control"]["both_cancelled"]
        assert demo["combined_local_control"]["historical_receipt"] == "recorded_matching"
        receipt_args = [executable, "training-events-receipt", *import_args[2:]]
        assert json.loads(run(*receipt_args))["state_in_this_journal"] == "recorded_matching"
        local = json.loads(
            run(
                executable,
                "training-start",
                "offline demo/email-plan.json",
                "--approval",
                "offline demo/email-approval.json",
                "--participant-id",
                "demo-email",
                "--ledger",
                "installed-local.sqlite",
            )
        )
        control_args = [
            "--training-ledger",
            "installed-local.sqlite",
            "--event-ledger",
            "installed-events.sqlite",
            "--plan-digest",
            event_digest,
        ]
        assert (
            json.loads(run(executable, "training-local-status", *control_args))[
                "cancellation_state"
            ]
            == "not_cancelled"
        )
        controlled = json.loads(run(executable, "training-local-cancel", *control_args))
        assert (
            controlled["cancellation_state"] == "both_cancelled"
            and controlled["stopped_sessions"] == 1
        )
        assert not json.loads(run(executable, "training-local-cancel", *control_args))["changed"]
        recovered = json.loads(run(*receipt_args))
        assert recovered["state_in_this_journal"] == "recorded_matching"
        assert recovered["plan_status"] == "cancelled"
        assert (
            json.loads(
                run(
                    executable,
                    "training-status",
                    local["session_id"],
                    "--ledger",
                    "installed-local.sqlite",
                )
            )["status"]
            == "stopped"
        )
        run(*receipt_args, "--output", "installed-receipt.json")
        run(*receipt_args, "--output", "installed-receipt.json", expected=2)
        run(
            executable,
            "training-events-cancel",
            "--ledger",
            "installed-events.sqlite",
            "--plan-digest",
            event_digest,
        )
        run(*import_args, expected=2)
        assert demo["authentication_checks"] == [
            "auth_distributed_failures",
            "auth_password_spray_pattern",
            "auth_repeated_failures",
            "auth_success_after_failures",
        ]
        assert demo["authentication_negative_findings"] == 0
        assert demo["ssh_journal_checks"] == demo["authentication_checks"]
        assert demo["ssh_journal_negative_findings"] == 0
        ssh = json.loads(
            run(
                executable,
                "review-ssh-journal",
                "offline demo/logins.ssh.jsonl",
                "--fail-on-findings",
                expected=1,
            )
        )
        assert ssh["target_kind"] == "ssh_journal"
        assert sorted(f["check"] for f in ssh["findings"]) == demo["ssh_journal_checks"]
        assert "192.0.2." not in json.dumps(ssh) and "fixture-account" not in json.dumps(ssh)
        run(
            executable,
            "review-ssh-journal",
            "offline demo/separated-logins.ssh.jsonl",
            "--fail-on-findings",
        )
        run(
            executable,
            "review-ssh-journal",
            "offline demo/logins.ssh.jsonl",
            "--min-failures",
            "2",
            expected=2,
        )
        run(
            executable,
            "review-ssh-journal",
            "offline demo/logins.ssh.jsonl",
            "--format",
            "html",
            "--output",
            "installed-ssh-review.html",
        )
        run(
            executable,
            "review-ssh-journal",
            "offline demo/logins.ssh.jsonl",
            "--output",
            "installed-ssh-review.html",
            expected=2,
        )
        run(executable, "scan-check", "offline demo/ssh-observations")
        run(executable, "scan-check", "offline demo/ssh-negative-control")
        login = json.loads(
            run(
                executable,
                "review-auth-log",
                "offline demo/logins.auth.jsonl",
                "--fail-on-findings",
                expected=1,
            )
        )
        assert sorted(f["check"] for f in login["findings"]) == demo["authentication_checks"]
        run(
            executable,
            "review-auth-log",
            "offline demo/separated-logins.auth.jsonl",
            "--fail-on-findings",
        )
        run(
            executable,
            "review-auth-log",
            "offline demo/logins.auth.jsonl",
            "--format",
            "html",
            "--output",
            "installed-auth-review.html",
        )
        run(
            executable,
            "review-auth-log",
            "offline demo/logins.auth.jsonl",
            "--output",
            "installed-auth-review.html",
            expected=2,
        )
        run(
            executable,
            "review-auth-log",
            "offline demo/logins.auth.jsonl",
            "--min-failures",
            "2",
            expected=2,
        )
        run(executable, "scan-check", "offline demo/authentication-observations")
        run(executable, "scan-check", "offline demo/authentication-negative-control")
        assert "fixture-account" not in json.dumps(login)
        assert demo["html_observations"] == 5
        assert demo["html_scan_observations"] == 2
        assert demo["html_mail_observations"] == 2
        assert demo["zip_candidate_checks"] == ["zip_path_escape", "zip_platform_ambiguous_path"]
        page = json.loads(
            run(
                executable,
                "review-html",
                "offline demo/saved-page.html",
                "--document-url",
                "https://website.example.invalid/login",
                "--fail-on-findings",
                expected=1,
            )
        )
        assert len(page["findings"]) == 5
        run(
            executable,
            "review-html",
            "offline demo/safer-page.html",
            "--document-url",
            "https://website.example.invalid/login",
            "--fail-on-findings",
        )
        run(
            executable,
            "review-html",
            "offline demo/saved-page.html",
            "--format",
            "html",
            "--output",
            "installed-html.html",
        )
        run(
            executable,
            "review-html",
            "offline demo/saved-page.html",
            "--output",
            "installed-html.html",
            expected=2,
        )
        for bundle in ("html-observations", "html-mail-observations", "zip-observations"):
            run(executable, "scan-check", "offline demo/" + bundle)
        archive = json.loads(run(executable, "audit", "offline demo/metadata.zip"))
        assert {f["check"] for f in archive["findings"] if f["status"] == "candidate"} == {
            "zip_path_escape",
            "zip_platform_ambiguous_path",
        }
        assert demo["header_observations"] == 6
        assert demo["kubernetes_observations"] == 10
        kube = json.loads(
            run(
                executable,
                "review-kubernetes",
                "offline demo/kubernetes-fixture/workload.json",
                "--fail-on-findings",
                expected=1,
            )
        )
        assert {f["check"] for f in kube["findings"]} == {
            "k8s_host_namespace",
            "k8s_privileged_container",
            "k8s_privilege_escalation",
            "k8s_root_user",
            "k8s_non_root_disabled",
            "k8s_unconfined_seccomp",
            "k8s_added_capabilities",
            "k8s_host_path",
            "k8s_host_port",
            "k8s_writable_root_filesystem",
        }
        assert "fictional-offline-pod" not in json.dumps(kube)
        assert "/fictional/host" not in json.dumps(kube)
        run(executable, "scan-check", "offline demo/kubernetes-observations")
        run(
            executable,
            "review-kubernetes",
            "offline demo/kubernetes-fixture/workload.json",
            "--format",
            "html",
            "--output",
            "kubernetes report.html",
        )
        headers = json.loads(
            run(
                executable,
                "review-headers",
                "offline demo/response-headers.json",
                "--fail-on-findings",
                expected=1,
            )
        )
        assert len(headers["findings"]) == 6
        assert "INERT-DEMO-VALUE" not in json.dumps(headers)
        run(
            executable,
            "review-headers",
            "offline demo/response-headers.json",
            "--format",
            "html",
            "--output",
            "header report.html",
        )
        assert "INERT-DEMO-VALUE" not in (work / "header report.html").read_text(encoding="utf-8")
        checked_batch = json.loads(run(executable, "batch-check", "offline demo/local-batch"))
        assert checked_batch["status"] == "integrity_verified"
        batch = json.loads(
            run(
                executable,
                "scan-batch",
                source,
                "offline demo/synthetic-message.eml",
                "--output-dir",
                "local batch",
                "--fail-on-findings",
                expected=1,
            )
        )
        assert batch["target_count"] == 2 and batch["unique_findings"] == 6
        run(executable, "batch-check", "local batch")
        run(
            executable,
            "exercise-export",
            "offline demo/email-plan.json",
            "--approval",
            "offline demo/email-approval.json",
            "--output-dir",
            "extra pack",
        )
        assert (work / "extra pack" / "manifest.json").is_file()
        print("Clean installed wheel: audit, costs, training and complete scan bundles passed.")


if __name__ == "__main__":
    main()
