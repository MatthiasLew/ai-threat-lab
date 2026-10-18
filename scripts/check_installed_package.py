"""Validate the built wheel in a clean venv and working directory containing spaces."""

import json
import os
import subprocess
import tempfile
import tomllib
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    wheel = ROOT / "dist" / f"ai_threat_lab-{version}-py3-none-any.whl"
    if not wheel.is_file():
        raise SystemExit("Build the wheel first with python -m build")
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
        assert version in run(executable, "--version")
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
        print(
            "Clean installed wheel: audit, cost, dependency, report and training workflows passed."
        )


if __name__ == "__main__":
    main()
