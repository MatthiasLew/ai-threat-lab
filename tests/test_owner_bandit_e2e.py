"""Combined acceptance requires Linux root coordination and dedicated delegation."""

import ctypes
import json
import os
import selectors
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path

import pytest

from ai_threat_lab.scanner_objects import digest


@pytest.fixture(scope="module")
def pinned_capture():
    if sys.platform != "linux" or os.geteuid() != 0:
        pytest.skip("BLOCKED: Linux coordinator needs separate unprivileged accounts")
    parent = os.environ.get("THREAT_LAB_OWNER_E2E_CGROUP")
    oci, wheels = os.environ.get("THREAT_LAB_CPYTHON_OCI"), os.environ.get(
        "THREAT_LAB_REFERENCE_WHEELS",
    )
    if not all((parent, oci, wheels)):
        pytest.skip("BLOCKED: dedicated cgroup delegation and pinned caches are required")
    from owner_bandit_handoff import pinned_tree
    from test_scanner_sandbox import _write_network_filter

    tree, elf = pinned_tree(Path(oci), Path(wheels))
    with tempfile.TemporaryDirectory(prefix="atl-filter-", dir="/tmp") as directory:
        rules = Path(directory) / "rules"
        _write_network_filter(rules, ctypes.CDLL("libseccomp.so.2"))
        yield tree, elf, rules.read_bytes(), Path(parent)


@pytest.fixture
def combined(pinned_capture):
    from owner_bandit_handoff import AGENT, BROKER, LAUNCHER, OWNER

    tree, elf, rules, parent = pinned_capture
    with tempfile.TemporaryDirectory(prefix="atl-owner-bandit-", dir="/tmp") as directory:
        root = Path(directory)
        root.chmod(0o755)
        repo = Path(__file__).resolve().parents[1]
        package = root / "ai_threat_lab"
        shutil.copytree(
            repo / "src" / "ai_threat_lab", package, ignore=shutil.ignore_patterns("__pycache__"),
        )
        for path in [package, *package.rglob("*")]:
            path.chmod(0o755 if path.is_dir() else 0o644)
        for name in (
            "owner_bandit_fixture", "owner_bandit_handoff", "owner_ipc_fixture",
            "cpython_elf", "cpython_oci", "linux_probe_supervision", "pinned_cpython_payload",
        ):
            shutil.copyfile(repo / "tests" / (name + ".py"), root / (name + ".py"))
            (root / (name + ".py")).chmod(0o644)
        state, output = root / "state", root / "output"
        state.mkdir(mode=0o755)
        output.mkdir(mode=0o700)
        os.chown(state, BROKER, BROKER)
        os.chown(output, LAUNCHER, LAUNCHER)
        (root / "host-canary").write_text("synthetic private host file")
        processes = []

        def launch(uid, role, *arguments, **options):
            process = subprocess.Popen(
                ["/usr/bin/python3", "-B", str(root / "owner_bandit_fixture.py"), role,
                 str(root), *map(str, arguments)],
                user=uid, group=uid, extra_groups=[], cwd=root, env={}, **options,
            )
            processes.append(process)
            return process

        yield root, launch, tree, elf, rules, parent
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=10)
        assert not list(parent.glob("atl-probe-*")), "Cgroup cleanup left an operation behind"
        assert len({AGENT, BROKER, OWNER, LAUNCHER}) == 4


def read_ready(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        assert selector.select(30), "Test child did not become ready"
    line = process.stdout.readline()
    assert line, f"Test child exited with {process.poll()}"
    return line


def approve(launch, operation, *, decision=True):
    from test_scanner_owner_ipc import decide

    decide(launch, operation, approval=decision)


@pytest.mark.parametrize("scenario", [
    "clean", "finding", "bad-config", "bad-format", "mutated-source",
])
def test_combined_bandit_and_sarif(combined, scenario):
    from owner_bandit_handoff import AGENT, BROKER, LAUNCHER, prepare_review, seal_review

    root, launch, tree, elf, rules, parent = combined
    review, policy = prepare_review(tree, elf, rules, root, parent, scenario)
    with ExitStack() as stack:
        meta, fds = seal_review(stack, review, policy)
        launcher = launch(
            LAUNCHER, "launcher", meta, "republish", pass_fds=fds,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        )
        assert read_ready(launcher) == b"CAPTURED\n"
        broker = launch(BROKER, "broker", meta, pass_fds=fds, stdout=subprocess.PIPE)
        operation, fingerprint = json.loads(read_ready(broker))
        assert fingerprint == review.fingerprint()
        custody = launch(AGENT, "custody", broker.pid)
        assert custody.wait(timeout=5) == 0
        approve(launch, operation)
        if scenario == "mutated-source":
            (root / "source.py").write_bytes(b"assert False\n")
            (root / "interpreter-source").write_bytes(b"substituted interpreter")
            for fd in fds:
                with pytest.raises(PermissionError):
                    os.pwrite(fd, b"changed", 0)
        stdout, _ = launcher.communicate((operation + "\n").encode(), timeout=90)
        assert launcher.returncode == 0
        result = json.loads(stdout)
        print(json.dumps({"scenario": scenario, "result": result}, sort_keys=True))
        output = Path(review.plan.output_directory)
        if scenario in {"bad-config", "bad-format"}:
            assert result["status"] == "SCANNER_FAILED" and result["exit"] == 2
            assert not output.exists()
        else:
            assert result["authorization"] == "APPROVED_AND_EXECUTED"
            assert result["exit"] == int(scenario == "finding")
            report = json.loads(output.read_bytes())
            assert report["runs"][0]["producer_version"] == "1.7.8"
            if scenario == "finding":
                finding, = report["observations"]
                assert (finding["rule_id"], finding["severity"], finding["confidence"]) == (
                    "B101", "LOW", "HIGH",
                )
                assert finding["locations"][0]["line"] == 3
            else:
                assert report["observations"] == []


@pytest.mark.parametrize("change", [
    "unapproved", "decline", "snapshot", "runtime", "configuration", "limits", "policy",
    "agent", "replay", "concurrent", "broker-crash", "launcher-crash", "no-cgroup",
    "lost-reply", "broker-restart",
])
def test_combined_refusals(combined, change):
    from owner_bandit_handoff import AGENT, BROKER, LAUNCHER, prepare_review, seal_review

    root, launch, tree, elf, rules, parent = combined
    review, policy = prepare_review(tree, elf, rules, root, parent, "clean")
    changed = review
    if change in {"snapshot", "runtime", "configuration", "limits", "policy"}:
        field = {
            "snapshot": "snapshot_sha256", "runtime": "dependencies_sha256",
            "configuration": "configuration_sha256", "limits": "memory_bytes",
            "policy": "backend_policy_sha256",
        }[change]
        # These are new valid immutable captures, not a bypass of capture validation.
        if change == "snapshot":
            entry, = review.snapshot.entries
            snapshot = replace(review.snapshot, entries=(replace(entry, data=b"pass\n"),))
            changed = replace(review, snapshot=snapshot, plan=replace(
                review.plan, snapshot_sha256=snapshot.fingerprint(),
            ))
        elif change in {"runtime", "configuration"}:
            target = "usr/local/bin/python3.12" if change == "runtime" else "input/config.yaml"
            entries = tuple(replace(e, data=e.data + b"\n") if e.path == target else e
                            for e in review.runtime.tree.entries)
            runtime = replace(review.runtime, tree=replace(review.runtime.tree, entries=entries))
            manifest = runtime.manifest()
            changed = replace(review, runtime=runtime, plan=replace(
                review.plan, executable_sha256=manifest["executable"],
                interpreter_sha256=manifest["interpreter"],
                configuration_sha256=manifest["configuration"],
                dependencies_sha256=digest(manifest),
            ))
        else:
            changed = replace(review, plan=replace(review.plan, **{
                field: 123 if change == "limits" else digest(policy | {"network": "changed"}),
            }))
    if change == "no-cgroup":
        missing_parent = parent / "without-cpu"
        missing_parent.mkdir()
        (missing_parent / "cgroup.subtree_control").write_text("+memory +pids")
        for name in ("", "cgroup.procs", "cgroup.subtree_control"):
            os.chown(missing_parent / name, LAUNCHER, LAUNCHER)
        policy = policy | {"cgroup_parent": str(missing_parent)}
        review = replace(review, plan=replace(review.plan, backend_policy_sha256=digest(policy)))
        changed = review
    with ExitStack() as stack:
        if change == "no-cgroup":
            stack.callback(missing_parent.rmdir)
        meta, fds = seal_review(stack, review, policy)
        changed_policy = policy | {"network": "changed"} if change == "policy" else policy
        other_meta, other_fds = (
            (meta, fds) if changed is review else seal_review(stack, changed, changed_policy)
        )
        fault = "launcher-crash" if change == "launcher-crash" else "none"
        broker = launch(
            BROKER, "broker", meta, "drop-reply" if change == "lost-reply" else "none",
            pass_fds=fds, stdout=subprocess.PIPE,
        )
        operation, fingerprint = json.loads(read_ready(broker))
        launcher = launch(
            AGENT if change == "agent" else LAUNCHER, "launcher", other_meta, fault,
            pass_fds=other_fds, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        )
        assert read_ready(launcher) == b"CAPTURED\n"
        concurrent = None
        if change == "concurrent":
            concurrent = launch(
                LAUNCHER, "launcher", meta, "none", pass_fds=fds,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            )
            assert read_ready(concurrent) == b"CAPTURED\n"
        if change == "agent":
            attempt = launch(AGENT, "approve", operation)
            assert attempt.wait(timeout=5) != 0
        if change != "unapproved":
            approve(launch, operation, decision=change != "decline")
        if change in {"broker-crash", "broker-restart"}:
            broker.kill()
            broker.wait(timeout=5)
        if change == "broker-restart":
            (root / "state" / "owner.sock").unlink()
            (root / "state" / "private" / "approval.sqlite").rename(
                root / "state" / "private" / "previous.sqlite",
            )
            broker = launch(BROKER, "broker", meta, pass_fds=fds, stdout=subprocess.PIPE)
            new_operation, _ = json.loads(read_ready(broker))
            assert operation != new_operation
            approve(launch, new_operation)
        if concurrent is not None:
            for process in (launcher, concurrent):
                process.stdin.write((operation + "\n").encode())
                process.stdin.flush()
            output, _ = launcher.communicate(timeout=90)
            other, _ = concurrent.communicate(timeout=90)
            outcomes = [json.loads(output), json.loads(other)]
            assert sorted(r["status"] for r in outcomes) == [
                "APPROVAL_DENIED", "SCANNER_COMPLETED_CLEAN",
            ]
            assert sum(r["attempted"] for r in outcomes) == 1
            return
        output, _ = launcher.communicate((operation + "\n").encode(), timeout=90)
        if change in {"replay", "concurrent", "launcher-crash"}:
            # All retries go through the very same dispatch entry point.
            retry = launch(
                LAUNCHER, "launcher", meta, "none", pass_fds=fds,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            )
            assert read_ready(retry) == b"CAPTURED\n"
            retried, _ = retry.communicate((operation + "\n").encode(), timeout=30)
            assert json.loads(retried)["status"] == "APPROVAL_DENIED"
            if change == "launcher-crash":
                assert launcher.returncode == 70
                assert not Path(review.plan.output_directory).exists()
            else:
                assert json.loads(output)["authorization"] == "APPROVED_AND_EXECUTED"
        else:
            result = json.loads(output)
            assert result["status"] == (
                "SANDBOX_BLOCKED" if change == "no-cgroup" else "APPROVAL_DENIED"
            )
            assert not Path(review.plan.output_directory).exists()
            assert not (root / "output" / "attempt.started").exists()
            if change == "no-cgroup":
                assert result["reason"] == "BLOCKED: missing cgroup controllers: cpu"
            if change == "lost-reply":
                with sqlite3.connect(root / "state" / "private" / "approval.sqlite") as db:
                    assert db.execute("SELECT count(*) FROM redeemed_approval").fetchone() == (1,)
                retry = launch(
                    LAUNCHER, "launcher", meta, "none", pass_fds=fds,
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                )
                assert read_ready(retry) == b"CAPTURED\n"
                retried, _ = retry.communicate((operation + "\n").encode(), timeout=30)
                assert json.loads(retried)["status"] == "APPROVAL_DENIED"


@pytest.mark.parametrize("fault", [
    "timeout", "cancel", "report-size", "report-corrupt", "supervisor-kill",
])
def test_actual_scanner_failure_and_cleanup(combined, fault):
    from owner_bandit_handoff import BROKER, LAUNCHER, prepare_review, seal_review

    root, launch, tree, elf, rules, parent = combined
    review, policy = prepare_review(
        tree, elf, rules, root, parent, "clean",
        timeout=60,
        output_limit=1024 if fault == "report-size" else 65536,
    )
    with ExitStack() as stack:
        meta, fds = seal_review(stack, review, policy)
        broker = launch(BROKER, "broker", meta, pass_fds=fds, stdout=subprocess.PIPE)
        operation, _ = json.loads(read_ready(broker))
        launcher = launch(
            LAUNCHER, "launcher", meta, fault, pass_fds=fds,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        )
        assert read_ready(launcher) == b"CAPTURED\n"
        approve(launch, operation)
        if fault == "supervisor-kill":
            launcher.stdin.write((operation + "\n").encode())
            launcher.stdin.flush()
            marker = root / "output" / "analysis-started"
            deadline = time.monotonic() + 75
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            assert marker.exists(), "Actual Bandit did not enter analysis"
            groups = list(parent.glob("atl-probe-*"))
            assert len(groups) == 1
            members = (groups[0] / "cgroup.procs").read_text().split()
            assert members
            launcher.send_signal(signal.SIGKILL)
            launcher.wait(timeout=10)
            recovery = launch(LAUNCHER, "recover", parent, stdout=subprocess.PIPE)
            stdout, _ = recovery.communicate(timeout=15)
            assert recovery.returncode == 0
            assert json.loads(stdout) == [groups[0].name]
            assert all(not Path("/proc", pid).exists() for pid in members)
        else:
            stdout, _ = launcher.communicate((operation + "\n").encode(), timeout=90)
            result = json.loads(stdout)
            assert result["analysis_started"] is True
            expected = {
                "timeout": "deadline", "cancel": "cancelled", "report-size": "output limit",
                "report-corrupt": "validation",
            }[fault]
            assert expected in result["reason"]
            print(json.dumps({"fault": fault, "result": result}, sort_keys=True))
        assert not Path(review.plan.output_directory).exists()
        assert not list(parent.glob("atl-probe-*"))
        retry = launch(
            LAUNCHER, "launcher", meta, "none", pass_fds=fds,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        )
        assert read_ready(retry) == b"CAPTURED\n"
        stdout, _ = retry.communicate((operation + "\n").encode(), timeout=30)
        assert json.loads(stdout)["status"] == "APPROVAL_DENIED"
