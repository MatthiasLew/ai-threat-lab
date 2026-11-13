"""Sandbox diagnostics and inert, OS-backed Linux acceptance tests."""

import ctypes
import errno
import os
import select
import socket
import subprocess
import sys
import time
from contextlib import ExitStack
from dataclasses import fields, replace
from hashlib import sha256
from pathlib import Path

import pytest

from ai_threat_lab import agent_resources
from ai_threat_lab.report_io import read_regular
from ai_threat_lab.scanner_sandbox import (
    ScannerExecutionPlan,
    sandbox_diagnostic,
    system_bubblewrap,
)


def test_native_diagnostics_do_not_claim_validation():
    diagnostic = sandbox_diagnostic()
    assert diagnostic.platform == sys.platform
    assert diagnostic.validation == "not_validated"
    assert diagnostic.execution == "blocked"
    assert diagnostic.verified_controls == ()
    if sys.platform == "win32":
        assert diagnostic.backend == "appcontainer"
        assert dict(diagnostic.prerequisites) == {
            "appcontainer_profile_api": True, "job_object_api": True,
        }
    if sys.platform == "linux":
        assert diagnostic.backend == "bubblewrap"
        assert dict(diagnostic.prerequisites)["system_bubblewrap_candidate"] == (
            system_bubblewrap() is not None
        )


@pytest.fixture
def execution_plan(tmp_path):
    digest = "0" * 64
    return ScannerExecutionPlan(
        scanner="bandit", target=str(tmp_path / "zażółć project"), snapshot_sha256=digest,
        executable_sha256=digest, interpreter_sha256=digest, dependencies_sha256=digest,
        configuration_sha256=digest, output_directory=str(tmp_path / "out"), timeout_seconds=10,
        memory_bytes=64 * 1024**2, max_processes=4, scratch_bytes=1024**2, max_output_bytes=4096,
        platform="linux", backend="bubblewrap", backend_policy_sha256=digest,
    )


def test_fingerprint_changes_with_each_approval_field(execution_plan):
    plan = execution_plan
    assert len(plan.fingerprint()) == 64
    assert plan.fingerprint() == replace(plan).fingerprint()
    for field in fields(plan):
        current = getattr(plan, field.name)
        changed = current + 1 if isinstance(current, int) else current + "1"
        modified = replace(plan, **{field.name: changed})
        assert modified.fingerprint() != plan.fingerprint(), field.name


@pytest.mark.parametrize(
    "field", ["executable_sha256", "interpreter_sha256", "dependencies_sha256"],
)
def test_review_fingerprint_detects_reread_after_file_replacement(tmp_path, execution_plan, field):
    artifact = tmp_path / field
    replacement = tmp_path / "replacement"
    artifact.write_bytes(b"original fixture")
    replacement.write_bytes(b"modified fixture")

    def read_plan():
        raw = read_regular(artifact, 1024)
        return replace(execution_plan, **{field: sha256(raw).hexdigest()})

    approved = read_plan().fingerprint()
    replacement.replace(artifact)
    assert read_plan().fingerprint() != approved


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Object")
def test_windows_trusted_worker_job_rejects_child_and_closes_on_supervisor_death(tmp_path):
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32.dll", winmode=0x800, use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    marker = tmp_path / "trusted-worker"
    worker_code = """
import os, subprocess, sys, time
from pathlib import Path
assert sys.stdin.buffer.read() == b'go'
try:
    subprocess.run([sys.executable, '-I', '-c', 'pass'], check=True, timeout=5)
except OSError as error:
    assert error.winerror in (5, 1816)  # access denied or quota exceeded
else:
    raise AssertionError('The job allowed an extra process')
marker = Path(sys.argv[1])
staged = marker.with_suffix('.staged')
staged.write_text(str(os.getpid()), encoding='ascii')
staged.replace(marker)
time.sleep(30)
"""
    supervisor_code = """
import subprocess, sys
sys.path.insert(0, sys.argv[1])
from ai_threat_lab.agent_resources import supervise_windows
with subprocess.Popen(
    [sys.executable, '-I', '-c', sys.argv[2], sys.argv[3]], stdin=subprocess.PIPE,
) as worker, supervise_windows(worker):
    worker.stdin.write(b'go')
    worker.stdin.close()
    raise SystemExit(worker.wait(timeout=20))
"""
    with subprocess.Popen([
        sys._base_executable, "-I", "-c", supervisor_code,
        str(Path(agent_resources.__file__).resolve().parents[1]), worker_code, str(marker),
    ]) as supervisor:
        try:
            deadline = time.monotonic() + 10
            while not marker.is_file() and supervisor.poll() is None:
                assert time.monotonic() < deadline, "Trusted worker did not reach readiness"
                time.sleep(0.05)
            assert marker.is_file(), f"Supervisor exited early: {supervisor.poll()}"
            handle = kernel.OpenProcess(0x00100000, False, int(marker.read_text(encoding="ascii")))
            assert handle
            try:
                assert kernel.WaitForSingleObject(handle, 0) == 258  # WAIT_TIMEOUT
                supervisor.kill()
                supervisor.wait(timeout=5)
                assert kernel.WaitForSingleObject(handle, 5000) == 0  # WAIT_OBJECT_0
            finally:
                kernel.CloseHandle(handle)
        finally:
            if supervisor.poll() is None:
                supervisor.kill()


def _write_network_filter(destination, seccomp):
    seccomp.seccomp_init.argtypes = (ctypes.c_uint32,)
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = (ctypes.c_char_p,)
    seccomp.seccomp_rule_add.argtypes = (
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint,
    )
    seccomp.seccomp_export_bpf.argtypes = (ctypes.c_void_p, ctypes.c_int)
    seccomp.seccomp_release.argtypes = (ctypes.c_void_p,)
    context = seccomp.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
    assert context
    try:
        for name in (b"socket", b"socketpair", b"io_uring_setup"):
            syscall = seccomp.seccomp_syscall_resolve_name(name)
            assert syscall >= 0
            assert seccomp.seccomp_rule_add(context, 0x00050000 | errno.EPERM, syscall, 0) == 0
        with destination.open("wb") as stream:
            assert seccomp.seccomp_export_bpf(context, stream.fileno()) == 0
    finally:
        seccomp.seccomp_release(context)


@pytest.fixture(scope="module")
def linux_probe(tmp_path_factory):
    if sys.platform != "linux":
        pytest.skip("Bubblewrap is Linux-only")

    def unavailable(reason):
        if os.environ.get("THREAT_LAB_REQUIRE_BWRAP_PROBE") == "1":
            pytest.fail(reason)
        pytest.skip(reason)

    launcher = system_bubblewrap()
    if launcher is None:
        unavailable("No system Bubblewrap candidate")
    if os.geteuid() == 0:
        unavailable("The probe requires an ordinary user")
    compiler = Path("/usr/bin/gcc")
    if not compiler.is_file():
        unavailable("The probe requires system GCC and static libc headers")
    try:
        seccomp = ctypes.CDLL("libseccomp.so.2")
    except OSError:
        unavailable("The probe requires system libseccomp")

    root = tmp_path_factory.mktemp("bubblewrap")
    fixture = Path(__file__).with_name("fixtures") / "sandbox_probe.c"
    executable = root / "probe"
    subprocess.run(
        [compiler, "-static", "-Wall", "-Wextra", "-Werror", fixture, "-o", executable],
        check=True, timeout=30, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    target = root / "zażółć project"
    target.mkdir()
    (target / "zażółć input").write_bytes(b"x")
    canary = root / "private"
    canary.write_bytes(b"private synthetic fixture")
    (target / "outside").symlink_to(canary)
    network_filter = root / "network.bpf"
    _write_network_filter(network_filter, seccomp)
    command = [
        str(launcher), "--unshare-user", "--disable-userns", "--unshare-net", "--unshare-pid",
        "--unshare-ipc", "--unshare-uts", "--cap-drop", "ALL", "--new-session",
        "--die-with-parent", "--clearenv", "--setenv", "TMPDIR", "/scratch",
        "--ro-bind", str(executable), "/probe", "--ro-bind", str(target), "/input",
        "--size", str(1024**2), "--tmpfs", "/scratch", "--remount-ro", "/",
        "--chdir", "/scratch", "--seccomp", "0", "--", "/probe",
    ]
    with network_filter.open("rb") as rules:
        ready = subprocess.run(
            [*command, "ready"], stdin=rules, capture_output=True, timeout=10, env={},
        )
    if ready.returncode:
        error = ready.stderr[:512].decode(errors="replace")
        if "Operation not permitted" in error or "No permissions to create" in error:
            unavailable(f"Bubblewrap setup rejected: {error}")
        pytest.fail(f"Bubblewrap probe configuration failed: {error}")
    return command, target, canary, network_filter


def test_linux_probe_denies_filesystem_network_and_inheritance(linux_probe):
    import fcntl

    command, target, canary, network_filter = linux_probe
    with ExitStack() as stack:
        endpoints = []
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
                server = stack.enter_context(socket.socket(family, kind))
                server.bind((host, 0))
                server.settimeout(3)
                endpoints.append(server)
                with socket.socket(family, kind) as client:
                    client.settimeout(3)
                    if kind == socket.SOCK_STREAM:
                        server.listen()
                        client.connect(server.getsockname())
                        connection, _ = server.accept()
                        connection.close()
                    else:
                        client.sendto(b"host control", server.getsockname())
                        assert server.recv(32) == b"host control"
        source = stack.enter_context(canary.open("rb+"))
        descriptor = fcntl.fcntl(source, fcntl.F_DUPFD, 100)
        stack.callback(os.close, descriptor)
        os.set_inheritable(descriptor, True)
        ports = [str(server.getsockname()[1]) for server in endpoints]
        rules = stack.enter_context(network_filter.open("rb"))
        subprocess.run(
            [*command, "boundaries", str(canary), str(descriptor), *ports],
            stdin=rules, capture_output=True, check=True, timeout=10,
            close_fds=True, env={"THREAT_LAB_PROBE_SECRET": "synthetic"},
        )
        assert not select.select(endpoints, [], [], 0)[0]
    assert (target / "zażółć input").read_bytes() == b"x"
    assert canary.read_bytes() == b"private synthetic fixture"


def test_linux_probe_per_process_memory_limit(linux_probe):
    command, _, _, network_filter = linux_probe
    with network_filter.open("rb") as rules:
        subprocess.run([*command, "memory"], stdin=rules, check=True, timeout=10, env={})


def test_linux_approved_sealed_handoff(linux_probe, tmp_path):
    from ai_threat_lab.local_history import write_new_report
    from ai_threat_lab.sarif_review import import_sarif
    from ai_threat_lab.scan_bundle import encoded
    from ai_threat_lab.scanner_approval import (
        ScannerReview,
        ScannerReviewBroker,
        issue_owner_approval,
    )
    from ai_threat_lab.scanner_objects import ScannerRuntime, capture_scanner_tree, digest
    from ai_threat_lab.scanner_staging import sealed_scanner_file

    command, _, _, rules = linux_probe
    source = tmp_path / "source"
    source.mkdir()
    input_path = source / "zażółć input"
    input_path.write_bytes(b"x")
    snapshot = capture_scanner_tree(source)
    runtime_path = tmp_path / "runtime"
    runtime_path.mkdir()
    # Copy only the fixed binary that the existing fixture compiled from repository source.
    (runtime_path / "probe").write_bytes(Path(command[command.index("--ro-bind") + 1]).read_bytes())
    (runtime_path / "interpreter-placeholder").touch()
    (runtime_path / "policy.bpf").write_bytes(rules.read_bytes())
    runtime = ScannerRuntime(
        capture_scanner_tree(runtime_path), "probe", "interpreter-placeholder", "policy.bpf",
        (), (), ("handoff",), (),
    )
    manifest = runtime.manifest()
    output = tmp_path / "published.json"
    policy = [*command[:command.index("--ro-bind")], "--ro-bind-data", "fixed descriptors"]
    plan = ScannerExecutionPlan(
        "synthetic-probe", snapshot.root, snapshot.fingerprint(), manifest["executable"],
        manifest["interpreter"], digest(manifest), manifest["configuration"], str(output),
        5, 64 * 1024**2, 1, 1024**2, 4096, "linux", "bubblewrap", digest(policy),
    )
    review = ScannerReview(plan, snapshot, runtime)
    key = os.urandom(32)
    broker = ScannerReviewBroker(tmp_path / "owner.sqlite", owner_key=key)
    approval = issue_owner_approval(
        review, owner_key=key, ledger_id=broker.ledger_id,
        confirmed_fingerprint=review.fingerprint(),
    )
    input_path.write_bytes(b"substituted")
    assert broker.redeem(review, approval) == plan.fingerprint()
    entries = {entry.path: entry.data for entry in runtime.tree.entries}
    with (
        sealed_scanner_file(entries["probe"], plan.executable_sha256) as executable,
        sealed_scanner_file(entries["policy.bpf"], plan.configuration_sha256) as filter_fd,
        sealed_scanner_file(
            snapshot.entries[0].data, snapshot.manifest()["entries"][0]["sha256"],
        ) as input_fd,
    ):
        launch = [
            *policy[:-2], "--perms", "0555", "--ro-bind-data", str(executable), "/probe",
            "--ro-bind-data", str(input_fd), "/input/zażółć input",
            "--size", str(plan.scratch_bytes), "--tmpfs", "/scratch", "--remount-ro", "/",
            "--chdir", "/scratch", "--seccomp", "0", "--", "/probe", *runtime.arguments,
        ]
        with subprocess.Popen(
            launch, stdin=filter_fd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={}, pass_fds=(executable, input_fd),
        ) as process:
            try:
                deadline = time.monotonic() + plan.timeout_seconds
                result = bytearray()
                while len(result) <= plan.max_output_bytes:
                    remaining = max(0, deadline - time.monotonic())
                    assert select.select([process.stdout], [], [], remaining)[0], "probe timed out"
                    allowance = plan.max_output_bytes + 1 - len(result)
                    chunk = os.read(process.stdout.fileno(), allowance)
                    if not chunk:
                        break
                    result.extend(chunk)
                assert len(result) <= plan.max_output_bytes
                assert process.wait(timeout=max(0, deadline - time.monotonic())) == 0
            finally:
                if process.poll() is None:
                    process.kill()
    source_report = tmp_path / "synthetic.sarif"
    source_report.write_bytes(result)
    report, failures = import_sarif(source_report)
    assert failures == 0
    assert report["runs"][0]["producer"] == "M4.4 synthetic probe"
    assert report["runs"][0]["producer_succeeded"] is True
    write_new_report(output, encoded(report))
    assert output.is_file()
    assert input_path.read_bytes() == b"substituted"


def test_linux_probe_scratch_is_bounded_and_fresh(linux_probe):
    command, _, _, network_filter = linux_probe
    for _ in range(2):
        with network_filter.open("rb") as rules:
            subprocess.run([*command, "scratch"], stdin=rules, check=True, timeout=10, env={})


@pytest.mark.parametrize("kill_supervisor", [False, True])
def test_linux_probe_stops_descendants(linux_probe, kill_supervisor):
    command, _, _, network_filter = linux_probe
    launch = [*command, "wait"]
    if kill_supervisor:
        launch = [
            sys.executable, "-I", "-c",
            "import subprocess,sys; subprocess.run(sys.argv[1:], env={}, check=True)",
            *launch,
        ]
    with network_filter.open("rb") as rules, subprocess.Popen(
        launch, stdin=rules, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={}, bufsize=0,
    ) as process:
        try:
            assert select.select([process.stdout], [], [], 5)[0]
            assert process.stdout.read(1) == b"R"
            if not kill_supervisor:
                with pytest.raises(subprocess.TimeoutExpired):
                    process.wait(timeout=0.1)
            process.kill()
            remaining, _ = process.communicate(timeout=5)
            assert remaining == b""
        finally:
            if process.poll() is None:
                process.kill()
