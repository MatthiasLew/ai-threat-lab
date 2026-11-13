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


@pytest.mark.parametrize("scenario", ["stdlib", "imports", "clean", "finding", "bad-config"])
def test_pinned_cpython_projection_in_bubblewrap(linux_probe, delegated_parent, tmp_path, scenario):
    import resource

    from cpython_oci import elf_interpreter, load_projection
    from linux_probe_supervision import delegated_group, supervise_probe

    from ai_threat_lab.scanner_staging import sealed_scanner_file

    packages = scenario != "stdlib"
    scan = scenario in {"clean", "finding", "bad-config"}
    if scan and delegated_parent is None:
        pytest.skip("BLOCKED: real Bandit requires delegated CPU, memory and pids controllers")
    cache = os.environ.get("THREAT_LAB_CPYTHON_OCI")
    if not cache:
        pytest.skip("Pinned OCI blobs unavailable")
    command, _, canary, rules = linux_probe
    native = {} if packages else None
    tree = load_projection(Path(cache), native=native)
    interpreter = "usr/local/bin/python3.12"
    assert elf_interpreter(tree[interpreter]) == "/lib64/ld-linux-x86-64.so.2"
    loader = "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
    tree["lib64/ld-linux-x86-64.so.2"] = tree[loader]
    tree["usr/lib/x86_64-linux-gnu/libz.so.1"] = tree[
        "usr/lib/x86_64-linux-gnu/libz.so.1.2.13"
    ]
    if packages:
        from cpython_elf import close_elf_tree

        from ai_threat_lab.bandit_wheel_tree import materialize_bandit_packages

        wheels = os.environ.get("THREAT_LAB_REFERENCE_WHEELS")
        assert wheels, "Pinned wheel cache is required for the import probe"
        snapshot, _ = materialize_bandit_packages(Path(wheels))
        for entry in snapshot.entries:
            tree["packages/" + entry.path] = entry.data
        dependencies = close_elf_tree(tree, native)
        assert dependencies[interpreter]
        from cpython_elf import elf_needed

        from ai_threat_lab.models import ValidationError

        altered = bytearray(tree[interpreter])
        altered[7] = 255
        with pytest.raises(ValidationError, match="ABI"):
            elf_needed(bytes(altered))
        altered = tree[interpreter].replace(b"$ORIGIN/../lib", b"/untrusted/lib")
        assert altered != tree[interpreter]
        with pytest.raises(ValidationError, match="search path"):
            elf_needed(altered)
        missing = dict(tree)
        del missing["usr/lib/x86_64-linux-gnu/libc.so.6"]
        with pytest.raises(ValidationError, match="Missing pinned ELF dependency: libc"):
            close_elf_tree(missing, {})
    if scan:
        fixtures = Path(__file__).with_name("fixtures") / "bandit_e2e"
        source = fixtures / ("finding.py" if scenario == "finding" else "clean.py")
        tree["input/sample.py"] = source.read_bytes()
        tree["input/config.yaml"] = (
            b"tests: [" if scenario == "bad-config" else (fixtures / "config.yaml").read_bytes()
        )
    launch = command[:command.index("--ro-bind")]
    script = """
import json, sys, zlib, os, _socket
assert sys.version_info[:3] == (3, 12, 12)
assert sys.executable == '/usr/local/bin/python3.12'
assert sys.path == ['/usr/local/lib/python312.zip', '/usr/local/lib/python3.12',
                    '/usr/local/lib/python3.12/lib-dynload']
assert zlib.decompress(zlib.compress(b'probe')) == b'probe'
try:
    _socket.socket()
except PermissionError:
    pass
else:
    raise AssertionError('socket creation permitted')
for module in tuple(sys.modules.values()):
    path = getattr(module, '__file__', None)
    assert path is None or path.startswith('/usr/local/lib/python3.12/'), path
try:
    open(sys.argv[1], 'rb')
except FileNotFoundError:
    pass
else:
    raise AssertionError('host canary visible')
try:
    open('/usr/local/bin/python3.12', 'wb')
except OSError as error:
    assert error.errno in (13, 30), error
else:
    raise AssertionError('runtime writable')
with open('/scratch/probe', 'xb') as result:
    result.write(b'probe')
for fd in range(3, int(sys.argv[2])):
    try:
        os.fstat(fd)
    except OSError as error:
        assert error.errno == 9, error
    else:
        raise AssertionError('unexpected inherited descriptor')
print(json.dumps({'version': sys.version, 'paths': sys.path, 'zlib': zlib.__file__}))
"""
    if packages:
        script = script[:script.rindex("print(")] + """
import importlib.metadata
sys.path.append('/packages')
import bandit, yaml, yaml._yaml, stevedore, rich, sarif_om, jschema_to_python
from bandit.core import extension_loader
manager = extension_loader.MANAGER
assert importlib.metadata.version('bandit') == '1.7.8'
assert yaml.__with_libyaml__
plugins = sorted(manager.plugins_mgr.names())
assert 'assert_used' in plugins
assert 'sarif' in manager.formatters_mgr.names()
for extension in manager.plugins_mgr.extensions:
    assert extension.plugin.__module__.startswith('bandit.plugins.')
for path in ('/packages/bandit/__init__.py', '/usr/lib/x86_64-linux-gnu/libc.so.6'):
    try:
        open(path, 'wb')
    except OSError as error:
        assert error.errno in (13, 30), error
    else:
        raise AssertionError('staged file writable')
origins = {}
for name, module in tuple(sys.modules.items()):
    path = getattr(module, '__file__', None)
    if path is not None and name != '__main__':
        origins[name] = path
print(json.dumps({'version': sys.version, 'zlib': zlib.__file__, 'paths': sys.path,
                  'origins': origins, 'plugins': plugins,
                  'meta_path': [finder.__name__ for finder in sys.meta_path]}))
"""
    if scan:
        script = script[:script.rindex("print(")] + """
import ctypes, errno
from bandit.cli.main import main
from bandit.core.config import BanditConfig

# Linux amd64 statfs starts with a signed long filesystem magic.
libc = ctypes.CDLL(None, use_errno=True)
for mount in (b'/', b'/scratch'):
    info = (ctypes.c_long * 32)()
    assert libc.statfs(mount, ctypes.byref(info)) == 0, ctypes.get_errno()
    assert info[0] == 0x01021994, (mount, info[0])
assert os.statvfs('/').f_flag & os.ST_RDONLY
assert not os.statvfs('/scratch').f_flag & os.ST_RDONLY
assert os.statvfs('/scratch').f_blocks * os.statvfs('/scratch').f_frsize <= 1048576
for absent in ('/dev', '/proc', '/sys', '/home'):
    assert not os.path.exists(absent), absent
try:
    open('/input/sample.py', 'wb')
except OSError as error:
    assert error.errno in (errno.EROFS, errno.EACCES)
else:
    raise AssertionError('input writable')
os.chdir('/')
sys.argv = ['bandit', '-q', '-c', '/input/config.yaml', '-f', 'sarif',
            '-o', '/scratch/report.sarif', 'input/sample.py']
try:
    main()
except SystemExit as exit:
    code = exit.code
else:
    raise AssertionError('Bandit returned without an exit status')
path = '/scratch/report.sarif'
if code in (0, 1):
    assert BanditConfig('/input/config.yaml').get_option('tests') == ['B101']
    with open(path, 'rb') as stream:
        report = stream.read(32769)
    assert 0 < len(report) <= 32768
    print(json.dumps({'exit': code, 'report': report.decode('utf-8')}))
else:
    assert not os.path.exists(path) or os.stat(path).st_size == 0
    print(json.dumps({'exit': code, 'report': None}))
"""
    with ExitStack() as stack:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        required = len(tree) + 64
        if soft != resource.RLIM_INFINITY and soft < required:
            assert hard == resource.RLIM_INFINITY or hard >= required, "Host descriptor hard limit"
            resource.setrlimit(resource.RLIMIT_NOFILE, (required, hard))
            stack.callback(resource.setrlimit, resource.RLIMIT_NOFILE, (soft, hard))
        group = None
        if delegated_parent is not None:
            group = stack.enter_context(delegated_group(
                delegated_parent, memory=128 * 1024**2, tasks=8,
            ))
        descriptors = []
        for path, raw in sorted(tree.items()):
            fd = stack.enter_context(sealed_scanner_file(raw, sha256(raw).hexdigest()))
            descriptors.append(fd)
            executable_paths = {interpreter, loader, "lib64/ld-linux-x86-64.so.2"}
            mode = "0555" if path in executable_paths else "0444"
            if mode == "0555":
                launch.extend(("--perms", mode, "--ro-bind-data", str(fd), "/" + path))
            else:
                launch.extend(("--file", str(fd), "/" + path))
        launch.extend((
            "--size", "1048576", "--tmpfs", "/scratch", "--remount-ro", "/",
            "--chdir", "/scratch", "--seccomp", "0", "--setenv", "LD_LIBRARY_PATH",
            "/usr/local/lib:/usr/lib/x86_64-linux-gnu", "--", "/usr/local/bin/python3.12",
            "-I", "-S", "-B", "-c", script, str(canary), str(max(descriptors) + 1),
        ))
        with rules.open("rb") as stream:
            raw = supervise_probe(
                launch, filter_fd=stream.fileno(), descriptors=tuple(descriptors),
                timeout=30, output_limit=65536, group=group,
            )
    import json

    result = json.loads(raw)
    if scan:
        from ai_threat_lab.models import ValidationError
        from ai_threat_lab.scanner_report import save_bandit_report

        output = tmp_path / "published.json"
        if scenario == "bad-config":
            assert result == {"exit": 2, "report": None}
            assert not output.exists()
            return
        assert result["exit"] == (1 if scenario == "finding" else 0)
        source = tmp_path / "actual.sarif"
        source.write_text(result["report"], encoding="utf-8")
        sarif = json.loads(result["report"])
        run, = sarif["runs"]
        assert set(run["properties"]["metrics"]) == {"_totals", "./input/sample.py"}
        assert not run["invocations"][0].get("toolConfigurationNotifications")
        report = save_bandit_report(source, output)
        assert report["runs"][0]["producer_version"] == "1.7.8"
        assert report["runs"][0]["producer_succeeded"] is True
        findings = report["observations"]
        if scenario == "finding":
            finding, = findings
            assert finding["rule_id"] == "B101"
            assert (finding["severity"], finding["confidence"]) == ("LOW", "HIGH")
            location, = finding["locations"]
            assert location["line"] == 3
            assert location["label"].removeprefix("./") == "input/sample.py"
        else:
            assert findings == []
        original = output.read_bytes()
        with pytest.raises(ValidationError):
            save_bandit_report(source, output)
        assert output.read_bytes() == original
        return
    assert result["version"].startswith("3.12.12 ")
    assert result["zlib"].startswith("/usr/local/lib/python3.12/lib-dynload/")
    if packages:
        assert result["meta_path"] == ["BuiltinImporter", "FrozenImporter", "PathFinder"]
        assert all(path.removeprefix("/") in tree for path in result["origins"].values())
        assert result["origins"]["bandit"] == "/packages/bandit/__init__.py"
        print(json.dumps({"imports": result, "elf_needed": dependencies}, sort_keys=True))


@pytest.fixture
def delegated_parent():
    configured = os.environ.get("THREAT_LAB_DELEGATED_CGROUP")
    if not configured and os.environ.get("THREAT_LAB_REQUIRE_CGROUP") == "1":
        pytest.fail("BLOCKED: THREAT_LAB_DELEGATED_CGROUP is required")
    return Path(configured) if configured else None


def test_linux_approved_sealed_handoff(linux_probe, tmp_path, delegated_parent):
    from linux_probe_supervision import delegated_group, publish_probe_report, supervise_probe

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
        5, 64 * 1024**2, 8, 1024**2, 4096, "linux", "bubblewrap", digest(policy),
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
        with ExitStack() as stack:
            group = None
            if delegated_parent is not None:
                registry = tmp_path / "registry"
                registry.mkdir(mode=0o700)
                group = stack.enter_context(delegated_group(
                    delegated_parent, memory=plan.memory_bytes, tasks=plan.max_processes,
                    registry=registry,
                ))
            result = supervise_probe(
                launch, filter_fd=filter_fd, descriptors=(executable, input_fd),
                timeout=plan.timeout_seconds, output_limit=plan.max_output_bytes, group=group,
            )
    publish_probe_report(result, tmp_path / "synthetic.sarif", output)
    assert output.is_file()
    assert input_path.read_bytes() == b"substituted"


@pytest.mark.parametrize("mode,reason", [
    ("wait", "deadline"), ("cancel", "cancelled"), ("stdout", "output limit"),
    ("stderr", "output limit"), ("missing", "no report"), ("error", "status 42"),
    ("setup", "exited"),
])
def test_linux_supervision_refusals(linux_probe, delegated_parent, mode, reason):
    from linux_probe_supervision import ProbeFailure, delegated_group, supervise_probe

    command, _, _, rules = linux_probe
    launch = [*command, "wait" if mode == "cancel" else mode]
    if mode == "setup":
        launch[1:1] = ["--invalid-probe-option"]
    with ExitStack() as stack:
        group = None
        if delegated_parent is not None:
            group = stack.enter_context(delegated_group(
                delegated_parent, memory=64 * 1024**2, tasks=8,
            ))
        stream = stack.enter_context(rules.open("rb"))
        cancelled_at = time.monotonic() + 0.2
        with pytest.raises(ProbeFailure, match=reason):
            supervise_probe(
                launch, filter_fd=stream.fileno(), descriptors=(), output_limit=1024,
                timeout=0.5 if mode == "wait" else 5, group=group,
                cancelled=lambda: mode == "cancel" and time.monotonic() >= cancelled_at,
            )
    assert group is None or not group.exists()


def test_linux_rejects_non_cgroup_parent(linux_probe, tmp_path):
    from linux_probe_supervision import ProbeFailure, delegated_group

    with pytest.raises(ProbeFailure, match="cgroup v2 mount"):
        with delegated_group(tmp_path, memory=64 * 1024**2, tasks=8):
            pytest.fail("a regular directory was accepted as a cgroup")
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("mode", ["malformed", "incomplete", "existing", "write-error"])
def test_probe_report_refusals(tmp_path, monkeypatch, mode):
    from linux_probe_supervision import ProbeFailure, publish_probe_report

    from ai_threat_lab.models import ValidationError

    source, output = tmp_path / "scratch.sarif", tmp_path / "published.json"
    raw = (
        b'{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"M4.4 synthetic probe"}},'
        b'"invocations":[{"executionSuccessful":true}],"results":[]}]}'
    )
    if mode == "malformed":
        raw = raw[:-4]
    if mode == "incomplete":
        raw = raw.replace(b"true", b"false")
    if mode == "existing":
        output.write_bytes(b"original")
    if mode == "write-error":
        def denied(*args, **kwargs):
            raise OSError("injected publication failure")

        monkeypatch.setattr("ai_threat_lab.local_history.write_new_report", denied)
    with pytest.raises((ValidationError, ProbeFailure, OSError)):
        publish_probe_report(raw, source, output)
    assert not source.exists()
    if mode == "existing":
        assert output.read_bytes() == b"original"
    else:
        assert not output.exists()


def test_linux_delegated_group_limits(linux_probe, delegated_parent):
    from linux_probe_supervision import ProbeFailure, delegated_group, supervise_probe

    if delegated_parent is None:
        pytest.skip("BLOCKED: no explicitly delegated cgroup parent")
    command, _, _, rules = linux_probe
    for mode, event, counter in (
        ("tasks", "pids.events", "max"), ("aggregate", "memory.events", "oom_kill"),
        ("cpu", "cpu.stat", "nr_throttled"),
    ):
        with delegated_group(delegated_parent, memory=64 * 1024**2, tasks=8) as group:
            with rules.open("rb") as stream:
                options = dict(
                    filter_fd=stream.fileno(), descriptors=(), output_limit=1024,
                    timeout=8, group=group,
                )
                if mode == "tasks":
                    assert supervise_probe([*command, mode], **options) == b"limited"
                elif mode == "cpu":
                    assert (group / "cpu.max").read_text().strip() == "20000 100000"
                    assert supervise_probe([*command, mode], **options) == b"cpu"
                else:
                    with pytest.raises(ProbeFailure, match="exited"):
                        supervise_probe([*command, mode], **options)
            counters = dict(row.split() for row in (group / event).read_text().splitlines())
            assert int(counters[counter]) > 0
        assert not group.exists()


@pytest.mark.parametrize("termination", ["terminate", "kill"])
def test_linux_recovers_recorded_group(linux_probe, delegated_parent, tmp_path, termination):
    from linux_probe_supervision import recover_groups

    if delegated_parent is None:
        pytest.skip("BLOCKED: no explicitly delegated cgroup parent")
    registry = tmp_path / "registry"
    registry.mkdir(mode=0o700)
    helper = """
import subprocess, sys, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from linux_probe_supervision import delegated_group
with delegated_group(Path(sys.argv[2]), memory=67108864, tasks=8,
                     registry=Path(sys.argv[3])) as group:
    # A trusted synthetic sleeper stands in for work surviving the supervisor.
    with subprocess.Popen(
        [sys.executable, "-I", "-c", "import sys,time; sys.stdin.read(1); time.sleep(30)"],
        stdin=subprocess.PIPE,
    ) as child:
        (group / "cgroup.procs").write_text(str(child.pid))
        child.stdin.write(b"G")
        child.stdin.flush()
        print(group.name, flush=True)
        time.sleep(30)
"""
    with subprocess.Popen(
        [sys.executable, "-I", "-c", helper, str(Path(__file__).parent),
         str(delegated_parent), str(registry)], stdout=subprocess.PIPE,
    ) as process:
        try:
            assert select.select([process.stdout], [], [], 5)[0]
            name = process.stdout.readline().decode("ascii").strip()
            assert name.startswith("atl-probe-")
            assert "populated 1" in (delegated_parent / name / "cgroup.events").read_text()
            assert recover_groups(delegated_parent, registry) == []
            getattr(process, termination)()
            process.wait(timeout=5)
            assert recover_groups(delegated_parent, registry) == [name]
            assert recover_groups(delegated_parent, registry) == []
            assert not (delegated_parent / name).exists()
        finally:
            if process.poll() is None:
                process.kill()


@pytest.mark.parametrize("mismatch", ["group", "boot", "owner"])
def test_linux_recovery_refuses_wrong_identity(linux_probe, delegated_parent, tmp_path, mismatch):
    import json

    from linux_probe_supervision import _boot_id, delegated_group, recover_groups

    if delegated_parent is None:
        pytest.skip("BLOCKED: no explicitly delegated cgroup parent")
    tmp_path.chmod(0o700)
    with delegated_group(delegated_parent, memory=64 * 1024**2, tasks=8) as group:
        parent = delegated_parent.stat()
        info = group.stat()
        identity = {
            "owner": os.getuid(), "boot": _boot_id(),
            "parent": [parent.st_dev, parent.st_ino], "group": [info.st_dev, info.st_ino],
        }
        identity[mismatch] = {"group": [0, 0], "boot": "previous-boot", "owner": -1}[mismatch]
        (tmp_path / group.name).write_text(json.dumps(identity))
        (tmp_path / "invalid-name").write_text("{}")
        assert recover_groups(delegated_parent, tmp_path) == []
        assert group.exists()


@pytest.mark.parametrize("phase", ["intent", "mkdir", "registered", "configured"])
@pytest.mark.parametrize("signal_number", [15, 9], ids=["term", "kill"])
def test_linux_recovery_creation_checkpoints(linux_probe, delegated_parent, tmp_path,
                                              phase, signal_number):
    from concurrent.futures import ThreadPoolExecutor

    from linux_probe_supervision import recover_groups

    if delegated_parent is None:
        pytest.skip("BLOCKED: no explicitly delegated cgroup parent")
    tmp_path.chmod(0o700)
    helper = """
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from linux_probe_supervision import delegated_group
def checkpoint(phase):
    if phase == sys.argv[4]:
        os.kill(os.getpid(), int(sys.argv[5]))
with delegated_group(Path(sys.argv[2]), memory=67108864, tasks=8,
                     registry=Path(sys.argv[3]), checkpoint=checkpoint):
    raise AssertionError('checkpoint did not terminate supervisor')
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", helper, str(Path(__file__).parent),
         str(delegated_parent), str(tmp_path), phase, str(signal_number)],
        timeout=10, check=False,
    )
    assert result.returncode == -signal_number
    record, = tmp_path.iterdir()
    group = delegated_parent / record.name
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            attempts = [pool.submit(recover_groups, delegated_parent, tmp_path) for _ in range(2)]
            outcomes = [attempt.result() for attempt in attempts]
        if phase == "mkdir":
            assert outcomes == [[], []]
            assert group.is_dir() and record.is_file()
            assert "populated 0" in (group / "cgroup.events").read_text().splitlines()
        else:
            assert sorted(name for names in outcomes for name in names) == (
                [] if phase == "intent" else [group.name]
            )
            assert not group.exists() and not record.exists()
    finally:
        if phase == "mkdir":
            group.rmdir()


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


def test_delegated_block_io(delegated_parent):
    """Use only an explicitly provisioned, disposable block-backed filesystem."""
    import tempfile

    from linux_probe_supervision import delegated_group, supervise_probe

    directory = os.environ.get("THREAT_LAB_IO_SCRATCH")
    device = os.environ.get("THREAT_LAB_IO_DEVICE")
    if sys.platform != "linux" or not delegated_parent or not directory or not device:
        pytest.skip("BLOCKED: dedicated block filesystem and delegated io controller required")
    root = Path(directory).resolve(strict=True)
    dev = root.stat().st_dev
    assert device == f"{os.major(dev)}:{os.minor(dev)}"
    assert Path(f"/sys/dev/block/{device}").exists(), "Scratch must be block-backed"
    assert "io" in (delegated_parent / "cgroup.subtree_control").read_text().split()
    script = """
import subprocess, sys
path, direction = sys.argv[1:]
args = ['if=/dev/zero', 'of=' + path, 'oflag=direct'] if direction == 'write' else [
    'if=' + path, 'of=/dev/null', 'iflag=direct',
]
subprocess.run(['/usr/bin/dd', *args, 'bs=1M', 'count=4', 'status=none'], check=True)
print('done')
"""
    with tempfile.TemporaryDirectory(prefix="atl-io-", dir=root) as directory:
        path = Path(directory) / "data"
        for direction, field in (("write", "wbytes"), ("read", "rbytes")):
            elapsed = []
            for limited in (False, True):
                with delegated_group(
                    delegated_parent, memory=64 * 1024**2, tasks=8,
                    io_device=device if limited else None,
                ) as group, open(os.devnull, "rb") as stdin:
                    start = time.monotonic()
                    assert supervise_probe(
                        [sys.executable, "-I", "-S", "-c", script, str(path), direction],
                        filter_fd=stdin.fileno(), descriptors=(), timeout=20,
                        output_limit=1024, group=group,
                    ) == b"done\n"
                    elapsed.append(time.monotonic() - start)
                    counters = next(
                        row.split()[1:] for row in (group / "io.stat").read_text().splitlines()
                        if row.split()[0] == device
                    )
                    assert int(dict(item.split("=") for item in counters)[field]) >= 4 * 1024**2
            assert elapsed[1] >= 3 and elapsed[1] >= elapsed[0] + 1
