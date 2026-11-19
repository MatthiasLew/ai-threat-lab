"""Test-only immutable capture shared by the existing owner broker and launcher."""

import fcntl
import json
import os
import resource
import signal
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path

from cpython_elf import close_elf_tree
from cpython_oci import load_projection
from linux_probe_supervision import delegated_group, supervise_probe
from pinned_cpython_payload import pinned_script

from ai_threat_lab.bandit_runtime_review import bandit_reference_lock
from ai_threat_lab.bandit_wheel_tree import materialize_bandit_packages
from ai_threat_lab.models import ValidationError
from ai_threat_lab.scan_bundle import encoded
from ai_threat_lab.scanner_approval import ScannerReview
from ai_threat_lab.scanner_objects import CapturedEntry, ScannerRuntime, ScannerSnapshot, digest
from ai_threat_lab.scanner_owner_ipc import owner_ipc_request
from ai_threat_lab.scanner_report import save_bandit_report
from ai_threat_lab.scanner_sandbox import ScannerExecutionPlan, system_bubblewrap
from ai_threat_lab.scanner_staging import MAX_STAGED_FILE, sealed_scanner_file

BROKER, OWNER, LAUNCHER, AGENT = 62001, 62002, 62003, 62004
INTERPRETER = "usr/local/bin/python3.12"
LOADER = "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
EXECUTABLES = {INTERPRETER, LOADER, "lib64/ld-linux-x86-64.so.2"}


def pinned_tree(oci, wheels):
    native = {}
    tree = load_projection(oci, native=native)
    tree["lib64/ld-linux-x86-64.so.2"] = tree[LOADER]
    tree["usr/lib/x86_64-linux-gnu/libz.so.1"] = tree[
        "usr/lib/x86_64-linux-gnu/libz.so.1.2.13"
    ]
    packages, _ = materialize_bandit_packages(wheels)
    tree.update(("packages/" + entry.path, entry.data) for entry in packages.entries)
    return tree, close_elf_tree(tree, native)


def prepare_review(tree, elf, rules, root, parent, scenario, *, timeout=60, output_limit=65536):
    fixtures = Path(__file__).with_name("fixtures") / "bandit_e2e"
    source = fixtures / ("finding.py" if scenario == "finding" else "clean.py")
    mutable_source = root / "source.py"
    mutable_source.write_bytes(source.read_bytes())
    snapshot = ScannerSnapshot("/input", (CapturedEntry(
        "sample.py", "file", 0o444, mutable_source.read_bytes(),
    ),))
    files = dict(tree)
    mutable_interpreter = root / "interpreter-source"
    mutable_interpreter.write_bytes(files[INTERPRETER])
    files[INTERPRETER] = mutable_interpreter.read_bytes()
    files["input/config.yaml"] = (
        b"tests: [" if scenario == "bad-config" else (fixtures / "config.yaml").read_bytes()
    )
    files["probe.py"] = pinned_script(True, True).encode()
    if scenario == "bad-format":
        files["probe.py"] = files["probe.py"].replace(b"'-f', 'sarif'", b"'-f', 'absent'")
    files["seccomp.bpf"] = rules
    entries = tuple(CapturedEntry(path, "file", 0o444, raw) for path, raw in sorted(files.items()))
    libraries = tuple(path for path, raw in sorted(files.items()) if raw[:4] == b"\x7fELF"
                      and path != INTERPRETER)
    others = tuple(path for path in sorted(files) if path not in {
        "probe.py", INTERPRETER, "input/config.yaml", *libraries,
    })
    runtime = ScannerRuntime(
        ScannerSnapshot("/", entries), "probe.py", INTERPRETER, "input/config.yaml",
        others, libraries, ("-I", "-S", "-B", "-c"),
        ("private tmpfs only",),
    )
    prefix = [
        str(system_bubblewrap()), "--unshare-user", "--disable-userns", "--unshare-net",
        "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--cap-drop", "ALL",
        "--new-session", "--die-with-parent", "--clearenv", "--setenv", "TMPDIR", "/scratch",
    ]
    policy = {
        "prefix": prefix, "root": "readonly tmpfs", "scratch": "private tmpfs",
        "seccomp": sha256(rules).hexdigest(), "cpu_max": "20000 100000",
        "memory_swap_max": 0, "cgroup_parent": str(parent), "io_max": "BLOCKED",
        "block_io": "tmpfs-only test exception; no writable persistent mounts",
        "publication": "exclusive complete Bandit 1.7.8 SARIF",
        "wheel_manifest": bandit_reference_lock(), "elf": elf,
        "canary": str(root / "host-canary"),
        "bubblewrap_sha256": sha256(Path(prefix[0]).read_bytes()).hexdigest(),
    }
    manifest = runtime.manifest()
    plan = ScannerExecutionPlan(
        "bandit", snapshot.root, snapshot.fingerprint(), manifest["executable"],
        manifest["interpreter"], digest(manifest), manifest["configuration"],
        str(root / "output" / "published.json"), timeout, 128 * 1024**2, 8,
        1024**2, output_limit, "linux", "bubblewrap", digest(policy),
    )
    return ScannerReview(plan, snapshot, runtime), policy


def seal_review(stack, review, policy):
    """Coordinator seals once. Each child gets the same open file descriptions."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    needed = max(map(int, os.listdir("/proc/self/fd"))) + len(review.runtime.tree.entries) + 128
    if soft < needed:
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(needed, hard), hard))
        stack.callback(resource.setrlimit, resource.RLIMIT_NOFILE, (soft, hard))
    rows = []
    descriptors = []
    for scope, entries in (("runtime", review.runtime.tree.entries),
                           ("snapshot", review.snapshot.entries)):
        for entry in entries:
            fingerprint = sha256(entry.data).hexdigest()
            fd = stack.enter_context(sealed_scanner_file(entry.data, fingerprint))
            descriptors.append(fd)
            rows.append({
                "scope": scope, "path": entry.path, "fd": fd, "sha256": fingerprint,
                "size": len(entry.data), "mode": entry.mode,
            })
    roles = {
        field: getattr(review.runtime, field)
        for field in ("executable", "interpreter", "configuration", "python_libraries",
                      "native_libraries", "arguments", "system_resources")
    }
    raw = encoded({"plan": asdict(review.plan), "policy": policy, "roles": roles, "rows": rows})
    meta = stack.enter_context(sealed_scanner_file(raw, sha256(raw).hexdigest()))
    return meta, tuple([meta, *descriptors])


def _sealed_bytes(fd, size):
    required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & required != required:
        raise ValidationError("Unsealed capture descriptor")
    if not 0 <= size <= MAX_STAGED_FILE or os.fstat(fd).st_size != size:
        raise ValidationError("Invalid capture size")
    return os.pread(fd, size, 0)


def load_review(meta):
    record = json.loads(_sealed_bytes(meta, os.fstat(meta).st_size))
    if len(record["rows"]) > 6000:
        raise ValidationError("Capture entry limit")
    entries = {"runtime": [], "snapshot": []}
    descriptors = {}
    for row in record["rows"]:
        raw = _sealed_bytes(row["fd"], row["size"])
        if sha256(raw).hexdigest() != row["sha256"]:
            raise ValidationError("Capture digest mismatch")
        scope, path = row["scope"], row["path"]
        if (
            path.startswith("/") or ".." in path.split("/") or "\\" in path
            or (scope, path) in descriptors
        ):
            raise ValidationError("Invalid capture path")
        entries[scope].append(CapturedEntry(path, "file", row["mode"], raw))
        descriptors[scope, path] = row["fd"]
    plan = ScannerExecutionPlan(**record["plan"])
    runtime = ScannerRuntime(ScannerSnapshot("/", tuple(entries["runtime"])), **record["roles"])
    if (
        runtime.interpreter != INTERPRETER or runtime.executable != "probe.py"
        or runtime.configuration != "input/config.yaml"
        or tuple(runtime.arguments) != ("-I", "-S", "-B", "-c")
    ):
        raise ValidationError("Unsupported fixed test entry point")
    review = ScannerReview(
        plan, ScannerSnapshot(plan.target, tuple(entries["snapshot"])), runtime,
    )
    review.fingerprint()
    if digest(record["policy"]) != plan.backend_policy_sha256:
        raise ValidationError("Capture policy mismatch")
    return review, record["policy"], descriptors


def execute_approved(review, policy, descriptors, socket_path, operation, *, fault="none"):
    """The only test dispatch path redeems before opening the supervisor gate."""
    if not owner_ipc_request(
        socket_path, BROKER, ["redeem", operation, review.fingerprint()],
    ):
        return {"status": "APPROVAL_DENIED", "attempted": False}
    if fault == "launcher-crash":
        os._exit(70)
    plan = review.plan
    if plan.backend_policy_sha256 != digest(policy):
        raise ValidationError("Approved execution policy changed")
    launch = list(policy["prefix"])
    fds = []
    for (scope, path), fd in sorted(descriptors.items()):
        destination = "/" + path if scope == "runtime" else "/input/" + path
        if path == "seccomp.bpf":
            continue
        fds.append(fd)
        if path in EXECUTABLES:
            launch.extend(("--perms", "0555", "--ro-bind-data", str(fd), destination))
        else:
            launch.extend(("--file", str(fd), destination))
    script = next(entry.data for entry in review.runtime.tree.entries if entry.path == "probe.py")
    launch.extend((
        "--size", str(plan.scratch_bytes), "--tmpfs", "/scratch", "--remount-ro", "/",
        "--chdir", "/scratch", "--seccomp", "0", "--setenv", "LD_LIBRARY_PATH",
        "/usr/local/lib:/usr/lib/x86_64-linux-gnu", "--", "/" + INTERPRETER,
        *review.runtime.arguments,
        script.decode(),
        policy["canary"], str(max(descriptors.values()) + 1),
    ))
    from linux_probe_supervision import ProbeFailure

    analysis_started = False
    attempted = False
    try:
        registry = Path(plan.output_directory).parent / "registry"
        registry.mkdir(mode=0o700, exist_ok=True)
        with delegated_group(
            Path(policy["cgroup_parent"]), memory=plan.memory_bytes, tasks=plan.max_processes,
            registry=registry,
        ) as group:
            def observe(chunk):
                nonlocal analysis_started
                if b"M415_BANDIT_ANALYSIS" in chunk and not analysis_started:
                    analysis_started = True
                    if fault in {"timeout", "cancel", "supervisor-kill"}:
                        for pid in (group / "cgroup.procs").read_text().split():
                            os.kill(int(pid), signal.SIGSTOP)
                    if fault == "supervisor-kill":
                        (Path(plan.output_directory).parent / "analysis-started").touch()

            with (Path(plan.output_directory).parent / "attempt.started").open("x") as marker:
                marker.write(review.fingerprint())
            attempted = True
            raw = supervise_probe(
                launch, filter_fd=descriptors["runtime", "seccomp.bpf"], descriptors=tuple(fds),
                timeout=plan.timeout_seconds, output_limit=plan.max_output_bytes, group=group,
                cancelled=lambda: fault == "cancel" and analysis_started,
                on_stderr=observe,
            )
    except ProbeFailure as error:
        status = "SCANNER_FAILED"
        if "BLOCKED" in str(error):
            status = "SANDBOX_BLOCKED"
        elif "output limit" in str(error):
            status = "REPORT_REJECTED"
        return {
            "status": status,
            "reason": str(error), "attempted": attempted, "analysis_started": analysis_started,
            "approval": "APPROVAL_CONSUMED",
        }
    result = json.loads(raw)
    if result["exit"] not in (0, 1):
        return {"status": "SCANNER_FAILED", "exit": result["exit"], "attempted": True}
    output = Path(plan.output_directory)
    source = output.with_name("actual.sarif")
    source.write_text(
        result["report"].rstrip()[:-1] if fault == "report-corrupt" else result["report"],
        encoding="utf-8",
    )
    try:
        report = save_bandit_report(source, output)
        if fault == "republish":
            original = output.read_bytes()
            try:
                save_bandit_report(source, output)
            except FileExistsError:
                assert output.read_bytes() == original
            else:
                raise AssertionError("Exclusive publication failed")
    except ValidationError:
        return {
            "status": "REPORT_REJECTED", "reason": "report validation",
            "attempted": True, "analysis_started": analysis_started,
        }
    finally:
        source.unlink()
    status = "SCANNER_COMPLETED_WITH_FINDINGS" if result["exit"] else "SCANNER_COMPLETED_CLEAN"
    return {
        "status": status,
        "authorization": "APPROVED_AND_EXECUTED", "exit": result["exit"], "attempted": True,
        "observations": report["observations"],
    }
