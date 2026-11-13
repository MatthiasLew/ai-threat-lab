"""Supervision for repository-owned Linux acceptance fixtures."""

import os
import selectors
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4


class ProbeFailure(RuntimeError):
    pass


@contextmanager
def delegated_group(parent, *, memory, tasks):
    required = {"memory", "pids"}
    mount = "/sys/fs/cgroup"
    if not parent.resolve().is_relative_to(mount) or not any(
        row.split()[1:3] == [mount, "cgroup2"]
        for row in Path("/proc/mounts").read_text(encoding="ascii").splitlines()
    ):
        raise ProbeFailure("BLOCKED: delegated parent must be on the cgroup v2 mount")
    try:
        controllers = (parent / "cgroup.subtree_control").read_text().split()
        if not required.issubset(controllers):
            raise ProbeFailure("BLOCKED: memory and pids controllers must be delegated and enabled")
        group = parent / ("atl-probe-" + uuid4().hex)
        group.mkdir()
    except OSError as error:
        raise ProbeFailure(
            f"BLOCKED: cannot create delegated cgroup (errno {error.errno})"
        ) from None
    try:
        try:
            for name, value in (
                ("memory.max", memory), ("memory.swap.max", 0),
                ("memory.oom.group", 1), ("pids.max", tasks),
            ):
                (group / name).write_text(str(value))
            # Prove kill permission while the group is still empty.
            (group / "cgroup.kill").write_text("1")
        except OSError as error:
            raise ProbeFailure(
                f"BLOCKED: cgroup configuration failed (errno {error.errno})"
            ) from None
        try:
            yield group
        finally:
            (group / "cgroup.kill").write_text("1")
            deadline = time.monotonic() + 5
            while "populated 1" in (group / "cgroup.events").read_text().splitlines():
                if time.monotonic() >= deadline:
                    raise ProbeFailure("cgroup did not drain after kill")
                time.sleep(0.02)
    finally:
        group.rmdir()


# This isolated, trusted gate has no project imports. EOF is refusal. exec preserves
# PID and membership. Bubblewrap's own parent-death handling takes over after exec.
_GATE = (
    "import os,sys;"
    "fd=int(sys.argv[1]);ready=os.read(fd,1);os.close(fd);"
    "os.execv(sys.argv[2],sys.argv[2:]) if ready==b'G' else sys.exit(125)"
)


def supervise_probe(command, *, filter_fd, descriptors, timeout, output_limit,
                    group=None, cancelled=lambda: False):
    """Capture both streams with a combined cap and a monotonic deadline."""
    deadline = time.monotonic() + timeout
    reader, writer = os.pipe()
    try:
        with subprocess.Popen(
            [sys.executable, "-I", "-S", "-c", _GATE, str(reader), *command],
            stdin=filter_fd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={}, pass_fds=(*descriptors, reader),
        ) as process:
            try:
                if group is not None:
                    try:
                        (group / "cgroup.procs").write_text(str(process.pid))
                        if str(process.pid) not in (group / "cgroup.procs").read_text().split():
                            raise ProbeFailure("BLOCKED: gate is outside the delegated cgroup")
                    except OSError as error:
                        raise ProbeFailure(
                            f"BLOCKED: cgroup placement failed (errno {error.errno})"
                        ) from None
                os.write(writer, b"G")
                return _collect(process, deadline, output_limit, cancelled)
            finally:
                try:
                    if group is not None:
                        (group / "cgroup.kill").write_text("1")
                finally:
                    if process.poll() is None:
                        process.kill()
    finally:
        os.close(reader)
        os.close(writer)


def _collect(process, deadline, limit, cancelled):
    output = bytearray()
    total = 0
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        selector.register(process.stderr, selectors.EVENT_READ)
        while selector.get_map() or process.poll() is None:
            if cancelled():
                raise ProbeFailure("probe cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeFailure("probe deadline exceeded")
            if not selector.get_map():
                time.sleep(min(0.05, remaining))
                continue
            for key, _ in selector.select(min(0.05, remaining)):
                chunk = os.read(key.fd, min(4096, limit + 1 - total))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total += len(chunk)
                if total > limit:
                    raise ProbeFailure("probe output limit exceeded")
                if key.fileobj is process.stdout:
                    output.extend(chunk)
    if process.returncode:
        raise ProbeFailure(f"probe exited with status {process.returncode}")
    if not output:
        raise ProbeFailure("probe returned no report")
    return bytes(output)


def publish_probe_report(raw, source, output):
    """Publish only a complete synthetic report after successful supervision."""
    from ai_threat_lab.local_history import write_new_report
    from ai_threat_lab.sarif_review import import_sarif
    from ai_threat_lab.scan_bundle import encoded

    stream = source.open("xb")
    try:
        with stream:
            stream.write(raw)
        report, failures = import_sarif(source)
        if failures or any(
            run["producer"] != "M4.4 synthetic probe" or run["producer_succeeded"] is not True
            or run["outside_page"] for run in report["runs"]
        ):
            raise ProbeFailure("probe returned an incomplete or unexpected report")
        write_new_report(output, encoded(report))
    finally:
        source.unlink()
