"""Supervision for repository-owned Linux acceptance fixtures."""

import json
import os
import re
import selectors
import subprocess
import sys
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path
from uuid import uuid4


class ProbeFailure(RuntimeError):
    pass


def _identity(descriptor):
    info = os.fstat(descriptor)
    return [info.st_dev, info.st_ino]


def _drain(group):
    (group / "cgroup.kill").write_text("1")
    deadline = time.monotonic() + 5
    while "populated 1" in (group / "cgroup.events").read_text().splitlines():
        if time.monotonic() >= deadline:
            raise ProbeFailure("cgroup did not drain after kill")
        time.sleep(0.02)


def recover_groups(parent, registry):
    """Recover recorded groups in an exclusively controlled delegation and registry."""
    import fcntl

    _validate_parent(parent)
    recovered = []
    with ExitStack() as stack:
        parent_fd = os.open(parent, os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, parent_fd)
        for record in registry.iterdir():
            if not re.fullmatch(r"atl-probe-[0-9a-f]{32}", record.name):
                continue
            with os.fdopen(os.open(record, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue
                try:
                    identity = json.loads(stream.read(4096))
                except ValueError:
                    continue
                if not isinstance(identity, dict) or (
                    identity.get("owner") != os.getuid()
                    or identity.get("parent") != _identity(parent_fd)
                ):
                    continue
                try:
                    group_fd = os.open(
                        record.name, os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd,
                    )
                except FileNotFoundError:
                    record.unlink()
                    continue
                try:
                    if identity.get("group") != _identity(group_fd):
                        continue
                    _drain(Path(f"/proc/self/fd/{group_fd}"))
                    current = os.stat(record.name, dir_fd=parent_fd, follow_symlinks=False)
                    if [current.st_dev, current.st_ino] != identity["group"]:
                        raise ProbeFailure("cgroup identity changed before removal")
                    os.rmdir(record.name, dir_fd=parent_fd)
                    record.unlink()
                    recovered.append(record.name)
                finally:
                    os.close(group_fd)
    return recovered


def _validate_parent(parent):
    mount = "/sys/fs/cgroup"
    if not parent.resolve().is_relative_to(mount) or not any(
        row.split()[1:3] == [mount, "cgroup2"]
        for row in Path("/proc/mounts").read_text(encoding="ascii").splitlines()
    ):
        raise ProbeFailure("BLOCKED: delegated parent must be on the cgroup v2 mount")


@contextmanager
def delegated_group(parent, *, memory, tasks, registry=None, io_device=None):
    import fcntl

    _validate_parent(parent)
    required = {"memory", "pids", "cpu"}
    if io_device is not None:
        if not re.fullmatch(r"[0-9]+:[0-9]+", io_device):
            raise ProbeFailure("BLOCKED: invalid block device identifier")
        required.add("io")
    try:
        controllers = (parent / "cgroup.subtree_control").read_text().split()
        if not required.issubset(controllers):
            missing = ", ".join(sorted(required.difference(controllers)))
            raise ProbeFailure(f"BLOCKED: missing cgroup controllers: {missing}")
        group = parent / ("atl-probe-" + uuid4().hex)
        group.mkdir()
    except OSError as error:
        raise ProbeFailure(
            f"BLOCKED: cannot create delegated cgroup (errno {error.errno})"
        ) from None
    with ExitStack() as resources:
        def remove():
            group.rmdir()
            if record is not None:
                record.unlink()

        record = None
        if registry is not None:
            candidate = registry / group.name
            try:
                stream = resources.enter_context(candidate.open("xb"))
            except OSError:
                group.rmdir()
                raise
            record = candidate
            resources.callback(remove)
            fcntl.flock(stream, fcntl.LOCK_EX)
            parent_stat, group_stat = parent.stat(), group.stat()
            stream.write(json.dumps({
                "owner": os.getuid(), "parent": [parent_stat.st_dev, parent_stat.st_ino],
                "group": [group_stat.st_dev, group_stat.st_ino],
            }).encode("ascii"))
            stream.flush()
            os.fsync(stream.fileno())
            registry_fd = os.open(registry, os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(registry_fd)
            finally:
                os.close(registry_fd)
        else:
            resources.callback(remove)
        try:
            for name, value in (
                ("memory.max", memory), ("memory.swap.max", 0),
                ("memory.oom.group", 1), ("pids.max", tasks),
                ("cpu.max", "20000 100000"),
            ):
                (group / name).write_text(str(value))
            if io_device is not None:
                (group / "io.max").write_text(f"{io_device} rbps=1048576 wbps=1048576")
            # Prove kill permission while the group is still empty.
            (group / "cgroup.kill").write_text("1")
        except OSError as error:
            raise ProbeFailure(
                f"BLOCKED: cgroup configuration failed (errno {error.errno})"
            ) from None
        try:
            yield group
        finally:
            _drain(group)


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
