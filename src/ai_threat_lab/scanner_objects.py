"""Bounded, immutable review objects for an offline scanner plan."""

import os
import stat
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from .agent_fs import _read, open_pinned_file, pinned_directory, pinned_read_scope
from .dependency_paths import linked
from .models import ValidationError
from .scan_bundle import encoded
from .scanner_plan import network_syntax


def digest(record):
    return sha256(encoded(record)).hexdigest()


@dataclass(frozen=True, slots=True)
class CapturedEntry:
    path: str
    kind: str
    mode: int
    data: bytes = b""

    def manifest_row(self):
        return {
            "path": self.path, "kind": self.kind, "mode": self.mode, "size": len(self.data),
            "sha256": sha256(self.data).hexdigest() if self.kind == "file" else None,
        }


@dataclass(frozen=True, slots=True)
class ScannerSnapshot:
    root: str
    entries: tuple[CapturedEntry, ...]

    def manifest(self):
        return {"schema_version": 1, "entries": [entry.manifest_row() for entry in self.entries]}

    def fingerprint(self):
        return digest(self.manifest())


def _state(info):
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns,
    )


def capture_scanner_tree(source, *, max_bytes=32 * 1024**2, max_entries=4000, max_depth=16):
    """Capture complete bytes or fail. The returned object never reopens source paths."""
    if network_syntax(source):
        raise ValidationError("Scanner capture requires a local directory")
    if not (0 < max_bytes <= 128 * 1024**2 and 0 < max_entries <= 10000 and 0 <= max_depth <= 32):
        raise ValidationError("Invalid scanner capture limits")
    root = Path(os.path.abspath(source))
    entries = []
    remaining = max_bytes

    def visit(folder, expected, depth):
        nonlocal remaining
        with pinned_read_scope(folder, expected=expected), pinned_directory(folder) as fd:
            before = os.fstat(fd) if fd is not None else folder.stat()
            if _state(before) != _state(expected):
                raise ValidationError("Scanner directory changed during capture")
            with os.scandir(fd if fd is not None else folder) as listing:
                names = []
                for entry in listing:
                    if len(entries) + len(names) >= max_entries:
                        raise ValidationError("Scanner capture entry limit exceeded")
                    info = (
                        entry.stat(follow_symlinks=False) if fd is not None
                        else (folder / entry.name).lstat()
                    )
                    names.append((entry.name, info))
            for name, info in sorted(names):
                if len(entries) >= max_entries:
                    raise ValidationError("Scanner capture entry limit exceeded")
                path = folder / name
                relative = path.relative_to(root).as_posix()
                mode = stat.S_IMODE(info.st_mode)
                if linked(path) or stat.S_ISLNK(info.st_mode):
                    raise ValidationError("Scanner capture contains a link or reparse point")
                if stat.S_ISDIR(info.st_mode):
                    if depth >= max_depth:
                        raise ValidationError("Scanner capture depth limit exceeded")
                    entries.append(CapturedEntry(relative, "directory", mode))
                    visit(path, info, depth + 1)
                elif stat.S_ISREG(info.st_mode):
                    with open_pinned_file(path) as stream:
                        current = os.fstat(stream.fileno()) if fd is not None else path.lstat()
                        if _state(current) != _state(info):
                            raise ValidationError("Scanner file changed before capture")
                        data = _read(stream, remaining)
                    remaining -= len(data)
                    entries.append(CapturedEntry(relative, "file", mode, data))
                else:
                    raise ValidationError("Scanner capture contains a special file")
            after = os.fstat(fd) if fd is not None else folder.stat()
            pending = {name for name, _ in names}
            with os.scandir(fd if fd is not None else folder) as listing:
                for entry in listing:
                    if entry.name not in pending:
                        raise ValidationError("Scanner directory changed during capture")
                    pending.remove(entry.name)
            if pending or _state(before) != _state(after) or not os.path.samestat(
                after, folder.lstat(),
            ):
                raise ValidationError("Scanner directory changed during capture")

    try:
        visit(root, root.lstat(), 0)
    except OSError:
        raise ValidationError("Scanner capture is incomplete or inaccessible") from None
    return ScannerSnapshot(str(root), tuple(sorted(entries, key=lambda entry: entry.path)))


@dataclass(frozen=True, slots=True)
class ScannerRuntime:
    tree: ScannerSnapshot
    executable: str
    interpreter: str
    configuration: str
    python_libraries: tuple[str, ...]
    native_libraries: tuple[str, ...]
    arguments: tuple[str, ...]
    system_resources: tuple[str, ...]

    def manifest(self):
        files = {row.path: sha256(row.data).hexdigest()
                 for row in self.tree.entries if row.kind == "file"}
        roles = (self.executable, self.interpreter, self.configuration,
                 *self.python_libraries, *self.native_libraries)
        if len(set(roles)) != len(roles) or set(roles) != files.keys():
            raise ValidationError("Runtime roles must account for every captured file exactly once")
        return {
            "schema_version": 1, "tree": self.tree.fingerprint(),
            "executable": files[self.executable], "interpreter": files[self.interpreter],
            "configuration": files[self.configuration], "executable_path": self.executable,
            "interpreter_path": self.interpreter, "configuration_path": self.configuration,
            "python_libraries": [(path, files[path]) for path in self.python_libraries],
            "native_libraries": [(path, files[path]) for path in self.native_libraries],
            "arguments": self.arguments, "system_resources": self.system_resources,
            "runtime_resolution": "unverified",
        }
