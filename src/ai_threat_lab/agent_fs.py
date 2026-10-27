"""Bounded private snapshots for agent operations; target files are never executed.

POSIX walks directories through no-follow descriptors. Windows pins directories
against rename/deletion and checks the final opened handle before reading bytes.
Snapshots are bounded copies, not atomic filesystem transactions.
"""

import os
import stat
from contextlib import ExitStack, contextmanager
from pathlib import Path

from .dependency_paths import linked
from .local_inventory import is_excluded_dirname
from .models import ValidationError

MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_ENTRIES = 10000
MAX_DEPTH = 16


def scoped_path(root, value, *, existing=True):
    if not isinstance(value, str) or not 1 <= len(value) <= 1024:
        raise ValidationError("Invalid scoped path")
    if any(ord(c) < 32 for c in value) or "://" in value:
        raise ValidationError("Only local scoped paths are supported")
    path = Path(value)
    path = path if path.is_absolute() else root / path
    path = Path(os.path.abspath(path))
    if not path.is_relative_to(root):
        raise ValidationError("Path is outside the approved root")
    for component in (path, *path.parents):
        if linked(component):
            raise ValidationError("Linked paths are not supported")
    if existing and not path.exists():
        raise ValidationError("Scoped path does not exist")
    return path


@contextmanager
def _windows_handle(path, directory):
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create.restype = wintypes.HANDLE
    final = kernel.GetFinalPathNameByHandleW
    final.argtypes = (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
    final.restype = wintypes.DWORD
    close = kernel.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    handle = create(
        str(path), 0x80000000, 3, None, 3, 0x00200000 | (0x02000000 if directory else 0), None
    )
    if handle == wintypes.HANDLE(-1).value:
        raise OSError("Scoped handle could not be opened")
    try:
        buf = ctypes.create_unicode_buffer(32768)
        length = final(handle, buf, len(buf), 0)
        actual = buf.value.removeprefix("\\\\?\\")
        if (
            not length
            or length >= len(buf)
            or os.path.normcase(actual) != os.path.normcase(str(path))
            or linked(path)
        ):
            raise ValidationError("Opened object differs from approved path")
        yield handle
    finally:
        close(handle)


@contextmanager
def pinned_directory(path):
    """Pin every directory component; no target-controlled parent links are followed."""
    path = Path(path)
    with ExitStack() as stack:
        if os.name == "nt":
            for folder in reversed((path, *path.parents)):
                stack.enter_context(_windows_handle(folder, True))
            yield None
        else:
            descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
            stack.callback(os.close, descriptor)
            for part in path.parts[1:]:
                descriptor = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
                )
                stack.callback(os.close, descriptor)
            yield descriptor


def read_scoped(path, maximum=MAX_FILE):
    """Read only after opening and checking an object; never return outside-root bytes."""
    with pinned_directory(path.parent) as parent:
        if os.name == "nt":
            import msvcrt

            with _windows_handle(path, False) as handle:
                # Duplicate the handle: fdopen owns only the duplicate.
                import ctypes
                from ctypes import wintypes

                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                current = kernel.GetCurrentProcess
                current.restype = wintypes.HANDLE
                duplicate = kernel.DuplicateHandle
                duplicate.argtypes = (
                    wintypes.HANDLE,
                    wintypes.HANDLE,
                    wintypes.HANDLE,
                    ctypes.POINTER(wintypes.HANDLE),
                    wintypes.DWORD,
                    wintypes.BOOL,
                    wintypes.DWORD,
                )
                copied = wintypes.HANDLE()
                if not duplicate(current(), handle, current(), ctypes.byref(copied), 0, False, 2):
                    raise OSError("Scoped handle duplication failed")
                descriptor = msvcrt.open_osfhandle(copied.value, os.O_RDONLY | os.O_BINARY)
                with os.fdopen(descriptor, "rb") as stream:
                    return _read(stream, maximum)
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(descriptor, "rb") as stream:
            return _read(stream, maximum)


def _read(stream, maximum):
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValidationError("Only regular files with a single link are supported")
    if info.st_size > maximum:
        raise ValidationError("Scoped file exceeds its byte limit")
    value = stream.read(maximum + 1)
    after = os.fstat(stream.fileno())
    if len(value) > maximum or (info.st_size, info.st_mtime_ns) != (
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ValidationError("Scoped file changed or exceeded its byte limit")
    return value


def snapshot(source, destination, *, bundle=False):
    """Copy bounded files to a private workspace, recording all skipped-entry counts."""
    from .scan_bundle import FILES

    counters = {"files": 0, "bytes": 0, "skipped": 0, "entries": 0}
    destination.mkdir()
    root = destination / source.name if source.is_file() else destination

    def copy_file(path, out):
        try:
            data = read_scoped(path, min(MAX_FILE, MAX_TOTAL - counters["bytes"]))
        except (OSError, ValidationError):
            if bundle:
                raise ValidationError("Saved artifact cannot be read securely") from None
            counters["skipped"] += 1
            return
        out.write_bytes(data)
        counters["files"] += 1
        counters["bytes"] += len(data)

    if source.is_file():
        copy_file(source, root)
    else:
        queue = [(source, destination, 0)]
        while queue:
            folder, out, depth = queue.pop(0)
            with pinned_directory(folder) as descriptor:
                with os.scandir(descriptor if descriptor is not None else folder) as stream:
                    entries = []
                    for entry in stream:
                        counters["entries"] += 1
                        if counters["entries"] > MAX_ENTRIES:
                            raise ValidationError(
                                "Snapshot entry limit exceeded; narrow the target"
                            )
                        entries.append(entry.name)
            for name in sorted(entries):
                path = folder / name
                if linked(path):
                    if bundle:
                        raise ValidationError("Linked bundle artifact")
                    counters["skipped"] += 1
                elif path.is_dir():
                    if bundle and name not in ("exports", "reports"):
                        raise ValidationError("Unexpected saved artifact directory")
                    if bundle or is_excluded_dirname(name) or name == ".ai-threat-lab":
                        counters["skipped"] += 1
                    elif depth >= MAX_DEPTH:
                        counters["skipped"] += 1
                    else:
                        (out / name).mkdir()
                        queue.append((path, out / name, depth + 1))
                elif bundle and name not in FILES | {"manifest.json"}:
                    # Export extras are not inputs to verification.
                    if not (name.endswith(".pdf") or name.startswith("costs.sqlite")):
                        raise ValidationError("Unexpected saved artifact")
                else:
                    copy_file(path, out / name)
    return root, counters
