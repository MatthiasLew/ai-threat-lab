"""Offline projection of the pinned reference image for the acceptance probe."""

import gzip
import io
import json
import struct
import tarfile
from hashlib import sha256
from pathlib import PurePosixPath

from ai_threat_lab.models import ValidationError

MANIFEST = "2986c55feb36e6cae00fa1fefb454283e4b33f35e75ff8bdd123b134130be301"
STDLIB = "usr/local/lib/python3.12/"
NATIVE = "usr/lib/x86_64-linux-gnu/"
LIBRARIES = {
    "ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6", "libz.so.1.2.13",
    "libpthread.so.0", "libdl.so.2", "librt.so.1",
}


def elf_interpreter(raw):
    if len(raw) < 64 or raw[:7] != b"\x7fELF\x02\x01\x01":
        raise ValidationError("Unsupported ELF format")
    if struct.unpack_from("<H", raw, 18)[0] != 62:
        raise ValidationError("Unsupported ELF machine")
    offset = struct.unpack_from("<Q", raw, 32)[0]
    size, count = struct.unpack_from("<HH", raw, 54)
    if size != 56 or offset + size * count > len(raw):
        raise ValidationError("Invalid ELF program headers")
    for index in range(count):
        kind, _, start, _, _, length = struct.unpack_from("<IIQQQQ", raw, offset + index * size)
        if kind == 3:
            path = raw[start:start + length]
            if path != b"/lib64/ld-linux-x86-64.so.2\0" or length != len(path):
                raise ValidationError("Unexpected ELF interpreter")
            return path[:-1].decode("ascii")
    raise ValidationError("Missing ELF interpreter")


def _checked(raw, descriptor):
    fingerprint = "sha256:" + sha256(raw).hexdigest()
    if len(raw) != descriptor["size"] or fingerprint != descriptor["digest"]:
        raise ValidationError("OCI descriptor mismatch")
    return raw


def _project_layer(raw, diff_id, output):
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
        tar = stream.read(96 * 1024**2 + 1)
    if len(tar) > 96 * 1024**2 or "sha256:" + sha256(tar).hexdigest() != diff_id:
        raise ValidationError("OCI layer expansion or diff ID mismatch")
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(tar), mode="r:") as archive:
        for entry in archive:
            path = entry.name
            if path == "." and entry.isdir():
                continue
            parts = path.split("/")
            if len(seen) >= 12000 or path in seen or any(
                part in {"", ".", ".."} or part.startswith(".wh.") for part in parts
            ) or "\\" in path:
                raise ValidationError("Unsupported OCI path, whiteout or collision")
            seen.add(path)
            if not (entry.isfile() or entry.isdir() or entry.issym() or entry.islnk()):
                raise ValidationError("Unsupported OCI entry type")
            if entry.islnk() and (
                entry.linkname.startswith("/") or ".." in entry.linkname.split("/")
            ):
                raise ValidationError("Unsafe OCI hardlink")
            selected = (
                path in {"usr/local/bin/python3.12", "usr/local/lib/libpython3.12.so.1.0"}
                or path.startswith(NATIVE) and PurePosixPath(path).name in LIBRARIES
                or path.startswith(STDLIB) and path.endswith(".py")
                and not {"site-packages", "test", "tests"}.intersection(parts)
                or path.startswith((STDLIB + "lib-dynload/zlib.", STDLIB + "lib-dynload/_socket."))
            )
            if selected:
                if not entry.isfile() or entry.size > 8 * 1024**2 or path in output:
                    raise ValidationError("Unsupported selected OCI member")
                output[path] = archive.extractfile(entry).read()


def load_projection(directory):
    def read(name, limit):
        with (directory / name).open("rb") as stream:
            return stream.read(limit + 1)

    raw = read("manifest.json", 16384)
    if sha256(raw).hexdigest() != MANIFEST:
        raise ValidationError("OCI manifest pin mismatch")
    manifest = json.loads(raw)
    config = manifest["config"]
    configuration = json.loads(_checked(read(config["digest"][7:], 16384), config))
    if (configuration["os"], configuration["architecture"]) != ("linux", "amd64"):
        raise ValidationError("Unsupported OCI platform")
    result = {}
    for layer, diff_id in zip(manifest["layers"], configuration["rootfs"]["diff_ids"], strict=True):
        _project_layer(_checked(read(layer["digest"][7:], 32 * 1024**2), layer), diff_id, result)
    if len(result) > 1500 or sum(map(len, result.values())) > 32 * 1024**2:
        raise ValidationError("CPython projection exceeds staging limits")
    return result
