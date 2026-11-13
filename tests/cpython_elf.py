"""Static loader checks for the pinned Linux acceptance runtime."""

import re
import struct
import subprocess
from hashlib import sha256
from pathlib import PurePosixPath

from cpython_oci import NATIVE, elf_interpreter

from ai_threat_lab.models import ValidationError
from ai_threat_lab.scanner_staging import sealed_scanner_file

PYTHON = "usr/local/bin/python3.12"
LOADER = "lib64/ld-linux-x86-64.so.2"
SYSTEM_LOADER = NATIVE + PurePosixPath(LOADER).name


def elf_needed(data):
    if (
        len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01" or data[7] not in (0, 3)
        or data[8] != 0 or struct.unpack_from("<H", data, 18)[0] != 62
    ):
        raise ValidationError("Unexpected ELF architecture or ABI")
    with sealed_scanner_file(data, sha256(data).hexdigest()) as fd:
        result = subprocess.run(
            ["/usr/bin/readelf", "-dW", f"/proc/self/fd/{fd}"],
            pass_fds=(fd,), capture_output=True, text=True, env={"LC_ALL": "C"}, timeout=5,
        )
    if result.returncode or result.stderr:
        raise ValidationError("ELF dynamic section rejected")
    needed = []
    for kind, value in re.findall(r"\((NEEDED|RPATH|RUNPATH)\).*?\[([^\]]*)\]", result.stdout):
        if kind != "NEEDED":
            if value != "$ORIGIN/../lib":
                raise ValidationError("Unexpected ELF search path")
        elif not re.fullmatch(r"[a-zA-Z0-9_.+-]+\.so(?:\.[0-9]+)*", value):
            raise ValidationError("Unexpected ELF dependency name")
        else:
            needed.append(value)
    return needed


def close_elf_tree(tree, native):
    if elf_interpreter(tree[PYTHON]) != "/" + LOADER:
        raise ValidationError("Unexpected ELF interpreter")
    tree[LOADER] = tree[SYSTEM_LOADER]
    pending = [path for path, data in tree.items() if data.startswith(b"\x7fELF")]
    checked = {}
    while pending:
        path = pending.pop()
        if path in checked:
            continue
        names = elf_needed(tree[path])
        checked[path] = names
        for name in names:
            target = "usr/local/lib/" + name
            if target not in tree:
                target = NATIVE + name
            if target not in tree:
                candidate = target
                seen = set()
                while isinstance(native.get(candidate), str):
                    alias = native[candidate]
                    if "/" in alias or alias in {".", ".."} or candidate in seen:
                        raise ValidationError("Unsupported native library alias")
                    seen.add(candidate)
                    candidate = NATIVE + alias
                if candidate not in native:
                    raise ValidationError(f"Missing pinned ELF dependency: {name}")
                tree[target] = native[candidate]
            pending.append(target)
    return checked
