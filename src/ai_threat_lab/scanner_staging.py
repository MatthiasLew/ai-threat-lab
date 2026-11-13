"""Linux sealed descriptors for a bounded, single-file test handoff."""

import os
from contextlib import contextmanager
from hashlib import sha256

from .models import ValidationError

MAX_STAGED_FILE = 8 * 1024**2


@contextmanager
def sealed_scanner_file(data: bytes, expected_sha256: str):
    """Materialize captured bytes in a kernel-sealed anonymous file."""
    if not hasattr(os, "memfd_create"):
        raise ValidationError("Sealed scanner staging is unavailable")
    if type(data) is not bytes or len(data) > MAX_STAGED_FILE:
        raise ValidationError("Invalid or oversized scanner staging input")

    import fcntl

    descriptor = os.memfd_create("scanner-review", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(descriptor), "wb") as stream:
            stream.write(data)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            stream.seek(0)
            actual = sha256(stream.read(MAX_STAGED_FILE + 1)).hexdigest()
        if actual != expected_sha256:
            raise ValidationError("Sealed scanner staging digest mismatch")
        os.lseek(descriptor, 0, os.SEEK_SET)
        yield descriptor
    finally:
        os.close(descriptor)
