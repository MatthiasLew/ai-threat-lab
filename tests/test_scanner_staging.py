import errno
import os
from hashlib import sha256

import pytest

from ai_threat_lab.models import ValidationError
from ai_threat_lab.scanner_staging import MAX_STAGED_FILE, sealed_scanner_file


def test_staging_unavailable_fails_closed(monkeypatch):
    monkeypatch.delattr(os, "memfd_create", raising=False)
    with pytest.raises(ValidationError, match="unavailable"):
        with sealed_scanner_file(b"x", "unused"):
            pytest.fail("unexpected staging")


@pytest.mark.skipif(not hasattr(os, "memfd_create"), reason="Linux memfd seals")
def test_sealed_file_denies_writes_and_closes_on_failure():
    data = b"approved"
    with pytest.raises(RuntimeError, match="injected"):
        with sealed_scanner_file(data, sha256(data).hexdigest()) as descriptor:
            assert os.read(descriptor, len(data)) == data
            assert not os.get_inheritable(descriptor)
            with pytest.raises(OSError) as error:
                os.pwrite(descriptor, b"x", 0)
            assert error.value.errno == errno.EPERM
            with pytest.raises(OSError) as error:
                os.ftruncate(descriptor, 0)
            assert error.value.errno == errno.EPERM
            raise RuntimeError("injected")
    with pytest.raises(OSError) as error:
        os.fstat(descriptor)
    assert error.value.errno == errno.EBADF


@pytest.mark.skipif(not hasattr(os, "memfd_create"), reason="Linux memfd seals")
@pytest.mark.parametrize("data,message", [
    (b"x", "digest mismatch"), (bytearray(b"x"), "oversized"),
    (b"x" * (MAX_STAGED_FILE + 1), "oversized"),
], ids=["digest", "mutable", "oversized"])
def test_invalid_staging_never_yields_a_descriptor(data, message):
    with pytest.raises(ValidationError, match=message):
        with sealed_scanner_file(data, "0" * 64):
            pytest.fail("unexpected staging")
