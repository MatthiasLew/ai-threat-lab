import gzip
import io
import tarfile
from hashlib import sha256

import pytest
from cpython_oci import _checked, _project_layer, elf_interpreter

from ai_threat_lab.models import ValidationError


@pytest.mark.parametrize("path", ["/outside", "../outside", "usr/.wh.lib"])
def test_oci_rejects_unsupported_archive_paths(path):
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as stream:
        stream.addfile(tarfile.TarInfo(path))
    raw = archive.getvalue()
    with pytest.raises(ValidationError, match="Unsupported OCI path"):
        _project_layer(gzip.compress(raw), "sha256:" + sha256(raw).hexdigest(), {})


def test_oci_rejects_digest_substitution():
    descriptor = {"size": 3, "digest": "sha256:" + sha256(b"abc").hexdigest()}
    with pytest.raises(ValidationError, match="descriptor mismatch"):
        _checked(b"xyz", descriptor)
    with pytest.raises(ValidationError, match="diff ID"):
        _project_layer(gzip.compress(b"xyz"), descriptor["digest"], {})


def test_rejects_non_elf():
    with pytest.raises(ValidationError, match="Unsupported ELF format"):
        elf_interpreter(b"not an executable")
