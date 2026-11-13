"""Fetch pinned OCI artifacts for the isolated acceptance probe."""

import json
import sys
from hashlib import sha256
from pathlib import Path
from urllib.request import Request, urlopen

PIN = "2986c55feb36e6cae00fa1fefb454283e4b33f35e75ff8bdd123b134130be301"
REGISTRY = "https://registry-1.docker.io/v2/library/python"


def main(output):
    output.mkdir()
    token_url = "https://auth.docker.io/token?service=registry.docker.io"
    with urlopen(token_url + "&scope=repository:library/python:pull", timeout=30) as response:
        token = json.loads(response.read(65536))["token"]

    def fetch(endpoint, name, fingerprint, limit):
        request = Request(REGISTRY + endpoint, headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.oci.image.manifest.v1+json",
        })
        with urlopen(request, timeout=60) as response:
            raw = response.read(limit + 1)
        if len(raw) > limit or sha256(raw).hexdigest() != fingerprint:
            raise ValueError("OCI download exceeds limit or differs from pin")
        (output / name).write_bytes(raw)
        return raw

    manifest = json.loads(fetch("/manifests/sha256:" + PIN, "manifest.json", PIN, 16384))
    for descriptor in [manifest["config"], *manifest["layers"]]:
        fingerprint = descriptor["digest"].removeprefix("sha256:")
        size = descriptor["size"]
        if not 0 < size <= 32 * 1024**2:
            raise ValueError("OCI descriptor exceeds limit")
        raw = fetch("/blobs/" + descriptor["digest"], fingerprint, fingerprint, size)
        if len(raw) != size:
            raise ValueError("OCI descriptor size mismatch")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
