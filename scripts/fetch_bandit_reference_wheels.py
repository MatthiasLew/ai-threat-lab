"""Fetch the pinned reference wheels as data for CI. Do not install them."""

import sys
from hashlib import sha256
from pathlib import Path
from urllib.request import urlopen

from ai_threat_lab.bandit_runtime_review import bandit_reference_lock


def main(destination):
    destination.mkdir()
    maximum = 2 * 1024**2
    for artifact in bandit_reference_lock()["artifacts"]:
        with urlopen(artifact["url"], timeout=30) as response:
            raw = response.read(maximum + 1)
        if len(raw) > maximum or sha256(raw).hexdigest() != artifact["sha256"]:
            raise ValueError(f"Unexpected wheel bytes for {artifact['name']}")
        with (destination / artifact["filename"]).open("xb") as stream:
            stream.write(raw)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
