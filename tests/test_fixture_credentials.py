"""Keep provider-shaped credential literals out of checked-in test data."""

import re
from pathlib import Path


def test_test_sources_and_fixtures_contain_no_google_key_literals():
    tests = Path(__file__).parent
    pattern = re.compile(rb"(?<![0-9A-Za-z_-])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])")
    locations = [
        f"{path.relative_to(tests).as_posix()}:{number}"
        for path in tests.rglob("*")
        if path.suffix.lower() in {".py", ".json", ".jsonl", ".sarif", ".txt", ".yaml", ".yml"}
        for number, line in enumerate(path.read_bytes().splitlines(), 1)
        if pattern.search(line)
    ]
    assert not locations, "Google key-shaped literals in test data: " + ", ".join(locations)
