"""Run every local release gate using the active interpreter, without shell commands."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    commands = [
        [sys.executable, "-m", "ruff", "check", "."],
        [sys.executable, "-m", "coverage", "run", "-m", "pytest", "-q"],
        [sys.executable, "-m", "coverage", "report"],
        [sys.executable, "-m", "build"],
        [sys.executable, "scripts/check_installed_package.py"],
    ]
    if (ROOT / ".git").exists():
        commands.append(["git", "diff", "--check"])
    else:
        print("Git whitespace check skipped: source archive has no Git metadata.")
    for command in commands:
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
