# Development

## Setup and validation

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m pytest -q
python -m build
```

CI runs lint, tests, package build, and an installed-wheel CLI smoke check on Linux and Windows with Python 3.12, 3.13 and 3.14. Local verification covers the interpreter/platform used by the contributor; CI supplies the other environments.

## AI Dev CLI Tools

This project uses [ai-dev-cli-tools](https://github.com/MatthiasLew/ai-dev-cli-tools) as a development helper, not a runtime dependency. The CLI/install milestone used checkout `9b4b4b9`; record the tool revision when reporting failures. Project check commands are in `.ai-dev-tools.toml`.

```bash
python -m pip install "git+https://github.com/MatthiasLew/ai-dev-cli-tools.git"
ai-dev --json map
ai-dev --json plan --task "describe the change" --mode fast
ai-dev --json check --mode full
ai-dev --json context build --task "describe the change" --profile implement --include "src/**/*.py" --token-budget source=6000
```

The current context builder includes untracked source files; inspect its selected-file list and truncation receipt. Keep generated `.ai/` logs and context out of commits. A context-budget truncation warning indicates bounded output, not a failed application test. Investigate reproducible tool failures or missing behavior and file a focused upstream issue after checking for duplicates, per maintainer workflow; do not create or merge upstream PRs.

## Verification scope

Tests exercise all 25 matrix inputs, label boundaries, invalid ratings, catalog validation, profile adjustments, duplicate and overlapping defenses, scenario-specific controls, reduction caps, deterministic results, report metadata and UTF-8, refusal to overwrite reports, CLI errors, guided input, and all six CLI scenarios. GUI parity checks will be added when GUI exists.

## Contribution workflow

Project changes currently go to main after local checks, per the maintainer workflow. Update documentation together with the public service contract. Domain/application modules must not import Qt, read console input, or send network requests. Fix the issue demonstrated by a failing check before broadening the test scope.

Code-review tests cover risky patterns, simple import aliases, nonmatching examples, source non-execution, file encodings, input-size limits, output redaction, CLI exit codes and export preservation.

Campaign/assessment checks cover scope-before-provider validation, exact-content approvals, expiry, channel mismatches, cancellation, ambiguous send failures, persistent duplicate prevention, absent video assets, offline network isolation, local project bounds, and untrusted message headers. CI runs the installed-wheel campaign demo and target-routing smoke checks as well.

## Complete release verification

Install the dev extra, then run `python scripts/verify.py`. Coverage is enforced at 90% with branch measurement. `scripts/check_installed_package.py` verifies the already-built wheel without editable installation/PYTHONPATH, using a fresh environment and path containing spaces. See TESTING.md for coverage scope and the CLI subprocess matrix.

## CLI and package release identity

Change `src/ai_threat_lab/_version.py` for a release; setuptools dynamic metadata and the CLI use this source. Reinstall an editable checkout after a version change, then run `doctor --installation`. See [CLI acceptance](CLI_OFFLINE_ACCEPTANCE.md) for exact options, stream behavior and archive/installed checks.
