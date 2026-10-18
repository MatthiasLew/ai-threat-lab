# Development

## Setup and validation

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m pytest -q
python -m build
```

CI runs lint, tests, package build, and an installed-wheel CLI smoke check on Linux and Windows with Python 3.12 and 3.13. Local verification covers the interpreter/platform used by the contributor; CI supplies the other environments.

## AI Dev CLI Tools

This project uses [ai-dev-cli-tools](https://github.com/MatthiasLew/ai-dev-cli-tools) as a development helper, not a runtime dependency. The foundation was checked with version 1.3.0. Project check commands are in `.ai-dev-tools.toml`.

```bash
python -m pip install ai-dev-cli-tools==1.3.0
ai-dev task --task "describe the change" --client codex --json
ai-dev check --mode full --json
ai-dev context build --profile implement --include "src/**/*.py"
```

Stage new source files before requesting change-focused context so Git exposes individual paths. Keep generated `.ai/` logs and context out of commits. A context-budget truncation warning indicates bounded output, not a failed application test. Investigate reproducible tool failures or missing behavior and propose a focused PR upstream; do not change that repository without evidence.

## Verification scope

Tests exercise all 25 matrix inputs, label boundaries, invalid ratings, catalog validation, profile adjustments, duplicate and overlapping defenses, scenario-specific controls, reduction caps, deterministic results, report metadata and UTF-8, refusal to overwrite reports, CLI errors, guided input, and all six CLI scenarios. GUI parity checks will be added when GUI exists.

## Contribution workflow

Project changes currently go to main after local checks, per the maintainer workflow. Update documentation together with the public service contract. Domain/application modules must not import Qt, read console input, or send network requests. Fix the issue demonstrated by a failing check before broadening the test scope.

Code-review tests cover risky patterns, simple import aliases, nonmatching examples, source non-execution, file encodings, input-size limits, output redaction, CLI exit codes and export preservation.

Campaign/assessment checks cover scope-before-provider validation, exact-content approvals, expiry, channel mismatches, cancellation, ambiguous send failures, persistent duplicate prevention, absent video assets, offline network isolation, local project bounds, and untrusted message headers. CI runs the installed-wheel campaign demo and target-routing smoke checks as well.
