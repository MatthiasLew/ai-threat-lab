# Install and run the console application

Use Python 3.12 or later. CI validates Python 3.12–3.14 on Linux and Windows. The application has no runtime package dependencies. Installation/build tooling may need network access; the installed offline workflows do not.

## Linux

From the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/ai-threat-lab --version
.venv/bin/ai-threat-lab doctor --installation
.venv/bin/ai-threat-lab --help
.venv/bin/ai-threat-lab offline-demo --output-dir "demo results/run-01"
```

## Windows PowerShell

From the repository root, with a supported Python selected by the launcher:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\ai-threat-lab.exe --version
.\.venv\Scripts\ai-threat-lab.exe doctor --installation
.\.venv\Scripts\ai-threat-lab.exe --help
.\.venv\Scripts\ai-threat-lab.exe offline-demo --output-dir "demo results/run-01"
```

These commands do not require virtual-environment activation or changes to PowerShell execution policy. You can substitute 3.13 or 3.14 when installed. After installation, `python -m ai_threat_lab` with the same venv interpreter accepts the same arguments as the console executable.

## Install a previously built wheel offline

Produce artifacts on a machine with the development tools:

```bash
python -m pip install -e ".[dev]"
python scripts/verify.py
```

Transfer the resulting `dist/ai_threat_lab-0.41.4-py3-none-any.whl` to the destination. Install using that destination's venv interpreter:

```bash
python -m pip install --no-index --no-deps /path/to/ai_threat_lab-0.41.4-py3-none-any.whl
python -m ai_threat_lab doctor --installation
```

A wheel can be installed without downloading build requirements. A source archive needs the declared setuptools build backend; installing source on a completely offline host requires those build tools to be available separately. Do not confuse the absence of application runtime dependencies with the availability of Python/pip/build tooling.

## Help, diagnostics and automation

Use `--help` at the root for the complete command list, then `COMMAND --help` for its options. Spell flags in full: abbreviations are rejected. Global `--config` precedes the subcommand and selects registered legacy workflow providers; it is not a universal network/API configuration override. Use the specific audit/AI command options documented in their help and guides.

`doctor` diagnoses selected adapter registrations. `doctor --installation` diagnoses local packaging. Neither checks live API availability. `readiness` lists implemented scope and deferred work; it is a static inventory. If installation reports a version mismatch after updating an editable checkout, reinstall it with the same interpreter and retry. If the catalog is missing/corrupt, reinstall a verified package. A source checkout without installed distribution metadata is explicitly reported as `source_checkout`.

| Exit | Meaning |
| --- | --- |
| 0 | Successful command; a report can still contain partial/not-configured assessment results. Inspect its module statuses. |
| 1 | Findings or incomplete results when the selected command's failure policy requests it; see command help. |
| 2 | Invalid arguments, inputs or local filesystem operation. Diagnostic goes to stderr. |
| 3 | Provider/integration/storage failure or failed doctor check. An uncertain API result must be reconciled before retrying. |
| 130 | Cancelled with Ctrl+C while running the command. |
| 141 | Downstream consumer closed a standard output/error pipe. |

Standard streams use UTF-8 regardless of legacy locale settings. JSON output is on stdout; command errors use stderr. Interactive prompts and report-saved notices are ordinary console output: use documented JSON/report options for machine consumers. A closed pipe can happen after a command has already written local artifacts; exit 141 does not undo those operations. Commands that save reports refuse existing output paths; choose a new run directory or filename.

See [the user guide](USER_GUIDE.md), [scan workflow](SCAN_WORKFLOW.md), [local report history](LOCAL_REPORT_HISTORY.md) and [the acceptance contract](CLI_OFFLINE_ACCEPTANCE.md).
