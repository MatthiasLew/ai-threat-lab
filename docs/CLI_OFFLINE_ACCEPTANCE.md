# CLI and installation completion — 0.34.0

This milestone closes the existing console interface and Python packaging contract. It adds no analyzer or provider. API setup remains deferred. The accepted platforms are Linux and Windows with Python 3.12, 3.13 and 3.14, as exercised by the release CI matrix. macOS and other interpreters are not validated by that matrix.

| Requirement | Observable acceptance |
| --- | --- |
| Release identity | `_version.py` supplies the public `__version__`, CLI version, wheel and source-distribution metadata. Installed console and module entrypoints report the same exact release. |
| Argument contract | Complete option names are required at the root and in every subcommand. `--ver`, `--hel` and `doctor --instal` fail with exit 2. Existing full option names remain valid. |
| Command availability | Every registered command has working process-level help; the clean wheel gate discovers the installed parser and exercises every command's help. Existing workflows retain dedicated functional tests. |
| Stream contract | Both process entrypoints use UTF-8 for standard input/output/error, including legacy locales. JSON stays parseable and Unicode organization/path text survives. Malformed UTF-8 interactive input gives a concise error. |
| Closed pipe | If the consumer closes output, the process exits 141 without a traceback or shutdown diagnostic. Help/version paths and ordinary commands receive the same handling. |
| Diagnostics | `doctor --installation` checks Python support, runtime/distribution identity and the bundled catalog without reading credentials or making network calls. Missing metadata is identified as source-checkout mode. Mismatched installed metadata or missing/corrupt catalog is a failure; catalog records use the same full schema/rule/identity validation as runtime analysis. |
| Distribution contents | Wheel and sdist metadata, Python minimum, entrypoint, runtime dependency absence, version file and catalog are checked. Catalog and version bytes agree across artifacts. |
| Installation isolation | `python -m build` creates the sdist and builds the wheel from it. The gate installs that wheel using `--no-index --no-deps` into a fresh venv and runs from a different directory, with spaces in both paths and without `PYTHONPATH`. |
| Regression gate | Full tests under branch coverage, Ruff, artifact build, installed workflows and six CI jobs must pass for the release commit. |

Run the complete gate with `python scripts/verify.py`. The process-level regressions live in `tests/test_cli_installation.py` and `tests/test_cli_process.py`; `scripts/check_installed_package.py` verifies the release artifacts and installed behavior. Subprocess tests provide behavioral evidence, but their child execution is not added to the parent coverage measurement.

`main(argv, registry=...)` remains the reusable Python command handler. The executable and `python -m ai_threat_lab` use `entrypoint()` to configure process streams and flush output before interpreter shutdown. Applications embedding the handler keep ownership of their streams.

This contract does not include a GUI, a standalone executable/Python installer, shell completion, distribution signing, macOS certification or real provider/account validation. It does not establish completeness of the assessment product. See [installation and usage](CLI_INSTALLATION.md) and [remaining product work](DELIVERY_STATUS.md).

Windows CRT output can report `EINVAL` for a closed pipe. The process boundary normalizes that error only on a write/flush to an actual pipe descriptor; regular-file errors retain their normal behavior. Failed buffered streams are closed before shutdown to avoid a second flush. Process tests run on Windows as well as Linux, and byte-level diagnostics allow each platform's line endings.
