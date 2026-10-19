# Offline Python review SARIF export — 0.13.0

`review-code` can export its fourteen bounded Python rule families as SARIF 2.1.0. This is a local interchange file for compatible analysis viewers; it does not upload to GitHub, contact a provider, execute the target or enable broader analysis.

## Console usage

```bash
# Default: source basename only, no absolute parent directories:
ai-threat-lab review-code src/example.py --format sarif --output review.sarif
# Keep the path relative to an explicit existing project root:
ai-threat-lab review-code src/example.py --format sarif --source-root . --output project-review.sarif --fail-on-findings
```

The report destination must be new. Exit 0 means the requested review/export completed; exit 1 means candidates were found with `--fail-on-findings`; exit 2 means invalid source/options/root or a file error. Findings still produce a complete report before exit 1. An invalid root is rejected before the output is created. Without `--output`, stdout contains the SARIF JSON and no progress messages on success.

`--source-root` is accepted only with SARIF. Both root and source are resolved on the local platform; the root must exist and be a directory, and the source must resolve inside it. Parent traversal and symlinks cannot be used to export an outside source under a misleading relative path. This path check is not an atomic filesystem snapshot or a general access-control boundary.

Default basenames omit private parent directories but may be ambiguous across separate reports. Supply the repository root to retain nested paths. Relative paths use forward slashes; spaces, Unicode, `%`, `#`, `?` and `:` are URI encoded. Filenames and relative paths can themselves be sensitive. Review them before sharing. A consumer must know the matching source checkout/root to navigate to it; the exporter does not package source files or preserve a repository commit.

## Document contract

Each document contains one run and one source artifact, even for an empty result. Rule descriptors include only observed rule IDs, sorted and deduplicated. Each observation carries its rule ID and matching descriptor index, static rationale and recommendation, and a source line. Repeated calls remain separate observations.

Every result is a `warning` with `candidateOnly: true`; `patternSeverity` preserves the original heuristic severity without claiming validated exploitability or a CVSS score. Run properties preserve the engine and coverage limitations. An empty `results` array is not a security all-clear. There are no source snippets/contents, source argument values, environment variables, invocation command lines, absolute root locations, fingerprints, suppressions, automatic fixes or upload receipts.

Python AST columns count UTF-8 bytes. SARIF locations intentionally provide `startLine` without a character column. The original one-based byte column is retained only as `properties.pythonUtf8ByteColumn`; it must not be interpreted as a SARIF character column. This keeps Unicode and emoji locations from being highlighted incorrectly. Text/JSON reports retain their existing byte-column behavior.

The export covers standalone Python review only. Combined scan bundles, binary/configuration/dependency/mailbox findings and training outcomes are not converted. Their existing JSON/HTML formats and scan engine remain unchanged. Automatic upload, source-control permissions and individual viewer compatibility have not been live validated.

## Python integration

```python
from pathlib import Path
from ai_threat_lab import review_file
from ai_threat_lab.code_review import render_code_review

result = review_file(Path("src/example.py"))
content = render_code_review(result, "sarif", source_root=Path("."))
with Path("review.sarif").open("x", encoding="utf-8") as output:
    output.write(content)
```

Rendering alone does not save a file. Default basename rendering uses the recorded filename without reopening the source. The optional root check resolves existing paths, so use it while the reviewed file remains available. The underlying review does not lock or snapshot the source.

Format references: [OASIS SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) and [official JSON schema](https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json). Regression/CLI coverage and the separate schema-validation check are described in [TESTING.md](TESTING.md).
