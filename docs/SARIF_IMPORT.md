# Import saved static-analysis results

`review-sarif` brings a saved SARIF 2.1.0 report into the same local summary and
optional AI evidence workflow. This enables review of observations from other
language analyzers without pretending the built-in Python analyzer covered them.
The command does not install or invoke a scanner, fetch rules, open source files,
apply fixes or visit any referenced URI.

```bash
ai-threat-lab review-sarif scanner-results.sarif --output imported.json
ai-threat-lab brief imported.json
ai-threat-lab review-sarif scanner-results.sarif --start 201 --max-entries 200 --output next.json
```

The producer report must already exist. Use the scanner's own configuration and
execution evidence to establish what it checked. Imported observations are always
unverified claims, even if a producer labels them an error or confirmed issue.

## Selected projection

Each retained result includes its run/result index, reported rule identity,
plain-text message, reported level/kind, baseline state, suppression status and
up to three physical locations with optional start lines. Index references into
the same run's driver rules and artifacts are resolved; contradictory references
are rejected. URI base identifiers remain explicitly unresolved. Paths are text,
not paths the importer opens.

Passing, suppressed and baseline-absent records remain visible with their stated
classification. They must not be read as active vulnerabilities. Missing severity
or kind remains labelled not reported; this projection does not infer configuration
defaults or CVSS.

Failed invocations and error notifications mark incomplete producer execution
while preserving supported results. Missing invocation evidence remains unknown.
External property references are not loaded and make the import incomplete.
The optional producer `properties.limitations` list is preserved as producer claims.
Malformed selected results are counted as unavailable; other results remain.

Source snippets, artifact contents, invocation environment, command lines,
code flows, fixes, related locations and external message catalogs are not imported.
Results requiring message IDs/catalog resolution or tool-component rule references
are marked unsupported. This is a bounded projection, not a full SARIF validator/viewer.

## Bounds and privacy

The input is a regular file up to 8 MiB, with 1–20 runs and at most 10,000 result
records per run. One call selects at most 200 results using a global one-based
index across available run result arrays. Rule/artifact tables are bounded at
10,000 entries, invocation lists at 100, and notification lists at 1,000.
Messages are limited to 2,000 characters and individual location URIs to 1,024.
Oversized or unsupported values remain explicit gaps.

Reports omit the input filename but retain selected producer messages, rule IDs
and source locations. **These can contain secrets or identifying data.** Read the
saved report and exact AI preview before sharing. This import is not anonymization.
All string values are treated as data; no imported instruction is executed.

The report works with `brief`, `ai-prepare` and `ai-review` after the SARIF source
is removed. Local integrity does not establish producer authenticity or source
freshness. An empty result list is not a clean bill of health.

Exit 2 indicates invalid input or an incomplete import, 1 indicates findings when
`--fail-on-findings` is selected, and 0 otherwise. Existing output files are never
overwritten. All acceptance fixtures are local and synthetic.

Reference: [OASIS SARIF 2.1.0 with Errata 01](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html).
