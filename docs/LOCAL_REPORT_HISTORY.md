# Reports and local history — 0.33.0

This module closes the [finite local reporting contract](REPORTS_OFFLINE_ACCEPTANCE.md): existing JSON/HTML reports, Python SARIF, verified saved single/batch runs, observation comparison, a bounded history catalog and saved-report export. It does not rescan original targets, invoke a model, contact providers or open a browser. No account/API setup is required.

## Organize and inspect history

Keep each single scan or batch in a separate directory under one private history root:

```bash
ai-threat-lab scan path/to/project --output-dir history/run-01
ai-threat-lab scan path/to/project --output-dir history/run-02 --baseline history/run-01
ai-threat-lab scan-batch path/to/project export.eml --output-dir history/batch-01
ai-threat-lab history-list history
ai-threat-lab history-list history --format html --output history/catalog.html
```

The catalog verifies immediate child directories only. It never follows targets named inside saved reports. A batch is one catalog entry; its indexed child bundles are checked but not displayed as independent top-level history entries. Directory-name ordering is deterministic and does not imply chronology or a latest result. Scan creation timestamps are saved claims. The existing batch format has no creation timestamp or global run ID, so those fields are explicitly null/“Not recorded”. Copied folders count as catalog entries, not proof of independent executions.

Each verified entry includes kind, available ID/time, saved target names, unique observation count, failed module/run names and any saved comparison summary. A verified entry can have failed assessment modules: consistency is separate from successful collection or secure targets. Invalid/incomplete/unreadable entries expose only their directory, invalid status and a fixed diagnostic reason; no zero-finding summary is invented. Linked entries are rejected visibly. Unrelated files/directories are omitted with counts. Directories containing familiar report artifact names but no completed marker are invalid, rather than silently treated as an empty run.

The root must already exist, be a directory and not be a preflight symlink/junction. Pass the parent of saved runs; passing an individual run is an input error. History names must be valid UTF-8. Limits are 100 immediate root entries, 20 recognized/rejected run entries and 32 immediate entries per candidate directory. Overlarge candidate directories appear invalid. Root/run-count exhaustion rejects the catalog without output; organize larger collections into separate history roots. There is no recursive discovery, automatic truncation, date inference or auto-deletion.

Verification shares a 128 MiB aggregate read budget, counting actual bytes read including repeated child/manifest verification and invalid captures. Exhaustion rejects the whole catalog without publishing output. Each existing scan/batch artifact limit remains in force. One extra sentinel byte can be read to detect a limit. Filesystem enumeration/stat calls are not content reads. The JSON/HTML catalog output is capped at 4 MiB.

History JSON/HTML can be written outside the root or as a new file directly in it. It cannot be placed inside any child saved-run directory, because adding an unindexed artifact would invalidate that run. Existing files are never overwritten. A newly exported catalog is private on POSIX (`0600`), with inherited directory ACLs on Windows. HTML escapes all displayed values and contains no executable script, remote assets or clickable untrusted targets.

## Export a saved report

```bash
ai-threat-lab report-export history/run-01 --output exported-report.json
ai-threat-lab report-export history/run-01 --format html --output exported-report.html
ai-threat-lab report-export history/batch-01 --format html --output exported-batch.html
```

The input must be a verified single/batch run, not an individual JSON file or a history root. JSON/HTML is regenerated from the saved assessment evidence and checked against the indexed report. It works after original targets are moved/deleted, including targets that originally required network collection. It never recollects data or contacts those services.

Exports are limited to 8 MiB. Output defaults to stdout; `--output` must name a new file outside the entire saved run, including its children. Invalid/incomplete input, unsupported format or an exceeded byte limit creates no export. File writes use exclusive creation and private new-file permissions. A write failure removes only the owned incomplete output if it has not been replaced by another file. A process crash can still leave incomplete output; there is no resume or power-loss durability guarantee.

SARIF remains the existing standalone Python review export through `review-code --format sarif`. Saved combined reports are not converted into SARIF or PDF. See [SARIF.md](SARIF.md).

## What verification establishes

Single bundles require exact indexed files, strict bounded JSON, manifest scope/digests, valid module records, matching assessment/dependency target scope, and regenerated JSON **and HTML**. JSON derivation distinguishes numeric types: Boolean true cannot impersonate an integer count. Comparison metadata requires the declared current run ID, strict Boolean/count fields, valid finding identity/provenance, disjoint groups and exact current-side coverage. An unavailable comparison cannot claim observation deltas.

The previous bundle is not embedded in a saved comparison. Verifying one run checks the comparison's structure/current side; it cannot independently establish its old-side claims. Use `scan-compare PREVIOUS CURRENT` with both verified bundles to recompute a comparison. Existing conservative scope/engine/module-coverage gates remain, and disappearance is not proof of remediation. Assessment engines and observation IDs are unchanged by this milestone; previously supported engine versions remain readable.

Batch verification retains its exact child-manifest/index, derived combined JSON/HTML and summary checks. Shared readers require regular files, reject preflight links/junctions/special files and check descriptor type; no-follow/nonblocking flags are used where available. A FIFO manifest cannot silently block waiting for input. Publication cleanup retains files that another actor replaced after an earlier write.

Hashes and regenerated content establish local consistency, not signatures, authenticity, completeness, immutable history or a verified security conclusion. A writer who can replace all input assessments and indexes can forge a consistent bundle. Parent directories must be trusted; verification is not an atomic filesystem snapshot or a general access-control boundary. Retain whole directories when copying/backing up results, verify the copy separately, and protect targets, evidence, dependency names and exports as sensitive data. No retention deletion, encryption or central multi-user history service is implemented here.

## Exit policy

| Command/result | Exit |
| --- | --- |
| History catalog produced with no invalid entries | 0, including an empty catalog; no security all-clear |
| Catalog produced with invalid entries | 2; JSON/HTML remains available for review |
| Invalid root, exhausted global limits, existing destination or output error | 2; no completed catalog/export |
| Verified saved report exported | 0; partial assessment status and limitations preserved |

An invalid catalog does not delete or repair history. Inspect individual entries with `scan-check`/`batch-check`, retain incomplete evidence if useful, and choose a new output directory for future scans. New scans never overwrite prior runs automatically.

## Acceptance evidence

Seven pre-fix regressions cover rehashed HTML, typed counts, scope/kind/dependency mismatches, false comparison counts, cleanup replacement loss and HTML summary escaping. History/export tests cover deleted source targets, single/batch/comparison provenance, invalid entries, limits, read accounting, escaping, links, special files and output failures. The synthetic demo and clean installed wheel exercise catalog/export without source access. See [REPORTS_OFFLINE_ACCEPTANCE.md](REPORTS_OFFLINE_ACCEPTANCE.md).
