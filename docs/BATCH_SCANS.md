# Offline multi-target batches — 0.15.0

Use one command to inspect several explicit local projects, Python files, exported `.eml` messages or program files and collect their candidate findings into one remediation queue.

```bash
ai-threat-lab scan-batch path/to/project path/to/export.eml path/to/program.exe --output-dir batch-results/run-01 --recursive-dependencies --fail-on-findings
ai-threat-lab batch-check batch-results/run-01
ai-threat-lab batch-check batch-results/run-01 --output checked-batch.json
```

Open `batch-results/run-01/report.html` locally after checking it. The JSON report preserves assessment sources, target names, candidate status and unchecked areas. New report/verification destinations must not already exist. There is no automatic browser opening, model call, network lookup, message sending, retry, resume or scheduler.

## Input and scope

Select 1–10 explicit local paths. Relative paths are resolved from the current working directory. Targets must exist and be regular files or directories; root symlinks/junctions, duplicates and overlapping project/child targets are rejected before the output directory is created. Output must remain outside every selected project. This prevents scanning newly generated reports as part of a target.

Remote website/GitHub/mail-domain/mailbox targets are rejected. No `--network`, package-sharing, advisory-cache or provider selection option is provided by this command. It uses the built-in local collectors. The global legacy `--config` does not replace them. Single target remote scans remain a separate explicitly opted-in operation.

`--recursive-dependencies` applies only to directory targets; file targets retain their normal collector. Dependency inventory is attached to project-directory targets. A single lockfile should be inspected with `audit-deps`; batch routing does not reinterpret a program-file target as a dependency project. Existing per-collector limits, skipped files and partial coverage remain in each child bundle and combined report. Sources are read individually without a filesystem snapshot or lock.

## Output and completion

| Path | Meaning |
| --- | --- |
| `run-01/` … `run-10/` | Existing scan bundles in input order, with their own manifests, module status and reports |
| `report.json` / `report.html` | Combined source assessments and dependency-result documents; escaped HTML with no active/external content |
| `batch.json` | Versioned local index, exact child-manifest SHA-256 values, parent artifact hashes/sizes and derived summary; written last |

A new private directory is claimed before collection (`0700` on POSIX; inherited ACLs on Windows). All target selection/scope validation happens first. Each child publishes independently using the existing manifest-last protocol. The parent reports are written after successful child verification; `batch.json` is written last. This is a logical completion marker, not an atomic directory snapshot or a power-loss durability guarantee.

Target collector/module failures are isolated by the existing scan service: a child can publish useful partial evidence with failed modules, and later targets still run. The parent summary lists `failed_runs` and the combined report retains their gaps. Disk/publication errors, cancellation or a batch resource limit abort the batch without the final marker. Already written child/parent files can remain; inspect them and choose a new output directory. Existing/incomplete destinations are never overwritten or automatically resumed. The checker rejects incomplete publication.

## Verification and limits

`batch-check` reads the saved results, not the original source files. It can verify a batch after those sources have moved or been deleted. It checks the bounded strict index, fixed child directory names, indexed root entries, child manifest hashes, existing child-bundle consistency, local offline scope, parent artifact hashes/sizes, exact regenerated combined JSON/HTML and recomputed summary. Changing a source after collection does not change saved evidence or prove remediation.

The marker is capped at 1 MiB; each parent report is capped at 8 MiB. Child artifacts plus their manifests share a 64 MiB total limit, and all standalone bundle limits still apply. The limit is checked after each child completes and before starting another. A child that exceeds the remaining budget can already be present on disk when the batch stops. At most 20 assessment documents (up to two per target) feed the existing merger, with its 2000-findings-per-document limit. Narrow scopes when limits are exceeded.

Hashes verify consistency, not authenticity. Someone able to rewrite all indexed artifacts can forge mutually consistent results. There is no signature, encryption, remote attestation or central retention policy. The filesystem can change during reads; the checker is not an atomic snapshot or a general access-control boundary. Reports contain sensitive target paths, package identities and selected evidence; protect the entire result directory.

## Exit policy

| Exit | Meaning |
| --- | --- |
| 0 | Batch published with no failed modules, or consistency check passed; coverage remains partial |
| 1 | Batch has observations and `--fail-on-findings` was selected |
| 2 | Invalid selection, existing destination, invalid/incomplete/tampered batch or file/publication error |
| 3 | Published batch contains failed target modules; takes precedence over finding-based exit 1 |
| 130 | Keyboard cancellation; inspect incomplete output before choosing another destination |

A checker exit 0 means saved evidence is internally consistent even when the checked assessment summary records module failures. It never means that the targets are secure or that an original failure is fixed. A zero-finding report also retains its unchecked areas.

## Python integration

```python
from pathlib import Path
from ai_threat_lab.batch_scan import run_batch, check_batch

summary = run_batch(["project-a", "export.eml"], Path("batch-results/run-01"))
verification = check_batch(Path("batch-results/run-01"))
```

The offline demo includes a two-target example, and installed-wheel acceptance checks both commands outside the checkout. See [TESTING.md](TESTING.md), [scan bundles](SCAN_WORKFLOW.md), and the [delivery matrix](DELIVERY_STATUS.md) for what remains outside this workflow.
