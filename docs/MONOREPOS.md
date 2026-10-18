# Monorepo dependency inventory — 0.10.0

Supported dependency manifests can now be discovered in subprojects. This is **explicitly opted in**; ordinary commands keep root-only selection. Parsing remains static: no package installation, workspace resolution, requirements includes, hooks, target execution or model calls.

## Local commands

```bash
# Root manifests only, as before:
ai-threat-lab audit-deps path/to/project --output root-inventory.json
# Discover supported manifests in bounded subdirectories:
ai-threat-lab audit-deps path/to/project --recursive-dependencies --output inventory.json
# Include the nested inventory in a complete scan bundle:
ai-threat-lab scan path/to/project --recursive-dependencies --output-dir scan-results/monorepo-01
ai-threat-lab scan-check scan-results/monorepo-01
```

The recursive option requires a project directory. It is rejected for a single file, website, mail domain or mailbox. No network flag is needed for a local inventory. `--max-files` still controls GitHub collection, not the independent fixed local traversal bounds.

Supported basenames remain `requirements*.txt`, npm `package-lock.json` v2/v3, `uv.lock`, `poetry.lock` `Cargo.lock` v3/v4 (selected crates.io entries) and `go.sum` (selected module-content records; see [GO.md](GO.md)). Unsupported ecosystems such as pnpm/yarn are not silently resolved. Discovering a lockfile in a workspace is not a full interpretation of that workspace's dependency graph.

## Origins and deduplication

| Input | Recorded package origin |
| --- | --- |
| `requirements.txt` | `requirements.txt:LINE` |
| `services/api/requirements.txt` | `services/api/requirements.txt:LINE` |
| `apps/web/package-lock.json` | `apps/web/package-lock.json` |
| `workers/jobs/uv.lock` | `workers/jobs/uv.lock` |

Relative origins use `/` on every platform. They identify a manifest, not the exact JSON/TOML entry. Names and versions retain the existing normalization rules. Identical ecosystem/name/version identities are merged across all selected manifests with every origin preserved; different versions remain separate identities. If OSV sharing is explicitly enabled, one identity produces one query regardless of how many origins it has. Origins and file contents are not sent in OSV queries; package identities/versions are shared.

The in-memory parser accepts nested relative origins only when its caller explicitly passes `allow_paths=True`. They are labels and are never opened as filesystem paths. Absolute, drive-qualified, traversal, empty-component, backslash and control-character paths are rejected. Origin length is at most 1024 characters, with components at most 255 characters. Local directories with non-portable manifest paths are skipped with a notice.

## Local discovery bounds

| Bound | Limit and behavior |
| --- | --- |
| Selected manifests | 20 across the entire selected project, not 20 per subproject |
| Manifest size | 2 MiB; an oversized selected manifest fails inventory |
| Aggregate raw bytes | 4 MiB; stop before exceeding it and preserve an explicit unchecked notice |
| Distinct package identities | 500 across selected manifests; overflow fails inventory |
| Directories visited | 1000 including the root |
| Directory entries inspected | 10000 across discovery |
| Nested directory depth | 8 below the root; root files are depth 0 |
| Discovery notices | First 90 plus an omitted-notice count |

Traversal is breadth-first, sorting names within each directory. Root manifests precede child manifests; shallower directories precede deeper ones. If the entry budget truncates a directory listing, only entries already returned by the filesystem can be sorted; selection in that case is not guaranteed identical across operating systems.

The traversal skips `.git`, `.venv`, `venv`, `node_modules`, `__pycache__`, `dist` and `build`. File/directory symlinks and Windows junctions are skipped; root links/junctions are rejected. Subproject-relative paths never cause reads outside the selected tree through an intentionally followed link. The local tree is not locked or atomically snapshotted: concurrent modification can still affect observations; run against a stable checkout.

Limits, inaccessible directories, non-regular paths and skipped inputs remain in `not_checked`. An incomplete or empty inventory does not prove an absence of dependencies or vulnerabilities. A malformed selected manifest fails the dependency module in `scan` while preserving useful source observations. Standalone `audit-deps` returns an input error for malformed/oversized inputs.

Root-only mode also uses bounded discovery and the new aggregate 4 MiB cap. More than 20 supported root manifests still raises an error rather than silently changing the established contract. Recursive mode preserves its selected prefix and reports the manifest limit instead.

## GitHub collection

```bash
ai-threat-lab scan https://github.com/owner/repository --network --allow-host github.com --recursive-dependencies --output-dir scan-results/github-monorepo
```

This reuses the existing immutable default-branch commit and shared source/manifest retrieval. It never downloads an archive or checks out/executes repository files. Selected manifests are prioritized by depth and path before other eligible text files. Identical verified Git blobs are fetched once but still count for each selected path's file/byte budget.

Remote recursive mode inspects at most the first 10000 returned tree entries and manifest paths at most eight directories deep. This is a flat GitHub tree response, not local directory traversal, so the local 1000-directory cap does not apply. Invalid/traversal paths, excluded directories, symlinks and submodules are omitted. GitHub tree truncation and bounded coverage remain explicit.

The existing shared bounds still apply: default 50 selected file paths, configurable `--max-files 1..100`, 4 MiB decoded bytes, at most 20 manifests and 2 MiB per manifest. Ordinary source inspection remains limited to 256 KiB per file. Manifest priority can leave source files unreviewed at low file limits. Parser/package limits apply globally after collection, not once per subproject.

To query OSV, separately opt into `--share-packages` (with `--network`). The existing advisory cache remains keyed by exact package identity. Adding recursive discovery alone never enables advisory or AI calls. This release was tested against synthetic wire responses, not live GitHub/OSV targets.

## History and demonstration

Scope engine `read-only-pipeline-4` records strict boolean `recursive_dependencies`. Changing it disables observation deltas because collection coverage changed. Older engines 1–3 remain readable without this field; cross-engine deltas remain unavailable. An injected GitHub snapshot whose recursive coverage disagrees with the scan options fails the inventory module rather than overstating its scope.

`offline-demo` now contains duplicate root/subproject requirements and uses the recursive mode. It still makes no network/model calls and retains the existing synthetic 3-before/0-after observation example. The installed-wheel verification exercises both the combined recursive scan and standalone nested inventory outside the source checkout.
