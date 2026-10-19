# User guide

## Install and start

Python 3.12+ is required. From the repository root, create and activate a virtual environment, then install:

```bash
python -m venv .venv
# PowerShell: .venv\Scripts\Activate.ps1
# Linux/macOS: source .venv/bin/activate
python -m pip install -e .
python -m ai_threat_lab --help
```

The runtime has no third-party dependencies. Default commands stay offline; `audit --network` and explicitly approved `ai-explain --send-evidence` can contact their documented services. The installation step may download build tools. All scenarios describe fictional targets.

## Guided mode

```bash
python -m ai_threat_lab interactive
```

Enter a scenario ID from the displayed list, a fictional organization and role, access level, urgency, and space-separated existing/proposed control IDs. Empty profile answers accept defaults. The result is printed in the terminal. To export, use command mode below. Invalid answers end with an explanation and exit code 2; rerun to correct them. Ctrl+C cancels with exit code 130.

## Command mode

```bash
python -m ai_threat_lab scenarios
python -m ai_threat_lab controls
python -m ai_threat_lab analyze voice_deepfake --proposed callback --proposed independent_approval
```

Default target: Example Company, the scenario's default role, medium access, normal urgency. The voice example produces baseline **4 × 5 = 20 (Critical)** and residual **2 × 5 = 10 (High)**. Results use provisional educational rules rather than measured effectiveness.

| Option | Values / behavior |
| --- | --- |
| positional scenario | ai_phishing, voice_deepfake, video_deepfake, brute_force, credential_stuffing, insecure_generated_code |
| --organization | Fictional organization name |
| --role | Fictional employee role; descriptive, not an inferred risk input |
| --access | low, medium, high; adjusts impact by -1, 0, +1 before controls |
| --urgency | low, normal, high; adjusts likelihood by -1, 0, +1 before controls |
| --existing | One existing control ID; repeat for additional controls |
| --proposed | One additional control ID; repeat for additional controls |
| --format | txt (default) or json |
| --output | New file path; parent directory must exist |

Organization and role identify the fictional target. Access and urgency explicitly affect scoring. Existing controls affect baseline and residual; proposed controls affect residual only. Duplicates and existing/proposed overlaps are counted once. An irrelevant control receives an explanation and no reduction.

## Export

```bash
python -m ai_threat_lab analyze ai_phishing --format json --output analysis.json
python -m ai_threat_lab analyze video_deepfake --proposed source_verification --output analysis.txt
```

TXT includes stages, warning signs, interventions, consequences, controls, recommended additions, both assessments, explanations, and assumptions. JSON includes the same structured result, schema_version 1, and a UTC generation timestamp. Model version is `educational-1.0`.

Existing files are preserved. Missing parent directories, unwritable destinations, unknown IDs, and invalid profile values return a readable error and exit code 2. Successful commands return 0. The analyzer itself does not save files.

## Interpretation

A score of 20 is not a 20% probability. Score changes are not percentage reductions in real-world risk. Controls are assumed to be correctly implemented and followed. No money-loss forecast or media authenticity detection is performed.

## Future GUI

PySide6 screens will use the same service. See [GUI handoff](GUI_HANDOFF.md) for the executable integration example.

## Code security module

`python -m ai_threat_lab review-code example.py` performs local static pattern checks. Use `--format json` or `--output new-report.txt` for export, and optionally `--fail-on-findings` for exit code 1 when candidates exist. See [code review](CODE_REVIEW.md) for exact coverage and limitations. The source is not executed or sent to an API.

## Target-based assessment and campaign previews

```bash
python -m ai_threat_lab assess path/to/project
python -m ai_threat_lab assess path/to/message.eml
python -m ai_threat_lab campaign-demo voice_training
python -m ai_threat_lab campaign-report examples/training-events.json
```

`assess` returns JSON with status, evidence and unchecked areas. A website/repository URL is recognized but requires a registered adapter; no remote scan occurs by default. `campaign-demo` uses fictional content and simulated receipts only. Video remains a preview until an approved generated asset exists. Detailed guides: ASSESSMENT.md, CAMPAIGNS.md and INTEGRATIONS.md.

## Versioned workflow files and provider selection (0.3.0)

Use the complete campaign workflow in the root README to create a fictional request, prepare an exact preview, record reviewer approval and simulate dispatch. Each step can write a new JSON file with `--output`; existing files are preserved. `campaign-example` creates an expiry one hour from the current time. The video scenario remains preview-only until an approved media reference and digest exist.

`--config` is a global option and precedes the command. `providers` lists registrations; `doctor` checks selection without network requests. Exit codes are 0 for completed commands, 1 only for requested code-review findings, 2 for invalid input/file/ledger operations, 3 for missing/failed adapters, and 130 for cancellation. A successful command with an assessment status of partial/not_configured is not a security all-clear.

The CLI currently exposes simulated campaign execution only, irrespective of the configuration. Actual adapters are registered by trusted application code; JSON cannot import them. See PROVIDER_DEVELOPMENT.md.

## Read-only integrations and AI costs (0.4.0)

Use `audit` for the new collectors and `assess` for legacy offline routing. See [LIVE_SETUP.md](LIVE_SETUP.md) for exact commands, scope and credentials, and [API_COSTS.md](API_COSTS.md) for dry-run, budgets, caching and usage reconciliation. Remote adapters are tested with fixtures; live accounts remain unvalidated.

New commands: `audit`, `ai-explain`, `api-costs`, `api-reconcile`. Each provides `--help` and optional `--output`. Missing network consent or invalid input returns 2; integration/storage errors return 3. No automatic retries occur.

## Dependency and report commands (0.5.0)

`audit-deps PATH` inventories supported exact versions offline. `audit-deps PATH --network --share-packages` queries OSV. `audit-report REPORT.json ... --format html --output report.html` exports a combined offline remediation report. See [DEPENDENCIES_AND_REPORTS.md](DEPENDENCIES_AND_REPORTS.md).

## Local interactive training (0.6.0)

Create and approve a campaign preview, then run `training-start PLAN.json --approval APPROVAL.json --participant-id trainee-01 --ledger training.sqlite`. Use its returned session ID with `training-run`; only numbered actions are accepted. `training-report --ledger training.sqlite --format html --output training-report.html` exports practice outcomes. `training-cancel --plan-digest DIGEST --ledger training.sqlite` revokes that local plan. Full details: [TRAINING_LAB.md](TRAINING_LAB.md).

## One-command scans (0.7.0)

`scan TARGET --output-dir NEW_DIRECTORY` runs applicable built-in collectors and publishes a JSON/HTML bundle with module status and limits. For a local project, dependency inventory is automatic; OSV still requires `--network --share-packages`. `scan-check DIRECTORY` verifies hashes and report consistency; `scan-compare BEFORE AFTER` compares observations. Use `scan ... --baseline BEFORE` to include a comparison in the new bundle. See [SCAN_WORKFLOW.md](SCAN_WORKFLOW.md).

## Saved pages and ZIP archives

```bash
ai-threat-lab review-html saved-page.html --document-url https://example.com/login
ai-threat-lab review-html saved-page.html --format html --output page-review.html
ai-threat-lab audit archive.zip
ai-threat-lab scan-batch saved-page.html archive.zip --output-dir scans/local-01
```

The declared document URL supplies context only; no request is made. Audit/scan routes also recognize saved HTML, and selected project/GitHub HTML and EML forms reuse the bounded parser. ZIP is an explicit file target and is inspected without reading or extracting members. All results remain partial. Details and limits: [HTML review](HTML_REVIEW.md), [archive review](ARCHIVE_REVIEW.md).

## Offline login-event review

```bash
ai-threat-lab review-auth-log logins.auth.jsonl --fail-on-findings
ai-threat-lab review-auth-log logins.auth.jsonl --format html --output login-review.html
ai-threat-lab scan logins.auth.jsonl --output-dir scans/logins-01
```

Supply the normalized UTC JSON Lines format described in [AUTHENTICATION_LOGS.md](AUTHENTICATION_LOGS.md). Selected failure patterns are candidates; no account access or login attempts occur. Source/project walks do not automatically ingest authentication logs.

## Signed local training-event claims

Five new commands create a local signing key, register an exact approved plan/participant mapping, import a signed saved event, aggregate reports and cancel local acceptance. They do not provide a webhook listener or external transport. Follow the complete [signed-event workflow and protocol](SIGNED_TRAINING_EVENTS.md). Keep this journal separate from existing rehearsal/delivery databases.

## Recover an import result or stop both local ledgers

Use `training-events-receipt ENVELOPE.json --key-file KEY --ledger EVENTS.sqlite` after a lost import response. Use `training-local-status` / `training-local-cancel` with `--training-ledger`, `--event-ledger` and `--plan-digest` to inspect/stop both existing local ledgers. Both databases must be distinct DELETE-mode files in the same private directory. See [LOCAL_TRAINING_CONTROL.md](LOCAL_TRAINING_CONTROL.md). These commands do not control external services.

## Saved SSH log analysis

Run `review-ssh-journal logins.ssh.jsonl` on a saved supported single-host journal export; use `--format html --output REPORT.html` or `--fail-on-findings` as needed. `.ssh.jsonl` paths also work with single and batch scans. Export instructions and strict supported formats are in [SSH_JOURNAL_REVIEW.md](SSH_JOURNAL_REVIEW.md). No SSH connection or login attempt occurs.

## Maintain the AI cost ledger

`api-costs --ledger costs.sqlite` separates recorded amounts from unconfirmed reservations. `api-cache-prune --ledger costs.sqlite` clears expired cached text; add `--all` to clear unexpired cached text too. Neither cleanup nor expiry refunds money, deletes accounting or unblocks a pending request. These operational commands require an existing compatible ledger. See [API_COSTS.md](API_COSTS.md).

## Browse and export saved reports

Keep saved scan/batch directories under a private history parent. `history-list HISTORY_ROOT` verifies immediate children; add `--format html --output NEW_FILE` for a local catalog. Invalid entries remain visible and cause exit 2. `report-export SAVED_RUN --format html --output NEW_FILE` regenerates a verified saved report even after sources are removed. Outputs must stay outside saved run directories. See [LOCAL_REPORT_HISTORY.md](LOCAL_REPORT_HISTORY.md).
