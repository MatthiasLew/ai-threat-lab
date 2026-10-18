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
