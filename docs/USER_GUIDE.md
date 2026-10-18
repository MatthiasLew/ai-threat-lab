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

The runtime has no third-party dependencies and makes no network requests. The installation step may download build tools. All scenarios describe fictional targets.

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
| positional scenario | ai_phishing, voice_deepfake, video_deepfake |
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
