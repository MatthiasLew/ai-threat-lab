# AI Threat Lab

Read-only security assessments, optional AI explanations with budget controls, and offline training exercises.

The intended workflow is **target → relevant checks → evidence → possible impact → remediation**. Local training rehearsals record selected practice actions using synthetic data. The same Python services can later power a GUI and optional provider integrations.

## Project status — 0.15.0

Implemented: offline multi-target batches with verified combined reports, one-command scoped scans with integrity-checked report bundles and observation comparison, bounded read-only GitHub retrieval/review with shared-commit root/opt-in nested dependency inventory, passive HTTPS header checks, basic SPF/DMARC and supplied-selector DKIM observations, authenticated Gmail forwarding/filter checks, local Python (nine AST rule families, text/JSON/SARIF export)/secret/manifest and literal Dockerfile/workflow review, pinned Python/npm/Cargo dependency inventory and opt-in OSV matches, combined JSON/HTML remediation reports, bounded PE/ELF header and flag observations, bounded exported-mail header/link/attachment-metadata observations, approved local text-training sessions with durable actions/cancellation, offline training workflows, and an OpenAI Responses explanation adapter with persistent cost controls.

Remote collection is explicit through `audit --network --allow-host ...`; default commands stay offline. All assessment results remain partial. Integrations are fixture-tested, not live-account validated. Live email/phone campaigns, media generation, active exploitation, comprehensive dependency/binary analysis and a GUI are not implemented. A key alone does not provide these features.

Local multi-target workflow: [batch scans](docs/BATCH_SCANS.md).

New offline checks: [Rust lockfiles](docs/CARGO.md) and [exported mail](docs/MAIL_REVIEW.md).

Start with [live setup and capability limits](docs/LIVE_SETUP.md), [AI cost controls](docs/API_COSTS.md), and the [capability matrix](docs/INTEGRATIONS.md).

## Offline acceptance kit

```bash
ai-threat-lab readiness
ai-threat-lab offline-demo --output-dir demo-results/run-01
```

Open the generated `index.html` for synthetic before/after scans and all three local training channels. Approved exercise packs can also be exported as inert email previews, voice scripts and video storyboards. No API, message sending, call or media generation occurs. [Offline walkthrough](docs/OFFLINE_ACCEPTANCE.md), [configuration rules](docs/CONFIGURATION_CHECKS.md) and [complete delivery/gap matrix](docs/DELIVERY_STATUS.md).

## Quick start

Requires Python 3.12 or later. No runtime dependencies, AI API, GPU, or network are needed after installation.

```bash
python -m venv .venv
```

Activate with `.venv\Scripts\Activate.ps1` in PowerShell or `source .venv/bin/activate` on Linux/macOS, then:

```bash
python -m pip install -e ".[dev]"
python -m ai_threat_lab scenarios
python -m ai_threat_lab interactive
python -m ai_threat_lab analyze voice_deepfake --proposed callback --proposed independent_approval
python -m ai_threat_lab analyze voice_deepfake --proposed callback --format json --output analysis.json
```

The installed `ai-threat-lab` entrypoint accepts the same arguments. Exports create a new file and refuse to overwrite existing reports. See the [user guide](docs/USER_GUIDE.md) for all options and expected results.

## One-command scans and comparison

```bash
ai-threat-lab scan path/to/project --output-dir scan-results/run-01
ai-threat-lab scan-check scan-results/run-01
# GitHub source and root lockfiles from the same commit:
ai-threat-lab scan https://github.com/owner/repository --network --allow-host github.com --output-dir scan-results/github-01
# Run again after reviewing or changing the same target:
ai-threat-lab scan path/to/project --output-dir scan-results/run-02 --baseline scan-results/run-01
ai-threat-lab scan-compare scan-results/run-01 scan-results/run-02
```

The bundle includes source observations, an automatic root dependency inventory, module status, JSON/HTML reports and a hash manifest. Online dependency checks additionally require `--network --share-packages`. Remote targets require `--network --allow-host EXACT_HOST`. No model call occurs. Failures remain explicit; disappearance is labeled **no longer observed**, never automatically **fixed**. [Scan workflow and limits](docs/SCAN_WORKFLOW.md).

For monorepos, add `--recursive-dependencies` to `scan` or `audit-deps` to inventory supported manifests in bounded subdirectories, preserving subproject origins. Root-only remains the default. [Monorepo rules and limits](docs/MONOREPOS.md).

## Read-only audits and optional AI

```bash
ai-threat-lab audit path/to/project --output assessment.json
ai-threat-lab audit https://github.com/owner/repository --network --allow-host github.com
ai-threat-lab audit https://your-domain.example --network --allow-host your-domain.example
ai-threat-lab audit mail-domain:your-domain.example --network --allow-host your-domain.example --dkim-selector actual-selector
# Estimate only: no key or API call. Replace the example model/prices before live use.
ai-threat-lab ai-explain assessment.json --ai-config examples/ai-budget.json --ledger costs.sqlite --dry-run
ai-threat-lab api-costs --ledger costs.sqlite
```

API costs are reduced by local checks first, deduplicated minimal evidence, explicit output limits and optional exact-match caching. Atomic SQLite reservations enforce a local daily budget and request count; uncertain calls retain reservations and are never automatically retried. Example prices are synthetic. See [API_COSTS.md](docs/API_COSTS.md) before transmitting evidence.

Local program-file paths now receive bounded PE/ELF header and flag observations, with malformed structures explicitly marked unchecked. No binary is executed. [Binary scope, checks and limitations](docs/BINARY_AUDIT.md).

## Dependency advisories and combined reports

```bash
# Offline pinned-version inventory; no installation or API call:
ai-threat-lab audit-deps path/to/project --output inventory.json
# Explicitly share package names/versions with OSV, without using an AI model:
ai-threat-lab audit-deps path/to/project --network --share-packages --advisory-cache advisories.sqlite --output dependencies.json
ai-threat-lab audit-report assessment.json dependencies.json --output combined.json
ai-threat-lab audit-report assessment.json dependencies.json --format html --output report.html
```

Supported inputs are `requirements*.txt` with exact pins, npm `package-lock.json` versions 2/3, `uv.lock` and `poetry.lock`. Only the specified directory's supported manifests are read; no recursive dependency installation or resolution occurs. OSV findings are advisory/version matches, not proof of exploitability. HTML works offline and contains no scripts or external assets. [Dependency and report guide](docs/DEPENDENCIES_AND_REPORTS.md).

## Complete offline campaign workflow

```bash
python -m ai_threat_lab --config examples/providers.json doctor
python -m ai_threat_lab campaign-example voice_training --output request.json
python -m ai_threat_lab campaign-prepare request.json --output plan.json
# Review plan.json before recording approval:
python -m ai_threat_lab campaign-approve plan.json --reviewer "Reviewer" --output approval.json
python -m ai_threat_lab campaign-simulate plan.json --approval approval.json --ledger attempts.sqlite --output result.json
```

This simulates only; it cannot send messages or place calls. Reusing the same plan and ledger is rejected. See [provider development](docs/PROVIDER_DEVELOPMENT.md) for API adapter contracts and [testing](docs/TESTING.md) for the full validation strategy.

## Local interactive training

Use the approved plan/approval files from the workflow above:

```bash
ai-threat-lab training-start plan.json --approval approval.json --participant-id trainee-01 --ledger training.sqlite --output session.json
# Copy session_id from session.json; enter only numbered menu selections:
ai-threat-lab training-run SESSION_ID --ledger training.sqlite
ai-threat-lab training-report --ledger training.sqlite --format html --output training-report.html
# Permanently revoke this local plan; copy plan_digest from session.json:
ai-threat-lab training-cancel --plan-digest PLAN_DIGEST --ledger training.sqlite
```

This is a **local text rehearsal** for email, voice or video scenarios. It never sends, calls, opens links, loads media or records raw responses. The SQLite session survives restarts and enforces preview approval, scope expiry, action replay protection and cancellation. Reports describe operator-selected actions, not measured employee behavior or proven identity verification. See [training lab guide](docs/TRAINING_LAB.md).

## Assessment and training demos

```bash
python -m ai_threat_lab assess path/to/project
python -m ai_threat_lab assess path/to/export.eml
python -m ai_threat_lab assess https://example.invalid
python -m ai_threat_lab campaigns
python -m ai_threat_lab campaign-demo voice_training
python -m ai_threat_lab campaign-report examples/training-events.json
```

Local checks report candidates and unchecked areas. Remote targets without adapters return `not_configured`, never a security guarantee. Training demos use fictional identities and synthetic information; no messages or calls are sent.

See [assessment](docs/ASSESSMENT.md), [campaign scenarios](docs/CAMPAIGNS.md), and [integration contracts](docs/INTEGRATIONS.md).

## Educational risk modules

The catalog also includes **brute force**, **credential stuffing**, and **security flaws in AI-generated code**. These describe fictional risks and defenses; no passwords are generated or attempted.

A separate local Python reviewer finds selected risky constructs:

```bash
python -m ai_threat_lab review-code path/to/example.py --format json
```

It never executes or uploads the source. Findings require human review. See [SARIF export](docs/SARIF.md), [code review](docs/CODE_REVIEW.md) and [catalog extension guide](docs/EXTENDING_SCENARIOS.md).

## Educational risk workflow

1. Select a social-engineering, authentication-threat, or code-security scenario.
2. Configure a fictional target, its access level, and organizational context.
3. Review campaign stages, warning signs, and potential consequences.
4. Inspect an explained likelihood and impact assessment.
5. Select applicable defenses and compare baseline and residual risk.
6. Export the analysis as TXT or JSON.

The educational risk module uses predefined scenarios and deterministic rules. It does not require an AI API, GPU, or online service. AI is the subject of the analysis; live content generation is not an MVP requirement.

## Technology

| Component | Choice |
| --- | --- |
| Shared engine | Python 3.12+ |
| Domain models | Typed dataclasses |
| First interface | CLI using argparse and interactive prompts |
| Desktop interface | PySide6, implemented after the core contract is agreed |
| Scenario catalog | Versioned JSON |
| Initial exports | TXT and JSON |
| Verification | pytest |

## Core design principle

The CLI and GUI will call the same application service. Domain logic will contain no `input()`, `print()`, or Qt dependencies. The GUI will be an additional interface, so the console application will not need to be rewritten.

Mateusz reviews the application behavior; development focuses on reusable services, CLI, exports, and tests. The GUI contributor will implement desktop screens and connect them to the shared service.

## Risk assessment

The initial educational matrix uses **risk = likelihood × impact**, with each input rated from 1 to 5.

| Score | Label |
| --- | --- |
| 1–4 | Low |
| 5–9 | Moderate |
| 10–14 | High |
| 15–19 | Very high |
| 20–25 | Critical |

Scores are illustrative ordinal assessments, not measured probabilities, financial forecasts, or certified security conclusions. Control adjustments must be scenario-specific and explained. The project will not present invented effectiveness percentages as evidence.

## Documentation

- [Documentation index](docs/README.md)
- [Design diagrams](docs/DIAGRAMS.md)
- [Planned user guide](docs/USER_GUIDE.md)

- [Project scope and requirements](docs/PROJECT_PLAN.md)
- [Implementation roadmap](docs/ROADMAP.md)
- [Architecture and proposed service contract](docs/ARCHITECTURE.md)
- [Scenario catalog](docs/SCENARIOS.md)
- [Risk model and limitations](docs/RISK_MODEL.md)
- [GUI handoff](docs/GUI_HANDOFF.md)
- [Development and acceptance checks](docs/DEVELOPMENT.md)

## Educational boundaries

Training demos and risk simulation consist of local fictional narratives and rule-based assessments. Actual local source/mail checks have explicitly limited coverage. It does not send phishing messages, collect credentials, impersonate real people, clone voices, generate deceptive videos, or attack external systems. Potential losses will be described qualitatively unless the user supplies explicitly fictional amounts.
