# AI Threat Lab

Offline security assessment foundation and training-scenario toolkit for AI-assisted threats.

The intended workflow is **target → relevant checks → evidence → possible impact → remediation**. Training campaigns separately measure verification/reporting behavior using synthetic data. The same Python services can later power a GUI and optional provider integrations.

## Project status — 0.2.0

Implemented: limited Python file/project review, exported-mail header observations, target routing, six educational risk scenarios, three prepared training-campaign scenarios, provider contracts, offline demos, event aggregation, and TXT/JSON outputs.

Not configured: actual GitHub retrieval, website testing, mailbox/DNS auditing, live email or phone dispatch, synthetic-media generation, or an AI provider. These need concrete adapters and relevant access, not just an API key. The CLI makes no network requests.

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

It never executes or uploads the source. Findings require human review. See [code review](docs/CODE_REVIEW.md) and [catalog extension guide](docs/EXTENDING_SCENARIOS.md).

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
