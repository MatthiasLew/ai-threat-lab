# AI Threat Lab

Educational simulator and risk analyzer for AI-driven social engineering and deepfake threats.

AI Threat Lab is a student project designed to explain who a threat targets, how a fictional campaign unfolds, what damage it could cause, and how protective measures change the assessment.

## Project status

**Planning stage.** This repository currently contains project documentation only. The Python engine, CLI, GUI, and report exporters are planned and are not yet implemented. No installation or execution commands are available yet.

## Planned workflow

1. Select an AI phishing, voice deepfake, or video deepfake scenario.
2. Configure a fictional target, its access level, and organizational context.
3. Review campaign stages, warning signs, and potential consequences.
4. Inspect an explained likelihood and impact assessment.
5. Select applicable defenses and compare baseline and residual risk.
6. Export the analysis as TXT or JSON.

The first version will use predefined scenarios and deterministic rules. It does not require an AI API, GPU, or online service. AI is the subject of the analysis; live content generation is not an MVP requirement.

## Planned technology

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

Mateusz will focus on the engine, scenario data, CLI, exports, and tests. The GUI contributor will implement desktop screens and connect them to the shared service.

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

Simulation consists of local fictional narratives and rule-based assessments. It does not send phishing messages, collect credentials, impersonate real people, clone voices, generate deceptive videos, or attack external systems. Potential losses will be described qualitatively unless the user supplies explicitly fictional amounts.
