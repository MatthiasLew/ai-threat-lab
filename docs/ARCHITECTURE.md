# Architecture

## Layers

| Layer | Responsibility |
| --- | --- |
| Domain | Scenario, TargetProfile, Control, RiskAssessment, AnalysisResult |
| Application | ThreatAnalyzer orchestrates validation, simulation, and assessment |
| Infrastructure | JSON catalog loading and report file writing |
| Interfaces | CLI first; PySide6 GUI later |

Dependencies flow from interfaces toward the application and domain. The engine must not import Qt or read terminal input. Report writing is explicit; analysis itself does not write files or use the network.

## Package layout

| Planned path | Purpose |
| --- | --- |
| src/ai_threat_lab/models.py | Typed request and result objects |
| src/ai_threat_lab/catalog.py | Scenario loading and validation |
| src/ai_threat_lab/analyzer.py | Shared application service |
| src/ai_threat_lab/risk.py | Scoring and control rules |
| src/ai_threat_lab/reports.py | TXT and JSON serialization |
| src/ai_threat_lab/cli.py | Console adapter |
| src/ai_threat_lab/gui/ | Future desktop adapter |
| src/ai_threat_lab/data/ | Versioned scenario and control JSON |
| tests/ | Domain, service, and export checks |

The core files and packaged data exist. The `gui/` directory remains planned.

## Service contract

`ThreatAnalyzer.list_scenarios() -> tuple[Scenario, ...]`

`ThreatAnalyzer.list_controls() -> tuple[Control, ...]`

`ThreatAnalyzer.analyze(request: AnalysisRequest) -> AnalysisResult`

`export_report(result: AnalysisResult, path: Path, format: str = "txt") -> Path`

`format` accepts `txt` or `json`; the destination must not exist.

AnalysisRequest contains scenario_id, target profile, existing_control_ids, and proposed_control_ids. Existing controls affect the baseline once; proposed controls affect the residual assessment only. Sets must be deduplicated.

AnalysisResult contains scenario identity, fictional target, campaign stages, consequences, baseline assessment, residual assessment, control explanations, assumptions, and model version.

Each assessment contains likelihood, impact, score, level, and explanation items. Unknown scenario/control IDs and invalid ratings produce explicit validation exceptions. User interfaces translate them into readable messages.

This contract is implemented in version 0.1.0. Results also include recommended_controls for unselected applicable defenses. Domain request/result objects are frozen dataclasses and expose tuples to both interfaces. See GUI_HANDOFF.md for a working example.
