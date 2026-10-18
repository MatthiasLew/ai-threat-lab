# Design diagrams

These diagrams describe the shared architecture. The engine, CLI, catalog, and TXT/JSON exporters are implemented; GUI is planned.

## Application components

```mermaid
flowchart TD
    CLI["Console interface"] --> Service["ThreatAnalyzer service"]
    GUI["Future PySide6 interface"] --> Service
    Service --> Catalog["Scenario catalog"]
    Service --> Risk["Risk engine"]
    Catalog --> Data["Versioned JSON data"]
    Risk --> Result["Structured analysis result"]
    Result --> View["Interface presentation"]
    Result --> Export["TXT and JSON exporters"]
```

CLI and GUI share the same analysis rules. Exporters serialize results without recalculating risk.

## Analysis lifecycle

```mermaid
flowchart TD
    Start["Choose scenario and fictional target"] --> Validate{"Valid request?"}
    Validate -->|No| Error["Show validation errors"]
    Error --> Start
    Validate -->|Yes| Baseline["Assess existing defenses"]
    Baseline --> Propose["Choose additional defenses"]
    Propose --> Residual["Assess residual risk"]
    Residual --> Compare["Show scores and explanations"]
    Compare --> Action{"Next action"}
    Action -->|Change defenses| Propose
    Action -->|Save report| Export["Export TXT or JSON"]
    Action -->|New scenario| Start
```

## Domain relationships

```mermaid
classDiagram
    AnalysisRequest --> TargetProfile
    AnalysisRequest --> Control : selected IDs
    ThreatAnalyzer --> AnalysisRequest : accepts
    ThreatAnalyzer --> Scenario : loads
    ThreatAnalyzer --> AnalysisResult : returns
    AnalysisResult --> RiskAssessment : baseline and residual
    AnalysisResult --> CampaignStage : narrative stages
    class AnalysisRequest {
        scenario_id
        existing_control_ids
        proposed_control_ids
    }
    class RiskAssessment {
        likelihood
        impact
        score
        level
        explanations
    }
    class AnalysisResult {
        assumptions
        model_version
        consequences
    }
```

These names match the implemented API concepts.
