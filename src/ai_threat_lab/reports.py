"""Serialize the same result displayed by either interface."""

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .models import AnalysisResult, ValidationError


def render_text(result: AnalysisResult) -> str:
    lines = [
        "AI THREAT LAB — EDUCATIONAL ANALYSIS",
        f"Model: {result.model_version}",
        f"Scenario: {result.scenario_title} ({result.scenario_id})",
        f"Fictional target: {result.target.organization} / {result.target.role}",
        f"Access: {result.target.access}; urgency: {result.target.urgency}",
        "",
        "CAMPAIGN STAGES",
    ]
    for index, stage in enumerate(result.stages, 1):
        lines.extend(
            [
                f"{index}. {stage.title}: {stage.narrative}",
                f"   Warning: {stage.warning_sign}",
                f"   Intervention: {stage.intervention}",
            ]
        )
    lines.extend(["", "POTENTIAL CONSEQUENCES", *[f"- {c}" for c in result.consequences]])
    lines.extend(
        [
            "",
            "CONTROLS",
            f"Existing: {', '.join(result.existing_control_ids) or 'none'}",
            f"Proposed additions: {', '.join(result.proposed_control_ids) or 'none'}",
        ]
    )
    lines.extend(
        [
            "",
            "RECOMMENDED ADDITIONAL DEFENSES",
            *[f"- {c.id}: {c.title}. {c.description}" for c in result.recommended_controls],
        ]
    )
    for label, assessment in (("BASELINE", result.baseline), ("RESIDUAL", result.residual)):
        lines.extend(
            [
                "",
                f"{label}: {assessment.likelihood} × {assessment.impact} = "
                f"{assessment.score}/25 — {assessment.level}",
                *[f"- {e}" for e in assessment.explanations],
            ]
        )
    lines.extend(["", "ASSUMPTIONS", *[f"- {a}" for a in result.assumptions]])
    return "\n".join(lines) + "\n"


def render_json(result: AnalysisResult) -> str:
    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "analysis": asdict(result),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def export_report(result: AnalysisResult, path: Path, format: str = "txt") -> Path:
    if format not in ("txt", "json"):
        raise ValidationError("Report format must be txt or json")
    content = render_json(result) if format == "json" else render_text(result)
    # Exclusive creation prevents accidental destruction of a previous report.
    with Path(path).open("x", encoding="utf-8") as output:
        output.write(content)
    return Path(path)
