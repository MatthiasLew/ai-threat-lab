"""Load packaged scenario data and reject malformed catalogs at the boundary."""

import json
from importlib.resources import files
from pathlib import Path

from .models import (
    CampaignStage,
    Control,
    ControlRule,
    Scenario,
    ValidationError,
    require_rating,
    require_text,
)


def _texts(item: dict, keys: tuple[str, ...]) -> None:
    for key in keys:
        require_text(item[key], key)


def load_catalog(path: Path | None = None) -> tuple[tuple[Scenario, ...], tuple[Control, ...]]:
    try:
        text = (
            path.read_text(encoding="utf-8")
            if path
            else files("ai_threat_lab").joinpath("data/catalog.json").read_text(encoding="utf-8")
        )
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ValidationError(f"Invalid scenario catalog: {exc}") from exc
    return parse_catalog(text)


def parse_catalog(text: str) -> tuple[tuple[Scenario, ...], tuple[Control, ...]]:
    """Validate already-read catalog text with the runtime catalog contract."""
    try:
        raw = json.loads(text)
        if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
            raise ValidationError("Unsupported catalog schema_version")
        if not isinstance(raw["controls"], list) or not isinstance(raw["scenarios"], list):
            raise ValidationError("controls and scenarios must be arrays")
        controls = []
        for item in raw["controls"]:
            _texts(item, ("id", "title", "description"))
            controls.append(Control(item["id"], item["title"], item["description"]))
        control_ids = {c.id for c in controls}
        if len(control_ids) != len(controls):
            raise ValidationError("Duplicate control ID")
        scenarios = []
        for item in raw["scenarios"]:
            _texts(item, ("id", "title", "description", "default_role", "rationale"))
            for key in ("likelihood", "impact"):
                require_rating(item[key], key)
            for key in ("stages", "consequences", "rules"):
                if not isinstance(item[key], list):
                    raise ValidationError(f"{key} must be an array")
            if not item["stages"] or not item["consequences"]:
                raise ValidationError("Scenario needs stages and consequences")
            stages = []
            for stage in item["stages"]:
                _texts(stage, ("title", "narrative", "warning_sign", "intervention"))
                stages.append(CampaignStage(**stage))
            for consequence in item["consequences"]:
                require_text(consequence, "consequence")
            rules = []
            for rule in item["rules"]:
                _texts(rule, ("control_id", "group", "rationale"))
                if rule["control_id"] not in control_ids:
                    raise ValidationError(f"Unknown catalog control: {rule['control_id']}")
                for key in ("likelihood_reduction", "impact_reduction"):
                    if type(rule[key]) is not int or not 0 <= rule[key] <= 2:
                        raise ValidationError(f"{key} must be an integer between 0 and 2")
                rules.append(ControlRule(**rule))
            if len({r.control_id for r in rules}) != len(rules):
                raise ValidationError("Duplicate scenario control rule")
            scenarios.append(
                Scenario(
                    **{
                        key: item[key]
                        for key in (
                            "id",
                            "title",
                            "description",
                            "default_role",
                            "likelihood",
                            "impact",
                            "rationale",
                        )
                    },
                    stages=tuple(stages),
                    consequences=tuple(item["consequences"]),
                    rules=tuple(rules),
                )
            )
        if not scenarios or len({s.id for s in scenarios}) != len(scenarios):
            raise ValidationError("Catalog needs scenarios with unique IDs")
        return tuple(scenarios), tuple(controls)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ValidationError(f"Invalid scenario catalog: {exc}") from exc
