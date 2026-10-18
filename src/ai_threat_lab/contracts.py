"""Versioned, strict JSON boundaries for configuration and campaign artifacts."""

import json
import re
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from .campaigns import CampaignPlan, CampaignScope, ContentApproval, TrainingContent
from .models import ValidationError, require_text
from .providers import ProviderConfig

MAX_JSON_BYTES = 1024 * 1024


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("Duplicate JSON object key")
        result[key] = value
    return result


def _nonfinite(value):
    raise ValidationError("Non-finite JSON numbers are not accepted")


def read_document(path: Path) -> dict:
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValidationError("JSON document exceeds the 1 MiB limit")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValidationError("Invalid JSON document") from exc
    if not isinstance(value, dict):
        raise ValidationError("JSON document must be an object")
    return value


def fields(value, required: set[str], optional: set[str] | None = None) -> dict:
    if (
        not isinstance(value, dict)
        or not required <= value.keys()
        or value.keys() - required - (optional or set())
    ):
        raise ValidationError("Document has missing or unsupported fields")
    return value


def version(value: dict) -> None:
    if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise ValidationError("Unsupported schema_version; expected integer 1")


def strings(value, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValidationError(f"{label} must be an array of strings")
    for item in value:
        require_text(item, label)
    return tuple(value)


def timestamp(value, label: str) -> datetime:
    require_text(value, label)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValidationError(f"{label} must be an ISO datetime") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError(f"{label} must include a timezone")
    return parsed


def config_from_document(value: dict) -> ProviderConfig:
    fields(value, {"schema_version"}, {"content", "assessment"})
    version(value)
    selected = value.get("assessment", {})
    if not isinstance(selected, dict):
        raise ValidationError("assessment must be an object of target kind/provider names")
    return ProviderConfig(value.get("content", "template"), tuple(selected.items()))


def scope_from_document(value) -> CampaignScope:
    fields(
        value,
        {"campaign_id", "authorized_by", "recipient_allowlist", "expires_at"},
        {"identity_reference"},
    )
    return CampaignScope(
        value["campaign_id"],
        value["authorized_by"],
        strings(value["recipient_allowlist"], "recipient_allowlist"),
        timestamp(value["expires_at"], "expires_at"),
        value.get("identity_reference", "fictional:example-company-coordinator"),
    )


def request_from_document(value: dict) -> dict:
    fields(value, {"schema_version", "scenario_id", "scope", "recipients"}, {"approved_facts"})
    version(value)
    require_text(value["scenario_id"], "scenario_id")
    return {
        "scenario_id": value["scenario_id"],
        "scope": scope_from_document(value["scope"]),
        "recipients": strings(value["recipients"], "recipients"),
        "approved_facts": strings(value.get("approved_facts", []), "approved_facts"),
    }


def plan_to_document(plan: CampaignPlan) -> dict:
    value = asdict(plan)
    value["scope"]["expires_at"] = plan.scope.expires_at.isoformat()
    value["scope"]["recipient_allowlist"] = list(plan.scope.recipient_allowlist)
    value["recipients"] = list(plan.recipients)
    value["approved_facts"] = list(plan.approved_facts)
    return {"schema_version": 1, "plan": value, "plan_digest": plan.digest}


def plan_from_document(value: dict) -> CampaignPlan:
    fields(value, {"schema_version", "plan", "plan_digest"})
    version(value)
    plan = fields(
        value["plan"],
        {"scenario_id", "channel", "scope", "recipients", "approved_facts", "content"},
    )
    content = fields(plan["content"], {"subject", "body"}, {"media_reference", "media_sha256"})
    result = CampaignPlan(
        plan["scenario_id"],
        plan["channel"],
        scope_from_document(plan["scope"]),
        strings(plan["recipients"], "recipients"),
        strings(plan["approved_facts"], "approved_facts"),
        TrainingContent(**content),
    )
    if not isinstance(value["plan_digest"], str) or value["plan_digest"] != result.digest:
        raise ValidationError("Plan digest does not match its contents")
    return result


def approval_to_document(approval: ContentApproval) -> dict:
    return {
        "schema_version": 1,
        "plan_digest": approval.plan_digest,
        "approved_by": approval.approved_by,
        "approved_at": approval.approved_at.isoformat(),
    }


def approval_from_document(value: dict) -> ContentApproval:
    fields(value, {"schema_version", "plan_digest", "approved_by", "approved_at"})
    version(value)
    if not isinstance(value["plan_digest"], str) or not re.fullmatch(
        r"[a-f0-9]{64}", value["plan_digest"]
    ):
        raise ValidationError("Approval needs a SHA-256 plan digest")
    require_text(value["approved_by"], "approved_by")
    return ContentApproval(
        value["plan_digest"], value["approved_by"], timestamp(value["approved_at"], "approved_at")
    )


def write_document(value: dict, path: Path | None = None) -> str:
    text = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if path is not None:
        with Path(path).open("x", encoding="utf-8") as stream:
            stream.write(text)
    return text
