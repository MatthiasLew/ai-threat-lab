"""Offline demonstration and fixture-based event reporting; no live CLI dispatch."""

import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .campaigns import (
    CampaignScope,
    CampaignService,
    ContentApproval,
    DemoTransport,
    TrainingEvent,
    campaign_scenarios,
    summarize_events,
)
from .models import ValidationError


def demo_campaign(scenario_id: str) -> dict:
    scenario = next((item for item in campaign_scenarios() if item.id == scenario_id), None)
    if scenario is None:
        raise ValidationError(f"Unknown campaign scenario: {scenario_id}")
    now = datetime.now(timezone.utc)
    recipient = "+12025550100" if scenario.channel == "voice" else "participant@example.invalid"
    scope = CampaignScope("demo", "offline-demo", (recipient,), now + timedelta(hours=1))
    service = CampaignService()
    plan = service.prepare(
        scenario.id, scope, (recipient,), ("TRAINING-ALPHA is fictional.",), now=now
    )
    # Video requires a separately generated/approved asset, so demo returns preview only.
    receipts = (
        ()
        if scenario.channel == "video"
        else service.execute(
            plan,
            ContentApproval(plan.digest, "offline-demo", now),
            DemoTransport(plan.channel),
            now=now,
        )
    )
    return {
        "mode": "offline_demo",
        "scenario": asdict(scenario),
        "plan_digest": plan.digest,
        "preview": asdict(plan.content),
        "receipts": [asdict(r) for r in receipts],
        "status": "preview_only_asset_missing" if scenario.channel == "video" else "simulated",
        "notice": "No messages sent, calls placed, likeness cloned or recording made.",
    }


def report_events(path: Path) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValidationError("Event file exceeds the 1 MiB limit")
    try:
        data = json.loads(raw)
        if type(data["schema_version"]) is not int or data["schema_version"] != 1:
            raise ValidationError("Unsupported event schema version")
        if not isinstance(data["events"], list):
            raise ValidationError("events must be an array")
        events = tuple(TrainingEvent(**event) for event in data["events"])
        return summarize_events(events)
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        raise ValidationError(
            "Invalid event file; use schema_version 1 and defined event fields"
        ) from exc
