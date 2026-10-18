"""Offline file workflows shared by the CLI and future GUI."""

from datetime import datetime, timedelta, timezone

from .campaigns import (
    CampaignService,
    ContentApproval,
    DemoTransport,
    _validate_plan,
    campaign_scenarios,
)
from .contracts import (
    approval_from_document,
    plan_from_document,
    plan_to_document,
    request_from_document,
)
from .delivery_ledger import MemoryLedger, SQLiteLedger
from .models import ValidationError
from .providers import ProviderConfig, ProviderRegistry


def example_request(scenario_id: str) -> dict:
    scenario = next((s for s in campaign_scenarios() if s.id == scenario_id), None)
    if scenario is None:
        raise ValidationError("Unknown campaign scenario")
    recipient = "+12025550100" if scenario.channel == "voice" else "participant@example.invalid"
    return {
        "schema_version": 1,
        "scenario_id": scenario.id,
        "scope": {
            "campaign_id": "offline-example",
            "authorized_by": "Exercise owner",
            "recipient_allowlist": [recipient],
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "identity_reference": "fictional:office-coordinator",
        },
        "recipients": [recipient],
        "approved_facts": ["TRAINING-ALPHA is fictional."],
    }


def prepare_campaign(document: dict, registry: ProviderRegistry, config: ProviderConfig) -> dict:
    request = request_from_document(document)
    service = CampaignService(registry.content(config.content))
    return plan_to_document(service.prepare(**request))


def approve_campaign(document: dict, reviewer: str) -> ContentApproval:
    plan = plan_from_document(document)
    now = datetime.now(timezone.utc)
    _validate_plan(plan, now)
    approval = ContentApproval(plan.digest, reviewer, now)
    # Reuse field validation; the actual identity of the reviewer belongs to the host application.
    from .contracts import approval_to_document

    approval_from_document(approval_to_document(approval))
    return approval


def simulate_campaign(plan_document: dict, approval_document: dict, ledger_path=None) -> dict:
    plan = plan_from_document(plan_document)
    approval = approval_from_document(approval_document)
    # No external transport can be selected through this workflow.
    ledger = SQLiteLedger(ledger_path) if ledger_path else MemoryLedger()
    receipts = CampaignService(ledger=ledger).execute(plan, approval, DemoTransport(plan.channel))
    return {
        "mode": "offline_simulation",
        "plan_digest": plan.digest,
        "receipts": [
            {"recipient": r.recipient, "status": r.status, "reference": r.reference}
            for r in receipts
        ],
        "ledger": "persistent" if ledger_path else "process_local",
        "notice": "No external message, phone call or media generation was performed.",
    }
