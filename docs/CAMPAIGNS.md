# Prepared training campaign scenarios

These are authorized exercise scenarios using fictional or separately consented identities and synthetic information. The shipped CLI does not send emails, place calls, clone voices or generate video.

| ID | Channel | Exercise objective | Signals |
| --- | --- | --- | --- |
| email_training | Email | Verification and reporting of an unusual request | Delivery, open, click, report, refusal |
| voice_training | Phone | Verify a caller before discussing a synthetic identifier | Identity verified, declined, synthetic information shared |
| video_training | Video distribution | Independently verify an instruction attributed to a synthetic speaker | Verification, reporting and synthetic interaction |

The voice scenario uses approved facts supplied to the exercise, not automated scraping of real people. Its sample caller is a fictional office coordinator and the identifier `TRAINING-ALPHA` is invented. Stop conditions prohibit real passwords, MFA codes, customer records and other production information. These templates can demonstrate the architecture without deceptive collection of real secrets.

## Offline CLI

```bash
python -m ai_threat_lab campaigns
python -m ai_threat_lab campaign-demo email_training
python -m ai_threat_lab campaign-demo voice_training
python -m ai_threat_lab campaign-demo video_training
python -m ai_threat_lab campaign-report examples/training-events.json
```

Email and voice demos simulate dispatch to reserved demonstration destinations. Video returns preview-only status because no generated media exists. The demo's automatic approval is limited to its built-in fictional data and DemoTransport; it is not approval for any live campaign.

## Reusable application workflow

```python
from datetime import datetime, timedelta, timezone
from ai_threat_lab.campaigns import (
    CampaignScope, CampaignService, ContentApproval, DemoTransport,
)

now = datetime.now(timezone.utc)
recipient = "participant@example.invalid"
scope = CampaignScope(
    campaign_id="exercise-001",
    authorized_by="Exercise owner",
    recipient_allowlist=(recipient,),
    expires_at=now + timedelta(hours=1),
    identity_reference="fictional:office-coordinator",
)
service = CampaignService()
plan = service.prepare("email_training", scope, (recipient,), now=now)
# Display the exact preview and obtain reviewer approval in the real application.
approval = ContentApproval(plan.digest, "Preview reviewer", now)
receipts = service.execute(plan, approval, DemoTransport("email"), now=now)
assert receipts[0].status == "simulated"
```

Use a persistent SQLiteLedger and provider-side idempotency before integrating a live transport. Scope/approval fields are application records, not cryptographic signatures or proof of actual organizational permission. The application must enforce reviewer identity and access. Approval becomes invalid when the plan changes. A video asset must be present with a SHA-256 reference before execution.

## Events and reporting

Event schema: `{"schema_version": 1, "events": [...]}`. Each event contains only `participant_id`, `type`, and optional boolean `automated`. Supported types: `delivered`, `opened`, `link_clicked`, `reported`, `identity_verified`, `synthetic_info_shared`, `declined`.

Raw transcripts, answers, passwords and arbitrary extra fields are not accepted by the file importer. Use pseudonymous participant IDs. Aggregation counts unique participants separately for each event type and excludes automated events from human counts. A person can both click and report. Opens/clicks are provider observations affected by mail scanners and privacy features; they do not prove account compromise.

Live webhook verification, event/campaign participant binding, retention and trusted bot classification belong to the future provider integration. Imported event files are not independent proof of their own authenticity.

## Later extensions

Optional model-generated preview content, consented synthetic media, mail/telephony transports and authenticated event ingestion can use these contracts. No live adapter is bundled yet. See [integration contracts](INTEGRATIONS.md).

## Voice dialogue policy

`VoiceExerciseSession` accepts only a typed `VoiceSignal` and returns the next `VoiceTurn`. Refusal, stop requests, offered real data, and verification requests end the exercise. Sharing the synthetic identifier records only a `synthetic_info_shared` event. Three unclassified turns end without inventing an outcome. A verification request is not falsely counted as completed verification.

A future speech/telephony adapter supplies intent classification and plays approved responses. It must enforce stop handling, suppress/redact real-data capture and obey scope expiry during the call, even if a speech/model component fails. This library does not currently recognize speech, classify free-form conversation or record calls.

## Saved-artifact CLI workflow (0.3.0)

`campaign-example` → `campaign-prepare` → reviewer inspects the preview → `campaign-approve` → `campaign-simulate`. The root README shows exact commands. The request, plan and approval have strict versioned JSON contracts; tampering invalidates the digest. `campaign-simulate` accepts an optional SQLite ledger and always uses the offline demo transport. It does not select live providers from configuration.
