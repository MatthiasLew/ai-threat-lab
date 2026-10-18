# Integration contracts and current capability boundary (0.3.0)

The product goal is an assessment assistant: accept a target, route it to appropriate modules, collect evidence, explain findings, and recommend action. Narrative risk simulations remain educational support. The current release provides local checks and tested adapter contracts; it is not a complete remote pentesting or communications platform.

## Current capabilities

| Capability | State | What is still required |
| --- | --- | --- |
| Python file/project review | Implemented, limited AST checks | More rules/languages and data-flow analysis if needed |
| Exported `.eml` review | Implemented, limited header observations | Trusted server logs, signature validation and attachment/link analysis |
| GitHub repository URL | Target routing implemented; result is not_configured | Repository retrieval/branch selection adapter and scoped credentials for private repositories |
| Website URL | Target routing implemented; result is not_configured | Scoped HTTP/TLS assessment adapter; separately authorized active tests |
| Mail domain | Target routing implemented; result is not_configured | DNS audit adapter for SPF, DKIM and DMARC |
| Mailbox account | Target routing implemented; result is not_configured | Provider OAuth/permissions and configuration audit adapter |
| Executable/binary | Target routing implemented; result is not_configured | File-format-specific inspection module |
| Training content | Offline templates implemented | Optional text/media provider implementing TrainingContentProvider |
| Email/voice training dispatch | DemoTransport implemented; no live CLI dispatch | Actual transport adapter, credentials, sender/caller setup and cancellation handling |
| Video training | Preview script implemented | Consented media generation, content-addressed approved asset and delivery adapter |
| Campaign outcomes | Local event aggregation implemented | Trusted event collection/webhooks and provider-specific deduplication |

A model API key alone does not supply mail delivery, telephony, mailbox access, DNS auditing or web vulnerability checks. There are no environment-variable credentials, network SDKs or automatic provider fallbacks in this release.

## Assessment adapter

Implement `TargetAdapter.assess(target: str) -> AssessmentResult`. Register it explicitly:

```python
from ai_threat_lab.assessment import AssessmentService

# github_adapter is an application-supplied implementation, not bundled software.
# service = AssessmentService({"github_repository": github_adapter})
```

Kinds are `github_repository`, `website`, `python_source`, `local_project`, `mail_message`, `mail_domain`, `mailbox_account`, and `program_file`. Results contain candidate/unverified findings and `not_checked` items. An unavailable adapter must not claim success or security.

A remote adapter must validate scope and destinations itself, enforce response/time/size bounds, and treat fetched code and page content as untrusted data. The default router makes no HTTP, DNS, mailbox or GitHub requests. Active checks must be a separate explicit operation with a defined target scope, not a side effect of target classification.

## Content provider

Implement `TrainingContentProvider.prepare(scenario, approved_facts, identity_reference) -> TrainingContent`. The campaign service validates scope and recipients before invoking it. The provider prepares a preview only. Identity references must begin with `fictional:` or `consent:` and refer to a real authorization record managed by the application; the library does not verify legal consent.

For video, return a media reference and a SHA-256 digest of the actual approved asset. The transport must verify those bytes before distribution. Changing the content, media reference, media digest, recipients, approved facts or scope changes the plan digest and invalidates prior content approval.

## Transport provider

Implement `TrainingTransport` with a `channel` (`email`, `voice` or `video`) and `deliver(plan, recipient) -> DeliveryReceipt`. The campaign service requires explicit ContentApproval for the exact plan digest, checks expiry/recipient scope/channel, and checks an optional cancellation callback before each dispatch.

A receipt status is `accepted`, `unknown` or `simulated`; acceptance is not proof of delivery or participant interaction. Live voice transports must also stop an in-progress call on a stop/refusal request, follow the approved script/identity and prevent collection of real secrets. They must not turn a synthetic-data exercise into open-ended information gathering. Recording and transcription need separately approved policies and retention controls.

The default ledger is process-local. Supply `SQLiteLedger(path)` for atomic persistence across restarts. It stores hashed attempt identifiers rather than addresses/content. An attempt is claimed before provider invocation, including an ambiguous timeout: investigate before retrying. Use the same plan/recipient-derived idempotency key at the provider; local SQLite alone cannot guarantee exactly-once external delivery. Protect the ledger and approval records with deployment access controls.

There is no global bulk-send command or configured live provider. The CLI exposes only offline demos; an application must register actual adapters and supply authorization/approval records explicitly.

## Integration acceptance before live use

Verify provider authentication, scope enforcement, idempotency, cancellation, expiry, event authenticity, rate controls and secret-free error handling in a controlled environment. Keep source-sharing decisions and usage budgets explicit for an optional AI provider. Test evidence is not automatically a confirmed vulnerability or a personnel judgment.

## Registration and saved-file workflows

ProviderRegistry now supplies explicit named registrations, guarded output validation and redacted failures. `--config` selects pre-registered names; `doctor` reports missing registrations. Strict request, preview and approval artifacts drive the complete offline CLI workflow. These additions do not bundle any external SDK. See PROVIDER_DEVELOPMENT.md and TESTING.md.
