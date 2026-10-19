# Integration contracts and current capability boundary (0.30.0)

Concrete read-only collectors are available through the explicit `audit` command. Optional AI explains their existing findings; it does not autonomously attack targets. The legacy `assess` command remains an offline router unless an application registers adapters.

| Capability | Implemented | Remaining limits |
| --- | --- | --- |
| Single-target scan workflow | Built-in collectors, local dependency inventory, opt-in OSV, committed bundles and observation deltas | Selected read-only checks only; no full-audit guarantee, automatic attacks or AI calls |
| Local source/project | Selected Python syntax/flows/package links, secrets, literal config and structured Kubernetes JSON | No full semantic/runtime audit; supported dependency/OSV coverage is separate below |
| Exported `.eml` | Bounded header/link/HTML-form/attachment-metadata candidates | No trusted authentication, rendered page, attachment content or malware validation |
| GitHub | Retrieve pinned default-branch commit/tree/blobs and review selected files | Scoped token for private repos, live validation, broader analysis |
| Saved HTTPS headers | `review-headers` over strict JSON field pairs | No URL fetch, trusted capture origin, effective browser or session validation |
| Saved HTML | `review-html` with optional declared context and bounded form/resource patterns | No rendering, submission, browser tree builder or JavaScript |
| Website | Explicit scoped HTTPS request and selected header/UTF-8 HTML checks | No crawling, auth/business-logic tests or exploitation |
| Mail domain | Basic SPF/DMARC checks, supplied-selector DKIM TXT presence via DoH | No full policy evaluation or signature validation |
| Gmail mailbox | Authenticated owner profile, forwarding and filter observations | External OAuth consent/refresh, required scopes/admin grants, no MFA/session audit |
| Pinned dependencies | requirements/npm/uv/Poetry/Cargo and Go checksum-record inventory and explicit OSV batch lookup/cache | Unsupported formats, unresolved versions, advisory coverage and runtime reachability remain gaps |
| Combined reporting | JSON and escaped standalone HTML with provenance and triage queue | No validated severity, automatic patching or personnel scoring |
| Program file | Bounded size/hash plus selected PE/ELF headers and ZIP metadata/path candidates | No signature trust, disassembly, execution, malware or confirmed-vulnerability conclusions |
| AI explanation | Concrete OpenAI Responses adapter and persistent cost controls | Available model, rates, key, evidence permission and live validation |
| Authentication logs | Explicit normalized .auth.jsonl or review-auth-log input; bounded failure-pattern candidates | No provider log conversion, login attempts, trusted provenance or compromise confirmation |
| Training content | Offline templates and approved scenario scripts | Live text/media integrations remain absent |
| Local training sessions | Approved text previews, structured selections, persistence, cancellation, JSON/HTML reports | No raw responses, speech analysis or real employee-behavior measurement |
| Email/voice/video dispatch | Demo transports and exact preview approval | No actual sending, phone calls, media generation or live tracking backend |
| Signed event claims | Local HMAC protocol, exact-plan binding, transactional replay checks and provenance-separated reports | No native provider/webhook/participant authentication, tracking endpoint or remote dispatch |
| Campaign outcomes | Legacy imported-event aggregation remains untrusted; separate signed local journal available | No trusted webhook collection or tracking endpoint |

Read [LIVE_SETUP.md](LIVE_SETUP.md) for commands, credential types, scopes and hard collection limits; read [API_COSTS.md](API_COSTS.md) for budget, cache, privacy and reconciliation behavior. Fixture-based tests establish local behavior, not real service readiness. A model key does not implement missing communications or assessment capabilities.

## Assessment adapter

Implement `TargetAdapter.assess(target: str) -> AssessmentResult`. Register it explicitly:

```python
from ai_threat_lab.assessment import AssessmentService

# GithubAudit is bundled for the explicit network audit workflow;
# an application may also inject its own provider implementation.
# service = AssessmentService({"github_repository": github_adapter})
```

Kinds are `github_repository`, `website`, `python_source`, `local_project`, `mail_message`, `html_document`, `authentication_log`, `mail_domain`, `mailbox_account`, and `program_file`. Results contain candidate/unverified findings and `not_checked` items. An unavailable adapter must not claim success or security.

A remote adapter must validate scope and destinations itself, enforce response/time/size bounds, and treat fetched code and page content as untrusted data. The legacy default router makes no HTTP, DNS, mailbox or GitHub requests; the new `audit` workflow explicitly opts into bounded read-only collectors. Active checks must be a separate explicit operation with a defined target scope, not a side effect of target classification.

## Content provider

Implement `TrainingContentProvider.prepare(scenario, approved_facts, identity_reference) -> TrainingContent`. The campaign service validates scope and recipients before invoking it. The provider prepares a preview only. Identity references must begin with `fictional:` or `consent:` and refer to a real authorization record managed by the application; the library does not verify legal consent.

For video, return a media reference and a SHA-256 digest of the actual approved asset. The transport must verify those bytes before distribution. Changing the content, media reference, media digest, recipients, approved facts or scope changes the plan digest and invalidates prior content approval.

## Transport provider

Implement `TrainingTransport` with a `channel` (`email`, `voice` or `video`) and `deliver(plan, recipient) -> DeliveryReceipt`. The campaign service requires explicit ContentApproval for the exact plan digest, checks expiry/recipient scope/channel, and checks an optional cancellation callback before each dispatch.

A receipt status is `accepted`, `unknown` or `simulated`; acceptance is not proof of delivery or participant interaction. Live voice transports must also stop an in-progress call on a stop/refusal request, follow the approved script/identity and prevent collection of real secrets. They must not turn a synthetic-data exercise into open-ended information gathering. Recording and transcription need separately approved policies and retention controls.

The default ledger is process-local. Supply `SQLiteLedger(path)` for atomic persistence across restarts. It stores hashed attempt identifiers rather than addresses/content. An attempt is claimed before provider invocation, including an ambiguous timeout: investigate before retrying. Use the same plan/recipient-derived idempotency key at the provider; local SQLite alone cannot guarantee exactly-once external delivery. Protect the ledger and approval records with deployment access controls.

There is no global bulk-send command or configured live provider. The campaign CLI exposes only offline demos; an application must register actual adapters and supply authorization/approval records explicitly.

## Integration acceptance before live use

Verify provider authentication, scope enforcement, idempotency, cancellation, expiry, event authenticity, rate controls and secret-free error handling in a controlled environment. Keep source-sharing decisions and usage budgets explicit for an optional AI provider. Test evidence is not automatically a confirmed vulnerability or a personnel judgment.

## Registration and saved-file workflows

ProviderRegistry now supplies explicit named registrations, guarded output validation and redacted failures. `--config` selects pre-registered names; `doctor` reports missing registrations. Strict request, preview and approval artifacts drive the complete offline CLI workflow. These additions do not bundle any external SDK. See PROVIDER_DEVELOPMENT.md and TESTING.md.

The [offline acceptance kit](OFFLINE_ACCEPTANCE.md) adds inert export and synthetic acceptance commands without live adapters. The [delivery matrix](DELIVERY_STATUS.md) records missing implementation separately from API/account validation.

Opt-in [monorepo inventory](MONOREPOS.md) adds bounded nested manifests to local/GitHub scans without adding a provider or enabling package sharing.

Local program-file paths now use the bounded [PE/ELF header collector](BINARY_AUDIT.md), not only magic-byte metadata. It does not execute files or provide signature/malware/runtime validation.

## Saved response headers (0.16.0)

`review-headers` is an explicit offline workflow, not automatic target routing or a provider adapter. Its assessment documents use `http_response_headers` for report interchange and can be merged by `audit-report`. `scan-batch` does not reinterpret arbitrary JSON files as response captures. See [HTTP_HEADERS.md](HTTP_HEADERS.md).

## Kubernetes JSON (0.17.0)

`review-kubernetes` is an explicit local workflow with assessment kind `kubernetes_manifest`, accepted by the existing report merger. Local/GitHub project collection also recognizes supported JSON resources. Arbitrary single JSON paths in the legacy `audit`/`scan` router remain program-file inputs: use the explicit command or select the containing project. No Kubernetes provider account, cluster access or YAML/Helm execution is configured. See [KUBERNETES.md](KUBERNETES.md).

HTML scope and limits: [HTML_REVIEW.md](HTML_REVIEW.md). ZIP metadata scope and limits: [ARCHIVE_REVIEW.md](ARCHIVE_REVIEW.md).

## Local control boundary (0.30.0)

Historical receipts require the original signed envelope and registered bindings; they attest only to current local journal contents. Combined local cancellation updates rehearsal and event databases together under documented SQLite prerequisites. It does not acknowledge a provider stop or delete exported assets. See [LOCAL_TRAINING_CONTROL.md](LOCAL_TRAINING_CONTROL.md).
