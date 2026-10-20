# Fictional stock-avatar video

An approved built-in `video_training` script can be submitted to Azure's asynchronous
stock-avatar service, inspected as an existing job, downloaded locally and attached
to a new plan for exact-media approval. Console option 17 guides these steps.
This creates a local training asset. It does not clone a likeness/voice, place calls
or distribute video to participants.

## Preparation without an account

```bash
ai-threat-lab campaign-example video_training --output request.json
ai-threat-lab campaign-prepare request.json --output plan.json
ai-threat-lab campaign-approve plan.json --reviewer operator --output approval.json
ai-threat-lab avatar-preview plan.json --approval approval.json --avatar-config avatar.json --output preview.json
ai-threat-lab setup-check --avatar-config avatar.json
```

Start from `examples/avatar.json`. Replace the resource hostname with your actual
Azure resource hostname. Its price is illustrative, not a current provider quote.
The configuration contains no secret. When ready for controlled live acceptance,
set `AI_THREAT_AVATAR_KEY` outside source control and verify resource access,
current pricing and provider terms.

The local preview includes the exact request, endpoint, job identifier, configuration
hash and preview hash. It accepts only the original built-in fictional script and
approved facts, at most 600 characters, with a stock English voice and stock Lisa
avatar. It contains no recipient list. Custom avatars, voices, backgrounds, arbitrary
SSML and remote media references are not accepted.

The configured estimate uses two video minutes. It is a planning assumption,
**not a provider-enforced spending limit**. The service may charge even if submission
becomes uncertain or the downloaded result is rejected. No automatic submission
retry or paid-call loop is implemented.

## Explicit generation and retrieval

Use the reviewed `preview_sha256` and `plan_digest` values below, and the exact
configured resource hostname. All output directories must be new.

```bash
ai-threat-lab avatar-submit plan.json --approval approval.json --avatar-config avatar.json --ledger jobs.sqlite --preview-sha256 REVIEWED_PREVIEW_SHA256 --allow-avatar-host RESOURCE.cognitiveservices.azure.com --send-script --output-dir submission
ai-threat-lab avatar-status --avatar-config avatar.json --ledger jobs.sqlite --plan-digest ORIGINAL_PLAN_DIGEST --network --allow-avatar-host RESOURCE.cognitiveservices.azure.com
ai-threat-lab avatar-download --avatar-config avatar.json --ledger jobs.sqlite --plan-digest ORIGINAL_PLAN_DIGEST --network --allow-avatar-host RESOURCE.cognitiveservices.azure.com --allow-asset-host REPORTED_ASSET_HOST --output-dir downloaded
```

Submission creates a durable journal claim and local pending marker before the
single PUT request. Accepted means the provider confirmed creation of the job,
not that video is ready. Interrupted or uncertain attempts remain blocked from
resubmission in that journal. Read status using the original configuration;
changing its resource or price fields changes the configuration binding.

Status performs one explicit GET. Running/NotStarted jobs remain pending, failed
jobs are visible, and a missing job never authorizes a new submission. Retrieval
is allowed after the original approval expires because it reads an existing job.
It does not extend approval or authorize distribution.

The successful status report exposes only the asset hostname. Download requires
confirmation of that exact host and a fresh successful job response. It uses a
separate GET to the approved Azure blob host, with no resource key forwarded.
Signed URL queries and echoed scripts are omitted from public receipts. URLs are
not followed to other hosts; public-address pinning, verified TLS, request budgets
and no redirects apply.

Downloads are bounded to 8 MiB and provider-reported duration up to 120 seconds.
The program checks selected MP4 container boundaries, then saves bytes, hash and
a receipt. It does not decode/play the video or establish its safety, codec quality,
content correctness or billing accuracy. A failed download can leave an incomplete
directory; only a matching `downloaded` receipt authorizes the next local step.
Use a new directory for a deliberate retrieval retry, never a new submission.

## Review and bind the exact asset

```bash
ai-threat-lab avatar-attach plan.json --approval approval.json --avatar-config avatar.json --download-dir downloaded --output media-plan.json
ai-threat-lab campaign-approve media-plan.json --reviewer media-reviewer --output media-approval.json
```

Review the actual downloaded video before the second command. Attaching verifies
the receipt against the original plan/configuration and the actual file hash,
then creates a new plan digest containing the local media URI/hash. The old approval
does not cover that new digest. The original script approval must still be valid
at attachment time. Local receipts are consistency evidence, not proof of provider
authenticity.

`avatar-cancel --ledger jobs.sqlite --plan-digest ORIGINAL_PLAN_DIGEST` blocks
future local submissions. It cannot recall or stop a submitted remote job, delete
provider artifacts, guarantee a refund or prevent already generated media from
being read. Native remote cancellation/distribution is not implemented.

The provider retains jobs according to its own policies; this adapter does not
list or delete unrelated account jobs. Status and retrieval are explicit, with no
background polling.

Exit 0 means the requested step completed; submission acceptance and running status
are not media completion. Exit 3 reports unsuccessful/uncertain submission, failed
or missing remote job, or unavailable download. Input/configuration/output errors
are nonzero. Existing files are never overwritten.

## Verification boundary

Tests exercise exact requests, malformed responses, duplicate/unknown/interrupted
submissions, private-URL omission, storage credential separation, local cancellation,
changed media and the new approval digest. Installed-package acceptance blocks all
sockets and uses inert container bytes. Actual resource/stock-avatar availability,
media quality, download compatibility and billing need controlled account acceptance.

Provider references: [create](https://learn.microsoft.com/en-us/rest/api/batchavatar/batch-syntheses/create?view=rest-batchavatar-2024-08-01),
[get](https://learn.microsoft.com/en-us/rest/api/batchavatar/batch-syntheses/get?view=rest-batchavatar-2024-08-01)
and [batch-avatar workflow](https://learn.microsoft.com/en-us/azure/ai-services/speech-service/text-to-speech-avatar/batch-synthesis-avatar).
