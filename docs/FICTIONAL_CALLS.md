# Approved fictional training calls

This console adapter places one explicitly approved, disclosed training announcement
through Twilio. It uses the unchanged built-in fictional voice script, a stock voice,
and a fixed preamble explaining that the recipient can hang up. There is no arbitrary
speech generation, voice cloning, recording, transcription, listening, autonomous
conversation or real-secret collection. Console option 19 exposes the same operations.

## Prepare without a token

Copy `examples/call.json` and replace the placeholder account SID, caller number and
configured prices. The caller must be authorized on your actual provider account;
local validation checks syntax only. The example price is not a current quotation.
The configured one-minute estimate is not a guarantee of the provider bill.

```bash
ai-threat-lab campaign-example voice_training --output request.json
```

In this new request, set the approved recipient and matching scope allowlist to one
consented E.164 number. Set `approved_facts` to `[]`: the call adapter intentionally
uses the fixed script without additions. Set the actual authorization/expiry and keep
a fictional identity. Do not modify a prepared plan or reuse an old approval after
changing the request.

```bash
ai-threat-lab campaign-prepare request.json --output plan.json
ai-threat-lab campaign-approve plan.json --reviewer YOUR_REVIEWER --output approval.json
ai-threat-lab setup-check --call-config my-call.json
ai-threat-lab call-preview plan.json --approval approval.json --call-config my-call.json --output preview.json
```

Preview reads no credential and makes no request. It contains the exact recipient,
caller, inline TwiML, requested parameters, estimate and SHA-256. Keep it private:
phone numbers are present for explicit review. A plan needs at least two minutes
of unexpired scope at preview and immediately before submission.

## Explicit submission after account setup

Configure `TWILIO_AUTH_TOKEN` outside source control; do not put it in JSON or a
command-line argument. The adapter supports an account SID and its account token,
not a separately provisioned API-key SID. Verify account/region permissions, caller
ownership, recipient consent, current charges and trial restrictions first.

```bash
ai-threat-lab call-submit plan.json --approval approval.json --call-config my-call.json --ledger calls.sqlite --preview-sha256 REVIEWED_SHA256 --allow-call-host api.twilio.com --send-call --output-dir attempt-01
```

One fixed-host create request carries URL-encoded `To`, `From`, inline `Twiml`,
`Record=false`, `Transcribe=false`, `Timeout=15` and `TimeLimit=60`. The TwiML contains
only stock `Say` and `Hangup`; it supplies no script/media URL, recording instruction,
stream or callback. Verify actual account-level behavior and audio before wider use.
No collection or loop of calls is provided.

The journal records a pending attempt before dispatch and blocks a repeated attempt
for the same plan/recipient. The new output directory contains `attempt.json` and,
when completion is recorded, `result.json`. Accepted means provider resource creation,
not that a person heard anything. Timeouts/malformed replies become unknown, and
interruptions retain pending. Neither is automatically retried. An unknown attempt
without a confirmed CallSid needs manual provider-console reconciliation; the tool
never guesses an ID or lists other calls. Keep the journal, original plan, config
and accepted receipt together in a trusted private directory.

## Inspect and stop an exact known call

```bash
ai-threat-lab call-status plan.json --call-config my-call.json --ledger calls.sqlite --receipt attempt-01/result.json --allow-call-host api.twilio.com --network
ai-threat-lab call-stop plan.json --call-config my-call.json --ledger calls.sqlite --receipt attempt-01/result.json --allow-call-host api.twilio.com --network --output-dir stop-01
```

Status/stop bind the accepted local receipt, original plan, configuration, journal,
account, recipient, caller and exact CallSid. Provider URLs or response prose cannot
choose a new destination. Status and stop remain available after plan expiry.

Stop first blocks future local submissions, then looks up the call. Queued/ringing
calls receive `Status=canceled`; in-progress calls receive `Status=completed`.
Already-terminal calls need no update. Only a returned terminal state is recorded
as provider confirmation. Races, errors or a still-active response remain
`stop_unknown`; inspect the call and explicitly repeat a stop if appropriate.
There is no automatic retry and no call creation during lookup/stop.
The separate foreground monitor below can initiate one bounded stop operation.

```bash
ai-threat-lab call-cancel --ledger calls.sqlite --plan-digest PLAN_SHA256
```

This last command is **local only**; it cannot stop a remote call. Use `call-stop`
for a known provider call. Interrupted local clients and provider queuing can delay
or prevent remote cancellation. Requested time limits are account-dependent and
are not a hard scope-expiry guarantee. The foreground monitor is optional; no
background service/webhook is implemented. Hanging up ends playback, but verbal refusal cannot be detected
because the adapter does not listen. Completed calls can be answered by voicemail
or an IVR; these results are not participant identity or behavioral evidence.

Receipts omit phone numbers, script, account token and provider prose. Their opaque
CallSid permits subsequent management and should still be protected. Local files
and reviewer labels are caller-controlled, not authenticated approvals or signed
provider evidence. Protect their integrity with deployment access controls.

Exit 0 means the selected operation succeeded within this contract, never a security
or human-delivery verdict. Unconfirmed submission/stop returns 3; submission or status also returns 3
when the provider already reports failed/busy/no-answer. Invalid input returns 2. Existing files are not replaced.

## Bounded foreground monitor

```bash
ai-threat-lab call-watch plan.json --call-config my-call.json --ledger calls.sqlite --receipt attempt-01/result.json --allow-call-host api.twilio.com --network --max-wait-seconds 90 --output-dir watch-01
```

This command only manages the exact already-created call. It checks status approximately
once per five seconds, for a chosen 1–120 seconds (default 90), and independently caps
status polls at 25. It never creates another call. It stops observing when a terminal
state is reported. Scope expiry, a local cancellation, the watch limit, a status/journal
error or one Ctrl-C triggers one bounded stop operation using the existing remote-stop
contract. A terminal call requires no update. Errors that prevent a confirmed stop remain
`stop_unknown`; the tool does not convert local cancellation into remote confirmation.

The new directory contains a pending marker, the final watch result, and a `stop/`
subdirectory if stopping was attempted. At most 27 status/stop requests are attempted
under the loop bound (the HTTPS budget is 28). Request/DNS delays can exceed the intended
observation period; this is a best-effort foreground control, not a provider-enforced
absolute deadline. Closing/killing the process, a second interruption, storage failures
or provider outages can prevent stopping. Keep the provider console available for
reconciliation. A local `call-cancel` can be noticed by this running monitor, but does
not itself contact the provider.

Exit 0 records a naturally observed terminal state other than failed/busy/no-answer;
it still does not prove human participation. Exit 3 indicates a failure or an automatic
stop reason, even if that stop was confirmed. An interrupted monitor returns 130 after
its stop attempt. Inspect `reason`, `status` and nested `stop` together. There is no
hidden background process and no resume that re-creates a call.

## Acceptance

`scripts/check_call_offline.py` exercises the installed CLI with sockets blocked:
preview, opt-in, one synthetic creation, duplicate blocking, status, remote stop and
terminal no-op and a bounded foreground timeout/stop. Unit tests cover interruption, expiry/cancellation, wrong identities,
wrong routes, redaction, journal errors, independent poll limits, expiry-triggered stop
and declined menu confirmations. These tests place no calls.
Real caller/recipient/account/audio, duration/cancellation and billing validation is
still required. Live conversation and authenticated participant-event collection
remain additional implementation work.

Provider references: [Call resource](https://www.twilio.com/docs/voice/api/call-resource)
and [stock speech instructions](https://www.twilio.com/docs/voice/twiml/say).
