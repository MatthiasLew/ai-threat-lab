# Approved fictional email delivery

The SMTP adapter sends the built-in fictional email training template and approved
facts to at most 20 explicitly scoped recipients. It does not send arbitrary
impersonation content, request credentials, add tracking, generate media or scrape
personal information. Local rehearsal commands remain local; actual email delivery
uses the separate commands below or console option 11.

## Offline preparation

Prepare and approve a normal `email_training` plan. Create settings based on
`examples/smtp.json`, with the actual account's authorized sender and server.
Settings contain no secrets. `starttls` uses port 587; `tls` uses port 465.
Certificate and hostname verification cannot be disabled. Plaintext SMTP is unsupported.

```bash
ai-threat-lab smtp-preview plan.json --approval approval.json --smtp-config smtp.json --output delivery-preview.json
```

Preview reads no credentials and opens no connection. It shows sender, server, exact
subject/body, each recipient and the SHA-256 of each serialized message. MIME line
endings/quoted-printable encoding do not change the displayed text. The final
`preview_sha256` binds all these values, plan and configuration. Subject/date/message
IDs are deterministic for the approved plan; no hidden tracking or attachments are added.

## Account setup and explicit sending

Configure `AI_THREAT_SMTP_USER` and `AI_THREAT_SMTP_PASSWORD` outside source control.
Use the provider's supported SMTP credential/app-password mechanism. This adapter
supports bounded ASCII credentials, not interactive OAuth. Never put passwords in
the settings file, plan, command arguments or a shared report.

After reviewing the exact preview, explicitly select its fingerprint and host:

```bash
ai-threat-lab smtp-send plan.json --approval approval.json --smtp-config smtp.json --ledger delivery.sqlite --preview-sha256 PREVIEW_SHA256 --allow-smtp-host smtp.example.invalid --send-approved --output delivery-result.json
```

Replace the example host and fingerprint. Sending revalidates approval/expiry and
content before claiming each attempt and again after connection/authentication.
Only the built-in fictional template with approved facts is supported. Other channels,
media, modified templates and recipients outside scope are rejected.

Every recipient uses a separate authenticated TLS connection. One local journal
claim is persisted **before** connection/submission. There is no automatic retry,
including after a definite rejection. Re-running with a different server does not
bypass the same plan/recipient claim. A new approved plan is required for a deliberate
new attempt after reviewing the old outcome. Do not delete/copy journals to retry.

## Recovery, status and cancellation

```bash
ai-threat-lab smtp-status --ledger delivery.sqlite --plan-digest PLAN_SHA256
ai-threat-lab smtp-cancel --ledger delivery.sqlite --plan-digest PLAN_SHA256
```

`accepted` means the SMTP server accepted the message, **not** inbox delivery or a
human action. `rejected` means submission was rejected or stopped before it started.
`unknown` means submission may have happened. `pending` can remain after interruption
or failure to record an outcome. Inspect uncertain states with the provider; never
automatically resend them. SMTP provides no universal idempotency guarantee.

Cancellation is permanent for the exact plan in that journal. It blocks later
claims and is checked again before submission. It cannot recall an accepted or
already in-flight message. `training-cancel` controls local rehearsals;
`smtp-cancel` controls this separate delivery journal. Cancel both when both are used.
Local signed training events do not automatically become authenticated delivery
or participant telemetry.

The journal stores plan/configuration hashes, recipient hashes, statuses and times;
no message body, password or raw provider error is stored. Hashes minimize information
but do not anonymize guessable addresses. Keep the journal in a private, durable local
directory. Schema, size, transaction, duplicate and cancellation checks protect
application consistency, not authenticity against someone who can rewrite the file.
Central deployment, retention and cross-machine coordination remain separate.

An output file is exclusively claimed before dispatch. Output/ledger/SQLite-sidecar
aliases are rejected. The journal remains the durable source of outcome information
if stdout or output writing fails. Exit 3 reports a non-accepted external outcome;
invalid scope/configuration/duplicate attempts use exit 2.

## Acceptance

Protocol fixtures cover TLS settings, exact MIME, approval/configuration fingerprints,
duplicate attempts, concurrent claims, interrupted/ambiguous outcomes, cancellation,
private error handling and CLI recovery. Installed acceptance blocks all sockets.
Actual account permissions, provider policies, inbox delivery and operational
behavior require a controlled live test after account setup.

Reference: [Python SMTP client](https://docs.python.org/3.14/library/smtplib.html).
