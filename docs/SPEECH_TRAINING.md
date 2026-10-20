# Fictional stock-voice assets

The optional Azure Speech adapter turns an approved fictional `voice_training` script
into a local WAV asset. It uses stock voices, without cloning a person's identity.
Console option 13 exposes preview, generation, status and cancellation.

## Offline preparation

```bash
ai-threat-lab campaign-example voice_training --output request.json
ai-threat-lab campaign-prepare request.json --output plan.json
ai-threat-lab campaign-approve plan.json --reviewer local-reviewer --output approval.json
ai-threat-lab speech-preview plan.json --approval approval.json --speech-config examples/speech.json --output preview.json
```

Review the exact script, endpoint, voice and estimated cost in the preview. The example
price is an illustrative configuration value, not a verified Azure tariff. Replace it
with the applicable price before using a real account. Preview needs neither a key nor
a connection. It includes no recipients, although the local plan still contains its scope.

The adapter supports the `eastus`, `westeurope` and `northeurope` public Azure regions
and stock `en-US-JennyNeural` / `en-US-ChristopherNeural` voices. The endpoint is fixed
from that selection. Custom deployment URLs, cloned voices, user-authored SSML and
remote audio references are not accepted. Approved facts are escaped as plain XML text.

## Optional generation after account setup

Provide the matching Speech resource key through `AI_THREAT_SPEECH_KEY` outside source
control. The program never prints it or saves it in the preview or result. Then use the
actual reviewed fingerprint:

```bash
ai-threat-lab speech-generate plan.json --approval approval.json --speech-config examples/speech.json --preview-sha256 REVIEWED_DIGEST --allow-speech-host westeurope.tts.speech.microsoft.com --ledger speech.sqlite --output-dir generated-audio --send-script
```

This explicitly sends the approved script to Azure and may incur charges. Generation
does not call participants, transmit their numbers, record them or distribute audio.
It uses one HTTPS POST without redirects or automatic retries. The new output directory
must be separate from the persistent generation journal.

The result directory contains a pre-request `attempt.json`, validated `speech.wav` on
success, and `result.json` after a handled outcome. The attempt marker remains `pending`
as a historical pre-request record; use the journal and result for the final outcome.
Listen to and review the generated asset before using it in an exercise. Its checksum
binds the saved bytes, not their spoken accuracy or a distribution approval.

```bash
ai-threat-lab speech-status --ledger speech.sqlite --plan-digest PLAN_DIGEST
ai-threat-lab speech-cancel --ledger speech.sqlite --plan-digest PLAN_DIGEST
```

Cancellation blocks future claims; it cannot recall an in-flight provider request.
An accepted, pending, rejected or unknown claim blocks another generation for the same
plan even if settings change. A fresh output directory does not bypass that journal.
Do not delete the journal to retry an uncertain operation: first check provider usage
and account records. A deliberately new plan requires a new preview and approval.

## Bounds and outcome semantics

Only the exact built-in fictional voice template with approved facts is accepted,
up to 3,000 text characters. A locally configured estimate uses the entire SSML UTF-8
byte length and supplied per-million-character price, rounded upward. Requests above
the configured per-request estimate limit are refused before network access. This is
not observed billing, a daily account budget or a guarantee about provider pricing.

Output must be complete RIFF WAV, mono 24 kHz 16-bit PCM, at most 6 MiB and 120 seconds.
Malformed, truncated, oversized or different-format output is not accepted as an asset.
An uncertain request or unusable provider response is recorded `unknown`: charges may
still have occurred. A process interruption leaves a `pending` claim. No automatic
retry follows either state.

`accepted` means a response passed these checks and was written locally; it does not
prove speech quality, delivery or participant behavior. `result.json` is local evidence,
not a signed provider receipt. Local journal/filesystem integrity is assumed.

The transport follows the [Azure Speech REST reference](https://learn.microsoft.com/en-us/azure/ai-services/speech-service/rest-text-to-speech).
Automated acceptance uses synthetic PCM and blocked sockets. Real resource authorization,
regional voice availability, audio quality and billed usage remain integration checks.
