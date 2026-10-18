# Offline acceptance kit — 0.19.0

The CLI can demonstrate source/configuration checks, exact dependency inventory, scan history and all three local training channels without keys, account access, network services or paid calls. This is repeatable synthetic acceptance evidence, not an audit of a real organization.

## Start with one command

```bash
ai-threat-lab readiness
ai-threat-lab offline-demo --output-dir demo-results/run-01
```

The output directory must be new. Open `demo-results/run-01/index.html` locally. It links to the before/after scan reports, training report and three escaped text previews and separate synthetic PE/ELF and Python-pattern and exported-mail observation reports. The demo uses only its own generated project; it cannot accept a website, mailbox, recipient list or external target. It does not install packages, execute fixture source or automatically open a browser.

Expected current fixture observations: 3 before, 0 after, 3 **no longer observed**. Those observations are Python `eval`, an unpinned Docker base and explicit root `USER`. The demo changes its own source and Dockerfile between scans. It does not infer that a real vulnerability was fixed or that the resulting application is secure. The dependency package is fictional; root and nested requirements now exercise the opt-in monorepo inventory and merge origins into one identity. The generated Cargo.lock adds one fictional crates.io identity, and a generated `go.sum` adds one fictional Go module-content identity. `dependency_ecosystems` is `["Go", "PyPI", "crates.io"]`. There is no Cargo/Go invocation, checksum verification or OSV request.

The training report contains three scripted selections: reporting the email exercise, requesting independent verification in the voice rehearsal and declining the video request. These are selected outcomes, not measured employee actions. Fictional recipients use `example.invalid` or a reserved demonstration phone number.

The separate Python fixture produces exactly eight candidate observations (PY005–PY012), recorded as `python_pattern_observations: 8`. It is parsed only and does not change the three-before/zero-after comparison.

The inert mail fixture produces exactly five aggregate candidates: HTTP, IP-literal host, displayed/destination hostname mismatch, active attachment extension and document-plus-active double extension. `mail_observations` is 5; no link is visited or attachment extracted/executed. This is synthetic acceptance, not a real phishing detection result.

The demo also produces `local-batch/`: a new scan of the after-project plus the fictional mail, with two targets and five candidate observations in one report. `batch_targets` is 2. `batch-check` validates the child bundles and derived report before the demo completion marker is written.

The generated `response-headers.json` capture contains two separate synthetic cookies and a permissive CSP. `header_observations` is 6. The local JSON/HTML review contains static observations without cookie/policy values; the declared `.invalid` URL is never fetched. This separate report is not a scan bundle and has no integrity signature.

The separate `kubernetes-fixture/workload.json` is an inert JSON document with ten explicit candidate settings. `kubernetes_observations` is 10. Its project scan has an integrity-checkable report bundle; no image, host path, workload or cluster is opened or started. This does not change the original three-before/zero-after comparison or two-target batch.

## Output layout

| Path | Purpose |
| --- | --- |
| `index.html` | Local entry point with relative report links and no external assets |
| `synthetic-project/` | The after-scan fixture, not a snapshot of the before version |
| `scan-before/`, `scan-after/` | Existing integrity-checkable scan bundles and observation comparison |
| `email-plan.json`, `voice-plan.json`, `video-plan.json` | Generated fictional plans |
| `*-approval.json` | Explicitly synthetic demo-review approvals, valid for one hour |
| `email-pack/` | Text preview, `.eml` preview, instructions, metadata and consistency index |
| `voice-pack/` | Text preview and structured voice script; no speech/call |
| `video-pack/` | Text preview and storyboard; no generated image/audio/video |
| `synthetic-pe.bin`, `synthetic-elf.bin` | Inert format descriptors with no machine-code payload; never executed |
| `synthetic-pe/`, `synthetic-elf/` | Bounded binary observation bundles, linked from the index |
| `python-patterns.py`, `python-patterns/` | Inert five-pattern source and its standalone scan bundle/report |
| `synthetic-message.eml`, `mail-observations/` | Fictional message and redacted five-observation scan report |
| `local-batch/` | Verified two-target offline batch, combined report and final batch index |
| `response-headers.json` | Synthetic HTTPS capture, including inert example values; never fetched |
| `headers-review.json`, `headers-review.html` | Redacted six-observation offline header review |
| `kubernetes-fixture/workload.json`, `kubernetes-observations/` | Inert Pod JSON and ten-observation project scan bundle |
| `training.sqlite` | Existing private local rehearsal ledger |
| `training-report.json`, `training-report.html` | Scripted selected outcomes and practice guidance |
| `readiness.json` | Static implementation inventory, including missing modules |
| `demo-result.json` | Completion marker, written last after acceptance checks |

A failed or interrupted demo can leave an incomplete directory. No `demo-result.json` means the demonstration did not complete. Inspect that directory and select a new destination; the command never overwrites or resumes an old one. The demo root is created with mode `0700` on POSIX; Windows inherits ACLs. No crash durability or atomic directory snapshot is promised. The entire demo directory has no integrity signature; only its scan sub-bundles have the scan-check contract.

## Use your own approved exercise

```bash
ai-threat-lab campaign-example email_training --output request.json
ai-threat-lab campaign-prepare request.json --output plan.json
# Review the exact plan before recording approval:
ai-threat-lab campaign-approve plan.json --reviewer "Exercise reviewer" --output approval.json
ai-threat-lab exercise-export plan.json --approval approval.json --output-dir rehearsal-pack
```

Use `voice_training` or `video_training` for the other channels. Exact digest, scope, expiry and approval time are checked **before** creating the export directory. Export never approves a supplied plan. The demo's automatic synthetic approval is restricted to its generated fictional scenarios and is not used by this command.

`exercise.json` preserves exact approved subject/body, allowed structured actions, digest and expiry. Recipient addresses, scope owner, approved facts and media references are not included as separate export fields; text already present in the approved subject/body is preserved. Review that text for private information before exporting. Media references are never opened. HTML content is escaped and has a restrictive CSP.

Email preview headers always use reserved `.invalid` addresses and a clear local simulation marker, regardless of the approved recipient list. There is no send action, queue, credential form, attachment or transport integration. Voice/video exports are JSON text assets, not generated media or live dialogues.

The pack's manifest contains byte lengths and SHA-256 values for local consistency only, not a signature or authenticated approval. Publication writes the manifest last; an interrupted write can leave an incomplete pack. Files do not enforce expiry or revocation after they have been copied. Use the original approved plan with `training-start` / `training-run` for the existing runtime scope/expiry/cancellation checks. Export does not consult a training ledger or authorize an external campaign.

## Capability inventory

```bash
ai-threat-lab readiness --output readiness.json
```

This is a static inventory of implementation scope, not an account health check. It does not read environment credentials, validate access, make API requests, or claim that adding a key completes the product. `complete_product` and `api_key_alone_sufficient` are explicitly false. A zero exit code means the inventory was produced, not that every capability exists.

| Status | Meaning |
| --- | --- |
| `partial` | Selected local checks/reports exist; documented gaps remain |
| `fixture_tested` | Concrete adapter tested against synthetic wire responses, not live accounts |
| `static_headers_partial` | Bounded PE/ELF header/flag observations, no signature/disassembly/runtime analysis |
| `local_rehearsal` / `text_assets_only` | Text exercises and assets, no communications/media |
| `teaching_scenarios` | Educational password-attack scenarios; no login attempts |
| `implemented` | The bounded offline demonstration exists |
| `integration_validation_required` | Controlled provider/account testing remains |
| `implementation_required` | Missing engineering work, not just configuration or keys |

## What remains after this offline kit

Live email delivery, telephony, speech/media providers, authenticated participant-event collection and broader application analysis and deeper binary validation are not implemented by the kit. Their adapters, consent/scope enforcement at the external boundary and controlled integration tests require separate work. No account or API setup is performed in this release. See [DELIVERY_STATUS.md](DELIVERY_STATUS.md) for the complete input/capability matrix and remaining order of work.
