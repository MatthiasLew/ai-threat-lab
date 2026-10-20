# Complete console workflow

Prepared tools collect observations. The application chooses applicable checks
deterministically, keeps evidence and limitations, and optionally asks AI to explain
what the user should review. **The model does not generate attack code, execute
commands, authorize collection or invent tools.** Its output remains advice,
separate from original observations. GUI development belongs to a separate
contributor; the same Python services are available to that client.

## Start without an account

Run `ai-threat-lab console` for target planning/inspection, saved summaries, AI
previews, fictional scenarios, setup and capability information. Network inspection
requires separate confirmation after destination/data disclosure. The menu never
calls AI. Invalid selections are recoverable; EOF/Ctrl+C exits the menu. Existing
`interactive` remains the fictional risk-scenario questionnaire.

The local training submenu covers example requests, exact previews, explicit
review/approval, approved sessions, continuing a rehearsal, HTML outcome reports,
permanent cancellation and inert asset export. It displays the preview and scope
before recording approval. The history submenu lists/verifies runs, compares scans,
exports reports and runs explicitly confirmed local batches. These menus use the
same existing contracts as their scriptable commands; no live dispatch is added.

```bash
ai-threat-lab plan path/to/project
ai-threat-lab inspect path/to/project --output-dir results/run-01
ai-threat-lab brief results/run-01
ai-threat-lab scan-check results/run-01
```

`plan` reads target metadata, not source bodies. It lists prepared tools, actual
service destinations, data disclosures, bounds and required opt-ins. It does not
collect data, inspect keys or call models. `collection_permitted` means scope flags
are present, not that an account/service works. Execution revalidates scope.

`inspect` uses the same `ScanOptions`/`ScanService` as `scan`, saving the same
verifiable bundle and printing a practical local summary. It preserves failures,
dependency omissions and baseline comparison. `--format json` returns the scan
result contract. Exit 2 means input/output or module failure; `--fail-on-findings`
returns 1 for candidates. No observation becomes a proven vulnerability/fix.

```bash
ai-threat-lab plan https://github.com/owner/repository
ai-threat-lab inspect https://github.com/owner/repository --network --allow-host github.com --output-dir results/github-01
```

Exact-host, public-address, request and file bounds still apply. Inspection supports
the existing recursive-dependency, package-sharing, file/page, DKIM, advisory-cache
and baseline options. OSV package disclosure is separate from AI evidence sharing.

## Saved evidence and summaries

`brief`, `ai-prepare`, `ai-explain` and `ai-review` accept single assessment JSON,
combined report JSON, or saved single/batch directories. Directories undergo full
bundle/derived-report verification; original targets need not exist. Bare reports
remain unverified saved claims. Combined identifiers, references, priorities,
summaries and limitations are checked for consistency. Original duplicate finding
counts are bounded claims because merging loses multiplicity. Hashes do not prove
authenticity.

```bash
ai-threat-lab brief results/run-01 --output review.txt
ai-threat-lab brief results/batch-01 --format json --output review.json
```

The text includes where to look, observations, existing recommendations, stable
references and every recorded limitation. Terminal controls are escaped. This
first-pass explanation needs no model or API account.

## Prepare optional AI interpretation

```bash
ai-threat-lab setup-check --ai-config examples/ai-budget.json
ai-threat-lab setup-check --smtp-config examples/smtp.json --speech-config examples/speech.json --avatar-config examples/avatar.json
ai-threat-lab ai-prepare results/run-01 --ai-config examples/ai-budget.json --structured --split --output preview.json
```

Example model/prices are placeholders, usable for estimates rather than live setup.
`setup-check` validates installation and configuration without reading credentials;
it never declares a live service ready. Console setup optionally accepts all four
profiles. SMTP, speech and avatar entries distinguish unselected profiles from valid local
configuration and describe the remaining account checks. The preview contains exact outgoing input,
instructions, output schema, evidence hashes and configured-price reservation
estimates. No ledger is written and no request occurs.

Structured review removes target fields in favor of per-report aliases and retains
SHA-256 observation references. **Evidence text can still contain sensitive data.**
Review the entire preview. Minimization is not anonymization. The program never
uploads an entire source tree or silently removes limitations.

Reports split into at most 100 packets by byte limit and `--group-size` (default 3;
allowed 1..20 observations). Each observation appears exactly once; every packet
contains all limitations. An individually oversized observation or limitation set
is rejected, not truncated. Narrow the assessment or explicitly adjust limits.
Group size does not guarantee a real model finishes within its output-token cap.

Use the same group size for preview and review:

```bash
ai-threat-lab ai-prepare results/run-01 --ai-config my-ai-budget.json --structured --packet-index 1
ai-threat-lab ai-review results/run-01 --ai-config my-ai-budget.json --ledger costs.sqlite --packet-index 1 --dry-run
```

Structured dry-run neither inspects keys nor creates a ledger. Multiple packets
require an explicit 1-based index. There is no hidden loop of paid calls. Aggregate
estimates do not check remaining daily budget: existing ledger reservations and
request limits still apply at dispatch.

## After account configuration

Choose an available Responses model supporting structured outputs, verify current
token prices and configure `OPENAI_API_KEY` outside source control. Authorize one
reviewed packet explicitly:

```bash
ai-threat-lab ai-review results/run-01 --ai-config my-ai-budget.json --ledger costs.sqlite --packet-index 1 --send-evidence --output interpretation-01.json
```

The result has summary, explanation/what-to-review/remediation per observation and
uncertainty. Each supplied reference must occur exactly once. Unknown, duplicate,
missing references or unexpected fields reject the interpretation. This validates
grounding structure, **not the truth of prose**. Original tool findings/limitations
stay authoritative; AI advice never changes them or becomes an executable command.

Known-usage invalid interpretations are charged locally without caching/retry.
Incomplete/uncertain responses retain reservations for reconciliation. Output paths
are exclusively claimed before dispatch; existing files are never overwritten.
`api-costs`, `api-reconcile` and `api-cache-prune` keep their existing semantics.

`ai-explain` remains the free-text route and now accepts combined reports/saved runs.
Preview it with `ai-prepare` without `--structured`. Legacy single-assessment prompt
projection remains compatible.

## Acceptance and remaining tests

`scripts/check_console_offline.py` checks deleted-source summaries, exact synthetic
wire/schema, caching, output conflicts, invalid advice and accounting with all
sockets blocked. Clean-wheel acceptance runs it outside the checkout. Unit/process
tests cover packets, malformed input, permissions, provenance, navigation and old
AI workflows. Live acceptance must still verify permissions, model/schema support,
prices, usage, output quality, quotas and controlled target behavior.

SMTP delivery, stock-speech WAV generation and stock-avatar job/download workflows
have separate console adapters and offline acceptance checks; see their linked guides.
GUI, active attacks, telephony, arbitrary language coverage and dynamic binary analysis
remain outside this interpretation layer and need further implementation, not just a key.

Reference: [official Responses structured output guide](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=responses).
