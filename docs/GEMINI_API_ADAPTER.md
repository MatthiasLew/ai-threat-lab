# Gemini adapter and controlled acceptance

The adapter uses the fixed Google `generateContent` endpoint and sends
`GEMINI_API_KEY` in the `x-goog-api-key` header. Model identifiers are syntax-checked;
this does not prove that a named model exists or is enabled for the account. Select
an available model and verify prices/terms with the provider before live use.

The model receives minimized evidence and limitations. It cannot execute tools or
code. Structured results must reference exactly the supplied observations; refusal,
truncation, unsupported responses and invalid grounding are failures, not clean audits.
No automatic paid retry occurs after an ambiguous request. Inspect the cost ledger
and provider billing before reconciliation. Usage and billed thinking tokens are
handled separately from interpretation validity; live billing acceptance is required.

## Configuration and preview

Copy `examples/ai-budget.json` to a private configuration and replace its example
model/prices/limits. For Gemini, supply your chosen Gemini model identifier.

```bash
ai-threat-lab ai-prepare results/run-01 --ai-config ai.json --provider gemini --structured --split --output preview.json
ai-threat-lab ai-review results/run-01 --ai-config ai.json --provider gemini --packet-index 1 --ledger costs.sqlite --dry-run
```

Review every evidence string: minimization does not guarantee that secrets or
personal data are absent. Model name, prices, selected packet and outgoing evidence
must match the eventual call. The command's `--help` documents required live flags
and ledger/output arguments. Preview and dry-run make no paid request.

The interactive menu now asks for the same explicit AI configuration used by the
call. If there are multiple packets it requires one selection, displays that
packet and its reservation, and sends only that packet after confirmation. Its
shared journal is `ai-costs.sqlite` beside the user's settings JSON; different
report destinations do not reset it. CLI users must deliberately reuse a ledger.
This is local accounting, not an account-wide or provider-enforced spending cap.
Changing config/ledger or using another client can change the effective budget.

## Saved interpretation and PDF

The PDF validates advisory schema, unique references and the exact minimized packet
digest against the technical report. Partial coverage is labeled as a count of
interpreted versus total findings. These checks establish consistency, not that the
provider authored the file or that its advice is correct. Legacy unbound advisory
JSON must be regenerated; do not fabricate a digest to bypass validation.

## Limits and tests

Transport timeouts are per socket operation, not a complete transaction deadline.
The adapter timeout argument does not replace the injected HTTP client's settings;
CLI/menu construct the bounded transport explicitly. DNS delays and real provider
behavior still require acceptance. Fixtures cover valid responses, usage, cache,
refusals, malformed/truncated responses and errors without network access.
