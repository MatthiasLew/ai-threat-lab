# CLI modernization

Preserve `scan`, `scan-check`, `scan-compare`, `history-list`, `report-export`,
`agent`, the guided `menu`, and legacy `console`. No terminal dependencies.

1. Optional `scan --progress` writes versioned JSON events to stderr, leaving
   stdout exclusively the existing result JSON. Do not invent percentages.
2. Show stage transitions in Polish/English guided audits; Ctrl+C cancels safely.
3. Replace the history placeholder with verified catalog, saved summary, finding
   details and comparison. Reuse public services; preserve export/settings flows.
4. Add offline analyzer/capability/installation diagnostics to the menu.
5. Preserve codes 0 normal, 1 explicit candidate gate, 2 invalid input,
   3 infrastructure/module failure, 130 cancellation, 141 closed output pipe.

Automation never prompts or invokes models implicitly. Existing explicit
`--fail-on-findings` is the opt-in post-change policy; candidates are not proven
vulnerabilities. Comparisons retain coverage mismatch and failure restrictions.
Acceptance: process-level JSON/stderr checks, bilingual simulated menu journeys,
saved corrupted-bundle checks and installed-wheel acceptance.
