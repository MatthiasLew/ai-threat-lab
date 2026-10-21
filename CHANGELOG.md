# Changelog

## [0.41.3] - Stage 5.3: Expanded Interactive Audit, Scan Profiles & Professional Security Reports

### Added & Enhanced
- **Structured 9-Choice Target Selection Menu (`interactive_menu.py`)**:
  - Replaced single-path prompt with a dedicated, human-friendly target selection menu supporting 9 specific target types:
    1. Local project directory (Python, Go, Rust, Java, C/C++, JS/TS, configs)
    2. Single source file, binary (PE/ELF), or archive (ZIP)
    3. Remote GitHub repository (HTTPS API analysis)
    4. Website / HTTPS service (TLS and security headers inspection)
    5. Mail domain (SPF, DMARC, DKIM DNS-over-HTTPS verification)
    6. Saved email message (.eml offline analysis)
    7. Gmail mailbox account (read-only OAuth2 inspection)
    8. Security event logs (authentication / SSH journals)
    9. Custom sources & fallbacks (allowing direct path/URL input for seamless UX and automation)
    0. Clean cancellation and return to main menu
- **Scan Profiles & File Limit Expansion (`scan_engine.py`, `gui_api.py`, `local_inventory.py`)**:
  - Expanded maximum audit file bounds from 100 up to 10,000 files (`1 <= max_files <= 10000`).
  - Added structured scan profiles accessible via CLI (`--profile`), Python API (`get_scan_profiles()`, `get_scan_profile(name)`), and interactive prompts:
    - **Szybki / Fast**: up to 100 key files (quick initial audit)
    - **Standardowy / Standard**: up to 1,000 files (recommended for most repositories)
    - **Rozszerzony / Extended**: up to 5,000 files (deep inspection of large codebases)
    - **Niestandardowy / Custom**: user-defined file limit (1 - 10,000)
  - Added deterministic file priority ordering (core sources and configurations indexed before generic assets).
  - Scaled directory visit limits proportionally with file limits (`min(50000, max_files * 10)`).
  - Added 64 MiB read memory protection budget.
- **Explicit Network Connection Consent Gates**:
  - Implemented mandatory user consent dialogs disclosing exact remote target hosts and request purposes prior to any remote network activity (GitHub API, HTTPS inspection, DNS-over-HTTPS, Gmail OAuth2).
  - Added setup instructions and permission guidelines for Gmail OAuth2 read-only scopes (`https://www.googleapis.com/auth/gmail.readonly`).
- **Publication-Grade PDF Security Reports (`pdf_report.py`)**:
  - Added dedicated **Audit Scope & Methodology** section displaying recognized technologies (Python, Go, Rust, Java, C/C++, JS/TS, Shell, HTML, SQL, Config), files inspected vs limit, data budget, network policy, and analysis mode.
  - Added **Recommended Next Steps** section providing deterministic, prioritized recommendations (addressing P1 vulnerabilities, expanding scope with profiles, OSV database verification, and baseline comparison).
  - Grouped and humanized limitation notices: grouped candidate data-flow checks into a single concise summary with file count, simplified dependency static scope notices, and eliminated repetitive entries.
  - Guaranteed zero raw Python dictionary representations (`{'source': ...}`) ever appear in reports.
- **Evidentiary Bundle & Export Isolation (`scan_bundle.py`, `gui_api.py`)**:
  - Resolved `ValidationError("Bundle has missing or unindexed artifacts")` by allowing derived export directories (`exports/`, `reports/`) and PDF reports (`audit.pdf`, `exports/*.pdf`) without invalidating SHA-256 cryptographic bundle checks.
  - Defaulted PDF report exports to `out_dir / "exports" / f"audit_{language}.pdf"` while maintaining root `audit.pdf` for backward compatibility.
- **Comprehensive Testing Suite**:
  - Added `tests/test_stage5_3_interactive_audit_and_pdf.py` covering all 9 target types, network consent grants and denials, Fast/Standard/Extended profiles, multi-tech scope metrics, PDF layout sections, and bundle verification.

## [0.41.2] - Stage 5.2: PDF Generator Quality, Unicode Fidelity & Audit Credibility

### Fixed & Enhanced
- **High-Fidelity Unicode & Typography in PDF (`pdf_writer.py`)**:
  - Extended Adobe Type-1 custom encoding and `/ToUnicode` CMap with complete support for Polish diacritics, dashes (em-dash `—`, en-dash `–`), typographic quotes (Polish `„` / `”`, English `“` / `”`, `‘` / `’`), bullet points (`•`), ellipsis (`…`), and symbols (`€`, `™`).
  - Replaced silent fallback substitution of `?` with intelligent character mapping and NFKD transliteration, completely eliminating question-mark artifacts in reports.
  - Implemented boundary-aware character wrapping for long unbroken strings (paths, URLs, stack traces), guaranteeing content never overflows beyond page margins.
  - Standardized cross-reference (`xref`) line terminations to CR LF without trailing spaces, achieving strict PDF specification adherence and passing Git whitespace validation.
- **Audit Credibility & Partial Scope Transparency (`pdf_report.py`)**:
  - Fixed audit executive summaries when findings are 0 on partial scans: explicitly clarifies that 0 findings applies strictly to the inspected subset of files, warning that traversal limits were reached rather than falsely certifying the entire project.
  - Added project identity extraction (`extract_project_identity`): resolves real directory/repository names (e.g. `Labrys`) from audit metadata and manifests instead of generic "Inspected Project" labels.
  - Overhauled `not_checked` reporting: replaced raw Python dictionary string dumps (`{'source': ..., 'target': ...}`) with structured, human-readable limitation cards grouped by category (traversal limits, oversized files, excluded directories, unconfigured scanners, and parser errors).
- **Target Inventory & Scope Exclusions (`local_inventory.py`)**:
  - Expanded directory pruning during file system walks: automatically skips temporary, cache, and IDE directories (`.ai`, `.gemini`, `.antigravity`, `.cursor`, `.vscode`, `.idea`, `tmp`, `temp`, `.cache`, `htmlcov`, etc.) to prevent artificial traversal limits on scratch files.
  - Expanded text-based inspection suffixes for multi-technology projects (`.go`, `.rs`, `.java`, `.c`, `.cpp`, `.h`, `.cs`, `.php`, `.rb`, `.sh`, `.bash`, `.sql`, `.xml`, `.ini`, `.cfg`), enabling comprehensive offline secret scanning across heterogeneous codebases.
  - Added explicit diagnostic notices in `not_checked` explaining how to adjust coverage limits with `--max-files`.
- **Comprehensive Acceptance Testing & Samples**:
  - Added test suite (`tests/test_stage5_2_pdf_quality_and_scope.py`) testing text extraction via `QPdfDocument.getAllText()`, visual page rendering to image via `QPdfDocument.render()`, Polish Unicode fidelity, project identity extraction, raw dict elimination, and multi-technology secret scanning.
  - Re-rendered official sample reports: `docs/samples/sample_audit_pl.pdf` and `docs/samples/sample_audit_en.pdf`.

## [0.41.1] - Stage 5.1: Windows Paths, Pre-Audit Validation & Interactive CLI Robustness

### Fixed
- **Windows Path Handling & Normalization (`clean_user_path`, `path_utils.py`)**:
  - Fixed critical `OSError [WinError 123]` when paths are pasted with double or single quotes (standard Windows Explorer "Copy as path" behavior or shell paste prefixes like `& "..."` or `@"..."`).
  - Implemented safe, non-destructive normalization that strips matching outermost quotes without calling dangerous shell expansions or corrupting internal paths or UNC prefixes.
- **Pre-Audit Validation & Conflict Avoidance**:
  - Added target path validation with in-place re-prompt loop (handling non-existent paths, syntax errors, and permissions without unhandled tracebacks).
  - Added strict destination directory validation: guarantees destination does not already exist (protecting scan bundle integrity), is not identical to the target, and is not nested within the target directory.
  - Added `suggest_output_dir` which auto-increments proposed output directory suffixes (`reports/name`, `reports/name_1`, etc.) when existing folders are present.
- **Analyzer Scope Display**:
  - Fixed empty analyzer list in audit plan preview caused by reading `analyzers` instead of `tools` from `plan_audit`.
  - Added `describe_planned_scope` providing friendly, human-understandable analyzer descriptions in Polish and English for code analysis (subprocess, shell=True, eval), secrets detection, and dependency inventory, or a clear warning if no analyzers match the target.
- **First-Run Language Screen & CLI Flags**:
  - Formatted first-run language selection screen cleanly with bilingual banner.
  - Automatically loads saved language preference on subsequent runs without re-prompting.
  - Added `--select-language` and `--lang pl|en` CLI flags to `menu` subcommand and updated Settings workflow (`Ustawienia → Zmień język`).
- **Resilient Exception Handling**:
  - Enclosed interactive audit and export workflows in user-friendly error handlers, ensuring invalid inputs or OS errors display clean actionable messages and return gracefully to the main menu without dumping raw tracebacks.

## [0.41.0] - Stage 5: Multilingual UX, Interactive CLI Menu & Professional PDF Reports

### Added
- **Interactive Terminal Workflow (`menu` / `ai-threat-lab`)**:
  - Interactive, human-friendly text console when invoked without arguments in a terminal.
  - Non-blocking execution in automated environments: non-interactive or piped stdin runs (`not sys.stdin.isatty()`) bypass prompts and immediately exit with usage instructions and code 2.
  - Language selection prompt on first run with persistent preference stored in `~/.ai-threat-lab/config.json`.
  - Guided audit flow: target path entry, plan preview, offline scan execution, automatic PDF report generation, and optional Google Gemini AI enrichment with explicit cost and token confirmation.
- **Pure-Python PDF 1.4 Reporting Engine (`pdf_writer.py`, `pdf_report.py`)**:
  - Zero external dependencies: completely standalone generator with no requirement for ReportLab, WeasyPrint, or browser engines.
  - Publication-grade A4 layout answering the 7 key user questions: What was inspected?, Were threats found?, Where are they?, What could happen?, How to fix it?, How to verify the fix?, and What could not be checked?
  - Universal Polish diacritics support via standard Adobe Type-1 glyph mapping (`/Differences`) and embedded `/ToUnicode` CMap table ensuring perfect copy-paste, rendering, and searchability across all PDF viewers without external font downloads.
  - Rich visual elements: colored severity badges (P1, P2, P3, P4), divider lines, overview KPI metric cards, and running header/footers with two-pass page numbering ("Strona X z Y" / "Page X of Y").
  - Source code snippet extraction (`code_snippet.py`) with line numbering, secret redaction (`[REDACTED_SECRET]`), target line highlight (`>`), and content hash divergence detection.
  - Optional Google Gemini AI advisory section with model metadata and explicit disclaimer distinguishing deterministic scanner findings from generative AI explanations.
- **Complete Internationalization Architecture (`i18n.py`)**:
  - Dual-language support (`pl` and `en`) with exhaustive translation dictionaries across all labels, prompts, error states, and report sections.
  - Safe parameter interpolation and multi-tier fallback ensuring no unhandled exceptions on missing keys or unfamiliar locales.
  - Persistent user preference loading and saving outside source control.
- **Python GUI Integration API (`gui_api.py`)**:
  - Added `export_audit_pdf(run_or_report, output, language="en", ai_review=None)`.
  - Extended `export_audit_report(run_dir, output, format="pdf", language="pl", ...)` to support direct PDF rendering.
  - CLI subcommand `report-export --format pdf --lang pl --ai-review ...` for offline and post-scan PDF export.
- **Automated Verification & Documentation**:
  - Comprehensive Stage 5 test suite (`tests/test_stage5_i18n_and_pdf_reports.py`) covering i18n, preference persistence, non-blocking CLI, snippet extraction, PDF writer syntax, Polish diacritics, and end-to-end PDF report generation.
  - Sample generated PDF reports: `docs/samples/sample_audit_pl.pdf` and `docs/samples/sample_audit_en.pdf`.
  - Comprehensive architecture guides: `docs/I18N_SYSTEM.md` and `docs/PDF_REPORTS.md`.

## [0.39.2] - Stage 4: Gemini API Integration Repair & Diagnostics

### Fixed
- **Unified 120s HTTP Timeout**: Aligned `PublicHTTPS` timeout ceiling with CLI and `GeminiGenerateContent` allowing up to 120 seconds (`0 < timeout <= 120`).
- **Zero Phantom Ledger Reservations**: Instantiated `PublicHTTPS` before `CostLedger` in CLI dispatch to guarantee that local validation errors leave SQLite cost databases completely untouched.
- **Delayed Response E2E Verification**: Added end-to-end tests for socket-level timeouts, ensuring unconfirmed retention, zero leakage, and safe reconciliation.
- **Outbound HTTP Routing**: Resolved `PublicHTTPS` whitelist restriction blocking `generativelanguage.googleapis.com/v1beta/models/{model}:generateContent`, allowing Gemini requests to proceed securely through the sandbox.
- **Diagnostics**: Replaced generic unconfirmed exception catching with 16 granular failure categories (`API_KEY_MISSING`, `API_KEY_INVALID`, `MODEL_NOT_FOUND`, `MODEL_NOT_AVAILABLE`, `FREE_TIER_LIMIT`, `RATE_LIMITED`, `BAD_REQUEST`, `INVALID_RESPONSE_SCHEMA`, `RESPONSE_VALIDATION_FAILED`, `MODEL_REFUSAL`, `MAX_OUTPUT_TOKENS`, `NETWORK_TIMEOUT`, `TLS_ERROR`, `CONNECTION_ERROR`, `PROVIDER_SERVER_ERROR`, `UNKNOWN_PROVIDER_ERROR`).
- **Thinking Token Budgeting**: Set `thinkingBudget: 0` for `gemini-2.5-flash` to prevent reasoning tokens from exceeding constrained max output budgets.
- **Secret Redaction**: Reinforced safe exception extraction guaranteeing zero credential leakage across all transport and socket failure paths.


## 0.40.0 — Real-project validation, AST performance optimizations, and Google Gemini adapter

- Added real-world project validation across 8 diverse Python repositories (psf/requests, pallets/click, bottlepy/bottle, pypa/packaging, MatthiasLew/ai-dev-cli-tools, MatthiasLew/freelance-dev-suite, MatthiasLew/hol-guard, MatthiasLew/github-org-sync) and synthetic scale targets (docs/REAL_PROJECT_VALIDATION.md).
- Optimized static code scanning performance: implemented single-pass AST sharing between syntax and project flow analysis, precompiled regex rules across config and finding formatters, combined credential heuristics, and added automated virtual environment filtering (.venv*, *-venv, pyvenv.cfg) with benchmark documentation (docs/PERFORMANCE_REPORT.md).
- Solved AI packet token bloat: deduplicated repeated per-file limitations in interpretation evidence, grouped recurring rule context, stripped private local path prefixes, and redacted high-entropy secrets while keeping technical reports intact.
- Enforced cryptographic cache key isolation across providers (OpenAI, Gemini), models, languages (pl, en), schemas, and parameters with backward compatibility for legacy OpenAI entries.
- Added offline Google Gemini REST adapter (src/ai_threat_lab/gemini_adapter.py) targeting v1beta/models/{model}:generateContent with strict JSON schema enforcement, tools/function-calling disabled, API key redaction in all failure modes, 84 offline test scenarios, and reference responses in PL/EN (docs/GEMINI_API_ADAPTER.md).
- Aligned Gemini adapter with current official Google Gemini API REST v1beta specification: enforced authentication strictly via the `x-goog-api-key` HTTP header (removed obsolete URL query depictions), updated model recommendations to active models (gemini-3.8-flash, gemini-3.5-flash-lite, gemini-2.5-flash, gemini-2.5-pro) while removing sunset 1.5/2.0 references, added Google RPC error status parsing with key redaction, and verified reasoning token (`thoughtsTokenCount`) and context cache (`cachedContentTokenCount`) accounting.
- Added Gemini integration to Workbench and Integration CLIs (--provider gemini) and exposed get_audit_limitations and Gemini review functions in gui_api.

## 0.39.1 — Offline CLI finalization, developer audit reports, and GUI API readiness

- Add structured `DetailedFinding` descriptions (`ai_threat_lab.finding_details`) answering all six developer remediation questions (*Co wykryto?*, *Dlaczego jest to potencjalnie niebezpieczne?*, *Do czego może doprowadzić?*, *Jak to naprawić?*, *Jak sprawdzić poprawkę?*, *Czego analizator nie ustalił?*) in English (`en`) and Polish (`pl`) without inventing line numbers or elevating heuristic observations to confirmed status.
- Upgrade `inspect`, `brief`, and HTML audit reports (`render_html`) with full remediation cards, target recognition summaries, executed/skipped check disclosures, and `--language en|pl` support.
- Add offline multilingual AI contract helpers (`build_multilingual_ai_packet`, `attach_ai_interpretation`, `review_instructions(language=...)`) that keep local technical reports immutable and isolated from invalid or hallucinated model output.
- Add the stable Python GUI integration API (`ai_threat_lab.gui_api`), `docs/GUI_API_HANDOFF.md`, `docs/QUICK_START.md`, and end-to-end tests across 8 representative reference projects (`tests/test_stage2_audit_and_gui_api.py`).
- Emit explicit `REQUIRES_LIVE_VALIDATION` status in `setup-check`, optional integration profiles and `doctor` diagnostics whenever a property cannot be confirmed without a live external service.
- Enforce strict separation between `--dry-run` and `--send-evidence` in `ai-explain` and `ai-review`, and detect model refusal (`type="refusal"`) and non-object/non-array wire payloads in `OpenAIResponses`.
- Fix cross-module pytest fixture resolution in `tests/test_ai_costs_closure.py` when running the full test suite.
- Add the 20-scenario simulated AI response contract suite (`tests/test_ai_review.py`), independent analyzer quality benchmark (`tests/test_analyzer_quality_benchmark.py`), and `docs/READY_FOR_API_TESTING.md`.

- Add bounded foreground call monitoring with one stop attempt on expiry, local cancellation, timeout, interruption or status failure; preserve uncertain outcomes and never create another call.
- Add one explicitly approved fictional training call with fixed speech, durable attempt blocking, exact status/remote stop, nonsecret setup diagnostics and synthetic installed acceptance.
- Add explicit local Office package declaration review with bounded XML processing, private-field omission, shared summaries/AI previews and installed offline acceptance.
- Add fictional stock-avatar preview, durable asynchronous submission, explicit status and
  bounded credential-separated media download. Bind downloaded bytes into a new plan digest
  requiring fresh media approval; preserve unknown attempts and local-only cancellation.

- Preserve immediate broken-pipe errors from argparse help/usage so the process boundary
  returns the documented quiet exit even when help exceeds the stream buffer (issue #6).

- Synchronize closed-output-pipe process checks before invoking the CLI, retaining strict
  exit-code/stderr assertions while removing a Windows scheduling race (issue #6).

- Import bounded saved SARIF 2.1.0 results into local/AI evidence workflows, retaining
  reported classifications, suppression states, locations, producer limitations and failures.
  Never invoke scanners, open referenced sources, load external properties or apply fixes.

- Add exact-hash preview and explicit existing VirusTotal reputation lookup, preserving
  local file evidence on provider failures. Validate returned identity, size, dates and
  bounded statistics; omit free-form provider content. No upload, rescan or execution.

- Integrate bounded attachment structure checks into ordinary EML assessment and scans,
  retaining message evidence on attachment failures. Engine 28 preserves historical bundles.
  Extend credential-free setup checks and console setup to optional SMTP and speech profiles.

- Add explicit saved-session headers to passive site review with exact host/path binding,
  UTC expiry and access-denial stop. Use aliased report targets and a separately claimed
  private URL map so authenticated paths do not enter AI evidence.

- Add bounded Composer and NuGet lock inventory to local/pinned-GitHub discovery,
  recorded OSV identities and installed acceptance. Preserve skipped/private-feed
  limitations; engine 27 keeps older bundles readable without cross-engine deltas.

- Add an optional stock-voice speech adapter for approved fictional scripts: exact SSML
  preview, configured cost estimate, explicit provider request, validated local PCM WAV,
  persistent attempt outcomes, cancellation and duplicate blocking. No calls or voice cloning.

- Add offline attachment structure review with bounded MIME decoding, byte-based PE/ELF/ZIP
  inspection, private indexed labels and combined evidence reports. No attachment extraction,
  execution or network access occurs.

- Add preview-bound fictional SMTP email delivery with verified TLS, explicit account/host
  confirmation, durable per-recipient claims/outcomes, cancellation and no automatic retries.
  Keep server acceptance distinct from delivery/participant telemetry; test only with fixtures.

- Add offline HAR 1.2 response review with no request replay, secret-free entry aliases,
  bounded paging/body decoding, preserved header evidence and explicit malformed/body gaps.

- Add `review-site` and guided passive site navigation: explicit host/path scope, bounded
  breadth-first discovery, reused header/HTML checks, per-page failures and standard combined
  evidence usable by brief/AI review. Exercise installed navigation with all sockets blocked.

- Add guided `console`, deterministic `plan`, `inspect` using the existing scan service,
  source-independent `brief`, exact `ai-prepare` previews and credential-free `setup-check`.
- Connect single assessments, internally validated combined reports and verified single/batch
  bundles to optional interpretation. Preserve limitations and stable observation references.
- Add `ai-review` with Responses structured output and exact supplied-reference coverage.
  AI advice stays separate from original evidence and never executes tools or attack code.
- Split large structured reviews losslessly into bounded, explicitly selected packets; preview
  per-packet/aggregate reservations without a key or ledger. No automatic paid call loop.
- Record known usage for invalid advice without caching/retrying. Preserve uncertain-outcome
  reservations, original cost controls, output claims and legacy free-text explanation support.
- Add console/packet/configuration/grounding regressions and socket-blocked installed acceptance.
  Document the owner's console-only scope; GUI remains a separate contributor's responsibility.
- Include public guides, examples and verification scripts in the source archive; verify their
  contents while keeping them out of the runtime wheel. Skip only the Git whitespace check when
  the release verifier runs from an unpacked source archive without Git metadata.

## 0.36.0

- Close the bounded passive HTTPS collector offline contract. Preserve valid header findings when the body is oversized, incomplete or unreadable; discard partial bytes and report the body gap. Skip declared oversized bodies before download.
- Detect outstanding HTTP response length after bounded reads, including valid-looking truncated JSON. Keep generic API clients strict; partial-body transport is explicit and GET-only.
- Use the current release identity in the HTTP User-Agent. Enforce website URL bounds/preflight and typed transport limits; normalize malformed adapter metadata to redacted provider errors. Clarify shared header-only coverage wording.
- Add native-parser regressions and socket-blocked installed before/after/failure/redirect workflows, with scope rejection and verified report checks.
- Advance scan engine to 23 for changed collection coverage; retain old bundle reads and prohibit cross-engine deltas. AI API setup and real-target validation remain deferred.

## 0.35.0

- Close the existing bounded GitHub collector offline contract with controlled malformed SHA/default-branch/truncation responses, boolean option checks and redacted local token-header validation.
- Bound provider JSON to 64 container levels and convert excessive depth or decoder recursion failures into controlled integration errors. Keep immutable source/manifest selection, digest verification, budgets and analysis engines unchanged.
- Add boundary regressions and a clean installed-wheel synthetic GitHub scan with blocked sockets, exact request/blob-reuse checks, verified reports and malformed/denied/rate-limit controls.
- Document snapshot and selection limits, socket timeout versus command deadline, usage and remaining live-account validation. AI API setup remains deferred.

## 0.34.0

- Reuse full runtime catalog validation in installation diagnostics; invalid schemas, records, control references and duplicate identities cannot report ready.

- Include the Windows CI correction: normalize CRT invalid-argument errors only for pipe output and close failed buffers before shutdown; preserve file errors and platform line endings.

- Close the finite CLI/install contract: require full option names on every parser, use one release-version source and add credential-free, network-free installation diagnostics.
- Share a UTF-8 process entrypoint between the console executable and module; flush help/version and command output and handle closed pipes with quiet exit 141. Reject malformed UTF-8 interactive input without a traceback.
- Verify wheel/sdist identity, Python minimum, console entrypoint and bundled resources; extend clean offline wheel installation to every command help, module parity, diagnostics, legacy locale and closed-pipe behavior.
- Add process regressions, Linux/Windows/offline installation instructions and explicit acceptance limits. Existing analysis engines and API configuration remain unchanged.

## 0.33.0

- Close the finite local reporting/history contract with history-list JSON/HTML and report-export for verified saved single/batch runs, without original target access or provider calls.
- Enforce bounded root/run enumeration and aggregate verification reads, visible invalid entries, source-free exports, private no-overwrite outputs and saved-run placement guards.
- Verify derived single-bundle HTML and typed JSON, target-kind/dependency scope and saved comparison schema/current-side coverage; preserve files replaced by another actor during publication failure.
- Harden saved-artifact readers against links/junctions/special files, include descriptor checks and fix summary HTML escaping for Python callers.
- Add seven pre-fix reproductions, history/export/failure/CLI controls, deleted-source demo and clean-wheel acceptance. Mark local reports offline-complete; central history/PDF/retention services remain outside this contract. Assessment engines are unchanged.

## 0.32.0

- Close the finite offline AI explanation/cost contract with strict legacy-compatible ledger validation, existing-only operational reads and no implicit recreation after deletion. Preserve billing/pending history.
- Sample BudgetedAI clocks after writer locks for cache TTL and UTC budgets. Record token overruns without caching them; validate legacy cache usage before reuse and preserve uncertain completion IDs.
- Use exact integer token-charge arithmetic and precision-independent price validation, validate structured evidence and skip empty findings at the service boundary.
- Add transactional api-cache-prune for expired/all cached text, separate pending versus recorded daily totals, and exclusive private AI output claims before dispatch.
- Add pre-fix reproductions, concurrency/fault/CLI tests and a network-blocked installed-wheel lifecycle. Mark AI offline-complete within the documented contract; live model/account/pricing/billing validation remains deferred. Assessment engines are unchanged.

## 0.31.0

- Add bounded single-host OpenSSH journal JSONL review, with exact process/machine scope, integer journal-reception timestamps, terminal outcome/method mapping and source-free original-line evidence.
- Reuse authentication-pattern windows and success resets; reject ambiguous/unsupported terminal outcomes and disclose omitted messages, duplicate collapse and collection limits. Do not infer MFA from keyboard-interactive authentication.
- Add review-ssh-journal, explicit .ssh.jsonl assessment/single/batch routing, paired offline-demo controls, installed-wheel workflows and native-format/privacy/resource regressions. No journal collection, subprocess, network or login attempts.
- Advance scan engine to 22, retain engine-21 bundle reading and disable cross-engine comparisons. Python engines are unchanged; API setup remains deferred.

## 0.30.0

- Add read-only historical signed-event receipts without replaying imports or renewing expired approvals. Require the original signed envelope and registered scope/key bindings.
- Add combined local rehearsal/event cancellation in one attached SQLite transaction, plus aggregate status that exposes partial cancellation. Require existing distinct DELETE-mode databases in the same private directory.
- Add rollback, concurrency, path/schema/privacy, real-process and installed-wheel checks, plus independent demo completion checks. No external API, delivery or provider cancellation is added; assessment engines remain unchanged.

## 0.29.0

- Add a local shared-key training-event protocol, exclusive private key creation and binding of exact caller-approved plans to explicit alias/index, channel, issuer and key fingerprints.
- Add bounded strict envelope validation, HMAC-SHA256, freshness/scope checks after the writer lock, transactional duplicate/conflict handling, provenance-scoped participant stops and permanent local plan cancellation.
- Aggregate simulation, automation and adapter assertions separately without claiming participant verification or external delivery. Keep native provider intake, dispatch and retention/rotation engineering deferred.
- Add five CLI commands, three-channel synthetic acceptance, installed-wheel workflows and signature/time/scope/concurrency/rollback regression controls including an independent OpenSSL signature vector. Assessment engines remain unchanged; API setup remains deferred.

## 0.28.0

- Add bounded normalized authentication-event review for repeated failures, password-spray-like and distributed patterns, and declared success after failures, without login attempts or account access.
- Preserve exact-identifier grouping, UTC ordering, inclusive windows, duplicate collapse, pair success reset, configurable bounded policy and source-free evidence. Reject invalid captures; disclose resource/interpretation gaps.
- Integrate review-auth-log JSON/HTML, explicit .auth.jsonl assessment/scan/batch routing, readiness, paired demo and installed-wheel acceptance. Project walks do not ingest logs.
- Add boundary/privacy/CLI regressions and independent generated prefix-window oracle controls. Advance scan engine to 21, retaining old bundle reading and disabled cross-engine comparisons. API setup remains deferred.

## 0.27.0

- Add bounded saved HTML form/resource authoring-pattern checks with optional declared document context, source-free line evidence and explicit browser/encoding/structure gaps.
- Reuse the parser in selected local/verified GitHub HTML, existing successful HTTPS response bodies and bounded EML HTML parts without additional resource requests or rendering.
- Add ZIP directory/local-header metadata review, directory preflight limits and aggregate path/collision/symlink/declared-expansion candidates without reading or extracting members.
- Integrate CLI, single/batch bundles, readiness, positive/negative demo fixtures and installed-wheel acceptance. Advance scan engine to 20; retain old bundle reading and disable cross-engine comparisons. API setup remains deferred.

## 0.26.1

- Fix false cross-file flows when assigned package attributes were silently replaced by collected child modules; retain uncertainty after skipped module-level namespace barriers.
- Separate from-import child loading from ordinary attribute access. Preserve bounded explicit dotted-import facts through aliases/returns and definite joins; model selected initializer child bindings and later cached-child reassignments without executing target code.
- Add paired positive/negative namespace fixtures, local/verified-GitHub and installed-wheel acceptance, regression tests, independent inert Python import-oracle checks and finite offline release criteria. Refresh stale testing/documentation status.
- Advance project pass to python-project-modules-1.4 and scan engine to 19. Retain Python AST engine 1.8, old bundle reading and disabled cross-engine comparisons. API setup remains deferred.

## 0.26.0

- Traverse selected synchronous default-factory SQLite connection contexts with simple as names, ordered items (at most eight), nested bodies and normal-body successor/termination handling.
- Carry connection kind through supported aliases, arguments, returns and definite joins; distinguish cursors/execute results for context selection. Keep unknown managers, custom factories, unsupported call/target forms and item/depth limits as explicit barriers.
- Preserve query-value versus query-text separation, source-free evidence and existing runtime/transaction/exception limitations. No target execution or database opening.
- Add context regression, CLI/SARIF, verified-GitHub and bundle tests, an inert offline fixture and installed-wheel acceptance checks.
- Advance Python AST engine to 1.8, project pass to python-project-modules-1.3 and scan engine to 18. Retain older bundle reading and suppress cross-engine comparisons. API setup remains deferred.

## 0.25.0

- Resolve selected imported/aliased importlib.import_module calls with literal absolute names or literal relative names and explicit package anchors over already collected sources.
- Enforce strict bounded argument/name decoding; retain gaps for computed/uncollected targets, missing or noncompleting modules, cycles and ambiguous mappings. Respect local importlib shadowing without target execution or additional network retrieval.
- Add positive/negative, CLI, verified-GitHub and bundle regression cases, an inert importlib demo and installed-wheel acceptance checks. Document the limited subset and incomplete construction-site history.
- Advance the project pass to python-project-modules-1.2 and scan engine to 17; retain Python AST engine 1.7 and old bundle reading with cross-engine comparisons disabled. API setup remains deferred.

## 0.24.0

- Extend supplementary Python linking to collected regular packages, conventional src layouts, absolute dotted imports, lexical relative imports and definite module/helper re-exports.
- Require collected package markers; expose ambiguous mappings, missing/unavailable or noncompleting parents, import cycles and package-depth limits. Reuse bounded source text without executing initializers or fetching imports.
- Add package-layout regression, CLI and pinned GitHub tests plus a three-file offline fixture and installed-wheel acceptance gate.
- Advance Python AST engine to 1.7, project pass to python-project-modules-1.1 and scan engine to 16. Retain older bundle reading, with cross-engine comparisons disabled. API setup remains deferred.

## 0.23.0

- Add a supplementary static pass linking selected flat root Python modules through absolute local imports, aliases, argument/return propagation and SQLite identities.
- Preserve file-qualified source/sink/call/helper evidence and report only supplementary cross-file flow observations. Reuse already-collected local/GitHub source text; perform no target import, installation, execution or additional fetch.
- Bound input count, selected file attempts/bytes and helper-definition evidence alongside shared flow budgets. Preserve cycle, unavailable/non-function export, unsupported layout, parse/encoding and noncompleting-module gaps; do not fall back to library bindings for known unavailable local modules.
- Share local source decoding between per-file and project passes; reject non-file Python sources before opening. Single-file review/SARIF remains single-file.
- Add a two-module inert demo and installed-wheel gate, 61 regression/integration/CLI cases, and scope/usage documentation. API setup remains deferred.
- Advance Python engine to python-ast-1.6 and scan engine to 15; identify the project pass as python-root-modules-1.0. Retain old bundle reading and suppress cross-engine comparisons.

## 0.22.0

- Extend PY013/PY014 to selected previously defined module-level same-file helpers, with strict positional/keyword/default binding and argument/return propagation.
- Carry selected HTTP origins, SQLite identities and known callable aliases across bounded contexts. Preserve call-site line evidence through returned values and merge repeated contexts by sink without source values.
- Stop recursion and enforce table/call/depth/parameter/evidence budgets alongside existing flow limits. Unsupported/invalid signatures, defaults, unpacking, decorators, generators, async/nested/forward/imported helpers retain gaps.
- Keep runtime globals, object effects, callee exceptions/termination, cross-file resolution and exploitability outside the abstraction. No Python target execution or imports.
- Add a separate inert same-file helper demo, installed-wheel acceptance and 65 regression/integration/CLI cases with updated documentation.
- Advance Python engine to python-ast-1.5 and scan engine to 14; retain earlier bundle reading and suppress cross-engine comparisons. API setup remains deferred.

## 0.21.0

- Extend PY013/PY014 with possible-origin if/else/elif joins, conditional/boolean expressions and nested condition operands. Exclude terminated branches from successor states and prune direct literal boolean choices.
- Preserve API/SQLite identity only when all reaching states agree; expose ambiguous-binding gaps rather than guessing runtime objects. No path-feasibility, correlated-condition or implicit-flow proof.
- Inspect selected for/while bodies once with zero/one-iteration joins and loop else; retain explicit loop-carried/convergence gaps. Skip loops containing break/continue as barriers.
- Add control-flow nesting bounds and keep function-scope/step/depth/origin/finding limits. No execution, framework import, database or network access.
- Add a separate inert branch/loop demo and installed-wheel checks, plus 62 control-flow regression/integration/CLI cases and documentation.
- Advance Python engine to python-ast-1.4 and scan engine to 13; retain earlier bundle reading and suppress cross-engine comparisons. API setup remains deferred.

## 0.20.0

- Add PY013/PY014: bounded straight-line dependencies from explicitly imported Flask request sources to selected shell command and recognized SQLite query APIs.
- Track simple assignments, aliases, selected string operations and imported SQLite connection/cursor identities; preserve source/sink lines without input values.
- Keep parameterized query values separate from query-text observations. Reset tracking at unsupported control-flow barriers; expose unknown-call, import, write and resource-limit gaps.
- Bound flow expression steps/depth, scopes, source origins and findings. No framework imports, source execution, HTTP calls, database opening or exploit validation.
- Reuse observations and coverage notices in standalone JSON/text/SARIF, local/GitHub assessments and reports. Add an inert flow demo plus installed-wheel gate and 92 regression/integration/CLI cases.
- Advance Python engine to python-ast-1.3 and scan engine to 12; retain older bundle reading and suppress cross-engine comparisons. API setup remains deferred.

## 0.19.0

- Extend Python review to twelve rule families: explicit Jinja autoescape=False, Django/MarkupSafe safe-HTML markers and PyJWT-style literal verify_signature=False options.
- Keep source-free candidate evidence and simple alias handling; do not infer HTML context, sanitizer correctness, installed library identity or authorization use. Leave ambiguous JWT dictionaries unchecked.
- Reuse the rules in standalone text/JSON/SARIF, local and immutable GitHub scans. No framework imports, template rendering, token handling, runtime execution or network calls.
- Extend offline demo and installed-wheel acceptance to eight PY005–PY012 observations. Add 55 tests and detailed rule/scope documentation.
- Advance Python engine to python-ast-1.2 and scan engine to 11; retain older bundle reading and disable cross-engine deltas. API setup remains deferred.

## 0.18.0

- Add bounded Go `go.sum` module-content inventory to existing local, recursive and pinned GitHub routes. Keep case-sensitive paths, exact v-prefixed versions and merged origins; omit metadata-only and unsupported records with redacted notices.
- Check supported h1 field syntax/canonical encoding without verifying checksums or resolving build selection, replacements, workspaces, pseudo-version provenance or reachability. Historical/unused versions may be included.
- Apply shared manifest/byte/package budgets plus a 20,000-line bound. No Go command, fetch or package installation.
- Extend offline demo and clean installed-wheel checks with a fictional Go identity; add 56 regression/integration/CLI cases and documentation. OSV requests are fixture-tested only.
- Advance scan scope to engine 10, retaining old bundle reading and suppressing cross-engine deltas. API setup remains deferred.

## 0.17.0

- Add bounded offline Kubernetes JSON review for Pod, selected apps/v1 and batch/v1 workload templates, v1 ReplicationController and nested v1 List resources.
- Observe ten explicit field families: host namespaces, privileged/escalation/root identity, non-root opt-out, writable root filesystem, selected added capabilities, unconfined seccomp, hostPath volumes and host ports. Do not infer defaults or effective runtime state.
- Add `review-kubernetes` with JSON/escaped HTML, no overwrite and finding-based exit behavior. Reuse the same checker in bounded local/GitHub project collection and existing scan/batch reports.
- Emit fixed-field JSON pointer evidence without names, namespaces, images, host paths or input values. Preserve malformed-selected-field, unsupported-resource, explicit non-Linux and resource-limit coverage notices.
- Enforce source bytes and lexical JSON depth before decoding; bound resources, List depth, containers, volumes, ports, findings and notices. No YAML/Helm rendering, kubectl, cluster/network access or admission/conformance validation.
- Extend synthetic demo and clean installed-wheel gates with ten Kubernetes observations. Advance scan scope to engine 9; retain prior bundle reading and suppress cross-engine deltas.
- Add positive/negative/workload/type/resource/privacy/no-execution/CLI/local/GitHub/batch/error/compatibility tests. API setup remains deferred.

## 0.16.0

- Add `review-headers` for bounded caller-supplied HTTPS response-header captures, JSON/HTML output, finding-based exits and no-overwrite files; never fetch the declared URL.
- Share selected HSTS/nosniff/header presence, cookie metadata and CSP script-pattern checks with the existing passive WebsiteAudit collector.
- Preserve duplicate wire headers in HttpResponse while retaining the legacy mapping; inspect every individual Set-Cookie without comma folding and report missing duplicate coverage for mapping-only adapters.
- Aggregate cookie observations with names/values omitted; cover selected flags, SameSite and Secure/Host prefixes, while treating malformed/ambiguous entries as unassessed candidates.
- Observe selected script CSP patterns with explicit nonce/hash, strict-dynamic, split-directive, duplicate and multiple-policy limitations. Do not claim effective browser enforcement.
- Enforce strict capture/schema/status/header controls and count/byte bounds; omit declared capture URL, unknown header values, tokens, cookies and policy values from new reports.
- Extend synthetic offline demo and clean installed-wheel acceptance with six header observations. Add no-network/privacy/duplicate/limit/error/CLI tests.
- Advance scan engine to 8; retain old bundle reading and suppress cross-engine deltas. No API/account setup or live target validation.

## 0.15.0

- Add `scan-batch` for 1–10 explicit distinct local targets, sequentially using built-in offline collectors; reject remote targets, links, overlapping sources and output inside scanned projects before claiming the destination.
- Publish each existing scan bundle independently, then combined JSON/HTML and `batch.json` last. Preserve per-target module failures and other useful results; no automatic retry/resume or network/model call.
- Add `batch-check`: bounded schema/path/index checks, child manifest hashes, child integrity/scope validation, combined report regeneration and summary consistency. Checks do not reread source files.
- Preserve no-overwrite and cancellation semantics; bound child artifact totals and combined-report sizes. Completion means publication, never security or authenticity.
- Extend synthetic offline demo and clean installed-wheel acceptance with two-target batches; add CLI exit-policy, malformed/tampered/missing output, privacy, resource, symlink and partial-failure tests. APIs remain deferred.

## 0.14.0

- Add Cargo.lock v3/v4 exact crates.io inventory through local, opted-in nested and shared immutable GitHub routes; preserve global parser/byte/package limits and source origins.
- Skip local/git/alternate registry sources with redacted notices; validate selected SemVer forms and use the existing opt-in OSV batch/cache contract for crates.io. Never call Cargo or install dependencies.
- Expand exported EML review with bounded plain/HTML link and attachment metadata candidates, aggregate source-free evidence, no network or payload execution.
- Report cleartext/IP/userinfo/active-scheme/display-host link patterns and executable/script/macro or document-plus-active attachment extensions as human-review candidates.
- Bound input, selected MIME depth/parts, decoded text, text parts and links; preserve explicit decoding, parser and omitted-coverage notices. Catch structural parser failures and reject linked/non-regular EML targets.
- Consider all Authentication-Results headers without trusting their provenance; retain explicit authenticity/reputation/cryptographic gaps.
- Extend offline demo with Python + Rust inventories, five-observation inert EML fixture and separate report bundle; acceptance failure cannot publish the completion marker.
- Advance scan scope to engine 7, keep older bundle reading and suppress cross-engine deltas. Add exported-mail readiness, CLI/package tests and updated capability docs. No API setup or live integrations.

## 0.13.0

- Add offline SARIF 2.1.0 export for the nine Python pattern rule families through `review-code --format sarif` and the existing renderer API.
- Keep candidate-only warnings, source-free evidence, line-only regions and explicit original UTF-8 byte-column metadata; avoid inaccurate Unicode highlighting.
- Use URI-encoded basenames by default; optional `--source-root` preserves relative paths and rejects resolved sources outside the root. Do not export absolute roots, source snippets or invocation/environment metadata.
- Preserve no-overwrite reports and existing exit behavior; test rule indexes, empty runs, repeated observations, URI encoding, root escapes, real CLI processes and clean installed wheels.
- Validate representative outputs against the official OASIS schema. No automatic upload, scan-engine change, API setup or live calls.

## 0.12.0

- Expand bounded Python AST review from four to nine rule families: OS shell APIs, non-atomic temporary names, the unverified TLS helper, explicit unsafe YAML loaders and MD5/SHA-1 candidates.
- Share the rules across standalone review, local assessments and immutable GitHub collection; retain source/argument redaction and no execution.
- Document literal-loader/hash exemptions, TLS override limitations and unresolved data-flow/scope semantics.
- Add a separate inert five-pattern offline demo/report, CLI and installed-wheel acceptance checks.
- Advance scan scope to engine 6; preserve reading older bundles and suppress cross-engine deltas. No API setup or live calls added.

## 0.11.0

- Keep large binary fixture test IDs compact, enforce a portable ID length during collection, and bound CI job duration.

- Add bounded static PE32/PE32+ and ELF32/ELF64 header observations to local program-file audits and scans; never execute or upload target bytes.
- Record selected PE hardening bits, section write/execute flags and bounded certificate-table presence without signature/trust claims.
- Add both ELF byte orders, selected program/load/stack flags and RELRO markers with explicit PIE/runtime/full-RELRO limitations.
- Preserve metadata and mark structural checks unavailable on malformed/unsupported input; suppress partially parsed mitigation candidates.
- Reject links/non-regular inputs and close descriptors on errors; cap bytes and record counts.
- Extend synthetic offline demo with inert binary descriptors and reports, scope engine 5, old-bundle reading, malformed/fuzz/CLI/resource tests and installed-package verification.

## 0.10.0

- Add opted-in `--recursive-dependencies` to local `audit-deps` and local/GitHub `scan`; retain root-only defaults.
- Discover nested manifests with global manifest/package/byte/directory/entry/depth bounds, deterministic breadth-first local traversal and explicit partial-coverage notices. Skip links/junctions and excluded directories.
- Preserve portable relative origins across all supported formats; deduplicate exact package identities across subprojects before optional advisory queries.
- Share nested GitHub inventory with the existing pinned commit and bounded blob retrieval; reject snapshot/scope disagreements.
- Add strict recursive scope to engine 4, retain old bundle reading and suppress cross-coverage comparisons.
- Extend synthetic demo, CLI/wire/resource/error tests and clean installed-wheel verification. No live API validation or model calls added.

## 0.9.0

- Add literal Dockerfile and GitHub Actions configuration observations, shared by local and immutable GitHub collection. All remain candidate findings with explicit parser/runtime gaps.
- Add exact-approved inert exercise exports: reserved-address `.eml`, escaped HTML, voice script and video storyboard. No sending, calling, source execution or media generation.
- Add `offline-demo`: generated project before/after scans, integrity checks, three scripted training sessions and linked reports; publish completion only after acceptance checks.
- Add `readiness` static capability inventory, explicit missing-engineering statuses and a complete delivery matrix; no credential inspection or service probes.
- Advance scan scope engine to 3; keep older bundle reading and suppress cross-engine deltas.
- Extend no-network, redaction/escaping, approval/expiry, no-overwrite, CLI and clean installed-wheel verification.

## 0.8.0

- Add GitHub root dependency inventory to combined scans using the same immutable commit and shared bounded retrieval as source checks.
- Parse in-memory requirements/npm/uv/Poetry inputs without saving repository source; reuse verified blobs and prioritize root manifests within shared limits.
- Extend explicit OSV sharing and advisory caching to GitHub scans. Preserve source/inventory evidence when parsing or advisory modules fail.
- Advance scan scope engine to version 2; retain version-1 bundle reading while conservatively disabling cross-engine deltas.
- Add synthetic CLI/wire, shared-budget/digest, malformed-manifest, provenance, redaction and compatibility checks. No live API validation.

## 0.7.0

- Add a one-command read-only `scan` workflow over existing collectors, automatic local-project dependency inventory and explicitly opted-in OSV lookup. No automatic AI calls.
- Preserve module failures and unchecked areas in useful partial reports; fail-on-findings is a separate opt-in exit policy.
- Add private no-overwrite report bundles with staged bytes, manifest-last commit, SHA-256/size indexes and bounded integrity/derived-report checks.
- Add `scan-check`, `scan-compare` and optional baseline comparison, preserving new/still/no-longer-observed labels without claiming remediation. Changed scope/module coverage disables deltas.
- Add malformed bundle, symlink, concurrent directory-claim, interrupted publication, redaction, scope, CLI and installed-package tests.

## 0.6.0

- Add approved local text-training sessions for email/voice/video scenarios, bound to exact preview digests, participant aliases and approved recipient indices.
- Add SQLite state, unique plan/participant/recipient sessions, atomic idempotent actions, expiry and persistent whole-plan cancellation.
- Add numbered interactive rehearsal, stop/EOF/Ctrl+C handling and deterministic voice dialogue with a three-unknown-turn bound. No raw replies, speech, calls, media or link visits.
- Add JSON/escaped standalone HTML session reports with selected outcomes, follow-up practice and explicit limits; do not label selections as observed susceptibility or identity verification.
- Extend CLI subprocess, approval, concurrency, expiry, privacy, cancellation and installed-wheel checks.

## 0.5.0

- Add static exact-version inventory for requirements, npm lockfiles v2/v3, uv and Poetry locks; normalize and deduplicate identities without installation or code execution.
- Add explicitly consented OSV batch queries, bounded pagination, advisory identity checks, partial-result notices and optional one-hour local cache. No AI/model call is needed.
- Add combined JSON/standalone HTML reports with exact finding deduplication, provenance, preserved gaps and explained human-triage priorities. Escape untrusted fields and block active/external content.
- Bound the legacy Python traversal by directories/entries; tighten GitHub repository path validation and keep POST restricted to two fixed query endpoints.
- Expand CLI/contract, cache, malformed-input, paging and installed-package verification.

## 0.4.0

- Add explicit read-only `audit` collectors for immutable GitHub source, passive HTTPS headers, basic mail DNS policy, authenticated Gmail forwarding/filter settings, and local secret/manifest/program inventory.
- Add exact target scope, public DNS pinning with original-host TLS verification, bounded reads and fixed provider endpoints. Do not follow redirects or execute downloaded code.
- Add a concrete optional OpenAI Responses explanation adapter; minimize/deduplicate structured evidence, require transmission opt-in, cap context/output, and offer no-network cost estimates.
- Add SQLite daily/request budget reservations, optional exact-match TTL cache, cross-process pending-request deduplication, conservative unknown-outcome handling and operator billing reconciliation.
- Add `ai-explain`, `api-costs` and `api-reconcile`, setup/cost documentation and a synthetic example configuration.
- Expand fixture, concurrency, CLI subprocess and installed-wheel verification. No paid requests or real mailbox/communications actions were performed.

All audit results remain partial. Training dispatch remains simulated; active exploitation, full dependency/binary audits, live calls, media generation and telemetry collection are not bundled. Account permissions, models/prices and real service behavior require validation before live use.
