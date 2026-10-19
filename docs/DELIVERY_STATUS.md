# Delivery status and remaining work — 0.39.1

The local signed-training-event milestone adds approved plan/alias/key bindings, strict shared-key envelope validation, transactional replay/conflict checks, local cancellation and provenance-separated aggregate reports. It is not a native provider webhook or participant-verification implementation. See [SIGNED_TRAINING_EVENTS.md](SIGNED_TRAINING_EVENTS.md).

The bounded normalized authentication-log milestone adds offline failure/spray/distributed/success-sequence candidates, explicit file routing, reports and acceptance controls. See [AUTHENTICATION_LOGS.md](AUTHENTICATION_LOGS.md). No login attempts or account access occur.

The bounded HTML/EML/ZIP milestone is implemented on top of the offline CLI. Saved pages now have a standalone command and shared form/resource checks; selected EML forms and existing successful HTTPS bodies reuse them. Explicit ZIP file targets receive metadata-only review. See [HTML_REVIEW.md](HTML_REVIEW.md) and [ARCHIVE_REVIEW.md](ARCHIVE_REVIEW.md). These checks retain partial results and limits; they do not implement live attack or delivery capabilities. API setup remains deferred.

This matrix maps the requested console workflow to its actual implementation. API setup/live calls are deferred. The offline kit is ready to demonstrate; the full original vision is not complete.

| Input/capability | Implemented now | Still missing |
| --- | --- | --- |
| Local project path | Fourteen bounded Python AST rule families including local Flask-to-shell/SQLite flows with branch joins/one-pass loops and bounded same-file calls/SQLite connection contexts plus selected regular root/src package, relative-import and literal importlib links, credential-pattern, literal config and structured Kubernetes JSON observations; root/opt-in nested Python/npm/Cargo exact-version and Go checksum-record inventory; reports | More language families, namespace packages/cross-method analysis, loop convergence/path feasibility, dependency-graph/reachability analysis and deeper validation |
| GitHub root URL | Immutable default-branch commit, verified bounded blobs, source/config and root/opt-in nested dependency inventory | Controlled account validation, broader repository analysis and workspace graph resolution |
| Website URL | Opted-in single HTTPS header and selected HTML observations; offline saved-header/HTML review | Crawling, authenticated application/business-logic tests and controlled active-assessment implementation |
| Program file | Bounded size/hash, PE/ELF structures and ZIP metadata/path candidates | Cryptographic signature verification, disassembly, malware detection, dynamic analysis and broader formats/platform semantics |
| Exported email | Bounded headers, selected plain/HTML links, HTML forms and attachment-metadata candidates | Trusted message-authenticity validation, gateway policy, rendered content and attachment/malware analysis |
| Mail domain | Basic SPF/DMARC and supplied-selector DKIM observations | Complete policy evaluation and delivery validation |
| Own mailbox | Selected authenticated Gmail forwarding/filter observations | Controlled OAuth/account validation, more providers and broader mailbox controls |
| Signed training claims | Local HMAC journal, exact-plan/alias/key scope, freshness, replay/conflict checks, stops and separate simulation/automation/adapter aggregates | Native provider authentication/collection, participant identity/action verification, remote dispatch/stop integration, retention/rotation |
| Email training | Exact-preview plans, local structured rehearsal, inert `.eml` export, selected-outcome report | Live transport, delivery telemetry and authenticated participant events |
| Voice/vishing training | Fictional identity/facts, local bounded dialogue, stop/verification actions, text-script export | Telephony/speech adapters and controlled end-to-end validation |
| Deepfake/video training | Scenario, approved preview, local selections and text storyboard | Consented media-generation integration and controlled media/delivery validation |
| Brute force / credential stuffing | Educational scenarios plus bounded normalized and selected OpenSSH journal failure/spray/distributed/success-sequence candidates | No login attempts, arbitrary native-provider conversion, password-reuse or compromise confirmation |
| AI explanation/cost control | Offline-complete within the finite contract: budgeted adapter, evidence validation/minimization, dry-run, cache cleanup, reservations/reconciliation and output claims | Chosen model/prices/account setup and controlled live validation |
| Reports/history | Offline-complete within the finite local contract: single/batch bundles, JSON/HTML, Python SARIF, triage, bounded verified history catalog, saved-report export and conservative comparisons | Authenticated centralized history, organization policy and retention |
| Offline acceptance | One-command generated fixture demo, all three local training channels, exports and readiness inventory | Real target/provider evidence remains separate |
| GUI | Existing service contracts/handoff documentation | GUI implementation, deferred by console-first scope |

## Completed without external APIs in the offline acceptance stage (0.9.0)

1. Added bounded configuration observations to local and GitHub collection.
2. Added exact-approved local rehearsal asset exports for all three channels.
3. Added one-command synthetic acceptance demo and linked local reports.
4. Added an explicit implementation inventory, including engineering gaps.
5. Added regression, CLI process, no-network, escaping, expiry, overwrite and installed-package checks.

## Monorepo follow-up (0.10.0)

Nested requirements/npm/uv/Poetry/Cargo manifests are now supported within explicit bounds. Exact package identities are merged with relative origins preserved, using the same commit on GitHub. Additional ecosystems, workspace graph interpretation and reachability are still open. See [MONOREPOS.md](MONOREPOS.md).

## Static binary follow-up (0.11.0)

Local PE/ELF header and flag observations now complement metadata, with bounded parsing, unsupported-input notices and no execution. Certificate-table presence is not signature trust; mitigation flags are not runtime validation. See [BINARY_AUDIT.md](BINARY_AUDIT.md).

## Python pattern follow-up (0.12.0)

Nine AST rule families now cover selected dynamic execution, subprocess/OS shell, pickle, TLS, temporary-name, YAML and weak-digest APIs. Local and pinned GitHub routes share these checks; the demo includes five new inert examples. These remain syntax-level candidates, without input provenance or data-flow validation. See [CODE_REVIEW.md](CODE_REVIEW.md).

## Local report interchange (0.13.0)

Python review exports SARIF 2.1.0 with the same candidate findings, no snippets and configurable basename/root-relative source references. It does not upload to a service or export all combined assessment types. Scan bundle contents/engine and finding semantics remain unchanged. See [SARIF.md](SARIF.md).

## Offline assessment milestone (0.14.0)

Cargo.lock v3/v4 crates.io identities and bounded EML link/attachment metadata now work through the existing CLI, reports and synthetic demo. Shared GitHub Cargo retrieval is fixture-tested; mail analysis remains entirely local. Offline acceptance checks the before/after project, Python + Rust inventory, five Python patterns, five mail observations, PE/ELF descriptors, three text-training channels and report consistency. See [CARGO.md](CARGO.md), [MAIL_REVIEW.md](MAIL_REVIEW.md) and [OFFLINE_ACCEPTANCE.md](OFFLINE_ACCEPTANCE.md).

Completion of this bounded milestone means these implemented routes pass their documented automated gates. It does not mean the original full product is complete. Live campaigns/media, authenticated observed events, broader languages/data flow and deeper application/binary validation still require engineering; API setup remains deferred.

## Local operational workflow (0.15.0)

`scan-batch` runs up to ten explicit non-overlapping local targets sequentially and publishes verified child bundles plus a combined remediation report. `batch-check` validates the index, child evidence and derived reports without reopening sources. A failed target module remains visible while other results are preserved; a publication failure leaves no batch completion marker. The offline demo and installed-package gate exercise the complete path. See [BATCH_SCANS.md](BATCH_SCANS.md).

## HTTP header follow-up (0.16.0)

Offline saved-header review now shares bounded checks with the one-response HTTPS collector. Duplicate Set-Cookie fields are retained by the built-in transport, and reports omit cookie/policy values. The demo and installed CLI gate exercise a six-observation synthetic capture. Browser enforcement, cookie purpose/session state, capture authenticity and broader application analysis remain unchecked. See [HTTP_HEADERS.md](HTTP_HEADERS.md).

## Kubernetes JSON follow-up (0.17.0)

Selected Pod/workload JSON controls now work in a standalone CLI and local/immutable GitHub project scans, preserving fixed JSON pointer evidence and explicit scope limits. The offline demo and installed-package gate cover ten candidate families without contacting a cluster or executing the manifest. YAML/Helm, admission/defaults/inheritance, RBAC, cluster state, Windows Pod controls and policy conformance remain outside this checker. See [KUBERNETES.md](KUBERNETES.md).

## Go checksum-record follow-up (0.18.0)

Local and pinned GitHub dependency collection now accept bounded `go.sum` module-content records. Metadata-only entries are omitted; names, versions and origins are retained without invoking Go or verifying hashes. Historical/unused versions may be included. The offline demo and installed-wheel gate cover all three generated ecosystems; build selection, replacements, workspace and reachability remain unchecked. See [GO.md](GO.md).

## Python web API follow-up (0.19.0)

The shared AST reviewer now observes explicit Jinja autoescape opt-out, Django/MarkupSafe HTML trust markers and literal PyJWT-style signature-verification opt-out. Standalone JSON/text/SARIF, local/GitHub scans and the eight-observation demo share these checks. Library identity, data provenance, sanitization, effective runtime settings and authorization use remain unchecked. See [CODE_REVIEW.md](CODE_REVIEW.md).

## Selected Python input-flow follow-up (0.20.0)

The shared AST reviewer now carries selected Flask input origins through bounded local assignments and string expressions to shell and recognized SQLite query APIs. Reports retain line-only source/sink evidence and explicit barriers/limits. The separate inert demo verifies two flow observations plus one existing shell API observation. Branches, loops, exceptions, heap mutation, wrappers, cross-function propagation, runtime binding and exploitability are not resolved. See [PYTHON_FLOW.md](PYTHON_FLOW.md).

## Local control-flow follow-up (0.21.0)

Selected if/else/elif, conditional expressions, boolean/comparison operands and single-pass for/while bodies now participate in local flow analysis. Input origins merge across possibly reaching paths; API/SQLite identities survive only when all reaching states agree. Return/raise paths are excluded from successor joins. Loop-carried dependencies, convergence, correlated conditions, break/continue and broader runtime feasibility remain unchecked with explicit gaps. See [PYTHON_FLOW.md](PYTHON_FLOW.md).

## Same-file function-call follow-up (0.22.0)

Selected previously defined module-level Python helpers now accept statically bound arguments and return source/SQLite/callable descriptors. Independent function review remains available; contextual observations merge by sink with bounded source/call-site line evidence. Signature, recursion, call-depth/count, function-table and general flow limits preserve explicit gaps. Nested/async/decorated/generator/variadic functions, forward/imported helpers, runtime globals/effects, exceptions and cross-file dispatch remain unresolved. See [PYTHON_FLOW.md](PYTHON_FLOW.md).

## Root Python module-linking follow-up (0.23.0)

Collected local/GitHub root modules now support selected absolute sibling imports, aliases, arguments, returns and SQLite identities through the shared bounded flow engine. Supplementary candidates preserve file-qualified source/sink/call/helper evidence. No target imports or extra GitHub requests occur. At this release, packages/src layouts and relative imports were unresolved; see the 0.24.0 follow-up below. Dynamic imports, installed-module selection, initializer effects and general cross-file semantics remain unresolved. See [PYTHON_PROJECT_FLOW.md](PYTHON_PROJECT_FLOW.md).

## Current completion criteria and remaining work

The current priority is closing confirmed defects and passing the finite [offline release criteria](OFFLINE_RELEASE_CRITERIA.md), with existing analyzer scope frozen. This avoids treating another Python feature as completion of the product. The remaining full-product engineering tracks are listed separately there and in the capability matrix above. They require implementation and real-environment decisions; API keys alone cannot close them.

## Regular Python packages and src layouts (0.24.0)

Selected collected regular packages now support absolute dotted and lexical relative imports, including a conventional src root and definite helper/module re-exports. Missing/unavailable initializers, ambiguous root/package mappings, cycles and resource limits retain explicit gaps. Namespace packages, dynamic imports, installed-module selection and initializer runtime effects remain unresolved. The offline demo and installed-wheel gate cover the new layout. API setup remains deferred; a key alone does not complete production readiness.

## Literal importlib linking (0.25.0)

Selected `importlib.import_module` calls now return static descriptors for already collected modules. Imported aliases, literal absolute names and literal relative names with explicit package anchors are supported. Computed names, implicit `__package__`, built-in `__import__`, namespace packages and runtime import selection remain unresolved. Missing or noncompleting target/parent passes retain gaps. The offline demo and installed-wheel gate verify cross-file shell/SQLite observations through this route. API setup and live validation remain deferred.

## Selected SQLite context bodies (0.26.0)

Known default-factory SQLite connections now permit bounded synchronous with-body analysis, including simple aliases, selected helper arguments/returns, nested contexts and up to eight ordered items. Connection/cursor ambiguity, unsupported factories/call shapes, non-name targets and unknown managers retain explicit gaps. Transaction state, exit/close effects, exceptions and general context-manager protocols remain unresolved. A separate inert fixture and installed-wheel gate cover shell/SQLite observations without opening the target database. API setup remains deferred.

## Package-binding correctness follow-up (0.26.1)

Assigned package attributes and uncertain module namespaces no longer silently resolve to collected child files. Ordinary attribute access is separated from child-loading imports. Explicit dotted imports retain bounded scope facts, and selected initializer imports establish their own child attributes. Positive/negative regression controls now run through local/GitHub assessment, the offline demo and the installed wheel. No target code is executed; API setup remains deferred.

## Historical receipts and combined local control (0.30.0)

Read-only receipts recover an accepted event result after freshness/expiry/cancellation without reimport. Combined local status exposes partial cancellation; one attached SQLite transaction revokes rehearsal starts, stops running sessions and blocks event acceptance for the registered plan. Existing distinct DELETE-mode files in the same private directory are required. This is local state only, with filesystem/SQLite durability assumptions; provider dispatch/stop and full-product gaps remain open. See [LOCAL_TRAINING_CONTROL.md](LOCAL_TRAINING_CONTROL.md).

## Saved OpenSSH journal adapter (0.31.0)

The CLI maps selected single-host journal JSONL records into the existing four authentication-pattern families. It preserves source line references, redacts identities and rejects ambiguous terminal outcomes. Explicit `.ssh.jsonl` single/batch scans, paired demo and installed-wheel workflows are covered. Native syslog/Windows/other-provider conversion, journal collection, log authenticity and real deployment acceptance remain open. See [SSH_JOURNAL_REVIEW.md](SSH_JOURNAL_REVIEW.md).

## AI/cost offline completion (0.32.0)

The finite [AI offline acceptance contract](AI_OFFLINE_ACCEPTANCE.md) covers the existing single-provider explanation module: strict evidence/configuration, exact local accounting, writer-lock time checks, validated legacy-compatible storage, cache lifecycle, uncertain outcomes/reconciliation and pre-dispatch output claims. This module is offline-complete after its automated release gates; no additional providers or analyzers are part of this milestone. Real account/model/price selection and controlled live validation remain deferred. See [API_COSTS.md](API_COSTS.md).

## Reports/local history completion (0.33.0)

The finite [reporting contract](REPORTS_OFFLINE_ACCEPTANCE.md) is offline-complete after release gates: existing JSON/HTML and Python SARIF, verified single/batch storage, conservative comparisons, a bounded one-level history catalog and saved-report export after source deletion. Invalid history stays visible; no source/provider access occurs. Central authenticated history, automated retention, encryption/signatures and PDF are outside this local contract. See [LOCAL_REPORT_HISTORY.md](LOCAL_REPORT_HISTORY.md).

## CLI and installation closure (0.34.0)

The finite [CLI/install contract](CLI_OFFLINE_ACCEPTANCE.md) covers exact option names, one release identity, UTF-8 process streams, quiet closed-pipe exit, local installation diagnostics and wheel/sdist resource/metadata parity. Fresh offline wheel installation exercises every command help and existing functional workflows outside the checkout. Linux/Windows Python 3.12–3.14 CI provides platform evidence. See [installation instructions](CLI_INSTALLATION.md). API setup/live validation remain deferred; broader collector/product work is separate.

## GitHub collector offline closure (0.35.0)

The existing bounded collector is covered by the finite [offline acceptance contract](GITHUB_OFFLINE_ACCEPTANCE.md): immutable shared source/manifest selection, verified blob reuse, strict provider metadata and local header boundaries, controlled failures without retries and a socket-blocked synthetic scan from the installed wheel. This closes the offline collector implementation/testing scope; public/private account and organization access remain deferred integration validation. Source-language coverage and assessment engines are unchanged. See [usage and exact limits](GITHUB_COLLECTION.md).

## Passive HTTPS offline closure (0.36.0)

The finite [passive HTTPS contract](WEBSITE_OFFLINE_ACCEPTANCE.md) covers exact scope/preflight, one GET, duplicate-preserving header review, complete-body-only HTML, retained headers with explicit body gaps, strict JSON/API defaults, native short-read regressions and socket-blocked installed workflows. Engine 23 records changed collection coverage; prior bundles remain readable without cross-engine deltas. Real target/configuration acceptance and authenticated/browser/business-logic assessment remain separate. See [usage and limits](WEBSITE_AUDIT.md).

## Mail-domain DNS offline closure (0.37.0)

The finite [mail-domain collector contract](MAIL_DOMAIN_AUDIT.md) closes typed provider responses, exact-owner TXT collection, optional question binding, truncation/alias/contradiction failures, bounded DNS quoted-string decoding, SPF version selection and visible DMARC tag ambiguity. The socket-blocked installed CLI acceptance checks scope, query count, redaction and saved failure bundles without live or AI calls. Engine 24 preserves prior bundles as readable but prevents cross-engine observation deltas. Full policy/DNSSEC/delivery evaluation and real-domain validation remain deferred; Gmail account integration is separately fixture-tested.

## Gmail settings offline closure (0.38.0)

The bounded [Gmail collector contract](GMAIL_AUDIT.md) closes identity matching, local token preflight, strict forwarding/filter metadata, all-rule validation and finite response limits. The socket-blocked installed CLI gate checks exact endpoint/header scope, no credential or destination disclosure, verified saved success/failure bundles and zero live/AI calls. Engine 25 preserves older bundles without cross-engine comparisons. Credential/OAuth setup, actual account validation and broader mailbox security remain deferred.

## Dependency workflow offline closure (0.39.0)

The finite [dependency acceptance contract](DEPENDENCIES_OFFLINE_ACCEPTANCE.md) covers existing manifest/inventory/OSV behavior, bounded cache files and response rows, finite clock/expiry metadata, validated writes/legacy reads and full per-package pagination-cycle detection. Socket-blocked installed CLI evidence covers pagination, cache-only reports/scans, disclosure consent and corrupt-cache failure without a clean conclusion. Engine 26 preserves historical bundles while rejecting cross-engine deltas. Broader ecosystems, dependency graphs, reachability and controlled live OSV validation remain separate.

### Cache clock ordering correction (0.39.1)

Expiry is rechecked after database reads, and new TTLs start after acquiring the SQLite writer lock. Independent SQL trace controls advance time during the database operation and reproduce both stale-read and shortened-TTL regressions. Invalid post-lock clocks roll back without replacing the previous cache row. Engine 26 and the existing cache schema remain unchanged.
