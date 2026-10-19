# Roadmap — current delivery and next milestones

The product is console-first. API/account setup and live provider calls are deferred; GUI is a later client. The implementation history is in [CHANGELOG.md](../CHANGELOG.md). The current input-by-input status is in [DELIVERY_STATUS.md](DELIVERY_STATUS.md).

## A. Offline CLI foundation — implemented

The package provides bounded target assessment, supported dependency/configuration inventories, local text training, cost-controlled explanation contracts and text/JSON/HTML reports. Python review also exports SARIF. Single-target and local-batch scans publish integrity-checked bundles with explicit partial results and coverage gaps.

Acceptance: documented local workflows run from a clean installed wheel without target execution or model calls. Remote collector contracts are exercised with deterministic transports; this is separate from live account validation.

## B. Correctness and scoped release — current acceptance milestone

- Fix confirmed package-attribute/import-binding defects and retain positive controls.
- Compare selected binding semantics with Python using only inert test-authored packages.
- Verify failure, resource, privacy, compatibility and no-overwrite paths across supported CLI routes.
- Keep delivery status, capability inventory and documentation consistent.
- Pass all [offline release criteria](OFFLINE_RELEASE_CRITERIA.md), including the six-platform/interpreter CI matrix.

The 0.28.0 bounded addition covers normalized offline authentication events with paired pattern controls and no login attempts. See [AUTHENTICATION_LOGS.md](AUTHENTICATION_LOGS.md). The 0.27.0 bounded addition extends this gate to saved HTML, EML form checks and ZIP metadata. See [HTML_REVIEW.md](HTML_REVIEW.md) and [ARCHIVE_REVIEW.md](ARCHIVE_REVIEW.md). Subsequent feature expansion requires another bounded milestone. Additional analyzer features do not replace closing a known defect. Passing this milestone accepts the existing offline subset, not the complete original product.

## C. Deployment-specific code assessment — pending separate scope

Choose the first real repository/language/framework layout and define a representative positive/negative fixture corpus. Extend only the unsupported constructs needed for that scope, such as a selected framework source, namespace layout or dependency graph. Track false positives, missed cases, parser bounds and runtime assumptions.

Acceptance: each new construct has independent controls, observable evidence and explicit unsupported cases; representative repositories stay within declared budgets. Finding candidates still require applicability review.

## D. Web-application assessment — pending implementation

Define an owned test application and the permitted navigation/authentication scope. Add bounded application-level collection and checks with session isolation, target boundaries, cancellation and request limits. Current one-response header observations remain a separate completed subset.

Acceptance: controlled application fixtures demonstrate both candidate and noncandidate cases, scope rejection, failure reporting and reproducible evidence. Header presence alone must not imply application security.

## E. Mail and mailbox assessment — pending expansion and live validation

Select the first deployment's mail provider and required settings/authenticity checks. Preserve account binding and secret-free evidence. Extend saved-message analysis only through a separately bounded parser contract.

Acceptance: supported settings and message cases have positive/negative fixtures; actual provider grants and account behavior are validated later in a controlled environment. Mail observations are distinct from training delivery.

## F. Training integrations and observed events — pending implementation

Select consented delivery/media services only when API work resumes. Implement concrete adapters behind existing preview, scope, expiry, cancellation and ledger contracts. The 0.29.0 local signed-claim journal implements shared-key validation, explicit plan/alias scope, provenance separation and transactional replay/cancellation controls. Native provider intake, participant authentication, actual delivery/stop integration and retention/rotation still require implementation. See [SIGNED_TRAINING_EVENTS.md](SIGNED_TRAINING_EVENTS.md).

Acceptance: distinguish preview, accepted delivery, actual participant action, automated event and uncertain outcome. Stop/cancellation works through the real adapter. Local scripted choices are never counted as observed employee behavior.

## G. Binary/platform depth — pending separate scope

Select a platform and format beyond the existing bounded PE/ELF header checks. Signature trust, disassembly, malware assessment and runtime analysis are separate capabilities requiring their own design and evidence.

Acceptance: independently constructed valid/malformed fixtures define supported semantics and limits; unsupported formats and missing trust evidence remain visible.

## H. Controlled live acceptance and operations — deferred

After the chosen adapters exist, configure accounts/models/rates outside source control. Verify permissions, quotas, timeouts, uncertain outcomes, retry policy, retention and operational recovery against controlled resources. The existing cost adapter is fixture-tested; a key alone does not satisfy this milestone.

GUI, PDF, additional providers and centrally authenticated history follow explicit product priorities after the console workflow's chosen deployment is accepted.

## Rule for advancing work

Every new milestone needs a bounded contract, independent positive/negative controls, failure/resource/privacy checks, CLI/installed-package evidence where applicable, and updated status documents. An unresolved regression blocks acceptance. No milestone is completed solely by adding scenarios, increasing test counts or supplying credentials.

The 0.30.0 [local control workflow](LOCAL_TRAINING_CONTROL.md) closes lost-import-result lookup and coordinated cancellation of existing local ledgers. Native event intake, provider stop reconciliation, durable organization-wide storage, retention and controlled live acceptance remain separate engineering work.

The 0.31.0 [OpenSSH journal adapter](SSH_JOURNAL_REVIEW.md) adds one bounded native saved-log mapping to the offline foundation. It does not collect logs or implement arbitrary syslog/Windows/provider conversion. Deployment-specific logging permissions, completeness, supported versions and authenticity require controlled acceptance later.

## AI/cost module closure (0.32.0)

Finish the existing explanation/cost module against [AI_OFFLINE_ACCEPTANCE.md](AI_OFFLINE_ACCEPTANCE.md) before expanding other tracks. Local controls and the synthetic installed-package lifecycle are accepted offline; model/account/pricing, quota, output quality and real billing checks are a separately deferred live stage. Automatic model routing, Batch API and centrally authenticated cross-machine budgets are outside this finite local contract.

## Local reports/history closure (0.33.0)

Close [REPORTS_OFFLINE_ACCEPTANCE.md](REPORTS_OFFLINE_ACCEPTANCE.md) before starting another module. This accepts existing report formats, verified single/batch history, bounded catalog and source-independent saved-report export. Central multi-user services, automatic retention, signatures/encryption and PDF remain separate product decisions rather than hidden requirements of this finite local module.
