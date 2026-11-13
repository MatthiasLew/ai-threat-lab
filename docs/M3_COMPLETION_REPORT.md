# M3 integration and release preparation

The M3.1 branch incorporates main at `f1c3bf3`, including the Gemini
credential-fixture correction. M3.2 planning stacks on the updated M3.1 branch.
The saved-report handoff stacks separately on planning.

The SARIF regression suite includes byte-limit and malformed-document checks
and a synthetic Trivy configuration case. The pinned Trivy tree has one
SARIF golden file, for an image. The available Semgrep trace-mode snapshot
contains no code flows. Authentic filesystem, configuration and code-flow
samples remain open. The synthetic regressions do not establish producer
conformance.

The Bandit planner checks a selected file and directory at plan time. It
cannot verify a wrapper's interpreter, imported dependencies or the identities
that would be used at launch. Execution requires a platform sandbox that
enforces a filesystem allowlist and default-deny network policy for the entire
process tree. Linux needs a verified kernel isolation backend or equivalent
container confinement. Windows needs a verified restricted execution backend
with filesystem access control and enforced network policy. Job Objects and
deadlines are resource controls. Snapshot staging, process supervision,
cancellation and launch authorization remain gated on that design.

The offline handoff accepts a saved SARIF report declaring Bandit 1.7.8,
requires an explicit successful producer outcome, rejects incomplete or
truncated projections, and exclusively writes the normalized report.
These claims are unverified. The handoff does not establish which program
produced the file or which project was scanned.

Review the [M3.1 checks](https://github.com/MatthiasLew/ai-threat-lab/pull/14/checks)
and [planning checks](https://github.com/MatthiasLew/ai-threat-lab/pull/15/checks).
The owner still needs to verify Secret Scanning alert #2.
