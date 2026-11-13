# M3.1 implementation plan

Extend the existing bounded SARIF parser and its legacy report projection.
Add an opt-in versioned external observation document for CLI and Python.
Keep producer and component identity, rule metadata, reported classifications,
invocation status and run/result provenance. Treat paths as inert labels.

1. Verify the upstream Bandit fixture and synthetic privacy and malformed cases.
2. Verify checked-in Semgrep, Trivy and Gitleaks examples with recorded provenance.
3. Exercise CLI export, existing report consumers and installed package checks.

Main regression risks are page offsets, exit codes, report shape, unstable
deduplication and accidental export of source snippets or private metadata.
Deduplicate exact claims in the same run and selected page only.
