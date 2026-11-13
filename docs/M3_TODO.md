# M3 tasks

- M3.1. Structured projection, CLI export and pinned Bandit, Semgrep, Trivy
  image and Gitleaks examples are implemented.
- M3.1 follow-up. Add upstream Trivy filesystem and configuration fixtures
  and broader SARIF conformance samples. The pinned Trivy tree contains
  one SARIF golden file, for an image. A pinned Semgrep OSS dataflow
  snapshot verifies safe omission of code flows.
- M3.2. Bandit discovery and plan validation use explicit fingerprints.
  [Threat model and execution gates](M3_BANDIT_PLANNING.md)
- M3.2 execution is blocked pending isolation and authorization evidence.
