# M3 tasks

- M3.1. Structured projection, CLI export and pinned Bandit, Semgrep, Trivy
  image and Gitleaks examples are implemented.
- M3.1 follow-up. Add upstream Trivy filesystem and configuration fixtures,
  additional Semgrep code-flow fixtures and broader SARIF conformance samples.
  The pinned Trivy tree contains one SARIF golden file, for an image. The
  checked Semgrep OSS trace snapshots do not contain code flows. Synthetic
  tests exercise the importer boundaries while authentic samples remain open.
- M3.2. Add Bandit discovery and plan validation with explicit fingerprints.
  [Threat model and execution gates](M3_BANDIT_PLANNING.md)
- M3.2 execution is blocked pending isolation and authorization evidence.
