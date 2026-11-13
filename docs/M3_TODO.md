# M3 tasks

- M3.1. Structured projection, CLI export and pinned Bandit, Semgrep, Trivy
  image and Gitleaks examples are implemented.
- M3.1 follow-up. Add upstream Trivy filesystem and configuration fixtures
  and broader SARIF conformance samples. The pinned Trivy tree contains
  one SARIF golden file, for an image. A pinned Semgrep OSS dataflow
  snapshot verifies safe omission of code flows.
- M3.2. Design optional scanner execution with explicit consent, verified
  executable identity and version, license review, restricted filesystem
  and network access, no shell, time and memory limits, and normalized
  outcomes. Review isolation and CLI/MCP contracts before implementing.
