# M3 proposal: import external analysis results

Start with the existing SARIF import contract and require explicit input selection.
Preserve producer, version, rule ID, severity, scope and provenance. Apply input size
limits and secret redaction before report storage. Inspect generated SARIF fixtures
for path normalization, duplicate observations, malformed records and secret handling.

| Tool | Project license | Installation and runtime | Result formats to evaluate |
| --- | --- | --- | --- |
| Bandit | Apache-2.0 | Isolated Python environment, pip package and SARIF extra | JSON, SARIF. [Upstream installation](https://github.com/PyCQA/bandit/blob/main/doc/source/start.rst) [Package metadata](https://pypi.org/project/bandit/) |
| Semgrep CLI | LGPL-2.1 | Pinned CLI from uv or an isolated container, with local rules. Review each rule pack's terms independently. | JSON, SARIF. [Upstream repository](https://github.com/semgrep/semgrep) [CLI documentation](https://semgrep.dev/docs/cli-reference) |
| Gitleaks | MIT | Pinned platform binary or container, reviewed configuration and redaction | JSON, CSV, JUnit, SARIF. [Upstream repository](https://github.com/gitleaks/gitleaks) |
| Trivy | Apache-2.0 | Pinned binary or container plus versioned advisory databases. Record freshness and stage databases before an offline run. | JSON, SARIF. [Upstream repository](https://github.com/aquasecurity/trivy) [Reporting](https://trivy.dev/latest/docs/configuration/reporting/) |

Defer execution adapters until explicit authorization and isolation design review.
Prefer fixed command arguments, an approved local snapshot, read-only input and
supervised resource limits for any later opt-in execution. Pin and review licenses
for the exact versions, rules and databases before distribution.
