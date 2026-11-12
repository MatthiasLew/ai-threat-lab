# Pinned external SARIF fixtures

These local reports are input data. No scanner runs during the test suite.
Producer versions below are reported by the fixture itself.

| Fixture | Producer version | Upstream source and license | Checked-in SHA-256 |
| --- | --- | --- | --- |
| Bandit | 1.7.8 | [Formatter documentation example](https://github.com/PyCQA/bandit/blob/22b4226078b041a16bf05163347a66ab4dbcf3a5/bandit/formatters/sarif.py), Apache-2.0 | `0d7e0a545a578b594049963059a86b2eb47de62a4ec6ec5991321c84d1aa921f` |
| Semgrep | Upstream snapshot masks it | [OSS output snapshot](https://github.com/semgrep/semgrep/blob/06d9993409f6698f78f6956cd39d968e7f4d7b6a/cli/tests/default/e2e/snapshots/test_output_sarif/test_sarif_output/notrace-eqeq/results.sarif), LGPL-2.1 | `20222d697699880cb4e06611340937ca69c2f680247919e422299da5b2b34be1` |
| Trivy | dev | [Image report golden](https://github.com/aquasecurity/trivy/blob/482bbeb9fd84054d30ba33be96eaf63105f31270/integration/testdata/alpine-310.sarif.golden), Apache-2.0 | `030e1258377520d96e99786127290a386f2688e45533f7ae861e9b187b38c9eb` |
| Gitleaks | v8.0.0 | [Report test output](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/testdata/expected/report/sarif_simple.sarif), MIT | `2410b487eac03ff0ccdba139c0ae0042713ed7d2bf0e7eeffea33349d955f4a4` |

The Bandit JSON was extracted from its formatter docstring and reformatted.
The Gitleaks derivative removes fingerprints and snippets and substitutes a
synthetic message and path. Semgrep and Trivy match the upstream bytes.

The additional [Semgrep trace-mode snapshot](https://github.com/semgrep/semgrep/blob/06d9993409f6698f78f6956cd39d968e7f4d7b6a/cli/tests/default/e2e/snapshots/test_output_sarif/test_sarif_output/trace-cwe_tag/results.sarif)
has two findings and SHA-256
`540d6e9128e1c6ca91cc7d8f44f27c305785bb8229dfacf88901f0f3d3c0cf84`.
The upstream version is masked. This LGPL-2.1 snapshot contains no
`codeFlows` field. Synthetic tests cover bounded omission of that field.

The [Semgrep dataflow snapshot](https://github.com/semgrep/semgrep/blob/06d9993409f6698f78f6956cd39d968e7f4d7b6a/cli/tests/default/e2e/snapshots/test_output_sarif/test_sarif_output_with_dataflow_traces/results.sarif)
is an LGPL-2.1 upstream Semgrep OSS report with masked version and one code flow.
Original SHA-256: `e56bbc86a088bbf196979098a932ed4abe70d81ddef749bd28078c449fe366db`.
The checked-in derivative removes snippet fields and reformats JSON. SHA-256:
`36ce2582bc5e1544dc6be4a20af979dbb4cc17fe24b414e5398d0cf561693bd6`.
