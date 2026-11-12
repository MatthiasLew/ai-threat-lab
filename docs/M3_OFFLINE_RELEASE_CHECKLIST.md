# M3 offline release candidate

Ready scope: local analyzers, PL/EN menu, reports, history, comparison, exports,
Agent Mode, STDIO MCP, SARIF import, Bandit discovery and planning, and saved
Bandit report publication.

1. Build wheel and sdist with `python -m build`. In a fresh virtual environment
   install the candidate wheel with `python -m pip install --no-index --no-deps PATH_TO_WHEEL`.
2. Start `ai-threat-lab menu --lang pl` or `--lang en`, select a local project
   and a new output directory. For automation use `ai-threat-lab scan PROJECT --output-dir RUN`.
3. Verify the bundle with `scan-check`, browse history, compare with a later run
   and export a report. See the [installation guide](CLI_INSTALLATION.md).
4. Use `review-sarif` or `review-sarif --structured` for external observations.
   Use `scanner import bandit` to publish a complete saved Bandit 1.7.8 report.
5. Verify all six Windows/Linux Python 3.12–3.14 jobs for the candidate commit.
   Require Ruff, pytest, at least 90% branch coverage, wheel/sdist and clean
   installed CLI and STDIO MCP checks.

Producer fixtures cover Bandit 1.7.8, pinned Semgrep OSS variants, Trivy image
and a sanitized Gitleaks sample. Trivy filesystem/configuration and Semgrep
code flows lack authentic fixtures. Producer claims remain unverified.
Review free text before sharing reports with an AI service.

`scanner run` is blocked and returns JSON status, a diagnostic on stderr and
exit code 2. No API credentials are required for these offline workflows.
Lifecycle regressions cover cancellation and incomplete publication. The
clean installed acceptance does not simulate a terminal Ctrl+C.
