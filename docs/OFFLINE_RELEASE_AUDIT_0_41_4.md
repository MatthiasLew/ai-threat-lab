# Offline 0.41.4 release audit

The integration baseline is main at ce063f8. The first-parent history records
the merges of #14, #15 and #17–#27. #16 addressed the test credentials earlier.
[Baseline CI](https://github.com/MatthiasLew/ai-threat-lab/actions/runs/43451494387)
provides the baseline result. The stabilization PR checks apply to the candidate
commit. Each matrix job publishes pytest-results.xml with the exact skipped tests
and coverage.json with the unrounded line and branch counts.

## Release verification

The compatibility matrix runs Ruff, full pytest, independent 90% combined and
branch coverage gates, wheel/sdist builds and clean installed-wheel smoke.
Installed checks cover PL/EN guided operation, local audits, PDF and history,
structured SARIF, saved Bandit report import, blocked scanner launch and
real STDIO MCP. The separate reference job tests pinned CPython in Bubblewrap.
See [M4 progress](M4_PROGRESS_REPORT.md) for the tested security scope.

Expected platform skips include Windows-specific junction, Job Object and
AppContainer checks on Linux, Linux namespaces, descriptor seals and native
rlimits on Windows, optional Qt PDF raster checks without Qt, and delegated
cgroup checks when the hosted runner lacks an explicitly delegated parent.
Use the per-job XML for the complete list and reasons. The reference CPython
check is mandatory in its own job.

## Main protection

GitHub returned protected=false and an empty effective rules list for main.
Create an active branch ruleset targeting refs/heads/main. Require pull
requests and one independent approving review. Dismiss stale approvals,
require approval of the latest reviewable push and resolve conversations.
Require the checks below from GitHub Actions and require an up-to-date base.
Block force pushes and deletions. Keep bypasses limited to an explicitly
designated recovery role. Configure these settings after a completed run
has made the checks selectable.

- cpython-reference
- verify (ubuntu-latest, 3.12)
- verify (ubuntu-latest, 3.13)
- verify (ubuntu-latest, 3.14)
- verify (windows-latest, 3.12)
- verify (windows-latest, 3.13)
- verify (windows-latest, 3.14)

A green workflow supports the release decision. Formal approval requires
an independent reviewer. This audit does not change repository settings
or publish a tag or release.
