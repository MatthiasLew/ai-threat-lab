# M4.15 acceptance

Run the combined tests on a Linux host with a dedicated delegated cgroup
parent owned by launcher UID 62003. The test coordinator requires root to
create subprocesses with separate UIDs. Keep its package copies and path
ancestors under trusted control.

    python -m pytest -q -s tests/test_owner_bandit_e2e.py

The host must supply THREAT_LAB_OWNER_E2E_CGROUP, THREAT_LAB_CPYTHON_OCI and
THREAT_LAB_REFERENCE_WHEELS. Absence is BLOCKED and pytest reports a skip.
Hosted CI still runs owner IPC account tests and the pinned import probe,
alongside the six Windows/Linux Python 3.12-3.14 quality jobs.

| Case | Required observation |
| --- | --- |
| Clean input | One approval, Bandit exit 0, complete SARIF, zero findings |
| Assert fixture | Exit 1, B101 LOW/HIGH at input/sample.py line 3 |
| Invalid YAML or formatter | Exit 2 and no published report |
| Changed source paths | The original sealed bytes execute |
| Snapshot, interpreter, config, limit or policy substitution | No scanner launch |
| Agent request, no approval or owner refusal | No launch or publication |
| Replay or parallel requests | At most one authorized dispatch |
| Lost redemption reply or launcher crash | Spent approval, no retry dispatch |
| Broker death or new generation | Old operation refused |
| Missing delegation | SANDBOX_BLOCKED before the supervisor gate |
| Timeout or cancellation after Bandit analysis entry | No report, empty removed group |
| Oversized or corrupted report | REPORT_REJECTED and no publication |
| SIGKILL of supervisor | Registered-group recovery and no residual processes |
| Existing result | Second publication refused, original bytes preserved |

Diagnostic states describe this test harness. APPROVED_AND_EXECUTED is
reported only after successful authorized sandbox execution.
SCANNER_COMPLETED_CLEAN and SCANNER_COMPLETED_WITH_FINDINGS describe the
validated producer result. SCANNER_FAILED, REPORT_REJECTED and
SANDBOX_BLOCKED distinguish failure stages. Broker expiry and transport
failures use the existing fail-closed response. The broker's internal
last_status distinguishes APPROVAL_EXPIRED and APPROVAL_CONSUMED from
APPROVAL_DENIED without exposing extra protocol authority.

Public scanner run remains blocked with exit 2. Production owner deployment,
VM/storage rollback resistance, block I/O, host-crash recovery and Windows
runtime handoff remain separate acceptance gates.
