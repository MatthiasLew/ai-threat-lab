# M2 final report

The bounded offline scope is ready for review when the six PR #13 checks pass.
The test and application changes were introduced at
`4d4ba06343bdd6c155da1d073af15fd2d5473969`. Later documentation commits carry
the benchmark evidence. The [PR checks](https://github.com/MatthiasLew/ai-threat-lab/pull/13/checks)
show the exact tested head, jobs and coverage. Windows 11 / Python 3.14 passed
77 focused filesystem, publication, MCP and API lifecycle tests with five
platform or environment skips.

## Detector validation

The pinned [representative corpus](benchmarks/m2-final-representative.json)
contains 1 TP, 0 FP, 2 TN, 0 FN, one unsupported case and zero errors.
The positive is Neurodesktop's literal final `USER root` instruction. The
upstream Dockerfile documents privileged bootstrap followed by a privilege drop.
Docker recommends a non-root user for services that can run without privileges.
This label validates the existing configuration observation, with effective
runtime privileges and exploitability outside its scope.
[Pinned Dockerfile](https://github.com/neurodesk/neurodesktop/blob/b84b0c441e954fe1125529d9c8d7847a8aa395e9/Dockerfile#L1847)
[Docker build guidance](https://docs.docker.com/build/building/best-practices/)

Flaskr 3.1.2 uses parameter binding in both labelled SQL cases. The same slice
also runs through multi-file inventory. The build metadata is unsupported by
the Python dataflow rule. The versioned result records hashes, licence,
expected and actual observations and timing. The sample is too small to infer
general recall. The earlier [synthetic corpus](benchmarks/2026-11-12-m2-closure-quality.json)
remains the evidence for synthetic cases.

## Performance and filesystem

The [same-host comparison](benchmarks/m2-final-ab.json) uses the same 1,000 files,
Python 3.14.0, Windows 11, one warm-up and three recorded repetitions per revision
and mode. Each scan starts a fresh process and writes to its own output directory.
The A/B script times walk iteration, shared reads and publication. The remainder
includes analysis, scan setup, other metadata calls and orchestration. Memory
figures are per benchmark process. Assessment digests include findings and
limitation text, and match across all measured runs.

| Mode | Before opened reads | Opened reads at `18df4a7` | Optimized at `4d4ba06` |
| --- | ---: | ---: | ---: |
| Plain median total | 0.63 s | 1.94 s | 1.92 s |
| Plain median read | 0.18 s | 1.42 s | 1.25 s |
| Traced median total | 1.32 s | 3.92 s | 3.18 s |
| Traced median read | 0.27 s | 2.71 s | 1.99 s |

The optimization caches Win32 function bindings and retains per-open handle,
reparse and identity checks. The plain optimized totals range from 1.43 to
2.75 s. A material cost remains relative to the pre-hardening baseline.
Existing opened-directory, changed-read and junction tests cover the retained
boundaries. Metadata-preserving writes and full snapshot isolation remain
architectural limits.

## MCP and publication

Use option A for synchronous MCP. A dispatch can finish after a client
disconnect. While the supervisor is alive, the worker is subject to its deadline
and resource limits. A nonreading client can stall a subsequent transport
write. The real-pipe test verifies that the worker has cleaned up and a report
verifies before the test terminates the stalled server. Existing oversized
worker response tests exercise the response cap independently.

The abrupt-exit test uses a finite inert worker under the real supervisor. On
Windows, the Job Object terminates the worker when the supervisor dies. On
Linux, the worker can outlive the supervisor and complete. The supervisor
deadline and scratch cleanup require a live supervisor. Both platforms can
leave parent-owned scratch after forced termination. The fixture leaves no
manifest. Check any visible report through the existing verification command.
Linux parent-death containment and descendant RSS remain future work. This scope
assumes a trusted offline worker and OS supervision for managed deployments.

Publication regressions cover no overwrite, prior report integrity, write
failure, interruption on both sides of the commit point and
`verification_required`. Durability across power loss requires separate testing.

## Review and M3.1

[PR #12](https://github.com/MatthiasLew/ai-threat-lab/pull/12) targets `main`.
[PR #13](https://github.com/MatthiasLew/ai-threat-lab/pull/13) stacks on PR #12
and remains in Draft for owner review. Review PR #12 first. Prepare the
Bandit-first offline SARIF work in its own PR after M2, following the
[integration plan](M3_INTEGRATIONS.md). The official Bandit 1.7.8 fixture was
extracted and accepted through the existing CLI outside the M2 branch.
