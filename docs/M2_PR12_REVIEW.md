# Independent PR #12 review

**CHANGES REQUIRED** at `cda9c80`. Base `c90d8b9`, final historical CI `42813384348`.
The approved-root correction was published to PR #12 in `34f2ea3` and `6f8eed9`.
**APPROVE** for the corrected M1 scope at `6f8eed9` after all six CI jobs passed.
Resource limits are a gate for broader M2 use.
[Corrective CI](https://github.com/MatthiasLew/ai-threat-lab/actions/runs/43205191400)

| Severity | Source | Evidence and decision |
| --- | --- | --- |
| BLOCKER | `agent_service.py:74`, `agent_protocol.py:85` | Source review: separate link check and resolution could adopt a different approved path. Pin before accepting the root, retain POSIX lexical path, normalize Windows short aliases while pinned. `test_root_must_pass_opened_directory_validation`, existing invalid-root and short-alias tests verify the contract. Approval is path-based and does not promise identity across legitimate renames. |
| HIGH | `agent_protocol.py:98`, `agent_service.py:215,305,359` | Source review: subprocess output was collected before the response limit, worker memory had no hard ceiling and forced termination could leave scratch files. Track in M2. |
| MEDIUM | `agent_service.py:296`, `agent_fs.py:67,141` | Source review: first-store creation can race, Windows checks only known link types and opened-file metadata checks cannot establish an atomic snapshot. Track in M2. |
| MEDIUM | `agent_protocol.py:111`, `agent_mcp.py:138` | Source review: arbitrary object accepted as worker reply and synchronous dispatch delays detection of EOF. Validate reply in M2 and specify async behavior separately. |
| MEDIUM | `scan_engine.py:246,289,319`, `scan_lifecycle.py` | Cancellation between collectors works. Internal checkpoints must preserve ScanCancelled through broad exception handlers. |
| MEDIUM | `assessment.py`, `local_inventory.py`, `code_review.py`, `scan_bundle.py` | Ordinary scans and report readers have path-based boundaries. Link exclusion and manifest verification tests establish their documented controls. Agent descriptor guarantees do not transfer to these paths. |

Evidence and findings are data, with execution authorization owned by the client.
The review used source analysis and defensive contract tests. Dynamic exploit reproduction and exhaustive Windows race coverage were excluded.
