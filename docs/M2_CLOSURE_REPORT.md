# M2 closure report

**PARTIAL. Keep PR #13 in Draft.** Its base is PR #12's
`feat/agent-mode-mcp`; PR #12 remains open against `main`.

## Security review

Ordinary local scan collectors and the saved-report reader now share the
opened-handle reader. ScanService verifies that the selected directory still
has the same identity at startup. POSIX project reads anchor to the open
directory descriptor and reject links while descending. Windows opens each
component without following its final reparse point and retains parent handles
without delete sharing. Directory discovery still uses path-based metadata:
concurrent changes can cause skipped files or failed modules. Byte reads compare
size, modification time and change time available from the opened object.

These checks do not promise a point-in-time snapshot. In particular, writes
that preserve compared metadata can evade change detection. Linux mount
changes, hard links in ordinary reads, and Windows filesystems with weaker
identity semantics were not exhaustively validated. The separate Agent copy
path still requires a single hard link.

The manifest is staged in full and made visible atomically, with an exclusive
rename on Windows or a same-filesystem hard link on POSIX. Publication fails
closed on a filesystem that cannot perform the required operation. Process
tests terminate a writer before destination creation, during artifact output,
and immediately before and after the marker operation. Existing reports are
compared byte for byte. This establishes process-exit behavior, not durability
across power loss. After a forced kill, first verify any visible bundle;
inspect leftover staging or incomplete destination directories separately and
remove them only after confirming their owner is gone and they contain no
unrelated data. Publication interrupted after it starts requires verification.

## Representative validation

The pinned Flaskr 3.1.2 source is a narrow initial corpus: two negative
controls for PY014 and one build metadata file outside that rule's scope.
Labels use SQL parameter binding documented by
[Flask](https://flask.palletsprojects.com/en/stable/tutorial/views/) and
[Python's SQLite guide](https://docs.python.org/3/library/sqlite3.html#how-to-use-placeholders-to-bind-values-in-sql-queries).
The corpus does not measure recall. Broader applications, labelled positives,
configuration/dependency coverage and independently documented cases remain open.
Keep these results separate from the 31 TP, 17 TN and 14 exclusions in the
synthetic M2 benchmark.

On Windows 11 / Python 3.14.0 at `9dd8cba`, the
[Flaskr results](benchmarks/2026-11-12-m2-flaskr.json) were 0 TP, 0 FP, 2 TN,
0 FN, one exclusion and no failed checks. Precision and recall are undefined.
The [synthetic rerun](benchmarks/2026-11-12-m2-closure-quality.json) retained
31 TP, 17 TN, 0 FP, 0 FN and 14 exclusions.
The [performance rerun](benchmarks/2026-11-12-m2-closure-performance.json)
retained all 500 expected observations for the 1,000-file fixture; it took
8.61/9.26 s with tracemalloc and 3.17/2.99 s for cold MCP round trips.
These are slower than the earlier run. The new run overlapped local verification,
so it cannot isolate how much overhead comes from the opened-handle reads.
Peak RSS was 60.2 MB for the benchmark process only.

## Worker security and compatibility

On Linux the limits bound address space and open descriptors. On Windows the
Job Object bounds aggregate memory commit and allows one active process.
Those limits and RSS measure different things. Existing supervision tests
cover deadlines and cleanup. The real STDIO tests cover idle EOF, output
closure and a worker started before a client disconnect. Synchronous dispatch
may still commit after disconnect. A peer that stops reading can stall the
transport write. Abrupt supervisor death and descendant RSS are not covered
by these checks.

The nine MCP tool schemas, native bundle schema and public CLI and Python API
signatures stay the same. Linked ancestors and replaced project directories
can now cause a local scan to fail instead of following the changed path.

## Quality gates and next work

See [M2 acceptance](M2_ACCEPTANCE.md) for the evidence matrix and
[M3 interoperability plan](M3_INTEGRATIONS.md) for the next iteration.
Start with offline Bandit SARIF fixtures; review optional execution separately.
No external scanner integration or GUI was added.
