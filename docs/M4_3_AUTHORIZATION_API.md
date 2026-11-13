# M4.3 offline approval API

A trusted owner application calls `capture_scanner_tree` separately for the
authorized project and a staged runtime tree. It constructs `ScannerRuntime`
with one role for each file and builds a `ScannerExecutionPlan` from the
captured digests, declared backend policy, network policy, limits and output
scope. The plan's dependencies digest binds the entire runtime manifest.

`ScannerReview.fingerprint()` checks that the plan describes the supplied
objects. The caller presents the exact review to the owner using an
independently controlled confirmation channel. After confirmation, it calls
`issue_owner_approval` with the confirmed fingerprint, broker ledger ID and
its private 32-byte HMAC key. Validity is 120 seconds by default and bounded
at 300 seconds. Keep the key out of environment variables, arguments, logs,
agent context and project directories. The signing and verification
components are equally trusted because both hold the symmetric key.

`ScannerReviewBroker.redeem` verifies the approval and commits a nonce under a
SQLite write lock before returning the reviewed fingerprint. An expired,
mismatched or already consumed approval fails. A rollback before commit
leaves it unused. A successful commit followed by a crash burns the approval.
Keep the local database and its parent directory under exclusive trusted
custody. Rollback from a filesystem backup or copying the whole ledger can
restore old state. Rotate the key and ledger identity during recovery.

The capture retains file bytes in memory. It detects common traversal races
and has no disk staging path to reopen. A changing source tree can still
produce a mixed-time capture, and the runtime manifest records declared roles
rather than resolving the loader, imports or host resources. Both objects
are suitable for offline review only. The broker has no production launch
or authorization endpoint. A future backend must consume verified immutable
objects under OS confinement and complete the runtime closure checks.
