# Historical event receipts and combined local control — 0.30.0

These commands recover a lost local import result and coordinate cancellation of two existing local ledgers. They make no network requests, send no messages and control no external provider queues, calls or media. API setup remains deferred.

## Recover an import result

Keep the original signed envelope and its private key. If import completed but its response was lost, query instead of submitting a fresh event:

```sh
ai-threat-lab training-events-receipt event.json --key-file local-signing.key --ledger event-claims.sqlite
```

The command strictly validates the envelope, HMAC and registered plan/channel/issuer/key/participant mapping. It reads the journal without inserting or changing records. It does not require the envelope to remain fresh or the plan to remain active: historical lookup works after expiry, stream stop or cancellation. Import freshness and cancellation rules remain unchanged.

| `state_in_this_journal` | Meaning |
| --- | --- |
| `recorded_matching` | This journal currently contains this event ID and canonical body hash |
| `event_id_conflict` | This plan/event ID exists with a different canonical body hash |
| `not_recorded` | This plan/event ID is absent from this journal |

The response includes computed plan status and the queried participant/provenance stream's stop marker, without recipient identity, raw envelope or key. A conflict is diagnostic: the command neither overwrites nor accepts it. A missing record does not prove another journal/provider never received the event. A matching receipt does not verify participant behavior, delivery, immutable history or external identity. File owners and backup restoration can change local history; receipt lookup does not cryptographically revalidate all stored records. Receipt/report commands require an existing compatible journal and never initialize one.

## Inspect or cancel both local ledgers

Place the existing rehearsal and event databases in the same private directory. The plan must already be registered in the event journal, with its exact approved digest. Do not pass the same file twice or use one ledger format in place of the other.

```sh
ai-threat-lab training-local-status --training-ledger training.sqlite --event-ledger event-claims.sqlite --plan-digest PLAN_SHA256
ai-threat-lab training-local-cancel --training-ledger training.sqlite --event-ledger event-claims.sqlite --plan-digest PLAN_SHA256
```

Both accept `--output REPORT.json` with the normal no-overwrite policy. Output contains aggregate stored session counts and `cancellation_state`:

| State | Meaning |
| --- | --- |
| `not_cancelled` | Neither ledger records plan cancellation |
| `partially_cancelled` | Exactly one ledger records it, for example after a previous individual cancel command |
| `both_cancelled` | Rehearsal revocation and event cancellation are both stored |

Status is read-only. `stored_session_counts` describes stored labels; it does not expire sessions as a side effect. Event plan status is computed using the current clock. Expiry is separate from cancellation.

Cancellation expires overdue running sessions for this plan, stops its other running sessions, permanently revokes future rehearsal starts and cancels further event acceptance. Already completed/stopped sessions, unrelated plans and event history are preserved. A registered event plan with no rehearsal sessions can still be cancelled to prevent later starts. Repeating the command is idempotent (`changed: false` once no work remains). Historical receipts remain readable. Individual `training-cancel` and `training-events-cancel` remain available for intentionally separate control.

## Transaction prerequisites and limits

The command accepts existing regular, non-linked, distinct files with the same resolved parent directory. Hardlink aliases are rejected. The rehearsal file is limited to 128 MiB and the event file to 32 MiB. The expected rehearsal schema has revision 0 and the event schema revision 1; incompatible tables/columns are rejected. No files or schemas are created implicitly. Operators must protect the parent directory against replacement races and use trusted local files.

Both databases must already use SQLite `DELETE` rollback-journal mode. WAL and other modes are rejected without conversion. Cancellation attaches the event database to the rehearsal connection, uses `BEGIN IMMEDIATE` and synchronous `FULL` on both databases, and commits both changes in one transaction. A SQL failure rolls back both. Status reads both within one transaction and reports partial state if it already existed.

SQLite documents multi-file commit atomicity for an attached database when the main database is a real file and WAL is not used: [ATTACH DATABASE](https://www.sqlite.org/lang_attach.html). Durability still depends on SQLite/VFS behavior, filesystem locking and storage flush guarantees; see [Atomic Commit](https://www.sqlite.org/atomiccommit.html). The tests inject SQL failures and concurrent calls; they do not establish physical power-loss behavior on every filesystem. This is not a distributed or tamper-proof control plane.

These commands cannot revoke previously copied exports, stop future unimplemented dispatchers, cancel remote deliveries or supply provider acknowledgements. Integrations must implement and reconcile their own stop semantics. Database deletion/restoration can undo cancellation history, so retain and reconcile the ledgers according to an operational backup policy.
