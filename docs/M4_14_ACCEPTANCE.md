# M4.14 acceptance

| Control | Scope |
| --- | --- |
| Owner confirmation | Linux test broker, independent UID and controlling PTY |
| Key custody | In-memory per-generation key, agent denied access to broker memory and ledger |
| Replay | Concurrent requests produce one grant, older generations are rejected |
| Clock | Boot-time deadline and injected forward/backward wall-clock shifts |
| Crash and rollback | Forced process death, reconnect and ledger replacement/restore |
| Pinned sandbox | Existing M4.13 tests, without IPC authorization in the launch path |
| Production | Public scanner run remains blocked with exit code 2 |

The next launch-gate review should verify the launcher receives the exact
approved sealed objects and commit result in a provisioned owner deployment,
then exercise the existing pinned sandbox in the same acceptance case.
