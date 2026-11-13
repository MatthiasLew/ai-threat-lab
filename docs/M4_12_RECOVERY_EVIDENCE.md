# M4.12 recovery evidence

The private owner-controlled registry durably records intent before mkdir.
A second locked, fsynced record is atomically promoted before configuring
limits or releasing the existing process gate. Cleanup holds the record
lock through removal. Recovery checks owner, boot and group identities
and uses a pinned cgroup descriptor for kill and drain.

A crash just after mkdir leaves an intent record and an empty group.
Without a recorded inode, automatic removal is refused. An operator must
verify ownership before removing it. Interrupted promotion can also leave
a pending file for manual inspection. The registry is trusted against
same-UID tampering. A changed boot ID is refused. Host reboot and power
loss were not exercised. The approval ledger is independent.
