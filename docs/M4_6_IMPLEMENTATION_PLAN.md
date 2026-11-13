# M4.6 implementation plan

- Record owned cgroup identities in a private registry and lock live runs.
- Recover recorded groups by descriptor after supervisor death.
- Apply CPU quota before release and verify throttling on a delegated host.
- Require an explicit delegated block device for I/O validation.
- Keep production execution blocked.

## Evidence and limits

The delegated WSL2 test exercises memory, pids and CPU throttling of a
descendant. CPU quota is 20 ms per 100 ms and does not cap total CPU time.
I/O enforcement is blocked on this host because its delegated subtree
does not enable the io controller. An explicit major:minor requires that
controller and configures read and write bandwidth before launch. No
block-device workload was validated. tmpfs does not exercise io.max.

Recovery is explicitly invoked from a trusted process. Keep registry and
delegation exclusively controlled. The registry records UID and parent/group
device and inode and a lock keeps live runs out of recovery. A process death
between mkdir and durable identity recording can leave an empty group that
requires manual review. Unrecorded or mismatched groups are left alone.
Same-UID registry tampering, inode reuse across a reboot and host power-loss
recovery are outside this prototype. No approval is restored.
