# M4.14 security evidence

Linux acceptance uses a privileged test coordinator to launch separate
unprivileged broker, owner, launcher and agent processes. The owner uses
a real controlling PTY. The test coordinator types the decision. It is not
part of the proposed deployment.

The WSL2 test covered UID separation, private ledger and broker memory
access denial, plan/runtime/snapshot changes, concurrent redemption, replay,
refusal, revocation, expiry, disconnect, forced broker death, new signing
generation, ledger replacement and rollback after redemption.
Clock jumps were injected inside the broker process while retaining Linux
CLOCK_BOOTTIME. Host clock and VM state were not changed.

The pinned sandbox acceptance and IPC acceptance are separate tests.
No end-to-end IPC-authorized pinned Bandit launch is established here.
Windows owner IPC, deployed account/session provisioning, VM rollback
resistance, block-device I/O and the earlier recovery gaps remain open.
