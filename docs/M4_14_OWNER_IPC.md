# M4.14 Linux owner IPC

The test broker takes one trusted, preloaded ScannerReview and policy. Its
Unix SOCK_SEQPACKET socket uses SO_PEERCRED in both directions. The launcher
requests only redemption of the broker generation and exact plan digest.
The owner receives the complete canonical plan, runtime and snapshot
manifests, execution policy and operation digest. The owner client prints
escaped JSON to its controlling terminal and waits for the full approval
phrase. It has no automatic confirmation argument on a public CLI.

Run the broker, owner and launcher with different non-root UIDs and keep
the agent on a fourth UID without privileges to switch identities, access
their terminal or control their code, directories or service definitions.
Peer credentials identify the account. The owner login and private terminal
identify the independent confirmation channel. Anyone controlling that
login can confirm. The broker trusts its installation and path ancestors.

The signing key is generated in memory and held by the broker only. Its
fingerprint, broker generation, protocol, owner, launcher and policy are
bound to the signed plan through the operation digest. The launcher gets a
positive reply only after the broker commits the SQLite nonce. No token or
key is exported. The filesystem stores the ledger in a broker-only directory.
The test broker expects a fresh ledger per generation. A restart requires a
new key and ledger and invalidates all pending operations. Clean up an old
socket and archive the old ledger through trusted service management.

The process discards a grant before attempting redemption. Revocation drops
an unspent grant. If a reply is lost after commit, the caller treats it as
denied and the broker keeps it spent. The boot-time deadline is independent
of wall clock and includes suspend. The legacy HMAC verifier also checks
wall time and can deny early when the clock changes.

An inode replacement is rejected. Same-inode database rollback cannot
restore a spent in-memory grant. This does not authenticate historical
ledger contents or defeat restoring an entire VM with running process
memory. Durable reusable approvals would require a rollback-resistant
counter or externally trusted state. There is no such dependency here.
