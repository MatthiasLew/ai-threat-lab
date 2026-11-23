# M4.14 implementation plan

Base: open PR #31 at 85fa4f581c746da1abd8e007446d393d6e95ac6b.

The agent controls its own process, workspace and requests. It may know the
plan digest, connect to the socket, stall a request or replay a prior message.
Trust the Linux kernel, the broker and launcher accounts, their code and
private directories, and the independently controlled owner session. Root,
privileged debugging and VM state rollback are outside this test boundary.
Code running as the owner can act as the owner. A shared login is insufficient.

- [x] Bind one preloaded review to a bounded Unix socket protocol with distinct
  broker, owner and launcher identities. Display the full canonical record
  in the owner session before accepting an explicit decision.
- [x] Generate a private per-session key and bind the signed approval to the
  owner, broker generation, plan, execution policy and expiry.
- [x] Commit redemption using the existing SQLite ledger. Discard pending
  approvals on restart and deny ambiguous delivery. Test revocation and replay.
- [ ] Gate the existing pinned Linux acceptance path on one-time approval.
  Exercise real credentials and separate processes. Keep public execution blocked.
- [ ] Record CI, coverage, verified controls and deployment blockers.
