# M4.15 implementation plan

Base is open PR #32 at ccb58f143b70ccb4e7d86ceff1f462b24de7d8b5.

The privileged test coordinator captures the pinned OCI projection, all 13
locked wheels, fixture input, Bandit configuration, probe script and seccomp
filter before review. A sealed descriptor carries this capture to separate
broker and launcher UIDs. Both reconstruct the same ScannerReview. Neither
opens the original inputs after owner confirmation.

The owner uses the existing authenticated IPC and controlling terminal.
Only the launcher UID can redeem. Its exact fingerprint must match the
broker's capture, policy, limits and fixed publication destination. Commit
precedes the existing supervisor gate. A lost response or launcher crash
burns the grant. An agent UID has neither grant issuance nor launch endpoint.

- [ ] Share the existing pinned probe payload with the combined acceptance test.
- [ ] Transport complete bounded review manifests through existing owner IPC.
- [ ] Capture and seal once, authorize exact objects and execute under delegation.
- [ ] Exercise clean, B101 and malformed configuration with actual Bandit.
- [ ] Exercise real refusal, replay, concurrency and process failure paths.
- [ ] Record UID, cgroup, timeout, cancellation and cleanup evidence.
- [ ] Keep six matrix jobs and both independent coverage gates.
- [ ] Publish a separate PR and report remaining production blockers.
