# M4.7 implementation plan

Bind a bounded captured runtime to an independently pinned manifest, inventory
startup hazards without importing code, and expose an expiring in-process
review prompt contract. Acceptance requires rejecting modified bytes, platform
mismatch and incomplete inventories. The demonstration never authorizes launch.

## Evidence and blockers

Verified the downloaded PyPI wheel byte-for-byte against its published SHA-256.
Its metadata declares PyYAML >=5.3.1, stevedore >=1.20.0 and rich. Windows adds
colorama >=0.3.9. The SARIF extra declares sarif-om >=1.0.4 and jschema-to-python
>=1.2.3. These are upstream requirements. Exact transitive wheels, stdlib and
native loader artifacts still need a platform-specific lock and provenance.
See [the PyPI release](https://pypi.org/project/bandit/1.7.8/#files).

The inventory API binds a captured tree, roles, declared platform, architecture
and interpreter version to the existing plan fingerprint and an independently
obtained pin. Startup filenames are leads for review. The inventory does not
prove ABI, package installation identity, namespace or import-hook behavior,
dynamic library resolution, or that all host resources are confined. Full
runtime materialization and staging limits must be validated with the exact
locked distribution. The real Bandit invocation remains blocked.

## Acceptance

- Reject an altered wheel before opening its ZIP metadata.
- Reject changed inventory, policy and platform fields against the reviewed pin.
- Report startup artifacts without importing them and retain unverified status.
- Reject a changed, expired, cancelled or declined demo prompt and reject its
  result as broker authorization.
- Run the existing synthetic sandbox flow on mandatory Ubuntu CI.
- Require both 90% coverage thresholds in the six-job matrix.

## Follow-up environments

Validate block I/O on a Linux host with the io controller enabled on an
explicitly delegated cgroup v2 subtree. Use an approved disposable block-backed
volume with known major:minor and verify read/write rates and io.stat deltas
for descendants against a host baseline. tmpfs results do not count.
The cgroup creation-to-journal window and host crash recovery remain open.

Windows follow-up should verify pinned-object handoff and ACL/reparse behavior,
then exact loader closure, Job Object limits and scratch quota, external
network denial, crash recovery and bounded SARIF publication.
