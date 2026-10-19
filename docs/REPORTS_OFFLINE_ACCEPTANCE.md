# Reports and local history completion — 0.33.0

This finite module covers existing JSON/HTML assessment reports, standalone Python SARIF, single/batch scan bundles and local observation history. No new analyzer, remote account, AI call, GUI, PDF, central history or automatic retention deletion is included.

Offline completion requires:

1. Existing JSON/HTML merging preserves candidate status, exact finding identity, provenance and limitations; HTML remains escaped and standalone. Python SARIF retains its separately documented scope.
2. Single/batch bundles verify indexed bytes and derived JSON/HTML without reopening original targets. Manifest, artifact and child readers reject links/junctions/special files and respect bounded reads. Publication cleanup preserves another actor's replacement files.
3. Saved comparison metadata is structurally validated and bound to the current bundle. Comparisons retain conservative scope/module rules; disappearance is never proof of remediation. A saved bundle alone cannot independently verify the absent previous bundle's findings.
4. A read-only history catalog enumerates one explicit directory level, identifies verified single/batch runs, exposes incomplete/invalid/unreadable entries without invented success summaries and reports omissions. Root/run/aggregate-read limits are explicit; limit exhaustion fails the catalog rather than publishing a misleading complete list.
5. JSON/HTML export regenerates the verified saved report without source access or source execution. Outputs never overwrite files or modify a saved run; incomplete/invalid input produces no completed export.
6. Deleted-source, tampering/recomputed-hash, provenance/escaping, failure/resource/file-type, real CLI, synthetic demo and clean installed-wheel workflows pass. Full release gates and all six Linux/Windows CI jobs pass.

After these gates pass, this local module is offline complete. Hashes establish internal consistency, not authenticity, immutable history, security completeness or a verified fix. Filesystem replacement races are not an atomic snapshot guarantee. Protect result directories and exports as sensitive data. Signatures/encryption, authenticated central multi-user history, provider uploads, automated retention and PDF are outside this local completion contract.
