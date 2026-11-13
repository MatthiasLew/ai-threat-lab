# M4.13 acceptance

Require delegated CPU, memory and pids before the fixed scanner test.
Require verified OCI and wheel inputs, read-only tmpfs root, bounded
scratch, no block-device mounts, network denial and closed descriptors.
Check exit 0 and exit 1 separately and publish only complete SARIF.
Reject invalid configuration and existing output.
Keep public scanner launch blocked.
