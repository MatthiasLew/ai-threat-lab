# M4.11 implementation plan

Reuse OCI projection, wheel RECORD validation, sealed descriptors and the
existing Bubblewrap supervisor. Resolve ELF dependencies against a bounded
image inventory using static readelf. Reject unknown search paths and missing
dependencies. Mount verified files and exercise a fixed in-sandbox import
and plugin diagnostic. Require observed origins to match the mounted
inventory. Keep scanner launch blocked pending full execution acceptance.
