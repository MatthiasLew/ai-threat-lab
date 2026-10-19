# ZIP metadata review

Version 0.27.0 extends the existing program-file route with selected ZIP directory and local-header metadata checks. ZIP members are never opened, decompressed, extracted, executed or sent to a service. No additional package is required.

```bash
ai-threat-lab audit archive.zip
ai-threat-lab scan archive.zip --output-dir scans/archive-01
ai-threat-lab scan-batch saved-page.html archive.zip --output-dir scans/batch-01
```

Recognition uses supported ZIP signatures, not the filename extension. `binary_metadata` retains size/SHA-256; `zip_metadata` reports unverified entry count, declared expanded bytes and encryption-flag count. These are declarations, not verified contents. Candidate families aggregate selected occurrences and show at most eight entry indexes; member names and payloads are omitted.

| Candidate | Metadata pattern |
| --- | --- |
| `zip_path_escape` | Absolute/drive-prefixed paths or parent components, including backslash separators |
| `zip_platform_ambiguous_path` | Selected Windows reserved names, alternate-stream syntax or trailing dots/spaces |
| `zip_duplicate_entries` | Repeated exact member names |
| `zip_portability_collision` | Selected separator, Unicode NFC, case-fold or trailing-dot/space collisions |
| `zip_control_filename` | ASCII control characters in a name |
| `zip_symlink_entry` | Unix symbolic-link type declared in external attributes |
| `zip_declared_expansion` | Individual declared expansion above 1 MiB and ratio above 100, or aggregate above 100 MiB |

These are review candidates. Actual extraction behavior depends on the consumer, platform and filesystem. A declared encryption flag does not establish protection; absence of a flag does not establish safe contents.

## Bounds and structural acceptance

The existing 16 MiB file bound applies. Preflight limits the central directory to 1,000 entries and 512 KiB before constructing ZipFile metadata objects. Names are bounded to 4,096 characters. Supported local headers must lie before the directory, agree with selected directory metadata, fit declared compressed spans and not overlap. Unsupported/malformed structure returns `binary_structure_unavailable` and suppresses ZIP candidates rather than trusting partial entries.

ZIP64, split archives, prefixed/self-extracting and trailing-data layouts are unsupported. Extra-field semantics, data descriptors, compression-method support, payload consistency, CRC validity, passwords, signatures, nested archives and malware detection remain unchecked. In particular, size/CRC field agreement is not a payload integrity check. No recursive archive inspection occurs inside project folders or mail attachments; pass an archive as an explicit file target.

The offline demo verifies path-escape and reserved-name candidates. Regression controls cover normal/empty archives, malformed/truncated headers, naming collisions, symlink/encryption declarations, bounds and CLI/bundle routes. Tests forbid ZipFile member read/extract methods during analysis. See the standard-library [ZIP metadata API](https://docs.python.org/3/library/zipfile.html) and [binary scope](BINARY_AUDIT.md).
