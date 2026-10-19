# Static PE/ELF observations — 0.11.0

A local program file now receives selected structural checks, not just a magic-byte/size/hash inventory. Everything runs offline with the Python standard library. The file is never executed, imported, loaded as a library, disassembled, unpacked or sent to a provider.

## Commands

```bash
ai-threat-lab audit path/to/program.exe --output binary-assessment.json
ai-threat-lab scan path/to/program.bin --output-dir scan-results/binary-01
ai-threat-lab scan-check scan-results/binary-01
```

Extensions do not select the format: the collector examines bytes for PE (`MZ`, then a validated PE signature) or ELF. Pass the file itself. A directory scan remains a source/configuration/dependency scan and does not recursively inspect every executable. GitHub source collection does not fetch or analyze arbitrary executable blobs.

All assessments remain `partial`. Metadata/header observations are `unverified`; review candidates are `candidate`. Nothing is automatically marked exploitable, trusted, malware-free or fixed. `scan --fail-on-findings` includes all observations, including metadata, so even a file without mitigation candidates can produce exit 1 under that explicit policy.

## Bounds and file handling

| Resource | Bound |
| --- | --- |
| Binary bytes | At most 16 MiB, read with a one-byte overflow sentinel |
| PE section records | 1–96 |
| PE data directories | At most 16; declared entries must fit the selected optional header |
| ELF program headers | At most 512 |
| Header/table/file ranges | Must fit the bytes actually read before dependent observations are emitted |

Root symlinks/junctions and non-regular paths are rejected. The descriptor's file type is checked after opening, and descriptors are closed on failure. Where supported, no-follow/nonblocking open flags further constrain special-file/link races. Concurrent filesystem modification is not an atomic snapshot guarantee. No subprocess, external parser, runtime loader or network client is used.

Unknown formats preserve size and SHA-256 with an explicit unsupported-format notice. Recognized but malformed/unsupported headers preserve metadata plus `binary_structure_unavailable`; no mitigation candidates from a partially parsed structure are retained. Unsupported structure is not proof of malicious content.

## PE32 and PE32+

The parser bounds-checks DOS `e_lfanew`, the PE signature, selected COFF/optional fields, section-table extent, raw section ranges and the certificate-table file range when declared. An executable-image marker is required by this narrow parser. Fields outside this subset, complete loader constraints and architecture-specific rules are not validated.

| Observation/check | Recorded meaning | Practical limit |
| --- | --- | --- |
| `pe_header` | Class, numeric machine ID, section count and selected flags | Unverified header data, not a loadability certificate |
| `pe_dynamic_base_unset` | DYNAMIC_BASE header bit absent | Review linker/platform requirements; not proof that all runtime address randomization is absent |
| `pe_nx_compat_unset` | NX_COMPAT header bit absent | Review linker/platform requirements; not proof that runtime DEP is absent |
| `pe_relocations_stripped` | COFF base-relocations-stripped bit present | No relocation-directory or actual loader behavior analysis |
| `pe_writable_executable_section` | A section records both write and execute characteristics | No effective mapping, reachability or exploit validation |
| Certificate-table field | Presence of an in-bounds declared table | No certificate parsing, Authenticode verification or trust decision |

Certificate-table offsets are interpreted as file offsets rather than RVAs. Missing certificate data does not prove that an executable is unsigned; external catalog signatures are not inspected. CFG is recorded only as a header bit; load-configuration details and effective CFG are not verified. Section names, embedded strings and raw instructions are not copied into evidence; section indices are used instead.

## ELF32 and ELF64

Both little- and big-endian encodings are supported. The parser checks identification/version/header sizes, bounded program-table layout, file-backed ranges and selected `PT_LOAD` size/alignment consistency. Extended program numbering, alternative record layouts, section/symbol/dynamic-table interpretation and complete ABI/loader validation remain unsupported.

| Observation/check | Recorded meaning | Practical limit |
| --- | --- | --- |
| `elf_header` | Class, byte order, numeric type/machine, segment counts and GNU markers | No runtime or provenance validation |
| `elf_writable_executable_load` | A nonempty `PT_LOAD` records write and execute flags | Effective page mappings are not measured |
| `elf_executable_stack` | `PT_GNU_STACK` records execute | Actual stack permissions depend on the target runtime/platform |
| `elf_exec_type` | `ET_EXEC` with load segments | Review PIE build requirements; runtime ASLR is not tested |
| GNU stack absent | Absence recorded, no candidate inferred from absence alone | No automatic executable/non-executable classification |
| GNU RELRO present | Marker recorded | Does not establish full RELRO, eager binding or actual protection |

Runtime-oriented candidates apply only to `ET_EXEC`/`ET_DYN` records. `ET_DYN` alone is not labeled PIE: shared libraries also use that file type. Multiple GNU_STACK records are treated as unsupported rather than selecting an arbitrary effective policy. PT_NULL fields are ignored; zero-memory load records do not create a W+X candidate. Addresses, imports and arbitrary embedded strings are not exported.

## Reporting and demonstration

The existing `audit-report`, JSON/HTML rendering and triage queue work with these results. Priorities remain human review ordering, not binary severity scores. Scan scope engine advances to `read-only-pipeline-5`; engines 1–4 remain readable, but comparisons across engine versions are unavailable.

`offline-demo` includes two tiny synthetic descriptor files and their scan bundles, linked from the generated `index.html`. They contain no machine-code payload and are never executed. The PE example records four review candidates plus metadata/header observations; the ELF example records two candidates plus metadata/header observations. These descriptor fixtures are not complete runnable programs and do not prove that a real OS would load them.

Tests include independent synthetic 32/64-bit PE/ELF builders, both ELF byte orders, every truncated prefix, random short inputs, maximal counters, malformed ranges/alignment, certificate bounds, descriptor cleanup, non-regular files, no-network/no-execution guards, CLI subprocesses and clean installed-package workflows. A small native executable from the test environment is also read when available, without execution. Unsupported formats, larger files, cryptographic trust, malware detection and dynamic behavior still require separate tools/work.

## Specification references

Implementation field/flag references: [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), [gABI ELF header](https://gabi.xinuos.com/elf/02-eheader.html), [gABI program headers](https://gabi.xinuos.com/elf/07-pheader.html), [GNU ld options](https://sourceware.org/binutils/docs/ld/Options.html). The collector intentionally implements a subset of these formats; these references are not evidence that all requirements are validated.

## ZIP metadata addition (0.27.0)

The program-file route also recognizes selected ZIP signatures and reads bounded directory/local-header metadata without opening or decompressing members. Its path, collision, symlink and declared-expansion candidates have separate [scope and limits](ARCHIVE_REVIEW.md). PE/ELF semantics remain unchanged.
