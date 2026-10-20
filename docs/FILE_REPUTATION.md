# Existing file reputation by SHA-256

Local PE/ELF/ZIP checks remain available without any service. The optional
VirusTotal adapter retrieves an existing file report using only the SHA-256
identifier. It does not upload bytes, request a rescan, download a sample or execute
anything. A hash may identify a private file; sharing it is a separate explicit decision.

```bash
ai-threat-lab reputation-preview sample.bin --output preview.json
ai-threat-lab review-reputation sample.bin --network --share-hash --allow-host www.virustotal.com --sha256 REVIEWED_SHA256 --output reputation.json
ai-threat-lab brief reputation.json
```

Replace `REVIEWED_SHA256` with the exact lower-case hash from the preview.
Console option 15 offers the same preview and lookup flow. Set `VIRUSTOTAL_API_KEY`
outside source control only when ready for a controlled account test. Account
terms, permissions and request quotas must be checked separately.

The source must be a regular file up to 16 MiB. Execution reads it once, verifies
the captured bytes against the reviewed hash, and uses those same bytes for local
structure observations. An existing output path prevents the request. A new report
is claimed before dispatch; failures before producing a report remove that claim.

The transport permits one HTTPS GET to the fixed host, with certificate validation,
public-address pinning, no redirects or retries, a 15-second timeout and a 1 MiB
response bound. The key is sent in `x-apikey`; the file name, path and bytes are not
sent. The API request is independent of any AI interpretation.

## Evidence

The provider response must identify the same SHA-256 and file size. Selected
analysis counts must be bounded nonnegative integers with at least one recorded
result, and the analysis timestamp must be valid and no more than five minutes
ahead of the local clock. Unknown/missing statistics are visible failures, not
zero detections. Response file names, comments, tags, engine-specific prose and
sandbox data are omitted.

The saved assessment combines local structure observations with dated, explicitly
unverified provider counts. It can feed `brief` or the AI evidence preview without
the original file. The report contains the hash: it is not anonymous.

A missing provider record remains unknown. Zero malicious counts is not a safety
claim. Engine counts are not independent probabilities, runtime validation,
signature trust or proof of malware. HTTP, response and identity errors preserve
local evidence and an explicit reputation failure. There is no automatic retry.

Exit 0 means the workflow produced a partial report (including a missing record);
3 means the provider lookup failed while local evidence was retained. Invalid
input, absent credentials and inaccessible output produce nonzero errors.

Tests use synthetic responses and blocked sockets. Actual account access,
provider response compatibility, quota behavior and real-file interpretation
require controlled live acceptance.

Provider contracts: [file report endpoint](https://docs.virustotal.com/reference/file-info)
and [file object fields](https://docs.virustotal.com/reference/files).
