# Saved browser traffic review

`review-har` reads saved HAR 1.2 response headers and eligible HTML locally. A browser
capture can include pages visited after login; the program does not need the account
or credentials. It never replays requests, follows links, logs in or sends forms.

```bash
ai-threat-lab review-har capture.har --output captured-report.json
ai-threat-lab brief captured-report.json
ai-threat-lab review-har capture.har --start 21 --max-entries 20 --output next-report.json
```

Console option 10 reviews the first 20 entries. The reader accepts at most 8 MiB and
200 entries; each report selects 1..20 consecutive entries. Original entry numbers
remain visible, so find the corresponding record in your local capture. Unselected
entries are explicitly noted. An empty capture, unsupported version or invalid
top-level document is rejected. This validates the consumed HAR subset, not every
timing or browser-specific field.

Request credentials, cookies, posted bodies and URL values are not exported.
Response header/body values are inspected by the existing redacting analyzers;
reports contain fixed entry aliases and observations. Avoid sharing the original
HAR: even sanitized browser exports may retain sensitive application data.

Only HTTPS response claims are assessed. Duplicate response headers are retained.
UTF-8 text and strict base64 bodies up to 256 KiB are supported; a declared size
mismatch, missing body, unsupported encoding or non-200 status suppresses HTML
analysis while retaining valid header evidence. Compressed response metadata is
conservatively left unchecked by the HTML analyzer; no decompression occurs.
Malformed entries remain explicit failed assessments rather than disappearing.
Exit 2 signals an entry/input/output failure, or optional `--fail-on-findings`
returns 1 when candidate observations exist.

The output is the standard combined report accepted by `brief`, `ai-prepare` and
`ai-review`. Captured data is unverified input: authenticity, complete collection,
effective browser policy, session isolation and business logic are not established.

Format references:
- [HAR 1.2 format](https://github.com/ahmadnassri/har-spec/blob/master/versions/1.2.md)
- [Chrome network capture/export](https://developer.chrome.com/docs/devtools/network/reference#save-as-har)
