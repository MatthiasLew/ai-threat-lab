# M2 implementation plan

M2 stacks on PR #12 at `6f8eed9`. Historical M1 measurements remain tied to their original revisions.

| Task | Priority | Expected result and acceptance | Regression risk and checks |
| --- | --- | --- | --- |
| Root and file boundaries | P0 | Pin approved directory, preserve alias behavior, tighten file metadata checks | Valid files and aliases work, invalid and changed files fail, parallel first scans succeed |
| Worker supervision | P0 | Cap response collection and lifetime, own scratch storage in parent, apply native limits where verified | Valid envelopes pass, invalid/truncated/oversized replies fail, synthetic timeout and quota cases terminate and clean up |
| Quality benchmark | P0 | Independent labels and per-rule measurements from inert source | Positive/negative parity and unsupported cases reported separately |
| Collector cancellation | P1 | Check between files and manifests and preserve existing events/API | Cancellation surfaces as cancellation and leaves no new bundle, parallel scans remain isolated |
| Performance | P1 | Measure larger fixtures, dependency workloads and transport latency | Explicit platform metadata and RSS versus Python allocation labels |
| Async and M3 | P2 | Specify task lifecycle and optional external scanners | Preserve existing nine tools and explicit execution boundaries |
