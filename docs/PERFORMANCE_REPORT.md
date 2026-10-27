# Performance verification

Historical timing and percentage claims have been removed because this repository
did not retain sufficient pinned input and raw measurement evidence to reproduce them.

The implementation bounds file counts, total input bytes, source/context parsing,
provider requests and AI packet sizes. It excludes common environments/build caches
and groups repeated limitations. These are implementation properties, not a speed
or detection-quality guarantee.

Use `tests/test_stage3_gemini_cache_and_perf.py` and the complete test gate for
regression controls. For a benchmark, record scanner and target commits, Python/OS,
scan options, cold/warm cache state, elapsed time and raw saved results. Compare
identical inputs and scope; do not attribute omitted work to an optimization.

AI cost estimates are configured-price bounds. Verify actual provider usage and
billing separately; no model availability, throughput or current-price claim is made.
