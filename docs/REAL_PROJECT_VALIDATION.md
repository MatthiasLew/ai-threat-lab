# Real-project validation: evidence required

The previous table of project timings and findings has been withdrawn. It did not
include pinned target commits or saved report artifacts, and described PY003 as an
HTTP rule although the implementation checks unsafe pickle deserialization. Those
numbers are not accepted as evidence of analyzer accuracy or production readiness.

For a reproducible evaluation:

1. Record the scanner commit/version, interpreter, platform and target commit.
2. Use a local checkout without executing target code or installing its dependencies.
3. Run `scan` with explicit bounds into a new directory; retain the command and time.
4. Run `scan-check`; preserve the report, manifest, failures and all limitations.
5. Manually classify a sample of findings and negative controls against source lines.
   Report candidate count separately from confirmed issues and false positives.
6. Record skipped files and unsupported semantics. A successful run or zero findings
   does not establish full security coverage.

Synthetic quality controls live in `tests/test_analyzer_quality_benchmark.py`.
CI verifies regression behavior and package installation, not real-target security.
No current real-project precision/recall or performance claim is made here.
