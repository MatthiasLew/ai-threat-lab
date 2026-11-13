# M3.1 acceptance

- Saved SARIF is parsed with byte, depth, run, result and page limits.
- Versioned output retains reported metadata, omission counts and provenance.
- Legacy CLI and Python reports preserve their existing shape and exit codes.
- Regressions cover malformed fields, local-only operation, redaction, Unicode,
  Windows paths and duplicate claims.
- Run the six Windows/Linux Python 3.12–3.14 CI jobs with the 90% coverage gate,
  build artifacts and clean installed CLI/MCP checks.
