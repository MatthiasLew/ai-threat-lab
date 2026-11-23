# M4.13 implementation plan

Reuse the sealed reference import fixture and delegated supervisor. Admit only
fixed repository-owned inputs. Check tmpfs and the read-only mount policy before
running the scanner. Validate successful producer outcomes with the existing
saved SARIF importer and keep scanner execution blocked in the public CLI.
