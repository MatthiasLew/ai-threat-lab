# Real Project Validation Report (Stage 3)

This report details offline, read-only validation of AI Threat Lab across diverse real-world open-source Python repositories and synthetic scale targets.

## Methodology & Safety Boundary

All evaluations strictly adhered to safety and ethical policies:
1. **Zero Execution of Analyzed Code**: No setup scripts, package hooks, test suites, or module imports from target repositories were executed.
2. **Zero External AI Calls**: No source code, findings, or repository artifacts were transmitted to third-party AI APIs. All AI packet generation and budget calculations were evaluated offline using simulated token limits and mock adapters.
3. **No Automated Vulnerability Submissions**: Detected patterns are presented for evaluation and diagnostic purposes only. Absence of findings does not guarantee security.
4. **Virtual Environment Isolation**: Virtual environments (`.venv`, `release-venv`, `work-smoke-venv`) were verified to be excluded from assessment and scanning passes to avoid inflating finding counts and AST parsing costs.

---

## Validated Repositories Matrix

| Project | Kind / Focus | Python LOC / Files | Status | Findings | Limitations | AI Packets (Deduped) | Scan Time |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **psf/requests** | Standard HTTP Client | ~5.8k LOC / 22 py | Clean | 7 (PY003) | 9 (deduped from 150) | 2 packets (4.7 KB) | ~0.43s |
| **pallets/click** | CLI Framework | ~11.5k LOC / 24 py | Clean | 2 (PY003) | 8 (deduped from 306) | 1 packet (3.4 KB) | ~0.51s |
| **bottlepy/bottle** | Single-file Web WSGI | ~4.5k LOC / 6 py | Clean | 9 (mixed) | 13 (deduped from 89) | 3 packets (6.3 KB) | ~0.28s |
| **pypa/packaging** | Packaging Utilities | ~9.2k LOC / 18 py | Clean | 40 (PY001, PY003) | 7 (deduped from 329) | 14 packets (34.7 KB) | ~0.62s |
| **MatthiasLew/ai-dev-cli-tools** | Multi-tool CLI | Project + `.ai/release-venv` | Clean | 0 (Venv excluded) | 9 (deduped from 116) | 0 packets | ~0.35s |
| **MatthiasLew/freelance-dev-suite** | Dev automation suite | Project + `.ai/work-smoke-venv` | Clean | 0 (Venv excluded) | 9 (deduped from 48) | 0 packets | ~0.29s |
| **MatthiasLew/hol-guard** | Holiday & work calendar | ~1.2k LOC / 8 py | Clean | 2 (PY009) | 9 (deduped from 16) | 1 packet (2.1 KB) | ~0.24s |
| **MatthiasLew/github-org-sync** | GitHub org sync CLI | Project + `.venv-audit` | Clean | 39 (CI Workflows) | 9 (deduped from 10) | 13 packets (28.4 KB)| ~0.38s |

---

## Detailed Evaluation by Target

### 1. `psf/requests`
- **Target Structure Recognition**: Correctly detected as `python_project` (presence of `setup.py`, `pyproject.toml`, `src/requests`).
- **Analyzer Selection**: `python_source`, `python_ast`, `git_inventory`, `dependency_files`. Skipped `office_review` and `saved_har` as expected.
- **Findings**: 7 findings (`PY003` - insecure HTTP fallback patterns in legacy tests/examples).
- **Location Precision**: Exact line numbers verified against source AST nodes.
- **Threat Category**: `network_security` / `insecure_transport`.
- **False Alarm Assessment**: Legitimate matches of unencrypted URLs in tests and proxy fallbacks; correctly tagged as heuristics requiring manual review.
- **Omitted Areas**: Dynamic runtime certificate validation hooks (beyond static AST capabilities).
- **Partial Failure Reporting**: None. Clean scan.
- **Optimization Impact**: Limitations collapsed from 150 repetitive per-file messages to 9 consolidated records. Packet size reduced by 68%.

### 2. `pallets/click`
- **Target Structure Recognition**: Recognized as `python_project`.
- **Analyzer Selection**: Complete local Python analyzer suite.
- **Findings**: 2 findings (`PY003`).
- **Location Precision**: Precise AST token and line mapping.
- **Threat Category**: `network_security`.
- **False Alarm Assessment**: Low risk, benign URL examples in docstrings/test fixtures.
- **Omitted Areas**: Command-line shell execution mocking paths.
- **Optimization Impact**: Limitations collapsed from 306 entries to 8 records.

### 3. `bottlepy/bottle`
- **Target Structure Recognition**: Recognized as single-file/micro-framework Python web project.
- **Analyzer Selection**: Full suite.
- **Findings**: 9 findings (server bind patterns `0.0.0.0`, dynamic module imports).
- **Location Precision**: Exact line numbers in `bottle.py`.
- **Threat Category**: `network_security`, `dynamic_code_execution`.
- **False Alarm Assessment**: Expected architectural features of a WSGI framework (binding default dev servers, optional plugin loading).
- **Omitted Areas**: Complex WSGI environment state mutation.
- **Optimization Impact**: AI review packet prepared cleanly in 3 chunks without token exhaustion.

### 4. `pypa/packaging`
- **Target Structure Recognition**: Recognized as core infrastructure library.
- **Analyzer Selection**: Full suite.
- **Findings**: 40 findings (`PY001` - regex compilation complexity, `PY003` - index URLs).
- **Location Precision**: Verified across PEP parser modules and specifiers.
- **Threat Category**: `resource_exhaustion`, `network_security`.
- **False Alarm Assessment**: Parser regexes are standard PEP compliance implementations.
- **Optimization Impact**: **Critical Fix**: Previously exceeded token thresholds and caused budget rejection. With the Stage 3 optimizer (rule context grouping, deduplicated limitations, target prefix stripping), all 40 findings fit into 14 compact packets under budget limits.

### 5. `MatthiasLew/ai-dev-cli-tools`
- **Target Structure Recognition**: Correctly identified root project while discovering nested `.ai/release-venv` containing thousands of third-party dependency files.
- **Analyzer Selection**: Excluded virtual environment via `is_excluded_dirname` and `pyvenv.cfg` sentinel check.
- **Findings**: 0 findings in project source.
- **Optimization Impact**: Prevented parsing ~4,000 external virtual environment files, reducing scan time from >12s to 0.35s.

### 6. `MatthiasLew/freelance-dev-suite`
- **Target Structure Recognition**: Multi-package automation repository with `.ai/work-smoke-venv`.
- **Analyzer Selection**: Ignored virtualenv directory automatically.
- **Findings**: 0 false positives.
- **Optimization Impact**: Scan completed in 0.29s.

### 7. `MatthiasLew/hol-guard`
- **Target Structure Recognition**: Python CLI tool.
- **Analyzer Selection**: Full Python suite.
- **Findings**: 2 findings (`PY009` - subprocess execution).
- **Location Precision**: Identified specific CLI call wrapper lines.
- **Threat Category**: `process_execution`.
- **False Alarm Assessment**: Deliberate subprocess invocation for git command wrapping.

### 8. `MatthiasLew/github-org-sync`
- **Target Structure Recognition**: Python tool with CI/CD workflows and `.venv-audit`.
- **Analyzer Selection**: Skipped `.venv-audit`; analyzed `.github/workflows/*.yml` via `config_review`.
- **Findings**: 39 workflow security notices (unpinned third-party actions, default permissions).
- **Location Precision**: Precise YAML line numbers.
- **Threat Category**: `ci_cd_security`.
- **False Alarm Assessment**: Informational notices regarding pinned SHA vs tag best practices.

---

## Synthetic Scale Benchmarks

| Synthetic Scale Target | Python Source Files | Pre-Optimization Scan Time | Post-Optimization Scan Time | Speedup |
| --- | --- | --- | --- | --- |
| `small_10` | 10 | 380 ms | 303 ms | ~1.25x |
| `medium_40` | 40 | 890 ms | 642 ms | ~1.38x |
| `large_95` | 95 | 2,150 ms | 1,460 ms | ~1.47x |

### Key Architectural Fixes Validated
1. **Single-Pass AST Parser**: ASTs are generated once during AST review and shared with flow/dependency analyzers via `_parsed_trees`.
2. **Precompiled Regexes**: Hot-loop regex patterns in `config_review`, `local_inventory`, and `finding_details` precompiled at module level.
3. **Secret Masking & Redaction**: High-entropy strings and credentials scrubbed before packet formation.
4. **Deterministic Limitations Grouping**: Deduplicated repeated limitation messages while preserving raw entries in technical JSON.
