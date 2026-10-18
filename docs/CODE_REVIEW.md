# Offline Python security review

The `review-code` module performs local, deterministic AST checks. It does not call AI, execute the inspected source, import its dependencies, contact endpoints, or generate attack payloads. This is a small teaching tool, not a comprehensive security audit.

## Usage

```bash
python -m ai_threat_lab review-code path/to/example.py
python -m ai_threat_lab review-code path/to/example.py --format json --output review.json
python -m ai_threat_lab review-code path/to/example.py --fail-on-findings
```

Only one explicitly selected `.py` file is inspected per call. The source limit is 256 KiB; the declared Python encoding is respected. Reports refuse to replace an existing file. No recursive filesystem search is performed.

| Rule | Candidate pattern | Suggested action |
| --- | --- | --- |
| PY001 | Direct eval/exec call | Prefer restricted parsing and explicit operations |
| PY002 | subprocess call with literal shell=True | Use an argument list with shell=False and validate allowed arguments |
| PY003 | pickle.load/loads | Avoid untrusted pickle input; prefer data-only formats |
| PY004 | requests call with literal verify=False | Enable certificate verification and configure trust roots |

A finding contains a rule ID, line, column, priority, rationale and recommendation. Priority describes the potentially risky pattern, not confirmed exploitability. Reports omit source snippets and argument values. A report includes the supplied filename, so consider that when sharing it.

## Limits

Simple import aliases are recognized. Aliases reassigned later, local scope/shadowing, dynamic imports, computed keyword arguments, wrapper functions, and interprocedural data flow are not resolved. This can produce both false positives and false negatives. The tool does not decide whether input is actually attacker controlled. A clean report does not establish security.

The narrative scenario `insecure_generated_code` is separate from static review: its ordinal risk score is not computed from AST findings. Selecting the `static_analysis` defense in a simulation means assuming relevant checks were performed; merely running this limited tool does not establish that assumption.

Exit codes: 0 for a completed review; 1 for findings only when `--fail-on-findings` is selected; 2 for invalid input, syntax/encoding errors, or file failures; 130 for cancellation.

## GUI integration

```python
from pathlib import Path
from ai_threat_lab import review_file, review_source

result = review_file(Path("example.py"))
snippet_result = review_source("value = 1", filename="editor-buffer")
for finding in result.findings:
    print(finding.line, finding.title, finding.recommendation)
```

The result is an immutable `CodeReviewResult`. The GUI can render findings separately from scenario risk scores. `review_file` is the local file boundary; `review_source` is suitable for a future editor widget. Neither function invokes a provider.
