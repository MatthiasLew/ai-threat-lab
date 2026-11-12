# M2 benchmark method

Use independently labelled, inert source fixtures. The unit is a case and a rule.
Expected positives and negatives are compared against emitted rule identifiers.
Unsupported examples are counted separately. Record raw counts, Python, OS,
scanner commit, corpus version and analysis configuration. Python allocation
peaks from tracemalloc describe Python allocations only.

Run `python scripts/benchmark_m2_quality.py` and
`python scripts/benchmark_security_engine.py --extended` from an installed development checkout.
Each PY001–PY014 rule has a positive, safe counterpart, formatting variant and
excluded runtime-generated-source case. Only the labelled rule is scored.
At `b006adf` the Python subset yielded 28 TP, 14 TN, 0 FP, 0 FN and 14 exclusions.
Each rule contributed 2 TP and 1 TN. The formatting variant repeats the underlying
observation. Configuration, secret-marker detection and manifest extraction each
contributed one TP and one TN. The manifest label tests exact-version extraction.
The next corpus needs representative applications and more cases per category.
[Quality output](benchmarks/2026-11-12-m2-quality.json)

The extended fixture contains 1000 Python files across ten directories, an empty
npm lockfile and one approximately 100 KiB file. At `b006adf`, Windows 11 and Python
3.14.0, two scans took 2.91 s and 1.77 s with tracemalloc and retained 500 observations.
Peak traced Python allocations were about 12 MB. The benchmark process reached
about 56 MB peak resident working set. Cold MCP STDIO summary calls on this fixture
took 2.60 s and 1.41 s, including server startup, initialization, worker and EOF.
[Performance output](benchmarks/2026-11-12-m2-performance.json)

For the closure reruns and a separate pinned Flaskr pilot, see
[M2 closure](M2_CLOSURE_REPORT.md#representative-validation).
