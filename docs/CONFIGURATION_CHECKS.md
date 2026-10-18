# Literal configuration checks — 0.9.0

`audit` and `scan` inspect selected configuration text locally or from verified GitHub blobs. No Docker image is built/pulled, action executed or YAML document evaluated. Findings are **candidates for review**, not validated vulnerabilities or runtime severity scores.

| Check | Recognized trigger | Review action |
| --- | --- | --- |
| `container_explicit_root` | A simple `USER root`, `USER 0` or matching group-qualified instruction | Review stage purpose and choose a suitable non-root runtime user |
| `container_mutable_base` | A simple literal `FROM` image without a full SHA-256 digest | Review provenance, pin the reviewed digest and plan updates |
| `container_remote_add` | A simple remote HTTP(S) `ADD`, optionally with flags | Review integrity and reproducible input handling |
| `workflow_write_all` | Literal `permissions: write-all` | Minimize job permissions and review untrusted event data |
| `workflow_mutable_action` | Literal external `uses: owner/repository[/path]@ref` with a ref other than a full commit SHA | Pin the reviewed commit and maintain updates |

Dockerfile selection includes `Dockerfile`, `Dockerfile.*` and `*.Dockerfile`. Known earlier build-stage aliases, numeric stages, `scratch`, variable bases and digest-pinned bases are not reported as mutable external images. Explicit root is observed in **any** stage; the checker does not claim that it is the final runtime user.

Workflow checks apply to `.github/workflows/*.yml` and `*.yaml`, including paths represented with Windows separators. Local actions, expression-based references and unrecognized forms are not resolved. No finding does not mean an action is trusted or a permission set is safe.

These are literal line heuristics, not Dockerfile/YAML parsers. Multiline instructions, platform-qualified FROM instructions, YAML block scalars/anchors/merges, inherited users, default permissions, variables and effective runtime state are not evaluated. Text inside unusual YAML structures can produce false positives. Comments and unrelated filenames are excluded where recognized. Raw instruction arguments/action identities are not copied into finding evidence; paths/line numbers and generic observations are included.

```bash
ai-threat-lab scan path/to/project --output-dir reports/config-review
# The opted-in GitHub scan shares the same commit and retrieval budgets:
ai-threat-lab scan https://github.com/owner/repository --network --allow-host github.com --output-dir reports/github-config
```

Existing source/file/traversal limits apply. Dockerfile observations do not add container scanning, package resolution or automatic fixes. Scan scope engine advances to `read-only-pipeline-3`; older engines remain readable, but comparison across engines is conservatively disabled.

## Structured Kubernetes JSON (0.17.0)

A separate JSON parser now observes selected explicit Pod/workload fields, including all three container groups. Local/GitHub project collectors preserve its findings and coverage notices alongside the literal checks above. It does not reuse line heuristics or parse Kubernetes YAML. `review-kubernetes manifest.json` selects it directly. See [KUBERNETES.md](KUBERNETES.md) for kinds, pointers, limits and unsupported runtime/cluster behavior.
