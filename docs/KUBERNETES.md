# Offline Kubernetes JSON review — 0.17.0

Inspect selected explicit configuration fields without running kubectl, Helm, a container, an image, a host-path mount or a cluster request. The checker uses Python's standard JSON parser with byte/depth bounds and no Kubernetes dependency. All findings are candidates for review; the report remains partial, including for an empty result.

```bash
ai-threat-lab review-kubernetes workload.k8s.json --output kubernetes-review.json
ai-threat-lab review-kubernetes workload.k8s.json --format html --output kubernetes-review.html --fail-on-findings
# Local project collection reuses the same checks:
ai-threat-lab scan path/to/project --output-dir scan-results/kubernetes-01
# Existing report interchange also applies:
ai-threat-lab audit-report kubernetes-review.json source-review.json --format html --output combined.html
```

No key, credentials, network permission or Kubernetes installation is required. Destinations must be new; existing files are never overwritten. Exit 0 means a bounded partial review completed; exit 1 means observations exist with `--fail-on-findings`; exit 2 means invalid input/options/file/destination; exit 130 means cancellation. Unsupported resources can produce an empty partial report with explicit gaps, not a security all-clear.

## Recognized resources

| apiVersion / kind | Selected Pod specification |
| --- | --- |
| `v1 / Pod` | `spec` |
| `v1 / ReplicationController` | `spec.template.spec` |
| `apps/v1 / Deployment`, `DaemonSet`, `StatefulSet`, `ReplicaSet` | `spec.template.spec` |
| `batch/v1 / Job` | `spec.template.spec` |
| `batch/v1 / CronJob` | `spec.jobTemplate.spec.template.spec` |
| `v1 / List` | Bounded traversal of `items`, including nested supported Lists |

Only these exact version/kind combinations are selected. Older APIs, typed `PodList` variants, CRDs, Secrets, Services, RBAC and other resources are not interpreted. Missing/invalid selected structures or unsupported identities create coverage notices without reproducing input values. This is not validation against a Kubernetes API schema.

Explicit non-Linux/unknown `spec.os.name` skips the Pod's selected checks with a notice. Linux-oriented settings on unspecified/explicit Linux specs are observed as written; OS selection and runtime applicability are not verified. Windows HostProcess and Windows-specific controls remain unsupported.

## Ten candidate families

| Check | Explicit observation |
| --- | --- |
| `k8s_host_namespace` | `hostNetwork`, `hostPID` or `hostIPC` is boolean true; one observation per selected field |
| `k8s_privileged_container` | Container securityContext has boolean `privileged: true` |
| `k8s_privilege_escalation` | Container securityContext has boolean `allowPrivilegeEscalation: true` |
| `k8s_root_user` | Selected Pod/container securityContext has integer `runAsUser: 0` |
| `k8s_non_root_disabled` | Selected Pod/container securityContext has boolean `runAsNonRoot: false` |
| `k8s_writable_root_filesystem` | Container securityContext explicitly sets `readOnlyRootFilesystem: false` |
| `k8s_unconfined_seccomp` | Selected securityContext declares seccompProfile type `Unconfined` |
| `k8s_added_capabilities` | Container capabilities.add contains `ALL`, `SYS_ADMIN`, `NET_ADMIN` or `SYS_PTRACE` |
| `k8s_host_path` | A selected volume declares a hostPath object |
| `k8s_host_port` | A container port declares an integer hostPort from 1 to 65535 |

The checker inspects `containers`, `initContainers` and `ephemeralContainers`. Pod-level identity/seccomp observations remain at the Pod field even when a container overrides it. They are not claims about the effective container. Missing values do not generate default-based findings. For example, an absent root-filesystem flag is not converted into a writable-root candidate.

Operational workloads may intentionally require these settings. Review context and actual policy before remediation. There are no automatic patches or deployment actions. P2 orders review for the selected access/privilege candidates; writable-root uses default P3. These are not CVSS values or a claim of exploitable vulnerabilities.

## Evidence and privacy

Evidence uses the source filename followed by a fixed-field JSON pointer, for example `workload.json#/spec/containers/0/securityContext/privileged`. It does not invent source line numbers or copy metadata names/namespaces, images, environment data, capability values, host paths, port values or other source snippets. Names are not used to build pointer components; numeric indices identify selected entries.

The filename/path is retained and may be sensitive. Other project modules, such as the existing credential-pattern checker, continue to produce their own redacted findings. JSON/HTML reports preserve target, candidate status and unchecked areas. HTML uses the existing escaped renderer with no active/external assets.

## Input and resource limits

The explicit command accepts a regular `.json` file, rejects root symlinks/junctions and decodes UTF-8 (optional UTF-8 BOM). The source limit is 256 KiB. A lexical pass caps JSON structural nesting at 64 before the standard parser runs; brackets/escapes inside strings are not counted. Duplicate keys, non-finite numbers, malformed syntax and structural parser failures are rejected with redacted errors. This depth bound is separate from the resource/List traversal below.

Global budgets per source file:

- 50 resource objects/entries, including List objects and malformed resource entries;
- List expansion stops at depth 4 (root depth 0); a List at depth 4 is not expanded;
- 100 total selected container entries across all three container groups;
- 100 total volume entries and 100 total port entries;
- 300 findings and 50 distinct detailed notices, plus the general limitation and an omitted-notice count when needed.

Reaching a selection limit preserves earlier findings and records that remaining input was unchecked. Invalid selected field types produce notices and are not coerced; booleans are not accepted as UID/port integers. Limits do not establish exhaustive coverage. Existing project/GitHub file, traversal, byte, report and request bounds also remain. Very broad combined reports can still require narrowing before publication.

## Project and GitHub collection

The local/GitHub collectors inspect selected `.json` text files within existing bounds. A parsed root object with apiVersion and kind is passed through this checker. Ordinary non-Kubernetes JSON is ignored by it. Invalid generically named JSON cannot reliably be recognized as a Kubernetes resource; the general coverage notice remains. Invalid named `*.k8s.json`, `*.kubernetes.json` or `kubernetes.json` receives a specific parse-coverage notice. The explicit CLI is strict for any selected JSON filename.

YAML and Helm/Kustomize templates are not rendered or interpreted by this module. Arbitrary single `.json` paths in `audit`/`scan` still use the legacy program-file router: use `review-kubernetes` or select the containing project. Directory-based `scan-batch` inherits the new project findings and gaps. GitHub collection uses the same immutable commit and verified bounded blobs as other source review; no manifest is applied or extracted.

Scan engine 9 marks the expanded observation scope. Older bundles remain readable; cross-engine comparison is conservatively disabled. A disappeared observation does not prove a deployment was fixed.

No cluster/API admission, mutating/defaulting behavior, effective inheritance, service account/RBAC, networking, image contents, node/runtime state, secret handling, volume permissions or Pod Security Standards conformance is evaluated. A manifest that produces no candidates is not certified deployable or secure.

## Offline acceptance

`offline-demo --output-dir NEW_DIR` now generates a fictional Pod JSON, scans its separate fixture directory and links a ten-observation report bundle. The manifest is inert text; its image and host path are never fetched/opened. `review-kubernetes` over the same file and `scan-check` are exercised by clean installed-wheel verification. A failed synthetic acceptance does not publish the demo completion marker.

Primary behavior references: [Kubernetes security context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/), [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/), and [Pod API reference](https://kubernetes.io/docs/reference/kubernetes-api/core/pod-v1/). These references describe real Kubernetes behavior; this bounded checker implements only the explicit observations above. See [testing](TESTING.md), [configuration checks](CONFIGURATION_CHECKS.md), and [remaining delivery work](DELIVERY_STATUS.md).
