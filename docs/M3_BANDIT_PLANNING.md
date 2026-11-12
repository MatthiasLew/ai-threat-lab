# Bandit adapter planning and threat model

The first M3.2 slice provides discovery and a local plan. Run is blocked on
Windows and Linux pending evidence of filesystem and network confinement.
Job Objects, resource limits and an isolated working directory are useful
process controls, but do not supply either confinement guarantee.

The project, executable location, environment, declared version and report
contents are independent trust boundaries. A local file may be substituted
after inspection, and an executable can load interpreter packages and plugins
outside its own file. A fingerprint matches the selected file at plan time.
It establishes neither provenance of the runtime nor authority to execute.
Before enabling a runner, require an independently approved runtime and
dependency manifest, scope-bound authorization and revalidation at launch.

1. Discover whether an executable is visible without invoking it.
2. Require an explicit executable path, expected SHA-256 and declared
   supported version. Validate the file and the selected directory with
   existing opened-handle helpers. Produce a JSON plan.
3. Keep execution blocked until approved read-only snapshots, private bounded
   scratch, no-network controls, process-tree limits, deadline and cancellation
   pass platform acceptance. Test path swaps, descendants and supervisor death.
4. When an independently reviewed runner exists, distinguish producer findings
   from execution failures, publish exclusively and import through the existing
   SARIF service. Keep the current MCP tools. A future MCP contract should
   separate plan/status/results from the owner's scope-bound launch consent.

The initial supported declaration is Bandit 1.7.8 because that version has a
pinned formatter fixture. The plan cannot independently query the executable
version. Users obtain the expected digest and version from trusted provenance.

```text
ai-threat-lab scanner doctor
ai-threat-lab scanner plan bandit ./project --executable /absolute/bandit --sha256 HEX --version 1.7.8
```

Valid discovery and plans return JSON and exit 0. A rejected plan or blocked
run exits 2. Plans contain local paths and are intended for local review.
The validation service lives in `ai_threat_lab.scanner_plan`.
Explicit UNC and device path syntax is rejected. Mapped drives and mounted
remote filesystems cannot be identified reliably by this syntax check.

Use `scanner import bandit saved.sarif --output report.json` to publish a
saved report declaring Bandit 1.7.8 with a successful producer outcome.
The handoff uses the existing bounded SARIF importer and refuses to overwrite
an existing output. Published observations remain unverified.

On Linux, evaluate a reviewed namespace or container backend with a
read-only snapshot and runtime, isolated network namespace and bounded
scratch. Check permission for unprivileged user namespaces and delegated
cgroup limits. On Windows, evaluate AppContainer without network
capabilities, explicit filesystem ACLs and restricted inherited handles.
Verify firewall and loopback policy. A Job Object supplies process-tree
lifetime and resource limits. Establish provisioning permissions separately
from ordinary scanner use.

Use inert process fixtures to prove denial of reads outside scope, network
access, unsafe inherited handles and writes outside scratch. Test wrapper
and dependency substitution, descendants, limits, timeout, cancellation,
supervisor death and cleanup before enabling execution.
