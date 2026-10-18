"""Bounded explicit Kubernetes JSON observations; no YAML, cluster or runtime access."""

import json
from collections import Counter
from pathlib import Path, PurePosixPath

from .assessment import AssessmentFinding, AssessmentResult
from .contracts import _nonfinite, _pairs
from .models import ValidationError

MAX_BYTES = 256 * 1024
MAX_JSON_DEPTH = 64
MAX_RESOURCES = 50
MAX_LIST_DEPTH = 4
MAX_CONTAINERS = 100
MAX_VOLUMES = 100
MAX_PORTS = 100
MAX_FINDINGS = 300
MAX_NOTICES = 50
NOTICE = (
    "Selected explicit Kubernetes JSON fields only; no YAML/Helm rendering, defaults, "
    "effective inheritance, API/admission validation, cluster access, RBAC, network policy, "
    "image/runtime or Pod Security conformance assessment. A clean result is not an all-clear."
)
WORKLOADS = {
    ("v1", "Pod"): ("spec",),
    ("v1", "ReplicationController"): ("spec", "template", "spec"),
    **{
        ("apps/v1", kind): ("spec", "template", "spec")
        for kind in (
            "Deployment",
            "DaemonSet",
            "StatefulSet",
            "ReplicaSet",
        )
    },
    ("batch/v1", "Job"): ("spec", "template", "spec"),
    ("batch/v1", "CronJob"): ("spec", "jobTemplate", "spec", "template", "spec"),
}


class _SelectionLimit(Exception):
    pass


def _check_json_nesting(source):
    depth, quoted, escaped = 0, False, False
    for character in source:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValidationError("Kubernetes JSON nesting limit exceeded")
        elif character in "]}":
            depth -= 1


def review_kubernetes_source(source, filename="manifest.json", *, explicit=False):
    if not isinstance(filename, str) or not filename.strip() or type(explicit) is not bool:
        raise ValidationError("Kubernetes review requires a filename and boolean selection mode")
    if not isinstance(source, str):
        raise ValidationError("Kubernetes JSON source must be text")
    try:
        if len(source.encode("utf-8")) > MAX_BYTES:
            raise ValidationError("Kubernetes JSON exceeds the 256 KiB source limit")
        _check_json_nesting(source)
        document = json.loads(
            source.removeprefix("\ufeff"), object_pairs_hook=_pairs, parse_constant=_nonfinite
        )
    except (ValueError, UnicodeError, RecursionError):
        if explicit:
            raise ValidationError("Cannot parse bounded Kubernetes JSON; values omitted") from None
        name = PurePosixPath(filename.replace("\\", "/")).name
        if name.endswith((".k8s.json", ".kubernetes.json")) or name == "kubernetes.json":
            return AssessmentResult(
                filename,
                "kubernetes_manifest",
                "partial",
                (),
                (
                    NOTICE,
                    f"{filename}: named Kubernetes JSON could not be parsed; values omitted.",
                ),
            )
        return None
    if not isinstance(document, dict) or not {"apiVersion", "kind"} <= document.keys():
        if explicit:
            raise ValidationError("Expected a Kubernetes JSON object with apiVersion and kind")
        return None
    findings, notices, counters = [], [], Counter()
    omitted = 0

    def note(message):
        nonlocal omitted
        message = f"{filename}: {message}"
        if message in notices:
            return
        if len(notices) < MAX_NOTICES:
            notices.append(message)
        else:
            omitted += 1

    def consume(label, maximum):
        counters[label] += 1
        if counters[label] > maximum:
            note(f"Kubernetes {label} selection limit reached; remaining input unchecked.")
            raise _SelectionLimit

    def add(check, pointer, title, action):
        consume("findings", MAX_FINDINGS)
        findings.append(
            AssessmentFinding(check, "candidate", f"{filename}{pointer}: {title}", action)
        )

    def obj(parent, key, pointer):
        value = parent.get(key)
        if value is None:
            return {}
        if not isinstance(value, dict):
            note(f"{pointer}/{key}: non-object selected field; values omitted.")
            return {}
        return value

    def flag(parent, key, pointer):
        value = parent.get(key)
        if value is not None and type(value) is not bool:
            note(f"{pointer}/{key}: non-boolean selected field; values omitted.")
            return None
        return value

    def entries(parent, key, pointer, label, maximum):
        values = parent.get(key)
        if values is None:
            return
        if not isinstance(values, list):
            note(f"{pointer}/{key}: non-array selected field; values omitted.")
            return
        for index, value in enumerate(values):
            consume(label, maximum)
            location = f"{pointer}/{key}/{index}"
            if not isinstance(value, dict):
                note(f"{location}: non-object selected entry; values omitted.")
                continue
            yield value, location

    def security(context, pointer, *, container=False):
        if flag(context, "runAsNonRoot", pointer) is False:
            add(
                "k8s_non_root_disabled",
                pointer + "/runAsNonRoot",
                "Explicit non-root requirement disabled",
                "Review effective Pod/container identity and require non-root where appropriate.",
            )
        user = context.get("runAsUser")
        if user is not None:
            if type(user) is not int or user < 0:
                note(f"{pointer}/runAsUser: invalid selected identity type/value; values omitted.")
            elif user == 0:
                add(
                    "k8s_root_user",
                    pointer + "/runAsUser",
                    "Explicit zero user identity",
                    "Review inherited/overridden identity and choose a suitable "
                    "non-root runtime user.",
                )
        profile = obj(context, "seccompProfile", pointer)
        if profile.get("type") == "Unconfined":
            add(
                "k8s_unconfined_seccomp",
                pointer + "/seccompProfile/type",
                "Explicit unconfined seccomp profile",
                "Review the workload and use an appropriate restrictive runtime/profile policy.",
            )
        if not container:
            return
        for key, check, title in (
            ("privileged", "k8s_privileged_container", "Explicit privileged container"),
            (
                "allowPrivilegeEscalation",
                "k8s_privilege_escalation",
                "Explicit privilege escalation enabled",
            ),
        ):
            if flag(context, key, pointer) is True:
                add(
                    check,
                    pointer + "/" + key,
                    title,
                    "Review operational need, capabilities and effective runtime/admission policy.",
                )
        if flag(context, "readOnlyRootFilesystem", pointer) is False:
            add(
                "k8s_writable_root_filesystem",
                pointer + "/readOnlyRootFilesystem",
                "Explicit writable root filesystem",
                "Review write requirements; use scoped writable volumes "
                "and a read-only root where suitable.",
            )
        capabilities = obj(context, "capabilities", pointer)
        additions = capabilities.get("add")
        if additions is not None:
            if not isinstance(additions, list) or any(not isinstance(v, str) for v in additions):
                note(
                    f"{pointer}/capabilities/add: unsupported selected capability list; "
                    "values omitted."
                )
            elif {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"}.intersection(additions):
                add(
                    "k8s_added_capabilities",
                    pointer + "/capabilities/add",
                    "Selected broad Linux capabilities added",
                    "Review exact operational requirements and minimize added Linux capabilities.",
                )

    def pod(spec, pointer):
        operating_system = obj(spec, "os", pointer)
        if operating_system and operating_system.get("name") not in (None, "linux"):
            note(f"{pointer}/os: explicit non-Linux or unknown OS is outside selected checks.")
            return
        for key in ("hostNetwork", "hostPID", "hostIPC"):
            if flag(spec, key, pointer) is True:
                add(
                    "k8s_host_namespace",
                    pointer + "/" + key,
                    "Explicit host namespace sharing",
                    "Review workload isolation and operational need for host namespace access.",
                )
        security(obj(spec, "securityContext", pointer), pointer + "/securityContext")
        for volume, location in entries(spec, "volumes", pointer, "volumes", MAX_VOLUMES):
            if volume.get("hostPath") is not None:
                if isinstance(volume["hostPath"], dict):
                    add(
                        "k8s_host_path",
                        location + "/hostPath",
                        "Host filesystem volume declared",
                        "Review host path exposure, read/write permissions "
                        "and safer volume alternatives.",
                    )
                else:
                    note(f"{location}/hostPath: non-object selected field; values omitted.")
        for key in ("containers", "initContainers", "ephemeralContainers"):
            for container, location in entries(spec, key, pointer, "containers", MAX_CONTAINERS):
                security(
                    obj(container, "securityContext", location),
                    location + "/securityContext",
                    container=True,
                )
                for port, port_location in entries(
                    container, "ports", location, "ports", MAX_PORTS
                ):
                    value = port.get("hostPort")
                    if value is None:
                        continue
                    if type(value) is not int or not 0 <= value <= 65535:
                        note(f"{port_location}/hostPort: invalid selected port; values omitted.")
                    elif value:
                        add(
                            "k8s_host_port",
                            port_location + "/hostPort",
                            "Explicit host port binding",
                            "Review host exposure and use scoped service/network controls "
                            "where suitable.",
                        )

    def walk(resource, pointer="#", depth=0):
        consume("resources", MAX_RESOURCES)
        if not isinstance(resource, dict):
            note(f"{pointer}: non-object resource; values omitted.")
            return
        api, kind = resource.get("apiVersion"), resource.get("kind")
        if not isinstance(api, str) or not isinstance(kind, str):
            note(f"{pointer}: missing/invalid resource identity; values omitted.")
            return
        if (api, kind) == ("v1", "List"):
            if depth >= MAX_LIST_DEPTH:
                note(f"{pointer}: Kubernetes List depth limit reached; nested resources unchecked.")
                return
            items = resource.get("items")
            if not isinstance(items, list):
                note(f"{pointer}/items: missing/non-array List items; values omitted.")
                return
            for index, child in enumerate(items):
                walk(child, f"{pointer}/items/{index}", depth + 1)
            return
        route = WORKLOADS.get((api, kind))
        if route is None:
            note(f"{pointer}: unsupported Kubernetes apiVersion/kind; values omitted.")
            return
        spec, location = resource, pointer
        for key in route:
            location += "/" + key
            spec = spec.get(key) if isinstance(spec, dict) else None
            if not isinstance(spec, dict):
                note(f"{location}: missing/non-object workload Pod spec; values omitted.")
                return
        pod(spec, location)

    try:
        walk(document)
    except _SelectionLimit:
        pass
    if omitted:
        notices.append(f"{filename}: additional omitted Kubernetes coverage notices: {omitted}.")
    return AssessmentResult(
        filename, "kubernetes_manifest", "partial", tuple(findings), (NOTICE, *notices)
    )


def review_kubernetes_file(path):
    path = Path(path)
    if path.suffix.lower() != ".json":
        raise ValidationError(
            "Kubernetes review accepts JSON manifests only; YAML/Helm are not rendered"
        )
    if path.is_symlink() or getattr(path, "is_junction", lambda: False)() or not path.is_file():
        raise ValidationError("Kubernetes manifest must be a regular file without links")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValidationError("Kubernetes JSON exceeds the 256 KiB source limit")
    try:
        source = raw.decode("utf-8-sig")
    except UnicodeError:
        raise ValidationError("Cannot decode Kubernetes JSON as UTF-8; values omitted") from None
    return review_kubernetes_source(source, str(path), explicit=True)
