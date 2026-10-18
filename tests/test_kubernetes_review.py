"""Bounded Kubernetes JSON field observations, source-free pointers and collector parity."""

import json
import socket
from dataclasses import asdict

import pytest
from test_cli_process import run_cli
from test_remote_audit import QueueHTTP, blob, repository

from ai_threat_lab.cli import main
from ai_threat_lab.kubernetes_review import review_kubernetes_file, review_kubernetes_source
from ai_threat_lab.local_inventory import local_inventory
from ai_threat_lab.models import ValidationError
from ai_threat_lab.remote_audit import GithubAudit
from ai_threat_lab.scan_bundle import read_bundle
from ai_threat_lab.scan_cli import assessor
from ai_threat_lab.scan_engine import ScanOptions, ScanService


def pod(spec=None):
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "PRIVATE_RESOURCE", "namespace": "PRIVATE_NAMESPACE"},
        "spec": spec
        if spec is not None
        else {"containers": [{"name": "PRIVATE_CONTAINER", "image": "PRIVATE_IMAGE"}]},
    }


def review(value, **kwargs):
    return review_kubernetes_source(json.dumps(value), "deployment.json", explicit=True, **kwargs)


@pytest.mark.parametrize(
    "field,value,check",
    [
        ("privileged", True, "k8s_privileged_container"),
        ("allowPrivilegeEscalation", True, "k8s_privilege_escalation"),
        ("runAsUser", 0, "k8s_root_user"),
        ("runAsNonRoot", False, "k8s_non_root_disabled"),
        ("readOnlyRootFilesystem", False, "k8s_writable_root_filesystem"),
        ("seccompProfile", {"type": "Unconfined"}, "k8s_unconfined_seccomp"),
        ("capabilities", {"add": ["SYS_ADMIN"]}, "k8s_added_capabilities"),
    ],
)
@pytest.mark.parametrize("group", ["containers", "initContainers", "ephemeralContainers"])
def test_explicit_container_fields_all_three_groups(field, value, check, group):
    result = review(
        pod({group: [{"name": "PRIVATE_CONTAINER", "securityContext": {field: value}}]})
    )
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.check == check and finding.status == "candidate"
    assert f"#/spec/{group}/0/securityContext/{field}" in finding.evidence
    assert "PRIVATE_CONTAINER" not in str(result.findings)


@pytest.mark.parametrize("field", ["hostNetwork", "hostPID", "hostIPC"])
def test_host_namespace_fields_have_precise_json_pointers(field):
    result = review(pod({field: True}))
    assert result.findings[0].check == "k8s_host_namespace"
    assert result.findings[0].evidence.startswith(f"deployment.json#/spec/{field}:")


@pytest.mark.parametrize("capability", ["ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"])
def test_selected_capabilities(capability):
    result = review(
        pod({"containers": [{"securityContext": {"capabilities": {"add": [capability]}}}]})
    )
    assert {f.check for f in result.findings} == {"k8s_added_capabilities"}


def test_pod_defaults_do_not_claim_effective_container_identity():
    resource = pod(
        {
            "securityContext": {
                "runAsUser": 0,
                "runAsNonRoot": False,
                "seccompProfile": {"type": "Unconfined"},
            },
            "containers": [{"securityContext": {"runAsUser": 1000, "runAsNonRoot": True}}],
        }
    )
    result = review(resource)
    assert {f.check for f in result.findings} == {
        "k8s_root_user",
        "k8s_non_root_disabled",
        "k8s_unconfined_seccomp",
    }
    assert all("#/spec/securityContext/" in f.evidence for f in result.findings)
    assert any("effective inheritance" in n for n in result.not_checked)


def test_host_path_and_ports_do_not_reproduce_values_or_open_paths():
    result = review(
        pod(
            {
                "volumes": [{"name": "PRIVATE_VOLUME", "hostPath": {"path": "/PRIVATE_HOST_PATH"}}],
                "containers": [{"ports": [{"hostPort": 30456, "containerPort": 8080}]}],
            }
        )
    )
    assert {f.check for f in result.findings} == {"k8s_host_path", "k8s_host_port"}
    evidence = json.dumps([asdict(f) for f in result.findings])
    assert "PRIVATE" not in evidence and "30456" not in evidence


@pytest.mark.parametrize(
    "spec",
    [
        {},
        {"containers": [{}]},
        {"hostNetwork": False, "hostPID": False, "hostIPC": False},
        {
            "containers": [
                {
                    "securityContext": {
                        "privileged": False,
                        "allowPrivilegeEscalation": False,
                        "runAsUser": 1000,
                        "runAsNonRoot": True,
                        "readOnlyRootFilesystem": True,
                        "seccompProfile": {"type": "RuntimeDefault"},
                        "capabilities": {"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]},
                    },
                    "ports": [{"hostPort": 0}],
                }
            ]
        },
        {
            "securityContext": {
                "seccompProfile": {"type": "Localhost", "localhostProfile": "PRIVATE_PROFILE"}
            }
        },
    ],
)
def test_missing_and_restrictive_fields_are_not_inferred_as_errors(spec):
    result = review(pod(spec))
    assert not result.findings and result.status == "partial"
    assert any("clean result" in n for n in result.not_checked)


@pytest.mark.parametrize(
    "kind,api,route",
    [
        ("Pod", "v1", ["spec"]),
        ("ReplicationController", "v1", ["spec", "template", "spec"]),
        ("Deployment", "apps/v1", ["spec", "template", "spec"]),
        ("DaemonSet", "apps/v1", ["spec", "template", "spec"]),
        ("StatefulSet", "apps/v1", ["spec", "template", "spec"]),
        ("ReplicaSet", "apps/v1", ["spec", "template", "spec"]),
        ("Job", "batch/v1", ["spec", "template", "spec"]),
        ("CronJob", "batch/v1", ["spec", "jobTemplate", "spec", "template", "spec"]),
    ],
)
def test_supported_workload_templates(kind, api, route):
    resource = {"apiVersion": api, "kind": kind}
    leaf = resource
    for key in route:
        leaf[key] = {}
        leaf = leaf[key]
    leaf["hostNetwork"] = True
    result = review(resource)
    assert len(result.findings) == 1
    assert "#/" + "/".join(route) + "/hostNetwork" in result.findings[0].evidence


def test_list_nested_resources_and_unrecognized_kinds_keep_gaps():
    root = {
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            pod({"hostNetwork": True}),
            {"apiVersion": "v1", "kind": "List", "items": [pod({"hostPID": True})]},
            {"apiVersion": "v1", "kind": "Secret", "data": {"token": "PRIVATE_SECRET"}},
        ],
    }
    result = review(root)
    assert len(result.findings) == 2
    assert "#/items/1/items/0/spec/hostPID" in result.findings[1].evidence
    assert any("unsupported" in n for n in result.not_checked)
    assert "PRIVATE_SECRET" not in str(result)


@pytest.mark.parametrize(
    "resource",
    [
        {"apiVersion": "apps/v1beta1", "kind": "Deployment", "spec": {}},
        {"apiVersion": "v1", "kind": "List", "items": {}},
        {"apiVersion": "apps/v1", "kind": "Deployment", "spec": {}},
        {"apiVersion": "v1", "kind": "Pod", "spec": None},
        {"apiVersion": "v1", "kind": []},
        {"apiVersion": "v1", "kind": "List", "items": ["PRIVATE_ENTRY"]},
        pod({"containers": ["PRIVATE_CONTAINER"]}),
        pod({"containers": "PRIVATE_LIST"}),
        pod({"securityContext": "PRIVATE_CONTEXT"}),
        pod({"hostNetwork": "PRIVATE_TRUE"}),
        pod({"securityContext": {"runAsUser": False}}),
        pod({"securityContext": {"runAsUser": -1}}),
        pod({"volumes": [{"hostPath": "PRIVATE_PATH"}]}),
        pod({"containers": [{"ports": [{"hostPort": True}]}]}),
        pod({"containers": [{"securityContext": {"capabilities": {"add": ["SYS_ADMIN", 1]}}}]}),
    ],
)
def test_malformed_selected_structures_are_explicit_redacted_gaps(resource):
    result = review(resource)
    assert not result.findings
    assert len(result.not_checked) > 1 and "PRIVATE" not in str(result.not_checked)


def test_explicit_non_linux_os_is_skipped_with_notice():
    result = review(
        pod(
            {
                "os": {"name": "windows"},
                "hostPID": True,
                "containers": [{"securityContext": {"privileged": True}}],
            }
        )
    )
    assert not result.findings and any("non-Linux" in n for n in result.not_checked)


def test_generic_json_is_ignored_and_named_invalid_kubernetes_is_visible():
    assert review_kubernetes_source('{"scripts":{"test":"echo test"}}', "package.json") is None
    assert review_kubernetes_source("PRIVATE invalid JSON", "other.json") is None
    named = review_kubernetes_source("PRIVATE invalid JSON", "worker.k8s.json")
    assert named is not None and not named.findings and len(named.not_checked) == 2
    assert "PRIVATE" not in str(named.not_checked)
    with pytest.raises(ValidationError, match="Expected"):
        review_kubernetes_source("[]", explicit=True)


@pytest.mark.parametrize(
    "source",
    [
        "{",
        '{"apiVersion":"v1","kind":"Pod","kind":"Secret"}',
        '{"apiVersion":"v1","kind":"Pod","spec":{"run":NaN}}',
    ],
)
def test_strict_json_rejects_malformed_duplicate_and_nonfinite_values(source):
    with pytest.raises(ValidationError, match="parse"):
        review_kubernetes_source(source, explicit=True)


def test_selection_limits_preserve_prior_findings_and_never_claim_full_coverage(monkeypatch):
    import ai_threat_lab.kubernetes_review as module

    monkeypatch.setattr(module, "MAX_RESOURCES", 2)
    result = review({"apiVersion": "v1", "kind": "List", "items": [pod({"hostNetwork": True})] * 4})
    assert len(result.findings) == 1 and any(
        "resources selection limit" in n for n in result.not_checked
    )
    monkeypatch.setattr(module, "MAX_RESOURCES", 50)
    for limit, spec in [
        ("MAX_CONTAINERS", {"containers": [{"securityContext": {"privileged": True}}] * 3}),
        ("MAX_VOLUMES", {"volumes": [{"hostPath": {}}] * 3}),
        ("MAX_PORTS", {"containers": [{"ports": [{"hostPort": 1234}] * 3}]}),
    ]:
        with monkeypatch.context() as scoped:
            scoped.setattr(module, limit, 1)
            result = review(pod(spec))
            assert len(result.findings) == 1
            assert any("selection limit" in n for n in result.not_checked)
    monkeypatch.setattr(module, "MAX_FINDINGS", 1)
    result = review(pod({"hostNetwork": True, "hostPID": True}))
    assert len(result.findings) == 1 and any(
        "findings selection limit" in n for n in result.not_checked
    )


def test_list_depth_and_notice_caps(monkeypatch):
    import ai_threat_lab.kubernetes_review as module

    resource = pod({"hostPID": True})
    for _ in range(6):
        resource = {"apiVersion": "v1", "kind": "List", "items": [resource]}
    result = review(resource)
    assert not result.findings and any("depth limit" in n for n in result.not_checked)
    monkeypatch.setattr(module, "MAX_NOTICES", 2)
    result = review(pod({"containers": ["PRIVATE"] * 5}))
    assert len(result.not_checked) == 4 and "omitted" in result.not_checked[-1]


def test_source_bytes_decoding_file_type_and_root_links(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps(pod({"hostNetwork": True})).encode())
    assert len(review_kubernetes_file(path).findings) == 1
    path.write_bytes(b"x" * (256 * 1024 + 1))
    with pytest.raises(ValidationError, match="256 KiB"):
        review_kubernetes_file(path)
    path.write_bytes(b"\xff")
    with pytest.raises(ValidationError, match="UTF-8"):
        review_kubernetes_file(path)
    with pytest.raises(ValidationError, match="JSON manifests"):
        review_kubernetes_file(tmp_path / "manifest.yaml")
    path.write_text(json.dumps(pod()))
    link = tmp_path / "linked.json"
    try:
        link.symlink_to(path)
    except (OSError, NotImplementedError):
        return
    with pytest.raises(ValidationError, match="without links"):
        review_kubernetes_file(link)


def test_local_github_scan_and_batch_share_source_free_findings(tmp_path, monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("No cluster/network access in offline Kubernetes review")

    import subprocess

    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(subprocess, "run", deny)
    project = tmp_path / "project"
    project.mkdir()
    source = json.dumps(pod({"hostNetwork": True}))
    (project / "deployment.json").write_text(source)
    local = local_inventory(str(project))
    assert [f.check for f in local.findings] == ["k8s_host_namespace"]
    assert "PRIVATE_RESOURCE" not in json.dumps(asdict(local))
    item, data = blob(source)
    item["path"] = "deployment.json"
    client = QueueHTTP(*repository(item), data)
    remote = GithubAudit(client).assess("https://github.com/owner/repo")
    assert len(client.calls) == 4 and remote.findings == local.findings
    ScanService(assessor).run(ScanOptions(str(project)), tmp_path / "scan")
    report = read_bundle(tmp_path / "scan")["documents"]["report.json"]
    assert report["findings"][0]["check"] == "k8s_host_namespace"
    assert "PRIVATE_RESOURCE" not in json.dumps(report)
    from ai_threat_lab.batch_scan import check_batch, run_batch

    batch = run_batch([str(project)], tmp_path / "batch")
    assert batch["unique_findings"] == 1 and not batch["failed_runs"]
    assert check_batch(tmp_path / "batch")["status"] == "integrity_verified"


def test_real_cli_json_html_exit_policy_and_no_overwrite(tmp_path, capsys):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(pod({"hostPID": True})))
    result = run_cli("review-kubernetes", path, "--fail-on-findings")
    assert result.returncode == 1 and not result.stderr
    assert json.loads(result.stdout)["findings"][0]["check"] == "k8s_host_namespace"
    output = tmp_path / "review.html"
    assert main(["review-kubernetes", str(path), "--format", "html", "--output", str(output)]) == 0
    original = output.read_bytes()
    assert b"PRIVATE_RESOURCE" not in original
    assert main(["review-kubernetes", str(path), "--output", str(output)]) == 2
    assert output.read_bytes() == original
    capsys.readouterr()
    path.write_text(json.dumps(pod()))
    assert run_cli("review-kubernetes", path, "--fail-on-findings").returncode == 0
    assert run_cli("review-kubernetes", path, "--network").returncode == 2


@pytest.mark.parametrize("changes", [{"source": None}, {"filename": None}, {"explicit": 1}])
def test_public_arguments_are_strict(changes):
    arguments = {"source": json.dumps(pod()), "filename": "manifest.json", "explicit": True}
    arguments.update(changes)
    with pytest.raises(ValidationError):
        review_kubernetes_source(**arguments)


def test_pure_source_byte_and_parser_recursion_limits_are_redacted():
    with pytest.raises(ValidationError, match="bounded"):
        review_kubernetes_source(" " * (256 * 1024 + 1), explicit=True)
    with pytest.raises(ValidationError, match="bounded"):
        review_kubernetes_source("[" * 1500 + "]" * 1500, explicit=True)


def test_invalid_cli_source_never_creates_a_report(tmp_path, capsys):
    source = tmp_path / "broken.json"
    source.write_text('{"apiVersion":"PRIVATE')
    output = tmp_path / "absent.html"
    assert (
        main(["review-kubernetes", str(source), "--format", "html", "--output", str(output)]) == 2
    )
    assert not output.exists() and "PRIVATE" not in capsys.readouterr().err


def test_engine_eight_reading_and_cross_engine_comparison(tmp_path):
    from ai_threat_lab.scan_bundle import compare_bundles, publish_bundle, scope_digest

    path = tmp_path / "source.py"
    path.write_text("eval(data)")
    ScanService(assessor).run(ScanOptions(str(path)), tmp_path / "current")
    current = read_bundle(tmp_path / "current")
    metadata = dict(current["manifest"])
    metadata["scope"] = {**metadata["scope"], "engine": "read-only-pipeline-8"}
    metadata["scope_digest"] = scope_digest(metadata["scope"])
    artifacts = {name: (tmp_path / "current" / name).read_bytes() for name in metadata["files"]}
    publish_bundle(tmp_path / "old", artifacts, metadata)
    comparison = compare_bundles(read_bundle(tmp_path / "old"), current)
    assert comparison["comparable"] is False and comparison["counts"] is None


def test_missing_kubernetes_demo_evidence_prevents_completion(tmp_path, monkeypatch):
    import ai_threat_lab.offline_cli as module
    from ai_threat_lab.assessment import AssessmentResult

    original = module.assessor

    def missing(options):
        if options.target.endswith("kubernetes-fixture"):
            return AssessmentResult(
                options.target, "local_project", "partial", (), ("Fixture only",)
            )
        return original(options)

    monkeypatch.setattr(module, "assessor", missing)
    with pytest.raises(ValidationError, match="Kubernetes acceptance"):
        module.offline_demo(tmp_path / "incomplete")
    assert not (tmp_path / "incomplete" / "demo-result.json").exists()


def test_json_depth_guard_ignores_escaped_brackets_in_strings():
    resource = pod({"hostNetwork": True})
    resource["metadata"]["private"] = '["\\' * 1000
    result = review(resource)
    assert len(result.findings) == 1
    assert "private" not in str(result.findings)
