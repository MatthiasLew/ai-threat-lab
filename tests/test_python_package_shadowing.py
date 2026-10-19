"""A collected child must not replace an assigned or uncertain package attribute."""

import json

import pytest
from test_cli_process import run_cli
from test_python_package_flow import HELPER, package_sources
from test_remote_audit import QueueHTTP, blob, repository

from ai_threat_lab.local_inventory import local_inventory
from ai_threat_lab.python_project_flow import project_flows
from ai_threat_lab.remote_audit import GithubAudit


@pytest.mark.parametrize("prefix", ["", "src/"])
@pytest.mark.parametrize("value", ["42", "None", "False", "'fixed'", "{}", "unknown", "unknown()"])
@pytest.mark.parametrize(
    "caller",
    [
        "from pkg import helpers\nhelpers.run(request.args['PRIVATE'])",
        "import pkg\npkg.helpers.run(request.args['PRIVATE'])",
    ],
)
def test_assigned_package_attributes_do_not_fall_back_to_collected_child(prefix, value, caller):
    findings, notices = project_flows(
        package_sources(caller, initializer="helpers = " + value, prefix=prefix)
    )
    assert not findings
    assert any("package attribute" in n for n in notices)
    assert "PRIVATE" not in str(notices) and value not in str(findings)


@pytest.mark.parametrize(
    "initializer",
    [
        "if flag:\n    helpers = 42",
        "helpers: object = None",
        "helpers = 42\ndel helpers",
        "helpers, other = unknown()",
    ],
)
def test_partial_annotated_deleted_and_destructured_bindings_are_not_guessed(initializer):
    findings, notices = project_flows(
        package_sources(
            "from pkg import helpers\nhelpers.run(request.args['q'])", initializer=initializer
        )
    )
    assert not findings and any("package attribute" in n for n in notices)


@pytest.mark.parametrize(
    "initializer",
    [
        "from external import *",
        "with unknown():\n    helpers = 42",
        "try:\n    helpers = 42\nexcept Exception:\n    pass",
        "class helpers:\n    pass",
        "for item in []:\n    helpers = 42\n    break",
        "if flag:\n    from external import *",
    ],
)
def test_uncertain_package_namespace_cannot_invent_absent_child_binding(initializer):
    findings, notices = project_flows(
        package_sources(
            "from pkg import helpers\nhelpers.run(request.args['q'])", initializer=initializer
        )
    )
    assert not findings and any("namespace" in n for n in notices)


@pytest.mark.parametrize("initializer", ["", "other = 42", "if False:\n    helpers = 42"])
def test_definitely_absent_attribute_can_still_resolve_collected_child(initializer):
    findings, _ = project_flows(
        package_sources(
            "from pkg import helpers\nhelpers.run(request.args['q'])", initializer=initializer
        )
    )
    assert len(findings) == 1 and findings[0].check == "PY013"


@pytest.mark.parametrize(
    "initializer",
    [
        "helpers = None\nfrom . import helpers",
        "helpers = 42\nfrom .helpers import run",
    ],
)
def test_explicit_child_function_import_can_bypass_unrelated_parent_attribute(initializer):
    findings, _ = project_flows(
        package_sources(
            "from pkg.helpers import run\nrun(request.args['q'])", initializer=initializer
        )
    )
    assert len(findings) == 1


def test_named_dotted_import_bypasses_shadowed_parent_attribute():
    findings, _ = project_flows(
        package_sources(
            "import pkg.helpers as h\nh.run(request.args['q'])", initializer="helpers = 42"
        )
    )
    assert len(findings) == 1


def test_known_function_after_namespace_barrier_remains_a_definite_export():
    findings, notices = project_flows(
        package_sources(
            "from pkg import run\nrun(request.args['q'])",
            initializer="from external import *\n" + HELPER,
        )
    )
    assert len(findings) == 1
    assert any("star imports" in n for n in notices)


def test_function_local_barrier_does_not_mark_module_namespace_uncertain():
    sources = package_sources(
        "from pkg import helpers\nhelpers.run(request.args['q'])",
        initializer="def other():\n    with unknown():\n        pass",
    )
    assert len(project_flows(sources)[0]) == 1


def test_local_cli_and_github_agree_on_shadowed_package(tmp_path):
    sources = package_sources(
        "from pkg import helpers\nhelpers.run(request.args['q'])",
        initializer="helpers = 42",
        prefix="src/",
    )
    for name, source in sources:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    result = local_inventory(str(tmp_path))
    assert {f.check for f in result.findings} == {"PY005"}
    process = run_cli("audit", tmp_path)
    assert process.returncode == 0
    assert {f["check"] for f in json.loads(process.stdout)["findings"]} == {"PY005"}
    entries, documents = [], []
    for name, source in sources:
        entry, document = blob(source)
        entry["path"] = name
        entries.append(entry)
        documents.append(document)
    client = QueueHTTP(*repository(*entries), *documents)
    snapshot = GithubAudit(client).collect("https://github.com/owner/repo")
    assert len(client.calls) == 6
    assert {f.check for f in snapshot.assessment.findings} == {"PY005"}


def test_unrelated_uncertain_package_does_not_disable_other_package_links():
    sources = package_sources(
        "from pkg import helpers\nhelpers.run(request.args['q'])", initializer="other = 42"
    )
    sources.extend([("other/__init__.py", "from external import *"), ("other/helpers.py", HELPER)])
    assert len(project_flows(sources)[0]) == 1


def test_known_direct_helper_export_after_barrier_remains_resolvable():
    sources = package_sources(
        "from pkg import run\nrun(request.args['q'])",
        initializer="from external import *\nfrom .helpers import run",
    )
    assert len(project_flows(sources)[0]) == 1


def test_missing_namespace_demo_control_prevents_completion(tmp_path, monkeypatch):
    from ai_threat_lab import offline_cli
    from ai_threat_lab.assessment import AssessmentResult
    from ai_threat_lab.models import ValidationError

    original = offline_cli.assessor

    def missing_control(options):
        if options.target.endswith("python-namespace-control-fixture"):
            return AssessmentResult(options.target, "local_project", "partial", (), ())
        return original(options)

    monkeypatch.setattr(offline_cli, "assessor", missing_control)
    with pytest.raises(ValidationError, match="package namespace acceptance failed"):
        offline_cli.offline_demo(tmp_path / "demo")
    assert not (tmp_path / "demo/demo-result.json").exists()


def test_engine_eighteen_readable_without_cross_engine_comparison(tmp_path):
    from ai_threat_lab.scan_bundle import compare_bundles, publish_bundle, read_bundle, scope_digest
    from ai_threat_lab.scan_cli import assessor
    from ai_threat_lab.scan_engine import ScanOptions, ScanService

    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("eval(user_value)")
    ScanService(assessor).run(ScanOptions(str(project)), tmp_path / "current")
    current = read_bundle(tmp_path / "current")
    assert current["manifest"]["scope"]["engine"] == "read-only-pipeline-26"
    metadata = dict(current["manifest"])
    metadata["scope"] = {**metadata["scope"], "engine": "read-only-pipeline-18"}
    metadata["scope_digest"] = scope_digest(metadata["scope"])
    artifacts = {name: (tmp_path / "current" / name).read_bytes() for name in metadata["files"]}
    publish_bundle(tmp_path / "old", artifacts, metadata)
    assert not compare_bundles(read_bundle(tmp_path / "old"), current)["comparable"]


@pytest.mark.parametrize(
    "caller",
    [
        "import pkg\npkg.helpers.run(request.args['q'])",
        "import pkg as p\np.helpers.run(request.args['q'])",
        "from importlib import import_module as load\np = load('pkg')\n"
        "p.helpers.run(request.args['q'])",
    ],
)
def test_attribute_access_does_not_implicitly_import_unloaded_child(caller):
    findings, notices = project_flows(package_sources(caller))
    assert not findings and any("child not established" in n for n in notices)


@pytest.mark.parametrize(
    "caller",
    [
        "import pkg.helpers\npkg.helpers.run(request.args['q'])",
        "import pkg.helpers\nimport pkg\npkg.helpers.run(request.args['q'])",
        "import pkg.helpers\nimport pkg.other\npkg.helpers.run(request.args['q'])",
    ],
)
def test_explicit_dotted_import_establishes_child_despite_old_parent_value(caller):
    sources = package_sources(caller, initializer="helpers = 42")
    sources.append(("pkg/other.py", ""))
    assert len(project_flows(sources)[0]) == 1


@pytest.mark.parametrize(
    "initializer",
    [
        "import pkg.helpers",
        "import pkg.helpers as h",
        "from .helpers import run",
    ],
)
def test_initializer_imports_establish_implicit_child_attribute(initializer):
    sources = package_sources(
        "import pkg\npkg.helpers.run(request.args['q'])", initializer="helpers = 42\n" + initializer
    )
    assert len(project_flows(sources)[0]) == 1


def test_child_loaded_on_only_one_branch_is_not_a_definite_attribute():
    sources = package_sources(
        "import pkg\nif flag:\n    import pkg.helpers\npkg.helpers.run(request.args['q'])"
    )
    findings, notices = project_flows(sources)
    assert not findings and any("child not established" in n for n in notices)


def test_imported_child_fact_survives_alias_and_helper_return():
    sources = package_sources(
        "import pkg.helpers\ndef identity(module):\n    return module\n"
        "alias = identity(pkg)\nalias.helpers.run(request.args['q'])"
    )
    assert len(project_flows(sources)[0]) == 1


def test_child_loaded_on_both_branches_is_a_definite_attribute():
    sources = package_sources(
        "if flag:\n    import pkg.helpers\nelse:\n    import pkg.helpers\n"
        "pkg.helpers.run(request.args['q'])"
    )
    assert len(project_flows(sources)[0]) == 1


def test_failed_dotted_import_does_not_invent_a_loaded_child():
    sources = package_sources("import pkg.missing\npkg.missing.run(request.args['q'])")
    findings, notices = project_flows(sources)
    assert not findings and any("unavailable" in n for n in notices)


@pytest.mark.parametrize(
    "caller",
    [
        "import pkg.helpers\npkg.helpers.run(request.args['q'])",
        "import pkg.helpers as h\nh.run(request.args['q'])",
        "from pkg import helpers\nhelpers.run(request.args['q'])",
    ],
)
def test_cached_child_reassigned_after_initializer_import_is_not_restored(caller):
    sources = package_sources(caller, initializer="from . import helpers\nhelpers = 42")
    findings, notices = project_flows(sources)
    assert not findings and any("package" in n for n in notices)


@pytest.mark.parametrize(
    "caller",
    [
        "from pkg.helpers import run\nrun(request.args['q'])",
        "from importlib import import_module as load\nh=load('pkg.helpers')\n"
        "h.run(request.args['q'])",
    ],
)
def test_direct_child_lookup_still_works_when_cached_parent_attribute_is_reassigned(caller):
    sources = package_sources(caller, initializer="from . import helpers\nhelpers = 42")
    assert len(project_flows(sources)[0]) == 1


@pytest.mark.parametrize(
    "setup",
    [
        "import pkg.helpers",
        "import pkg.helpers as h",
        "from importlib import import_module as load\nh=load('pkg.helpers')",
    ],
)
def test_from_import_observes_child_loaded_in_current_scope(setup):
    sources = package_sources(
        setup + "\nfrom pkg import helpers\nhelpers.run(request.args['q'])",
        initializer="helpers = 42",
    )
    assert len(project_flows(sources)[0]) == 1


def test_conditional_initializer_import_and_later_rebind_cannot_invent_loaded_child():
    sources = package_sources(
        "import pkg.helpers\npkg.helpers.run(request.args['q'])",
        initializer="if flag:\n    from . import helpers\nhelpers = 42",
    )
    findings, notices = project_flows(sources)
    assert not findings and any("nested initializer import effects" in n for n in notices)


def test_direct_qualified_helper_import_survives_conditional_initializer_gap():
    sources = package_sources(
        "from pkg.helpers import run\nrun(request.args['q'])",
        initializer="if flag:\n    from . import helpers\nhelpers = 42",
    )
    assert len(project_flows(sources)[0]) == 1


@pytest.mark.parametrize(
    "initializer,setup,reference",
    [
        ("", "import pkg", "pkg.helpers.run"),
        ("helpers = 42", "from pkg import helpers", "helpers.run"),
        ("helpers = 42", "import pkg.helpers", "pkg.helpers.run"),
        ("helpers = 42", "import pkg.helpers as h", "h.run"),
        ("from . import helpers\nhelpers = 42", "import pkg.helpers", "pkg.helpers.run"),
        ("from . import helpers\nhelpers = 42", "import pkg.helpers as h", "h.run"),
        ("from . import helpers\nhelpers = 42", "from pkg.helpers import run", "run"),
        (
            "from . import helpers\nhelpers = 42",
            "from importlib import import_module as load\nh = load('pkg.helpers')",
            "h.run",
        ),
    ],
)
def test_package_binding_matches_python_on_test_authored_inert_fixtures(
    tmp_path, initializer, setup, reference
):
    # This oracle imports only inert test-authored files, never the analyzed target source.
    import os
    import subprocess
    import sys

    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text(initializer, encoding="utf-8")
    (package / "helpers.py").write_text("def run(value):\n    return value\n", encoding="utf-8")
    script = "import sys\nsys.path.insert(0," + repr(str(tmp_path)) + ")\n" + setup
    script += "\ntry:\n    candidate = " + reference
    script += "\nexcept AttributeError:\n    candidate = None\nprint(callable(candidate))"
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "SYSTEMROOT", "SystemRoot", "WINDIR", "TEMP", "TMP"}
    }
    process = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    actual_binding = process.stdout.strip() == "True"
    sources = package_sources(
        setup + "\n" + reference + "(request.args['q'])", initializer=initializer
    )
    findings, _ = project_flows(sources)
    assert bool(findings) == actual_binding


def test_scoped_loaded_child_lookup_consumes_shared_step_budget(monkeypatch):
    import ai_threat_lab.python_flow as flow_limits

    monkeypatch.setattr(flow_limits, "MAX_STEPS", 80)
    caller = "import pkg.helpers\n" + "\n".join(f"value{i}=0" for i in range(12))
    caller += "\n" + "\n".join("from pkg import helpers" for _ in range(15))
    caller += "\nhelpers.run(request.args['q'])"
    findings, notices = project_flows(package_sources(caller, initializer="helpers=42"))
    assert not findings and any("scoped import lookup step limit" in n for n in notices)
