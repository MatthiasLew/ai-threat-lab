import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from threading import Barrier

import pytest

from ai_threat_lab import scanner_approval, scanner_objects
from ai_threat_lab.models import ValidationError
from ai_threat_lab.scanner_approval import ScannerReview, ScannerReviewBroker, issue_owner_approval
from ai_threat_lab.scanner_objects import ScannerRuntime, capture_scanner_tree, digest
from ai_threat_lab.scanner_sandbox import ScannerExecutionPlan

KEY = b"test owner key".ljust(32, b"!")


@pytest.fixture
def review(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "empty").mkdir()
    (project / "zażółć.txt").write_bytes(b"source")
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    for name in ("wrapper", "python", "library.py", "native.bin", "config"):
        (runtime_root / name).write_bytes(name.encode())
    snapshot = capture_scanner_tree(project)
    runtime = ScannerRuntime(
        capture_scanner_tree(runtime_root), "wrapper", "python", "config",
        ("library.py",), ("native.bin",), ("--offline",), ("system loader",),
    )
    manifest = runtime.manifest()
    plan = ScannerExecutionPlan(
        "bandit", snapshot.root, snapshot.fingerprint(), manifest["executable"],
        manifest["interpreter"], digest(manifest), manifest["configuration"],
        str(tmp_path / "out"), 10, 64 * 1024**2, 4, 1024**2, 4096,
        "linux", "bubblewrap", "1" * 64,
    )
    return ScannerReview(plan, snapshot, runtime)


@pytest.fixture
def broker(tmp_path):
    return ScannerReviewBroker(tmp_path / "approval.sqlite", owner_key=KEY)


def issue(review, broker, **options):
    return issue_owner_approval(
        review, owner_key=KEY, ledger_id=broker.ledger_id,
        **({"confirmed_fingerprint": review.fingerprint()} | options),
    )


def test_snapshot_retains_approved_bytes_after_source_replacement(review):
    source = Path(review.snapshot.root) / "zażółć.txt"
    source.unlink()
    source.write_bytes(b"replacement")
    rows = review.snapshot.entries
    assert rows[0].kind == "directory"
    assert rows[1].data == b"source"
    assert capture_scanner_tree(source.parent).fingerprint() != review.plan.snapshot_sha256
    assert review.fingerprint() == review.plan.fingerprint()


@pytest.mark.parametrize("file", ["wrapper", "python", "library.py", "native.bin", "config"])
def test_recaptured_runtime_substitution_invalidates_plan(review, file):
    root = Path(review.runtime.tree.root)
    (root / file).write_bytes(b"substituted")
    runtime = replace(review.runtime, tree=capture_scanner_tree(root))
    with pytest.raises(ValidationError, match="captured objects"):
        replace(review, runtime=runtime).fingerprint()
    assert review.fingerprint() == review.plan.fingerprint()


def test_runtime_requires_all_roles_and_binds_arguments(review):
    with pytest.raises(ValidationError, match="every captured file"):
        replace(review.runtime, native_libraries=()).manifest()
    with pytest.raises(ValidationError, match="captured objects"):
        replace(review, runtime=replace(review.runtime, arguments=())).fingerprint()


@pytest.mark.parametrize("limits,message", [
    ({"max_depth": 0}, "depth limit"), ({"max_bytes": 2}, "byte limit"),
    ({"max_entries": 1}, "entry limit"), ({"max_entries": 2}, "entry limit"),
    ({"max_bytes": 0}, "Invalid scanner capture limits"),
])
def test_bounded_capture_refuses_partial_tree(tmp_path, limits, message):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "child").write_bytes(b"abc")
    (tmp_path / "tail").touch()
    with pytest.raises(ValidationError, match=message):
        capture_scanner_tree(tmp_path, **limits)


def test_capture_refuses_missing_and_remote_tree(tmp_path):
    with pytest.raises(ValidationError, match="incomplete"):
        capture_scanner_tree(tmp_path / "missing")
    with pytest.raises(ValidationError, match="local"):
        capture_scanner_tree("//remote.invalid/project")


def test_capture_refuses_directory_link(tmp_path):
    root = tmp_path / "approved"
    root.mkdir()
    alias = root / "alias"
    if os.name == "nt":
        from _winapi import CreateJunction

        CreateJunction(str(tmp_path), str(alias))
    else:
        alias.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValidationError, match="link or reparse"):
        capture_scanner_tree(root)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX special file")
def test_capture_refuses_fifo(tmp_path):
    os.mkfifo(tmp_path / "pipe")
    with pytest.raises(ValidationError, match="special file"):
        capture_scanner_tree(tmp_path)


def test_capture_detects_change_while_reading(tmp_path, monkeypatch):
    artifact = tmp_path / "source"
    artifact.write_bytes(b"before")
    read = scanner_objects._read

    def change(stream, limit):
        data = read(stream, limit)
        (tmp_path / "added").touch()
        return data

    monkeypatch.setattr(scanner_objects, "_read", change)
    with pytest.raises(ValidationError, match="directory changed"):
        capture_scanner_tree(tmp_path)


@pytest.mark.parametrize("change", [
    {"backend_policy_sha256": "2" * 64}, {"memory_bytes": 128}, {"output_directory": "new-out"},
    {"network": "allowed"}, {"scanner": "different"},
])
def test_approval_is_bound_to_plan(review, broker, change):
    approval = issue(review, broker)
    with pytest.raises(ValidationError, match="different scanner plan"):
        broker.redeem(replace(review, plan=replace(review.plan, **change)), approval)
    assert broker.redeem(review, approval) == review.fingerprint()


def test_untrusted_approval_inputs_are_rejected(review, broker, tmp_path, monkeypatch):
    with pytest.raises(ValidationError, match="confirmation"):
        issue(review, broker, confirmed_fingerprint="wrong")
    with pytest.raises(ValidationError, match="lifetime"):
        issue(review, broker, ttl=301)
    with pytest.raises(ValidationError, match="256-bit"):
        scanner_approval._signature(b"short", issue(review, broker))
    with pytest.raises(ValidationError, match="required"):
        broker.redeem(review, None)
    approval = issue(review, broker)
    with pytest.raises(ValidationError, match="signature"):
        broker.redeem(review, replace(approval, signature="0" * 64))
    other = ScannerReviewBroker(tmp_path / "other.sqlite", owner_key=KEY)
    with pytest.raises(ValidationError, match="different scanner plan"):
        other.redeem(review, approval)
    monkeypatch.setattr(scanner_approval.time, "time", lambda: approval.expires_at)
    with pytest.raises(ValidationError, match="expired"):
        broker.redeem(review, approval)


def test_concurrent_and_post_restart_redemption(review, broker):
    approval = issue(review, broker)
    barrier = Barrier(2)

    def attempt():
        barrier.wait(timeout=5)
        try:
            return broker.redeem(review, approval)
        except ValidationError as error:
            return str(error)

    with ThreadPoolExecutor(max_workers=2) as workers:
        pending = [workers.submit(attempt) for _ in range(2)]
        assert sorted(job.result() for job in pending) == sorted([
            review.fingerprint(), "Owner approval was already used",
        ])
    restarted = ScannerReviewBroker(broker._ledger, owner_key=KEY)
    with pytest.raises(ValidationError, match="already used"):
        restarted.redeem(review, approval)


def test_sqlite_abort_rolls_back_redemption(review, broker):
    approval = issue(review, broker)
    with closing(sqlite3.connect(broker._ledger)) as db:
        db.execute(
            "CREATE TRIGGER injected_failure AFTER INSERT ON redeemed_approval "
            "BEGIN SELECT RAISE(ROLLBACK, 'injected failure'); END"
        )
        with pytest.raises(ValidationError, match="durably consumed"):
            broker.redeem(review, approval)
        assert db.execute("SELECT count(*) FROM redeemed_approval").fetchone() == (0,)
        db.execute("DROP TRIGGER injected_failure")
    assert broker.redeem(review, approval) == review.fingerprint()


def test_ledger_replacement_and_disappearance_fail_closed(review, broker):
    approval = issue(review, broker)
    original = broker._ledger.with_suffix(".original")
    broker._ledger.rename(original)
    with pytest.raises(ValidationError, match="durably consumed"):
        broker.redeem(review, approval)
    ScannerReviewBroker(broker._ledger, owner_key=KEY)
    with pytest.raises(ValidationError, match="ledger identity changed"):
        broker.redeem(review, approval)
    original.replace(broker._ledger)
    assert broker.redeem(review, approval) == review.fingerprint()


def test_ledger_rejects_remote_and_linked_paths(tmp_path):
    with pytest.raises(ValidationError, match="local path"):
        ScannerReviewBroker("//remote.invalid/ledger", owner_key=KEY)
    root = tmp_path / "private"
    root.mkdir()
    alias = tmp_path / "alias"
    if os.name == "nt":
        from _winapi import CreateJunction

        CreateJunction(str(root), str(alias))
    else:
        alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(ValidationError, match="link or reparse"):
        ScannerReviewBroker(alias / "approval.sqlite", owner_key=KEY)
    assert not list(root.iterdir())


@pytest.mark.parametrize("suffix", ["", "-journal", "-wal", "-shm"])
def test_ledger_rejects_hardlinked_database_or_sidecar(tmp_path, suffix):
    ledger = tmp_path / "approval.sqlite"
    canary = tmp_path / "canary"
    canary.write_bytes(b"private")
    os.link(canary, tmp_path / (ledger.name + suffix))
    with pytest.raises(ValidationError, match="unlinked regular files"):
        ScannerReviewBroker(ledger, owner_key=KEY)
    assert canary.read_bytes() == b"private"


def test_capture_rejects_hardlink(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"private")
    project = tmp_path / "project"
    project.mkdir()
    os.link(target, project / "linked")
    with pytest.raises(ValidationError, match="single link"):
        capture_scanner_tree(project)


def test_capture_rejects_entry_replaced_before_open(tmp_path, monkeypatch):
    from contextlib import contextmanager

    artifact = tmp_path / "file"
    artifact.write_bytes(b"before")
    opened = scanner_objects.open_pinned_file

    @contextmanager
    def change(path):
        artifact.write_bytes(b"changed length")
        with opened(path) as stream:
            yield stream

    monkeypatch.setattr(scanner_objects, "open_pinned_file", change)
    with pytest.raises(ValidationError, match="changed before capture"):
        capture_scanner_tree(tmp_path)


def test_mcp_has_no_approval_operation(tmp_path):
    from ai_threat_lab.agent_protocol import perform
    from ai_threat_lab.agent_service import OPERATIONS

    assert "approve_scanner" not in OPERATIONS
    assert perform(tmp_path, "approve_scanner", {})["error"]["code"] == "invalid_request"


def test_owner_demo_decline_cancel_expiry_and_plan_swap(review, broker, monkeypatch):
    from ai_threat_lab import scanner_owner_review

    monkeypatch.setattr(scanner_owner_review.time, "monotonic", lambda: 10)
    prompt = scanner_owner_review.OwnerReviewPrompt.prepare(review)
    assert prompt.plan == review.plan
    assert prompt.fingerprint == review.fingerprint()
    for decision in (False, None, "yes"):
        assert not prompt.record_demo_confirmation(review, decision)
    changed = replace(review, plan=replace(review.plan, output_directory="different"))
    assert not prompt.record_demo_confirmation(changed, True)
    intent = prompt.record_demo_confirmation(review, True)
    assert intent is True
    with pytest.raises(ValidationError, match="approval is required"):
        broker.redeem(review, intent)
    monkeypatch.setattr(scanner_owner_review.time, "monotonic", lambda: 400)
    assert not prompt.record_demo_confirmation(review, True)


def test_runtime_inventory_binds_platform_and_plan(review):
    from ai_threat_lab.bandit_runtime_review import review_runtime_inventory, runtime_inventory

    options = {"platform": "linux", "architecture": "x86_64", "python_version": "3.12"}
    inventory = runtime_inventory(review, **options)
    pin = digest(inventory)
    result = review_runtime_inventory(review, pinned_digest=pin, **options)
    assert result["runtime_resolution"] == "unverified"
    assert result["startup_artifacts"] == ()
    with pytest.raises(ValidationError, match="expected platform"):
        runtime_inventory(review, **(options | {"platform": "win32"}))
    for change in ({"architecture": "arm64"}, {"python_version": "3.13"}):
        with pytest.raises(ValidationError, match="pinned inventory"):
            review_runtime_inventory(review, pinned_digest=pin, **(options | change))
    changed = replace(review, plan=replace(review.plan, network="allowed"))
    with pytest.raises(ValidationError, match="pinned inventory"):
        review_runtime_inventory(changed, pinned_digest=pin, **options)


def test_runtime_inventory_reports_pth_without_executing_it(review):
    from ai_threat_lab.bandit_runtime_review import review_runtime_inventory, runtime_inventory

    path = Path(review.runtime.tree.root) / "startup.pth"
    path.write_bytes(b"import synthetic_never_execute")
    runtime = replace(
        review.runtime, tree=capture_scanner_tree(path.parent),
        python_libraries=(*review.runtime.python_libraries, path.name),
    )
    changed = replace(
        review, runtime=runtime,
        plan=replace(review.plan, dependencies_sha256=digest(runtime.manifest())),
    )
    options = {"platform": "linux", "architecture": "x86_64", "python_version": "3.12"}
    pin = digest(runtime_inventory(changed, **options))
    result = review_runtime_inventory(changed, pinned_digest=pin, **options)
    assert result["startup_artifacts"] == ("startup.pth",)


@pytest.mark.parametrize("name", ["bandit", "other"])
def test_wheel_metadata_is_read_only_after_digest_check(monkeypatch, name):
    from io import BytesIO
    from zipfile import ZipFile

    from ai_threat_lab import bandit_runtime_review

    archive = BytesIO()
    with ZipFile(archive, "w") as wheel:
        wheel.writestr(
            "bandit-1.7.8.dist-info/METADATA",
            f"Name: {name}\nVersion: 1.7.8\nRequires-Dist: stevedore\n",
        )
    raw = archive.getvalue()
    with pytest.raises(ValidationError, match="pinned PyPI"):
        bandit_runtime_review.inspect_bandit_wheel(raw)
    from hashlib import sha256

    monkeypatch.setattr(bandit_runtime_review, "BANDIT_WHEEL_SHA256", sha256(raw).hexdigest())
    if name == "bandit":
        assert bandit_runtime_review.inspect_bandit_wheel(raw)["declared_dependencies"] == (
            "stevedore",
        )
    else:
        with pytest.raises(ValidationError, match="distribution identity"):
            bandit_runtime_review.inspect_bandit_wheel(raw)
