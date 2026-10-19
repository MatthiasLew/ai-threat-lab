"""Normalized authentication patterns, independent window oracle and offline CLI contracts."""

import json
import random
import socket
from datetime import datetime, timedelta, timezone

import pytest
from test_cli_process import run_cli

from ai_threat_lab.auth_log_review import AuthPolicy, inspect_auth_log, review_auth_log_file
from ai_threat_lab.models import ValidationError
from ai_threat_lab.scan_bundle import read_bundle

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def event(
    second=0,
    *,
    account="PRIVATE_ACCOUNT",
    source="PRIVATE_SOURCE",
    outcome="failure",
    method="password",
):
    return {
        "timestamp": (BASE + timedelta(seconds=second)).isoformat(),
        "account": account,
        "source": source,
        "outcome": outcome,
        "method": method,
    }


def encoded(events):
    return "\n".join(json.dumps(e) for e in events)


def review(events, policy=None):
    result = inspect_auth_log(encoded(events), policy=policy)
    assert result.status == "partial"
    assert "PRIVATE" not in str(result) and "2026-01-01" not in str(result)
    assert all(f.status == "candidate" for f in result.findings)
    return result


def checks(events, policy=None):
    return {f.check for f in review(events, policy).findings}


def test_repeated_failures_and_later_success_are_separate_candidates():
    events = [event(i) for i in range(5)] + [event(5, outcome="success")]
    assert checks(events) == {"auth_repeated_failures", "auth_success_after_failures"}
    result = review(events)
    assert "Line 6" in next(
        f.evidence for f in result.findings if f.check == "auth_success_after_failures"
    )
    assert all("account group 1, source group 1" in f.evidence for f in result.findings)


@pytest.mark.parametrize("method", ["password", "public_key", "mfa", "unknown"])
def test_general_failure_pattern_does_not_assume_password_method(method):
    assert checks([event(i, method=method) for i in range(5)]) == {"auth_repeated_failures"}


def test_spray_pattern_requires_password_failures_on_distinct_accounts():
    assert checks([event(i, account="PRIVATE_ACCOUNT_" + str(i)) for i in range(5)]) == {
        "auth_password_spray_pattern"
    }


@pytest.mark.parametrize("method", ["public_key", "mfa", "unknown"])
def test_other_methods_do_not_imply_password_spraying(method):
    assert not checks(
        [event(i, account="PRIVATE_ACCOUNT_" + str(i), method=method) for i in range(5)]
    )


def test_distributed_failures_need_multiple_declared_source_identifiers():
    assert checks([event(i, source="PRIVATE_SOURCE_" + str(i % 3)) for i in range(5)]) == {
        "auth_distributed_failures"
    }


@pytest.mark.parametrize(
    "times,expected",
    [
        ([0, 60, 120, 180, 300], True),
        ([0, 60, 120, 180, 301], False),
        ([0, 301, 602, 903, 1204], False),
    ],
)
def test_inclusive_failure_window_boundary(times, expected):
    assert ("auth_repeated_failures" in checks([event(i) for i in times])) is expected


@pytest.mark.parametrize("second,expected", [(299, True), (300, True), (301, False), (4, False)])
def test_success_needs_strictly_earlier_failures_within_window(second, expected):
    assert (
        "auth_success_after_failures"
        in checks([event(i) for i in range(5)] + [event(second, outcome="success")])
    ) is expected


def test_success_clears_pair_history_and_does_not_reuse_failures():
    events = [event(i) for i in range(4)] + [
        event(4, outcome="success"),
        event(5),
        event(6, outcome="success"),
    ]
    assert not checks(events)


def test_exact_duplicates_do_not_inflate_thresholds_or_expose_values():
    result = review([event()] * 100)
    assert not result.findings
    assert any("99 exact normalized duplicate" in notice for notice in result.not_checked)


def test_timestamp_spelling_duplicates_are_collapsed_and_unsorted_records_reordered():
    first = event()
    second = {**first, "timestamp": first["timestamp"].replace("+00:00", "Z")}
    result = review([event(3), first, second])
    assert not result.findings
    assert any("Collapsed 1" in notice for notice in result.not_checked)
    assert any("reordered" in notice for notice in result.not_checked)


def test_input_order_preserved_in_line_references_after_time_sort():
    result = review([event(4), event(3), event(2), event(1), event(0)])
    assert "Line 1" in result.findings[0].evidence


def test_distinct_thresholds_are_required_in_addition_to_failure_count():
    assert not checks([event(i, account="PRIVATE_ACCOUNT_" + str(i % 2)) for i in range(5)])
    assert not checks([event(i, source="PRIVATE_SOURCE_" + str(i % 2)) for i in range(5)])
    assert checks(
        [event(i, account="PRIVATE_ACCOUNT_" + str(i % 2)) for i in range(5)],
        AuthPolicy(min_accounts=2),
    ) == {"auth_password_spray_pattern"}


def test_case_sensitive_identifiers_are_not_merged():
    events = [event(i, account="PRIVATE_ACCOUNT" if i < 3 else "private_account") for i in range(5)]
    assert not checks(events)


def test_window_pruning_removes_expired_distinct_accounts_and_sources():
    events = [event(0, account="PRIVATE_ACCOUNT_OLD")]
    events += [event(301 + i, account="PRIVATE_ACCOUNT_" + str(i % 4)) for i in range(5)]
    assert not checks(events)
    events = [event(0, source="PRIVATE_SOURCE_OLD")]
    events += [event(301 + i, source="PRIVATE_SOURCE_" + str(i % 2)) for i in range(5)]
    assert not checks(events)


@pytest.mark.parametrize(
    "changes",
    [
        {"timestamp": "2026-01-01T00:00:00"},
        {"timestamp": "2026-01-01T01:00:00+01:00"},
        {"timestamp": "2026-01-01T00:00:60Z"},
        {"timestamp": "2026-02-30T00:00:00Z"},
        {"timestamp": "0001-01-01T00:00:00Z"},
        {"timestamp": "2026-01-01T00:00:00.1234567Z"},
        {"timestamp": 1},
        {"timestamp": None},
        {"account": ""},
        {"account": "a b"},
        {"account": "x" * 129},
        {"account": "a\nb"},
        {"account": "é"},
        {"source": ""},
        {"source": []},
        {"source": "x" * 129},
        {"outcome": "unknown"},
        {"outcome": []},
        {"method": "PASSWORD"},
        {"method": []},
        {"method": {}},
        {"SECRET": "PRIVATE"},
    ],
)
def test_invalid_event_fields_reject_capture_without_values(changes):
    with pytest.raises(ValidationError) as caught:
        inspect_auth_log(encoded([event(), {**event(1), **changes}]))
    assert "line 2" in str(caught.value) and "PRIVATE" not in str(caught.value)


@pytest.mark.parametrize("key", ["timestamp", "account", "source", "outcome", "method"])
def test_missing_required_fields_are_rejected(key):
    item = event()
    del item[key]
    with pytest.raises(ValidationError):
        inspect_auth_log(encoded([item]))


@pytest.mark.parametrize(
    "source",
    [
        "[]",
        "null",
        "true",
        '"PRIVATE"',
        "{",
        '{"account":"a","account":"PRIVATE"}',
        '{"value":NaN}',
        "[" * 1200 + "]" * 1200,
    ],
)
def test_bad_json_structures_are_redacted(source):
    with pytest.raises(ValidationError) as caught:
        inspect_auth_log(source)
    assert "PRIVATE" not in str(caught.value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("window_seconds", 0),
        ("window_seconds", 3601),
        ("window_seconds", True),
        ("min_failures", 2),
        ("min_failures", 101),
        ("min_failures", 3.0),
        ("min_accounts", 1),
        ("min_accounts", 101),
        ("min_accounts", None),
        ("min_sources", 1),
        ("min_sources", 101),
        ("min_sources", "3"),
    ],
)
def test_policy_bounds(field, value):
    with pytest.raises(ValidationError):
        AuthPolicy(**{field: value})


def test_policy_endpoints_and_wrong_policy_type():
    AuthPolicy(1, 3, 2, 2)
    AuthPolicy(3600, 100, 100, 100)
    with pytest.raises(ValidationError):
        inspect_auth_log("", policy={})


@pytest.mark.parametrize(
    "source",
    [None, b"{}", "\ud800", "x" * (4 * 1024 * 1024 + 1)],
    ids=["none", "bytes", "surrogate", "bytes-limit"],
)
def test_source_bounds(source):
    with pytest.raises(ValidationError):
        inspect_auth_log(source)


def test_physical_line_and_line_length_limits_and_empty_capture():
    assert not inspect_auth_log("").findings
    assert not inspect_auth_log(" \r\n\n").findings
    assert not inspect_auth_log("\n" * 10000).findings
    with pytest.raises(ValidationError, match="10000-line"):
        inspect_auth_log("\n" * 10001)
    with pytest.raises(ValidationError, match="4096-character"):
        inspect_auth_log(" " * 4097)
    assert not inspect_auth_log(" " * 4096).findings


def test_finding_cap_is_explicit_and_existing_groups_still_update():
    events = [
        event(i, account="PRIVATE_ACCOUNT_" + str(group), source="PRIVATE_SOURCE_" + str(group))
        for group in range(205)
        for i in range(6)
    ]
    result = review(events)
    assert len(result.findings) == 200
    assert any("finding limit" in n for n in result.not_checked)
    assert all("failures=6;" in f.evidence for f in result.findings)


def oracle(events, policy):
    # Small independent O(n²) specification over chronological prefixes.
    answer = set()
    ordered = sorted(events, key=lambda e: e["timestamp"])
    last_success = {}
    for index, current in enumerate(ordered):
        time = datetime.fromisoformat(current["timestamp"])
        prefix = ordered[: index + 1]
        failures = [
            e
            for e in prefix
            if e["outcome"] == "failure"
            and 0
            <= (time - datetime.fromisoformat(e["timestamp"])).total_seconds()
            <= policy.window_seconds
        ]
        key = (current["account"], current["source"])
        pair = [
            e
            for e in failures
            if (e["account"], e["source"]) == key
            and datetime.fromisoformat(e["timestamp"])
            > last_success.get(key, BASE - timedelta(seconds=1))
        ]
        if current["outcome"] == "success":
            if (
                sum(datetime.fromisoformat(e["timestamp"]) < time for e in pair)
                >= policy.min_failures
            ):
                answer.add("auth_success_after_failures")
            last_success[key] = time
        else:
            if len(pair) >= policy.min_failures:
                answer.add("auth_repeated_failures")
            account = [e for e in failures if e["account"] == current["account"]]
            if (
                len(account) >= policy.min_failures
                and len({e["source"] for e in account}) >= policy.min_sources
            ):
                answer.add("auth_distributed_failures")
            password = [
                e
                for e in failures
                if e["source"] == current["source"] and e["method"] == "password"
            ]
            if (
                current["method"] == "password"
                and len(password) >= policy.min_failures
                and len({e["account"] for e in password}) >= policy.min_accounts
            ):
                answer.add("auth_password_spray_pattern")
    return answer


@pytest.mark.parametrize("seed", range(15))
def test_generated_timelines_match_independent_prefix_oracle(seed):
    rng = random.Random(seed)
    events = [
        event(
            i,
            account="PRIVATE_ACCOUNT_" + str(rng.randrange(3)),
            source="PRIVATE_SOURCE_" + str(rng.randrange(3)),
            outcome=rng.choice(["failure"] * 4 + ["success"]),
            method=rng.choice(["password", "unknown"]),
        )
        for i in range(100)
    ]
    policy = AuthPolicy(window_seconds=12, min_failures=3, min_accounts=2, min_sources=2)
    assert checks(events, policy) == oracle(events, policy)


def test_file_no_network_or_subprocess_bom_and_crlf(tmp_path, monkeypatch):
    import subprocess

    def forbidden(*a, **k):
        pytest.fail("offline review must not execute or connect")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    path = tmp_path / "events.auth.jsonl"
    path.write_bytes(
        b"\xef\xbb\xbf" + encoded([event(i) for i in range(5)]).replace("\n", "\r\n").encode()
    )
    assert review_auth_log_file(path).findings[0].check == "auth_repeated_failures"
    with pytest.raises(ValidationError):
        review_auth_log_file(tmp_path)
    path.write_bytes(b"\xff")
    with pytest.raises(ValidationError):
        review_auth_log_file(path)
    path.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
    with pytest.raises(ValidationError):
        review_auth_log_file(path)


def test_file_link_rejected(tmp_path):
    path = tmp_path / "events.auth.jsonl"
    path.write_text("")
    link = tmp_path / "link.auth.jsonl"
    try:
        link.symlink_to(path)
    except OSError:
        pytest.skip("No symlink support")
    with pytest.raises(ValidationError):
        review_auth_log_file(link)


def test_cli_custom_policy_html_no_overwrite_and_verified_scan_batch(tmp_path):
    path = tmp_path / "próbne.AUTH.JSONL"
    path.write_text(encoded([event(i) for i in range(5)]))
    result = run_cli("review-auth-log", path, "--fail-on-findings")
    assert result.returncode == 1, result.stderr
    assert json.loads(result.stdout)["target_kind"] == "authentication_log"
    result = run_cli("review-auth-log", path, "--min-failures", "6", "--fail-on-findings")
    assert result.returncode == 0, result.stderr
    report = tmp_path / "report.html"
    result = run_cli("review-auth-log", path, "--format", "html", "--output", report)
    assert result.returncode == 0 and "auth_repeated_failures" in report.read_text()
    result = run_cli("review-auth-log", path, "--output", report)
    assert result.returncode == 2
    result = run_cli("review-auth-log", path, "--window-seconds", "0")
    assert result.returncode == 2
    result = run_cli("audit", path)
    assert (
        result.returncode == 0 and json.loads(result.stdout)["target_kind"] == "authentication_log"
    )
    result = run_cli("scan", path, "--output-dir", tmp_path / "bundle", "--fail-on-findings")
    assert result.returncode == 1, result.stderr
    bundle = read_bundle(tmp_path / "bundle")
    assert "PRIVATE" not in json.dumps(bundle)
    result = run_cli("scan-batch", path, "--output-dir", tmp_path / "batch")
    assert result.returncode == 0, result.stderr
    assert run_cli("batch-check", tmp_path / "batch").returncode == 0


def test_project_walk_does_not_ingest_authentication_logs(tmp_path):
    from ai_threat_lab.local_inventory import local_inventory

    (tmp_path / "events.auth.jsonl").write_text(encoded([event(i) for i in range(5)]))
    assert not any(f.check.startswith("auth_") for f in local_inventory(str(tmp_path)).findings)


def test_exact_maximum_event_count_and_future_upper_date_are_bounded():
    result = review([event(i * 301) for i in range(10000)])
    assert not result.findings and any("10000 unique" in n for n in result.not_checked)
    assert not inspect_auth_log(
        encoded([{**event(), "timestamp": "9999-12-31T23:59:59Z"}])
    ).findings


def test_file_descriptor_closes_on_type_race_and_stream_setup_error(tmp_path, monkeypatch):
    import stat
    from types import SimpleNamespace

    import ai_threat_lab.auth_log_review as auth

    path = tmp_path / "logins.auth.jsonl"
    path.write_text("")
    close, fstat = auth.os.close, auth.os.fstat
    closed = []

    def closing(fd):
        closed.append(fd)
        close(fd)

    monkeypatch.setattr(auth.os, "close", closing)
    monkeypatch.setattr(auth.os, "fstat", lambda _: SimpleNamespace(st_mode=stat.S_IFIFO))
    with pytest.raises(ValidationError, match="regular"):
        review_auth_log_file(path)
    assert len(closed) == 1
    monkeypatch.setattr(auth.os, "fstat", fstat)

    def unavailable(*a, **k):
        raise OSError("stream unavailable")

    monkeypatch.setattr(auth.os, "fdopen", unavailable)
    with pytest.raises(OSError):
        review_auth_log_file(path)
    assert len(closed) == 2


def test_demo_missing_authentication_candidate_blocks_completion(tmp_path, monkeypatch):
    import ai_threat_lab.offline_cli as offline

    monkeypatch.setattr(offline, "synthetic_auth_log", lambda **kwargs: "")
    with pytest.raises(ValidationError, match="authentication acceptance"):
        offline.offline_demo(tmp_path / "demo")
    assert not (tmp_path / "demo" / "demo-result.json").exists()


def test_demo_false_candidate_on_negative_control_blocks_completion(tmp_path, monkeypatch):
    import ai_threat_lab.offline_cli as offline

    sample = offline.synthetic_auth_log
    monkeypatch.setattr(offline, "synthetic_auth_log", lambda **kwargs: sample())
    with pytest.raises(ValidationError, match="authentication negative control"):
        offline.offline_demo(tmp_path / "demo")
    assert not (tmp_path / "demo" / "demo-result.json").exists()


def test_engine_twenty_remains_readable_but_cannot_compare_new_semantics(tmp_path):
    from ai_threat_lab.scan_bundle import compare_bundles, publish_bundle, scope_digest
    from ai_threat_lab.scan_cli import assessor
    from ai_threat_lab.scan_engine import ScanOptions, ScanService

    path = tmp_path / "logins.auth.jsonl"
    path.write_text("")
    ScanService(assessor).run(ScanOptions(str(path)), tmp_path / "new")
    current = read_bundle(tmp_path / "new")
    metadata = dict(current["manifest"])
    metadata["scope"] = {**metadata["scope"], "engine": "read-only-pipeline-20"}
    metadata["scope_digest"] = scope_digest(metadata["scope"])
    artifacts = {name: (tmp_path / "new" / name).read_bytes() for name in metadata["files"]}
    publish_bundle(tmp_path / "old", artifacts, metadata)
    assert not compare_bundles(read_bundle(tmp_path / "old"), current)["comparable"]
