"""Independent inert OpenSSH journal records, boundaries and public offline workflows."""

import json
import os
import socket
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

import pytest
from test_cli_process import run_cli

from ai_threat_lab.assessment import AssessmentService, identify_target
from ai_threat_lab.auth_log_review import AuthPolicy, inspect_auth_log
from ai_threat_lab.models import ValidationError
from ai_threat_lab.scan_bundle import compare_bundles, read_bundle, scope_digest
from ai_threat_lab.scan_cli import assessor
from ai_threat_lab.scan_engine import ScanOptions, ScanService
from ai_threat_lab.ssh_journal_review import (
    inspect_ssh_journal,
    parse_ssh_journal,
    review_ssh_journal_file,
)

BASE = 1767225600000000  # 2026-01-01 UTC, in integer microseconds.
HOST = "0123456789abcdef0123456789abcdef"
PATTERNS = {
    "auth_repeated_failures",
    "auth_success_after_failures",
    "auth_distributed_failures",
    "auth_password_spray_pattern",
}


def row(
    second=0,
    *,
    state="Failed",
    method="password",
    account="private-user",
    address="192.0.2.19",
    invalid=False,
    tail="",
    **metadata,
):
    return {
        "_COMM": "sshd",
        "_MACHINE_ID": HOST,
        "__REALTIME_TIMESTAMP": str(BASE + second * 1000000),
        "MESSAGE": f"{state} {method} for {'invalid user ' if invalid else ''}{account} "
        f"from {address} port 22000 ssh2{tail}",
        **metadata,
    }


def encoded(rows):
    return "\n".join(json.dumps(item) for item in rows) + "\n"


def checks(result):
    return {f.check for f in result.findings}


def test_independent_four_pattern_corpus_preserves_original_lines_and_redacts_values():
    rows = [{"_COMM": "other", "SYSLOG_IDENTIFIER": "sshd", "MESSAGE": "PRIVATE-other"}]
    rows += [row(i) for i in range(5)]
    rows += [row(5, state="Accepted", method="publickey", tail=": ED25519 SHA256:PRIVATE-key")]
    rows += [row(10 + i, account=f"private-spray-{i}", address="192.0.2.20") for i in range(5)]
    rows += [
        row(20 + i, account="private-distributed", address=f"2001:db8::{1 + i % 3}")
        for i in range(5)
    ]
    result = inspect_ssh_journal(encoded(rows))
    assert checks(result) == PATTERNS and result.status == "partial"
    success = next(f for f in result.findings if f.check == "auth_success_after_failures")
    assert "Line 7;" in success.evidence
    text = json.dumps(asdict(result))
    for value in ["private-user", "PRIVATE-key", "PRIVATE-other", HOST, "192.0.2.", "2001:db8:"]:
        assert value not in text
    assert "other/missing process rows=1" in text


@pytest.mark.parametrize(
    "method,expected",
    [
        ("password", "password"),
        ("publickey", "public_key"),
        ("keyboard-interactive/pam", "unknown"),
        ("gssapi-with-mic", "unknown"),
        ("none", "unknown"),
    ],
)
def test_method_mapping_does_not_infer_mfa_and_any_accepted_method_resets_pair(method, expected):
    rows = [row(i) for i in range(4)] + [row(4, state="Accepted", method=method), row(5)]
    events, _ = parse_ssh_journal(encoded(rows))
    assert events[4].method == expected
    assert not checks(inspect_ssh_journal(encoded(rows)))


def test_partial_postponed_pam_and_disconnect_are_not_failures_or_successes():
    rows = [row(i) for i in range(4)]
    for state in ("Partial", "Postponed"):
        rows.append(row(4, state=state))
    rows += [
        row(4, MESSAGE="pam_unix(sshd:auth): authentication failure; PRIVATE"),
        row(4, MESSAGE="Disconnected from authenticating user PRIVATE port 22000"),
    ]
    events, notices = parse_ssh_journal(encoded(rows))
    assert len(events) == 4 and not inspect_ssh_journal(encoded(rows)).findings
    assert any("nonterminal/unrecognized SSH messages=4" in n for n in notices)


@pytest.mark.parametrize(
    "changes",
    [
        {"_COMM": ["sshd"]},
        {"_MACHINE_ID": None},
        {"_MACHINE_ID": "A" * 32},
        {"_MACHINE_ID": [HOST]},
        {"__REALTIME_TIMESTAMP": 123},
        {"__REALTIME_TIMESTAMP": "-1"},
        {"__REALTIME_TIMESTAMP": "1.5"},
        {"__REALTIME_TIMESTAMP": "1e9"},
        {"__REALTIME_TIMESTAMP": "253402300800000000"},
        {"__REALTIME_TIMESTAMP": [str(BASE)]},
        {"__REALTIME_TIMESTAMP": None},
        {"MESSAGE": None},
        {"MESSAGE": [65, 66]},
        {"MESSAGE": ["one", "two"]},
        {"MESSAGE": "Failed password for SECRET from 192.0.2.1 port 22 ssh2\nINJECT"},
        {"MESSAGE": "Accepted password for SECRET from example.invalid port 22 ssh2"},
        {"MESSAGE": "Accepted password for SECRET from 192.0.2.1 port 0 ssh2"},
        {"MESSAGE": "Failed password for SECRET from 192.0.2.1 port 65536 ssh2"},
        {"MESSAGE": "Accepted password for invalid user SECRET from 192.0.2.1 port 22 ssh2"},
        {"MESSAGE": "Failed password for SECRET from 192.0.2.999 port 22 ssh2"},
        {"MESSAGE": "Accepted password for SECRET from 192.0.2.1 port 22 ssh2 [preauth]"},
        {"MESSAGE": "Failed custom/unknown/method for SECRET from 192.0.2.1 port 22 ssh2"},
        {"MESSAGE": "Accepted password for SECRET from fe80::1%eth0 port 22 ssh2"},
    ],
)
def test_ambiguous_invalid_and_unsupported_selected_records_reject_whole_capture(changes):
    with pytest.raises(ValidationError) as caught:
        inspect_ssh_journal(encoded([row(), row(1, **changes)]))
    assert "line 2" in str(caught.value) and "SECRET" not in str(caught.value)


@pytest.mark.parametrize(
    "bad", ["null", "[]", "true", "{", '{"x":NaN}', '{"MESSAGE":"SECRET","MESSAGE":"SECRET"}']
)
def test_malformed_native_json_rejected_even_for_an_unselected_process(bad):
    with pytest.raises(ValidationError) as caught:
        inspect_ssh_journal(bad)
    assert "SECRET" not in str(caught.value)


def test_missing_or_other_process_cannot_be_selected_via_syslog_identifier():
    rows = [
        row(i, _COMM=comm, SYSLOG_IDENTIFIER="sshd")
        for i, comm in enumerate(["other", None, "SSHD", "sshd-auth"])
    ]
    result = inspect_ssh_journal(encoded(rows))
    assert not result.findings and "other/missing process rows=4" in str(result.not_checked)


def test_mixed_hosts_rejected_including_a_nonterminal_ssh_message():
    for message in [
        row(1, _MACHINE_ID="f" * 32),
        row(1, _MACHINE_ID="f" * 32, MESSAGE="Connection closed"),
    ]:
        with pytest.raises(ValidationError):
            inspect_ssh_journal(encoded([row(), message]))


def test_ipv6_spelling_canonicalized_but_mapped_ipv4_and_accounts_stay_distinct():
    rows = [
        row(i, address="2001:0db8:0000:0:0:0:0:1" if i % 2 else "2001:db8::1") for i in range(5)
    ]
    assert checks(inspect_ssh_journal(encoded(rows))) == {"auth_repeated_failures"}
    rows = [row(i, address="192.0.2.19" if i % 2 else "::ffff:192.0.2.19") for i in range(5)]
    assert not checks(inspect_ssh_journal(encoded(rows)))
    rows = [row(i, account="USER" if i % 2 else "user") for i in range(5)]
    assert not checks(inspect_ssh_journal(encoded(rows)))


def test_invalid_user_failures_suffix_metadata_and_both_process_names():
    events, _ = parse_ssh_journal(
        encoded(
            [
                row(invalid=True, tail=" [preauth]"),
                row(
                    1,
                    _COMM="sshd-session",
                    method="publickey",
                    tail=": ED25519 SHA256:PRIVATE [preauth]",
                ),
                row(2, method="keyboard-interactive/pam", tail=": private metadata"),
            ]
        )
    )
    assert len(events) == 3 and {e.outcome for e in events} == {"failure"}
    assert {e.method for e in events} == {"password", "public_key", "unknown"}


def test_time_precision_extremes_reorder_duplicates_and_port_not_in_group_identity():
    first = row(__REALTIME_TIMESTAMP="0")
    last = row(__REALTIME_TIMESTAMP="253402300799999999")
    events, _ = parse_ssh_journal(encoded([first, last]))
    assert events[0].time == datetime(1970, 1, 1, tzinfo=timezone.utc)
    assert events[1].time.year == 9999 and events[1].time.microsecond == 999999
    a = row(__REALTIME_TIMESTAMP=str(BASE + 1))
    b = row(__REALTIME_TIMESTAMP=str(BASE + 2))
    duplicate = {**a, "MESSAGE": a["MESSAGE"].replace("22000", "22001"), "__CURSOR": "PRIVATE"}
    events, notices = parse_ssh_journal(encoded([b, a, duplicate]))
    assert len(events) == 2 and [e.line for e in events] == [2, 1]
    assert events[1].time - events[0].time == timedelta(microseconds=1)
    assert any("Collapsed 1" in n for n in notices)
    assert any("reordered" in n for n in notices)


def test_username_and_key_metadata_length_bounds():
    assert len(parse_ssh_journal(encoded([row(account="a" * 99, tail=": " + "x" * 1024)]))[0]) == 1
    for value in [row(account="a" * 100), row(account="two users"), row(tail=": " + "x" * 1025)]:
        with pytest.raises(ValidationError):
            parse_ssh_journal(encoded([value]))


@pytest.mark.parametrize(
    "source",
    [None, b"", "\ud800", "x" * (4 * 1024 * 1024 + 1), "\n" * 10001, " " * 4097],
    ids=["none", "bytes", "surrogate", "byte-limit", "line-count", "line-length"],
)
def test_capture_resource_encoding_limits(source):
    with pytest.raises(ValidationError):
        inspect_ssh_journal(source)


def test_empty_and_exact_blank_line_boundary_and_policy_validation():
    assert not inspect_ssh_journal("").findings
    assert not inspect_ssh_journal("\n" * 10000).findings
    with pytest.raises(ValidationError):
        inspect_ssh_journal("", policy={})
    rows = [row(i * 301) for i in range(5)]
    assert not checks(inspect_ssh_journal(encoded(rows)))
    assert checks(inspect_ssh_journal(encoded(rows), policy=AuthPolicy(3600))) == {
        "auth_repeated_failures"
    }


def test_generated_mapping_matches_explicit_normalized_timeline_and_retains_blank_lines():
    # An independent expected normalized timeline controls time/method/outcome mapping.
    import random

    randomizer = random.Random(741)
    for _ in range(12):
        native, normalized = [], []
        for second in range(35):
            account = f"u{randomizer.randrange(3)}"
            address = f"192.0.2.{randomizer.randrange(3) + 1}"
            method = randomizer.choice(["password", "publickey", "keyboard-interactive/pam"])
            state = randomizer.choice(["Failed"] * 5 + ["Accepted"])
            native.append(row(second, state=state, method=method, account=account, address=address))
            normalized.append(
                {
                    "timestamp": f"2026-01-01T00:00:{second:02d}Z",
                    "account": account,
                    "source": address,
                    "outcome": "failure" if state == "Failed" else "success",
                    "method": {"password": "password", "publickey": "public_key"}.get(
                        method, "unknown"
                    ),
                }
            )
        actual = inspect_ssh_journal("\n" + encoded(native))
        expected = inspect_auth_log("\n" + encoded(normalized))
        assert actual.findings == expected.findings


def test_file_read_bom_crlf_rejection_and_no_execution_or_network(tmp_path, monkeypatch):
    import subprocess

    def forbidden(*a, **k):
        pytest.fail("Saved journal review must not execute or connect")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    path = tmp_path / "próbne #.ssh.jsonl"
    path.write_bytes(
        b"\xef\xbb\xbf" + encoded([row(i) for i in range(5)]).replace("\n", "\r\n").encode()
    )
    assert checks(review_ssh_journal_file(path)) == {"auth_repeated_failures"}
    for invalid in [tmp_path, tmp_path / "missing"]:
        with pytest.raises(ValidationError):
            review_ssh_journal_file(invalid)
    path.write_bytes(b"\xff")
    with pytest.raises(ValidationError):
        review_ssh_journal_file(path)
    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "pipe"
        os.mkfifo(fifo)
        with pytest.raises(ValidationError):
            review_ssh_journal_file(fifo)


def test_file_link_rejected(tmp_path):
    path, link = tmp_path / "source", tmp_path / "link"
    path.write_text("")
    try:
        link.symlink_to(path)
    except OSError:
        pytest.skip("No symlink support")
    with pytest.raises(ValidationError):
        review_ssh_journal_file(link)


def test_cli_thresholds_html_escaping_privacy_no_overwrite_and_scan_batch(tmp_path):
    path = tmp_path / "próbne.SSH.JSONL"
    path.write_text(encoded([row(i) for i in range(5)]))
    result = run_cli("review-ssh-journal", path, "--fail-on-findings")
    assert result.returncode == 1, result.stderr
    assert json.loads(result.stdout)["target_kind"] == "ssh_journal"
    assert "private-user" not in result.stdout and "192.0.2.19" not in result.stdout
    assert (
        run_cli("review-ssh-journal", path, "--min-failures", "6", "--fail-on-findings").returncode
        == 0
    )
    assert run_cli("review-ssh-journal", path, "--min-failures", "2").returncode == 2
    report = tmp_path / "report.html"
    assert (
        run_cli("review-ssh-journal", path, "--format", "html", "--output", report).returncode == 0
    )
    assert "auth_repeated_failures" in report.read_text()
    assert run_cli("review-ssh-journal", path, "--output", report).returncode == 2
    audit = run_cli("audit", path)
    assert audit.returncode == 0 and json.loads(audit.stdout)["target_kind"] == "ssh_journal"
    bundle = tmp_path / "bundle"
    scanned = run_cli("scan", path, "--output-dir", bundle, "--fail-on-findings")
    assert scanned.returncode == 1, scanned.stderr
    verified = read_bundle(bundle)
    assert verified["manifest"]["scope"]["engine"] == "read-only-pipeline-27"
    assert "private-user" not in json.dumps(verified)
    assert run_cli("scan-check", bundle).returncode == 0
    batch = tmp_path / "batch"
    batched = run_cli("scan-batch", path, "--output-dir", batch)
    assert batched.returncode == 0, batched.stderr
    assert run_cli("batch-check", batch).returncode == 0


def test_project_walks_do_not_ingest_and_standalone_does_not_require_suffix(tmp_path):
    path = tmp_path / "event.ssh.jsonl"
    path.write_text(encoded([row(i) for i in range(5)]))
    assert not AssessmentService().assess(str(tmp_path)).findings
    assert identify_target(str(path)) == "ssh_journal"
    raw = tmp_path / "raw.txt"
    raw.write_bytes(path.read_bytes())
    assert checks(review_ssh_journal_file(raw)) == {"auth_repeated_failures"}
    assert identify_target(str(raw)) == "program_file"


def test_engine_21_bundle_remains_readable_but_comparison_is_not_supported(tmp_path):
    path = tmp_path / "events.auth.jsonl"
    path.write_text("")
    service = ScanService(assessor)
    service.run(ScanOptions(str(path)), tmp_path / "scan")
    current = read_bundle(tmp_path / "scan")
    import copy

    old = copy.deepcopy(current)
    old["manifest"]["scope"]["engine"] = "read-only-pipeline-21"
    old["manifest"]["scope_digest"] = scope_digest(old["manifest"]["scope"])
    from ai_threat_lab.scan_bundle import validate_manifest

    validate_manifest(old["manifest"])
    assert not compare_bundles(old, current)["comparable"]


@pytest.mark.parametrize("negative", [False, True])
def test_demo_missing_candidate_or_false_negative_control_blocks_completion(
    tmp_path, monkeypatch, negative
):
    import ai_threat_lab.offline_cli as offline

    original = offline.synthetic_ssh_journal
    monkeypatch.setattr(
        offline, "synthetic_ssh_journal", lambda **kwargs: original(negative=not negative)
    )
    with pytest.raises(ValidationError, match="SSH journal acceptance"):
        offline.offline_demo(tmp_path / "demo")
    assert not (tmp_path / "demo" / "demo-result.json").exists()
