"""Close the finite local AI cost contract using inert providers and controlled clocks."""

import json
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from decimal import localcontext

import pytest
from test_ai_costs import Provider
from test_cli_process import run_cli
from test_inventory_integration_cli import sample

import ai_threat_lab.integration_cli as integration
from ai_threat_lab.ai_costs import AIConfig, BudgetedAI, CostLedger, money
from ai_threat_lab.cli import main
from ai_threat_lab.models import ValidationError
from ai_threat_lab.providers import ProviderError

pytest_plugins = ["test_ai_costs"]


def stored(ledger):
    with sqlite3.connect(ledger.path) as db:
        return db.execute("SELECT * FROM calls ORDER BY rowid").fetchall()


def test_overrun_response_never_reused_from_cache(config, evidence, tmp_path):
    class Excess:
        calls = 0

        def respond(self, *args):
            self.calls += 1
            return "Over limit", 100, 601

    ledger, provider = CostLedger(tmp_path / "costs.sqlite"), Excess()
    ai = BudgetedAI(config, ledger, provider, clock=lambda: 100)
    for _ in range(2):
        with pytest.raises(ProviderError, match="exceeded"):
            ai.explain(evidence)
    assert provider.calls == 2
    assert ledger.report()["days"][0]["calls"] == 2
    assert all(row[8] is None for row in stored(ledger))


def test_existing_output_refuses_before_dispatch_or_accounting(tmp_path, monkeypatch, capsys):
    from test_ai_costs import API

    configuration, document = sample(tmp_path)
    output, database = tmp_path / "output.json", tmp_path / "costs.sqlite"
    output.write_text("KEEP")
    api = API()
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-only")
    monkeypatch.setattr(integration, "PublicHTTPS", lambda *a, **k: api)
    args = [
        "ai-explain",
        str(document),
        "--ai-config",
        str(configuration),
        "--ledger",
        str(database),
        "--send-evidence",
        "--output",
        str(output),
    ]
    assert main(args) == 2
    assert api.calls == [] and not database.exists()
    assert output.read_text() == "KEEP"
    assert "synthetic-only" not in capsys.readouterr().err


def test_incompatible_existing_database_is_not_silently_augmented(tmp_path):
    path = tmp_path / "foreign.sqlite"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE unrelated (value TEXT)")
    original = path.read_bytes()
    with pytest.raises(ValidationError):
        CostLedger(path)
    assert path.read_bytes() == original


def test_money_precision_does_not_round_invalid_fraction_into_valid_price():
    with pytest.raises(ValidationError):
        money("0.100000000000000000000000000001")
    with pytest.raises(ValidationError):
        money("1e999999999")
    assert money("0.000000001") == 1
    with localcontext() as context:
        context.prec = 3
        assert money("123456.123456789") == 123456123456789
        conf = AIConfig("fixture", "0.123456789", "8.123456789")
        assert conf.charge(123456789, 999999999) == 8138698359627


def test_budget_clock_sampled_after_writer_lock_and_midnight(config, tmp_path):
    ledger = CostLedger(tmp_path / "costs.sqlite")
    entered, release, sampled = threading.Event(), threading.Event(), threading.Event()
    original_connect = ledger.connect
    clock = [86399]

    def connect(**kwargs):
        entered.set()
        return original_connect(**kwargs)

    ledger.connect = connect
    lock = sqlite3.connect(ledger.path)
    lock.execute("BEGIN IMMEDIATE")

    def now():
        sampled.set()
        return clock[0]

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(ledger.reserve, "boundary", config, 1, now)
            assert entered.wait(3)
            assert not sampled.is_set()
            clock[0] = 86400
            lock.commit()
            identifier, _ = future.result(timeout=5)
    finally:
        release.set()
        lock.close()
    assert sampled.is_set()
    assert ledger.report()["unconfirmed"] == [
        {"id": identifier, "day_utc": "1970-01-02", "reserved_nanodollars": 1}
    ]


def test_budgeted_ai_passes_live_clock_through_writer_lock(config, evidence, tmp_path):
    ledger, provider = CostLedger(tmp_path / "costs.sqlite"), Provider()
    original_connect = ledger.connect
    entered, observed = threading.Event(), threading.Event()
    now = [86399]

    def connect(**kwargs):
        entered.set()
        return original_connect(**kwargs)

    def clock():
        observed.set()
        return now[0]

    ledger.connect = connect
    lock = sqlite3.connect(ledger.path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                BudgetedAI(config, ledger, provider, clock=clock).explain, evidence
            )
            assert entered.wait(3)
            before_lock_release = observed.is_set()
            now[0] = 86400
            lock.commit()
            assert future.result(timeout=5)["status"] == "generated"
    finally:
        lock.close()
    assert not before_lock_release
    assert ledger.report()["days"][0]["day_utc"] == "1970-01-02"


def test_expired_cache_during_wait_cannot_be_reused(config, evidence, tmp_path):
    ledger, provider = CostLedger(tmp_path / "costs.sqlite"), Provider()
    BudgetedAI(config, ledger, provider, clock=lambda: 100).explain(evidence)
    entered, now = threading.Event(), [159]
    original_connect = ledger.connect

    def connect(**kwargs):
        entered.set()
        return original_connect(**kwargs)

    ledger.connect = connect
    lock = sqlite3.connect(ledger.path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                BudgetedAI(config, ledger, provider, clock=lambda: now[0]).explain, evidence
            )
            assert entered.wait(3)
            now[0] = 160
            lock.commit()
            assert future.result(timeout=5)["status"] == "generated"
    finally:
        lock.close()
    assert provider.calls == 2


def test_cleanup_expired_and_all_preserves_accounting_pending_and_hit_counters(config, tmp_path):
    ledger = CostLedger(tmp_path / "costs.sqlite")
    old, _ = ledger.reserve("old", config, 100, 100)
    ledger.complete(old, config, "PRIVATE expired", 10, 5, 100)
    fresh, _ = ledger.reserve("fresh", config, 100, 130)
    ledger.complete(fresh, config, "PRIVATE current", 10, 5, 130)
    assert ledger.reserve("fresh", config, 100, 131)[1] == "PRIVATE current"
    pending, _ = ledger.reserve("pending", config, 100, 140)
    before = ledger.report()
    result = ledger.prune_cache(clock=lambda: 160)
    assert result["cleared_responses"] == 1 and result["accounting_rows_deleted"] == 0
    assert ledger.prune_cache(clock=lambda: 160)["cleared_responses"] == 0
    report = ledger.report()
    assert report["unconfirmed"] == before["unconfirmed"]
    for key in ["calls", "charged_or_reserved_usd", "cache_hits", "unconfirmed_calls"]:
        assert report["days"][0][key] == before["days"][0][key]
    assert report["days"][0]["stored_cache_responses"] == 1
    result = ledger.prune_cache(all_entries=True, clock=lambda: 160)
    assert result["cleared_responses"] == 1
    assert all(row[8] is None for row in stored(ledger))
    assert ledger.report()["unconfirmed"][0]["id"] == pending
    assert "PRIVATE" not in json.dumps(result) + json.dumps(report)
    ledger.reconcile(pending, "0")
    assert not ledger.report()["unconfirmed"]


def test_cache_cleanup_fault_rolls_back_and_does_not_reset_costs(config, tmp_path):
    ledger = CostLedger(tmp_path / "costs.sqlite")
    identifier, _ = ledger.reserve("one", config, 100, 100)
    ledger.complete(identifier, config, "PRIVATE", 10, 5, 100)
    with sqlite3.connect(ledger.path) as db:
        db.execute(
            "CREATE TRIGGER fail BEFORE UPDATE OF response ON calls "
            "BEGIN SELECT RAISE(ABORT,'PRIVATE failure'); END"
        )
    before = stored(ledger)
    with pytest.raises(sqlite3.Error):
        ledger.prune_cache(all_entries=True, clock=lambda: 200)
    assert stored(ledger) == before


def test_concurrent_cleanup_cannot_double_clear_or_delete_pending(config, tmp_path):
    ledger = CostLedger(tmp_path / "costs.sqlite")
    for i in range(10):
        identifier, _ = ledger.reserve(str(i), config, 100, 100)
        ledger.complete(identifier, config, "Private cached", 1, 1, 100)
    ledger.reserve("pending", config, 100, 100)
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda _: ledger.prune_cache(clock=lambda: 200), range(6)))
    assert sum(r["cleared_responses"] for r in results) == 10
    assert len(stored(ledger)) == 11 and len(ledger.report()["unconfirmed"]) == 1


def test_completion_storage_failure_keeps_discoverable_pending_and_redacts(
    config, evidence, tmp_path
):
    ledger = CostLedger(tmp_path / "costs.sqlite")
    with sqlite3.connect(ledger.path) as db:
        db.execute(
            "CREATE TRIGGER fail BEFORE UPDATE OF state ON calls "
            "BEGIN SELECT RAISE(ABORT,'PRIVATE failure'); END"
        )
    provider = Provider()
    with pytest.raises(ProviderError, match="usage recording unconfirmed") as caught:
        BudgetedAI(config, ledger, provider, clock=lambda: 100).explain(evidence)
    report = ledger.report()
    assert report["unconfirmed"][0]["id"] in str(caught.value)
    assert "PRIVATE" not in str(caught.value) and provider.calls == 1
    with pytest.raises(ProviderError, match="pending"):
        BudgetedAI(config, ledger, provider, clock=lambda: 101).explain(evidence)
    assert provider.calls == 1


def test_legacy_revision_zero_is_read_unchanged_with_costs_and_pending_preserved(config, tmp_path):
    ledger = CostLedger(tmp_path / "costs.sqlite")
    identifier, _ = ledger.reserve("pending", config, 100, 100)
    with sqlite3.connect(ledger.path) as db:
        db.execute("PRAGMA user_version=0")
    original = ledger.path.read_bytes()
    for create in (False, True):
        reopened = CostLedger(ledger.path, create=create)
        assert reopened.report()["unconfirmed"][0]["id"] == identifier
        assert ledger.path.read_bytes() == original
    with pytest.raises(ProviderError, match="pending"):
        reopened.reserve("pending", config, 100, 100)


@pytest.mark.parametrize(
    "mutation",
    [
        "PRAGMA user_version=99",
        "ALTER TABLE calls ADD COLUMN secret TEXT",
        "UPDATE calls SET charge=-1",
        "UPDATE calls SET charge='PRIVATE'",
        "UPDATE calls SET state='PRIVATE'",
        "UPDATE calls SET cache_hits=-1",
        "UPDATE calls SET created=-1",
        "UPDATE calls SET expires=-1",
        "UPDATE calls SET day='2000-01-01'",
        "UPDATE calls SET id='PRIVATE'",
    ],
)
def test_invalid_schema_or_accounting_never_resets_history(config, tmp_path, mutation):
    ledger = CostLedger(tmp_path / "costs.sqlite")
    ledger.reserve("pending", config, 100, 100)
    with sqlite3.connect(ledger.path) as db:
        db.execute(mutation)
    original = ledger.path.read_bytes()
    with pytest.raises(ValidationError) as caught:
        CostLedger(ledger.path)
    assert "PRIVATE" not in str(caught.value)
    assert ledger.path.read_bytes() == original


def test_deleted_or_empty_operational_ledger_is_not_recreated(config, tmp_path):
    ledger = CostLedger(tmp_path / "costs.sqlite")
    ledger.reserve("one", config, 1, 100)
    ledger.path.unlink()
    for operation in (
        ledger.report,
        lambda: ledger.reserve("two", config, 1, 100),
        lambda: CostLedger(ledger.path, create=False),
    ):
        with pytest.raises(ValidationError):
            operation()
        assert not ledger.path.exists()
    ledger.path.touch()
    with pytest.raises(ValidationError):
        CostLedger(ledger.path, create=False)
    assert ledger.path.read_bytes() == b""


def test_special_file_oversize_schema_pk_and_uri_paths(config, tmp_path):
    with pytest.raises(ValidationError):
        CostLedger(tmp_path)
    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "pipe"
        os.mkfifo(fifo)
        with pytest.raises(ValidationError):
            CostLedger(fifo)
    big = tmp_path / "large.sqlite"
    with big.open("wb") as stream:
        stream.truncate(128 * 1024 * 1024 + 1)
    with pytest.raises(ValidationError):
        CostLedger(big)
    path = tmp_path / "próbne % #.sqlite"
    ledger = CostLedger(path)
    ledger.reserve("one", config, 1, 100)
    original = path.read_bytes()
    assert CostLedger(path, create=False).report()["days"][0]["calls"] == 1
    assert path.read_bytes() == original
    with pytest.raises(ValidationError):
        CostLedger(path, create=1)
    with pytest.raises(ValidationError):
        ledger.prune_cache(all_entries=1)


@pytest.mark.parametrize("value", [-1, True, float("nan"), float("inf"), "PRIVATE", 253370764800])
def test_invalid_clock_does_not_mutate_budget(config, tmp_path, value):
    ledger = CostLedger(tmp_path / "costs.sqlite")
    with pytest.raises(ValidationError):
        ledger.reserve("one", config, 1, lambda: value)
    assert ledger.report()["days"] == []


def test_empty_findings_skip_at_service_boundary_and_future_cache_is_not_used(
    config, evidence, tmp_path
):
    ledger, provider = CostLedger(tmp_path / "costs.sqlite"), Provider()
    ai = BudgetedAI(config, ledger, provider, clock=lambda: 100)
    result = ai.explain({"findings": [], "not_checked": ["Still partial"]})
    assert result["status"] == "skipped_no_findings" and result["not_checked"] == ["Still partial"]
    assert provider.calls == 0 and ledger.report()["days"] == []
    ai.explain(evidence)
    BudgetedAI(config, ledger, provider, clock=lambda: 99).explain(evidence)
    assert provider.calls == 2


@pytest.mark.parametrize(
    "document",
    [
        {"findings": [{}]},
        {"findings": [], "not_checked": "PRIVATE"},
        {"findings": [], "not_checked": [None]},
        {"findings": [], "target_kind": 123},
        {"findings": [], "not_checked": ["\ud800"]},
        {"findings": [{}] * 2001},
    ],
)
def test_malformed_or_unencodable_evidence_rejected_before_budget(document, tmp_path, config):
    ledger, provider = CostLedger(tmp_path / "costs.sqlite"), Provider()
    with pytest.raises(ValidationError):
        BudgetedAI(config, ledger, provider).explain(document)
    assert provider.calls == 0 and ledger.report()["days"] == []


@pytest.mark.parametrize(
    "change", [{"model": "x" * 129}, {"namespace": "private\nname"}, {"model": "\ud800"}]
)
def test_configuration_strings_are_bounded(config, change):
    with pytest.raises(ValidationError):
        replace(config, **change)


def test_report_exposes_recorded_usage_and_pending_separately(config, tmp_path):
    ledger = CostLedger(tmp_path / "costs.sqlite")
    completed, _ = ledger.reserve("complete", config, 1000000, 100)
    ledger.complete(completed, config, "Private", 100, 20, 100)
    pending, _ = ledger.reserve("pending", config, 1000000, 100)
    report = ledger.report()["days"][0]
    assert report["recorded_usage_or_reconciled_usd"] == "0.000360000"
    assert report["reserved_unconfirmed_usd"] == "0.001000000"
    ledger.reconcile(pending, "0.000001")
    assert ledger.report()["days"][0]["reserved_unconfirmed_usd"] == "0.000000000"
    assert ledger.report()["days"][0]["recorded_usage_or_reconciled_usd"] == "0.000361000"


def test_cli_prune_missing_files_no_overwrite_and_ledger_aliases(config, tmp_path):
    configuration, document = sample(tmp_path)
    path = tmp_path / "costs.sqlite"
    for command in ("api-costs", "api-cache-prune"):
        result = run_cli(command, "--ledger", path)
        assert result.returncode == 2 and not path.exists()
    ledger = CostLedger(path)
    identifier, _ = ledger.reserve("one", config, 1, 100)
    ledger.complete(identifier, config, "PRIVATE cached", 1, 1, 100)
    result = run_cli("api-cache-prune", "--ledger", path)
    assert result.returncode == 0 and json.loads(result.stdout)["cleared_responses"] == 1
    assert "PRIVATE" not in result.stdout
    output = tmp_path / "cleanup.json"
    assert run_cli("api-cache-prune", "--ledger", path, "--all", "--output", output).returncode == 0
    assert run_cli("api-cache-prune", "--ledger", path, "--output", output).returncode == 2
    other = tmp_path / "new.sqlite"
    for output in (other, tmp_path / "new.sqlite-journal", tmp_path / "new.sqlite-wal"):
        result = run_cli(
            "ai-explain",
            document,
            "--ai-config",
            configuration,
            "--ledger",
            other,
            "--dry-run",
            "--output",
            output,
        )
        assert result.returncode == 2 and not other.exists() and not output.exists()


def test_failed_ai_command_releases_output_claim_success_is_private(tmp_path, capsys):
    configuration, document = sample(tmp_path)
    output, path = tmp_path / "output.json", tmp_path / "costs.sqlite"
    args = [
        "ai-explain",
        str(document),
        "--ai-config",
        str(configuration),
        "--ledger",
        str(path),
        "--output",
        str(output),
    ]
    assert main(args) == 2
    assert not output.exists() and not path.exists()
    assert main(args + ["--dry-run"]) == 0
    assert json.loads(output.read_text())["status"] == "estimate_only"
    if os.name != "nt":
        assert output.stat().st_mode & 0o777 == 0o600
    assert main(args + ["--dry-run"]) == 2
    capsys.readouterr()


def test_output_created_between_cli_preflight_and_dispatch_never_spends_request(
    tmp_path, monkeypatch
):
    from test_ai_costs import API

    import ai_threat_lab.cli as cli

    configuration, document = sample(tmp_path)
    output, ledger = tmp_path / "output.json", tmp_path / "costs.sqlite"
    api = API()
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-only")
    monkeypatch.setattr(integration, "PublicHTTPS", lambda *a, **k: api)
    original = cli.run_command

    def another_process_won(args):
        with output.open("x") as stream:
            stream.write("KEEP OTHER RESULT")
        return original(args)

    monkeypatch.setattr(cli, "run_command", another_process_won)
    assert (
        cli.main(
            [
                "ai-explain",
                str(document),
                "--ai-config",
                str(configuration),
                "--ledger",
                str(ledger),
                "--send-evidence",
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert not api.calls and not ledger.exists()
    assert output.read_text() == "KEEP OTHER RESULT"


def test_different_requests_cannot_exceed_shared_daily_money_or_call_limit(config, tmp_path):
    ledger = CostLedger(tmp_path / "costs.sqlite")
    config = replace(config, daily_budget_usd="0.000000003", max_calls_per_day=10)

    def reserve(number):
        try:
            return ledger.reserve(str(number), config, 1, 100)[0]
        except ProviderError:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(reserve, range(12)))
    assert sum(item is not None for item in results) == 3
    assert ledger.report()["days"][0]["reserved_unconfirmed_usd"] == "0.000000003"


def test_completed_charge_stays_on_reservation_day_when_response_crosses_midnight(config, tmp_path):
    ledger = CostLedger(tmp_path / "costs.sqlite")
    identifier, _ = ledger.reserve("one", config, 1000, 86399)
    ledger.complete(identifier, config, "Private text", 1, 1, 86400)
    report = ledger.report()["days"]
    assert len(report) == 1 and report[0]["day_utc"] == "1970-01-01"
    assert report[0]["unconfirmed_calls"] == 0


def test_minimal_finding_deduplication_and_byte_limit_preserve_scope(config, evidence, tmp_path):
    from ai_threat_lab.ai_costs import compact_evidence

    evidence["findings"] *= 3
    prompt = compact_evidence(evidence, 12000)
    assert len(json.loads(prompt)["findings"]) == 1
    assert json.loads(prompt)["not_checked"] == evidence["not_checked"]
    maximum = len(prompt.encode("utf-8"))
    assert compact_evidence(evidence, maximum) == prompt
    with pytest.raises(ValidationError):
        compact_evidence(evidence, maximum - 1)
    with pytest.raises(ValidationError):
        compact_evidence(evidence, True)


def test_output_claim_removed_on_provider_failure_but_pending_cost_retained(tmp_path, monkeypatch):
    configuration, document = sample(tmp_path)
    ledger, output = tmp_path / "costs.sqlite", tmp_path / "output.json"

    class Broken:
        def request(self, *a, **k):
            raise TimeoutError("PRIVATE")

    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-only")
    monkeypatch.setattr(integration, "PublicHTTPS", lambda *a, **k: Broken())
    assert (
        main(
            [
                "ai-explain",
                str(document),
                "--ai-config",
                str(configuration),
                "--ledger",
                str(ledger),
                "--send-evidence",
                "--output",
                str(output),
            ]
        )
        == 3
    )
    assert not output.exists()
    assert len(CostLedger(ledger, create=False).report()["unconfirmed"]) == 1


@pytest.mark.parametrize("column,value", [("input_tokens", 1000000000), ("output_tokens", 601)])
def test_legacy_cached_overrun_is_not_reused(config, evidence, tmp_path, column, value):
    ledger, provider = CostLedger(tmp_path / "costs.sqlite"), Provider()
    ai = BudgetedAI(config, ledger, provider, clock=lambda: 100)
    ai.explain(evidence)
    # These are fixed test-owned column names, not parser or caller input.
    with sqlite3.connect(ledger.path) as db:
        db.execute(f"UPDATE calls SET {column}=?,response='Legacy overrun'", (value,))
        db.execute("PRAGMA user_version=0")
    assert ai.explain(evidence)["status"] == "generated"
    assert provider.calls == 2 and ledger.report()["days"][0]["cache_hits"] == 0


@pytest.mark.parametrize("now", [86399.9999, 86399.99999999999])
def test_subsecond_before_midnight_is_valid_and_charged_to_original_utc_day(config, tmp_path, now):
    ledger = CostLedger(tmp_path / "costs.sqlite")
    ledger.reserve("fractional", config, 1, now)
    report = ledger.report()["days"]
    assert len(report) == 1 and report[0]["day_utc"] == "1970-01-01"
