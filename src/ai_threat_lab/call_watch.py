"""Bounded foreground observation of one known call with best-effort terminal stop."""

import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from .call_jobs import bound_call, status, stop, write_new
from .call_training import HOST, NOTICE, TERMINAL
from .campaigns import _utc
from .models import ValidationError
from .providers import ProviderError


def watch(
    plan,
    config,
    journal,
    receipt,
    *,
    network,
    allowed_host,
    output_dir,
    client,
    max_wait_seconds=90,
    clock=None,
    monotonic=None,
    sleep=None,
):
    if network is not True or allowed_host != HOST:
        raise ValidationError("Call watch requires explicit network and exact provider host")
    if type(max_wait_seconds) is not int or not 1 <= max_wait_seconds <= 120:
        raise ValidationError("Watch between 1 and 120 seconds")
    _, call_sid, _ = bound_call(plan, config, journal, receipt)
    clock = clock or (lambda: datetime.now(timezone.utc))
    monotonic, sleep = monotonic or time.monotonic, sleep or time.sleep
    destination = Path(output_dir)
    destination.mkdir(exist_ok=False)
    started = monotonic()
    result = {
        "schema_version": 1,
        "mode": "call_watch",
        "plan_digest": plan.digest,
        "configuration_sha256": config.digest,
        "call_sid": call_sid,
        "status": "pending",
        "max_wait_seconds": max_wait_seconds,
        "observed_states": [],
        "notice": NOTICE,
    }
    write_new(destination / "attempt.json", result)
    reason = "poll_limit"
    try:
        for _ in range(25):  # Independent bound even if a clock/sleep implementation misbehaves.
            current = clock()
            _utc(current, "watch time")
            if current >= plan.scope.expires_at:
                reason = "scope_expired"
                break
            elapsed = monotonic() - started
            if elapsed >= max_wait_seconds:
                reason = "watch_timeout"
                break
            if journal.status(plan.digest)["cancelled"]:
                reason = "local_cancelled"
                break
            observed = status(
                plan, config, journal, receipt, network=True, allowed_host=HOST, client=client
            )
            result["observed_states"].append(observed["provider_status"])
            if observed["provider_status"] in TERMINAL:
                result["status"] = "provider_terminal"
                reason = "terminal_observed"
                break
            refreshed = clock()
            _utc(refreshed, "watch time")
            remaining = min(
                max_wait_seconds - (monotonic() - started),
                (plan.scope.expires_at - refreshed).total_seconds(),
            )
            if remaining > 0:
                sleep(min(5, remaining))
    except KeyboardInterrupt:
        reason = "interrupted"
    except (ProviderError, ValidationError, OSError, sqlite3.Error):
        reason = "status_error"
    if result["status"] != "provider_terminal":
        try:
            stopped = stop(
                plan,
                config,
                journal,
                receipt,
                network=True,
                allowed_host=HOST,
                output_dir=destination / "stop",
                client=client,
            )
            result["stop"] = stopped
            result["status"] = (
                "provider_terminal"
                if stopped["status"] in ("provider_terminal", "already_terminal")
                else "stop_unknown"
            )
        except (ProviderError, ValidationError, OSError, sqlite3.Error):
            result["status"] = "stop_unknown"
    result["reason"] = reason
    result["notice"] += (
        " Foreground monitor only. Timeout, scope expiry, interruption or status error triggers "
        "one bounded stop operation, never another call creation. Process termination, resolver "
        "delays or provider outages can prevent timely stopping; no hard remote deadline is "
        "guaranteed. A second interruption can abort the stop attempt."
    )
    write_new(destination / "result.json", result)
    return result
