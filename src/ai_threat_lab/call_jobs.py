"""Durable one-attempt fictional call creation, exact status and explicit remote stop."""

import base64
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

from .call_training import HOST, NOTICE, STATES, TERMINAL, phone, preview, sha, sid, validate_call
from .dispatch_journal import delivery_key
from .models import ValidationError
from .providers import ProviderError


def credential(config):
    token = os.environ.get("TWILIO_AUTH_TOKEN", "")
    if not re.fullmatch(r"[a-fA-F0-9]{32}", token):
        raise ProviderError("Configure the provider account token outside source control")
    encoded = base64.b64encode(f"{config.account_sid}:{token}".encode("ascii")).decode("ascii")
    return {"Authorization": "Basic " + encoded}


def write_new(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def submit(
    plan,
    approval,
    config,
    journal,
    expected_preview,
    *,
    allowed_host,
    output_dir,
    client,
    clock=None,
):
    clock = clock or (lambda: datetime.now(timezone.utc))
    prepared = preview(plan, approval, config, now=clock())
    if allowed_host != HOST or expected_preview != prepared["preview_sha256"]:
        raise ValidationError("Confirm the exact fictional-call preview and provider host")
    headers = credential(config)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    destination = Path(output_dir)
    destination.mkdir(exist_ok=False)
    recipient = plan.recipients[0]
    attempt = journal.claim(plan.digest, recipient, config.digest)
    receipt = {
        "schema_version": 1,
        "mode": "call_submission",
        "plan_digest": plan.digest,
        "configuration_sha256": config.digest,
        "preview_sha256": expected_preview,
        "attempt_id": attempt,
        "recipient_sha256": sha(recipient.encode()),
        "status": "pending",
        "notice": NOTICE,
    }
    sent, outcome = False, "unknown"
    try:
        write_new(destination / "attempt.json", receipt)
        preview(plan, approval, config, now=clock())
        if journal.status(plan.digest)["cancelled"]:
            raise ValidationError("Call cancelled before submission")
        sent = True
        response = client.request(
            prepared["endpoint"],
            method="POST",
            headers=headers,
            body=urlencode(prepared["request"]).encode("ascii"),
        )
        if response.status != 201:
            raise ProviderError("Provider did not confirm call creation")
        receipt.update(validate_call(response.document(), config, receipt["recipient_sha256"]))
        outcome = "accepted"
    except (ProviderError, ValidationError, OSError):
        outcome = "unknown" if sent else "rejected"
    journal.outcome(attempt, outcome)
    receipt["status"] = outcome
    receipt["notice"] += (
        " Accepted means provider creation, not human delivery. Pending/unknown attempts "
        "must not be submitted again. Without a confirmed call ID, reconcile in the provider "
        "console; this tool will not guess a call or enumerate other recipients."
    )
    write_new(destination / "result.json", receipt)
    return receipt


def bound_call(plan, config, journal, receipt):
    if plan.channel != "voice" or plan.scenario_id != "voice_training" or len(plan.recipients) != 1:
        raise ValidationError("Call status requires the original single-recipient voice plan")
    recipient = phone(plan.recipients[0])
    expected = delivery_key(plan.digest, recipient)
    state = journal.status(plan.digest)
    rows = [row for row in state["attempts"] if row["key"] == expected]
    required = {
        "schema_version",
        "mode",
        "plan_digest",
        "configuration_sha256",
        "preview_sha256",
        "attempt_id",
        "recipient_sha256",
        "status",
        "notice",
        "call_sid",
        "provider_status",
        "provider_duration_seconds",
    }
    if (
        len(rows) != 1
        or rows[0]["status"] != "accepted"
        or rows[0]["configuration_sha256"] != config.digest
        or rows[0]["recipient_sha256"] != sha(recipient.encode())
        or not isinstance(receipt, dict)
        or set(receipt) != required
        or type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != 1
        or receipt["mode"] != "call_submission"
        or receipt["status"] != "accepted"
        or receipt["plan_digest"] != plan.digest
        or receipt["attempt_id"] != expected
        or receipt["configuration_sha256"] != config.digest
        or receipt["recipient_sha256"] != sha(recipient.encode())
    ):
        raise ValidationError("Call receipt, original plan and journal do not match")
    if (
        not isinstance(receipt["preview_sha256"], str)
        or not re.fullmatch(r"[a-f0-9]{64}", receipt["preview_sha256"])
        or not isinstance(receipt["provider_status"], str)
        or receipt["provider_status"] not in STATES
        or (
            receipt["provider_duration_seconds"] is not None
            and (
                type(receipt["provider_duration_seconds"]) is not int
                or not 0 <= receipt["provider_duration_seconds"] <= 9999999
            )
        )
        or not isinstance(receipt["notice"], str)
        or len(receipt["notice"]) > 4096
    ):
        raise ValidationError("Call receipt metadata is invalid")
    return state, sid(receipt["call_sid"], "CA"), sha(recipient.encode())


def status(plan, config, journal, receipt, *, network, allowed_host, client):
    if network is not True or allowed_host != HOST:
        raise ValidationError("Call status requires explicit network and exact provider host")
    state, call_sid, recipient_hash = bound_call(plan, config, journal, receipt)
    response = client.request(config.endpoint(call_sid), headers=credential(config))
    if response.status != 200:
        raise ProviderError("Call status unavailable; no automatic retry")
    result = validate_call(response.document(), config, recipient_hash, expected_sid=call_sid)
    return {
        "schema_version": 1,
        "mode": "call_status",
        "plan_digest": plan.digest,
        "configuration_sha256": config.digest,
        "local_cancelled": state["cancelled"],
        **result,
        "notice": NOTICE,
    }


def stop(plan, config, journal, receipt, *, network, allowed_host, output_dir, client):
    if network is not True or allowed_host != HOST:
        raise ValidationError("Remote call stop requires explicit network and exact provider host")
    _, call_sid, recipient_hash = bound_call(plan, config, journal, receipt)
    destination = Path(output_dir)
    destination.mkdir(exist_ok=False)
    journal.cancel(plan.digest)  # Permanent local stop, even if the remote request fails.
    result = {
        "schema_version": 1,
        "mode": "call_stop",
        "plan_digest": plan.digest,
        "configuration_sha256": config.digest,
        "call_sid": call_sid,
        "local_cancelled": True,
        "status": "pending",
        "notice": NOTICE,
    }
    write_new(destination / "attempt.json", result)
    try:
        current = status(
            plan, config, journal, receipt, network=True, allowed_host=HOST, client=client
        )
        result["provider_status"] = current["provider_status"]
        if current["provider_status"] in TERMINAL:
            result["status"] = "already_terminal"
        else:
            chosen = "completed" if current["provider_status"] == "in-progress" else "canceled"
            headers = credential(config)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            response = client.request(
                config.endpoint(call_sid),
                method="POST",
                headers=headers,
                body=urlencode({"Status": chosen}).encode("ascii"),
            )
            if response.status != 200:
                raise ProviderError("Remote stop was not confirmed")
            stopped = validate_call(
                response.document(), config, recipient_hash, expected_sid=call_sid
            )
            result.update(stopped)
            result["status"] = (
                "provider_terminal" if stopped["provider_status"] in TERMINAL else "stop_unknown"
            )
    except (ProviderError, ValidationError, OSError):
        result["status"] = "stop_unknown"
    result["notice"] += (
        " Local cancellation alone cannot stop a remote call. Only a reported terminal state "
        "is recorded as provider confirmation; otherwise inspect the exact call in the provider "
        "console. An explicitly repeated stop is allowed; call creation is never repeated."
    )
    write_new(destination / "result.json", result)
    return result
