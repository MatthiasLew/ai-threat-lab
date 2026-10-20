"""Durable single avatar submission and explicit read-only job status."""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from .avatar_training import (
    ASSET,
    MAX_VIDEO,
    NOTICE,
    asset_url,
    encoded,
    preview,
    sha,
    validate_job,
    video_metadata,
)
from .dispatch_journal import delivery_key
from .models import ValidationError
from .providers import ProviderError
from .training_lab import validate_approval


def credential():
    key = os.environ.get("AI_THREAT_AVATAR_KEY", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,256}", key):
        raise ProviderError("Configure the avatar resource key outside source control")
    return key


def write_new(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def submit(plan, approval, config, journal, expected_preview, *, allowed_host,
           output_dir, client, clock=None):
    clock = clock or (lambda: datetime.now(timezone.utc))
    prepared = preview(plan, approval, config, now=clock())
    if prepared["preview_sha256"] != expected_preview or allowed_host != config.resource_host:
        raise ValidationError("Confirm the exact stock-avatar preview and provider host")
    key = credential()
    destination = Path(output_dir)
    destination.mkdir(exist_ok=False)
    attempt = journal.claim(plan.digest, ASSET, config.digest)
    receipt = {
        "schema_version": 1, "mode": "avatar_job_attempt", "plan_digest": plan.digest,
        "configuration_sha256": config.digest, "preview_sha256": expected_preview,
        "job_id": attempt, "host": config.resource_host, "status": "pending", "notice": NOTICE,
    }
    submitted, outcome = False, "unknown"
    try:
        write_new(destination / "attempt.json", receipt)
        validate_approval(plan, approval, clock())
        if journal.status(plan.digest)["cancelled"]:
            raise ValidationError("Avatar generation cancelled before submission")
        submitted = True
        response = client.request(
            prepared["endpoint"], method="PUT",
            headers={"Ocp-Apim-Subscription-Key": key, "Content-Type": "application/json"},
            body=encoded(prepared["request"]),
        )
        if response.status != 201:
            raise ProviderError("Avatar provider did not confirm job creation")
        receipt.update(validate_job(response.document(), attempt, config))
        outcome = "accepted"
    except (ProviderError, OSError, ValidationError):
        outcome = "unknown" if submitted else "rejected"
    journal.outcome(attempt, outcome)
    receipt["status"] = outcome
    receipt["notice"] += (
        " Accepted means job creation, not completed video. Pending/unknown attempts "
        "must not be resubmitted; inspect status using the same journal/configuration."
    )
    write_new(destination / "result.json", receipt)
    return receipt


def bound_attempt(journal, plan_digest, config):
    state = journal.status(plan_digest)
    expected = delivery_key(plan_digest, ASSET)
    matches = [item for item in state["attempts"] if item["key"] == expected]
    if (len(matches) != 1 or matches[0]["recipient_sha256"] != sha(ASSET.encode())
            or matches[0]["configuration_sha256"] != config.digest
            or matches[0]["status"] == "rejected"):
        raise ValidationError("No submitted avatar attempt matches this plan and configuration")
    return state, matches[0]


def fetch_job(journal, plan_digest, config, *, network, allowed_host, client):
    if network is not True or allowed_host != config.resource_host:
        raise ValidationError("Avatar status requires explicit network and exact provider host")
    state, attempt = bound_attempt(journal, plan_digest, config)
    key = credential()
    response = client.request(config.endpoint(plan_digest),
                              headers={"Ocp-Apim-Subscription-Key": key})
    base = {
        "schema_version": 1, "mode": "avatar_job_status", "plan_digest": plan_digest,
        "configuration_sha256": config.digest, "job_id": attempt["key"],
        "local_submission_status": attempt["status"], "local_cancelled": state["cancelled"],
        "notice": NOTICE + " Local cancellation cannot recall a submitted job. "
                  "A missing job does not authorize a repeated submission.",
    }
    if response.status == 404:
        return {**base, "provider_status": "not_found"}, None
    if response.status != 200:
        raise ProviderError("Avatar status request failed; no automatic retry")
    document = response.document()
    base.update(validate_job(document, attempt["key"], config))
    if base["provider_status"] == "Succeeded":
        _, host = asset_url(document)
        base["asset_host"] = host
    return base, document


def status(journal, plan_digest, config, *, network, allowed_host, client):
    receipt, _ = fetch_job(journal, plan_digest, config, network=network,
                           allowed_host=allowed_host, client=client)
    return receipt


def download(journal, plan_digest, config, *, network, allowed_host, allowed_asset_host,
             output_dir, client, asset_client):
    if (network is not True or allowed_host != config.resource_host
            or not isinstance(allowed_asset_host, str)
            or not re.fullmatch(r"[a-z0-9]{3,24}\.blob\.core\.windows\.net", allowed_asset_host)):
        raise ValidationError("Confirm the exact provider and reported asset hosts")
    _, attempt = bound_attempt(journal, plan_digest, config)
    credential()  # Local preflight before claiming output; fetch revalidates before dispatch.
    destination = Path(output_dir)
    destination.mkdir(exist_ok=False)
    receipt = {
        "schema_version": 1, "mode": "avatar_download", "plan_digest": plan_digest,
        "configuration_sha256": config.digest, "job_id": attempt["key"],
        "status": "pending", "notice": NOTICE,
    }
    write_new(destination / "attempt.json", receipt)
    try:
        current, document = fetch_job(
            journal, plan_digest, config, network=network, allowed_host=allowed_host, client=client)
        receipt["provider_status"] = current["provider_status"]
        if current["provider_status"] != "Succeeded":
            receipt["status"] = "not_ready"
        else:
            url, _ = asset_url(document, allowed_host=allowed_asset_host)
            # The storage request never receives the resource key or other headers.
            response = asset_client.request(url)
            if response.status != 200 or response.body_status != "complete":
                raise ProviderError("Avatar asset download did not complete")
            metadata = video_metadata(response.body)
            with (destination / "avatar.mp4").open("xb") as stream:
                stream.write(response.body)
                stream.flush()
                os.fsync(stream.fileno())
            receipt.update(status="downloaded", file="avatar.mp4", video=metadata,
                           provider_duration_ms=current["provider_duration_ms"])
    except (ProviderError, OSError, ValidationError):
        receipt["status"] = "failed"
        receipt["notice"] += (
            " No complete download is claimed. A file without a matching downloaded receipt "
            "must not be approved. Job submission is not repeated."
        )
    write_new(destination / "result.json", receipt)
    return receipt


def attach_asset(plan, approval, config, download_dir, *, now=None):
    from dataclasses import replace

    from .contracts import read_document
    from .report_io import read_regular

    preview(plan, approval, config, now=now)  # Exact original script/approval/configuration.
    root = Path(download_dir)
    receipt = read_document(root / "result.json")
    expected = {
        "schema_version", "mode", "plan_digest", "configuration_sha256", "job_id", "status",
        "notice", "provider_status", "file", "video", "provider_duration_ms",
    }
    if (not isinstance(receipt, dict) or set(receipt) != expected
            or type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1
            or receipt["mode"] != "avatar_download" or receipt["status"] != "downloaded"
            or receipt["provider_status"] != "Succeeded"
            or receipt["plan_digest"] != plan.digest
            or receipt["configuration_sha256"] != config.digest
            or receipt["job_id"] != delivery_key(plan.digest, ASSET)
            or receipt["file"] != "avatar.mp4"):
        raise ValidationError("Downloaded avatar receipt does not match the approved plan")
    path = root / "avatar.mp4"
    observed = video_metadata(read_regular(path, MAX_VIDEO))
    if receipt["video"] != observed:
        raise ValidationError("Downloaded avatar bytes no longer match the saved receipt")
    # This creates a new digest and intentionally does not carry approval forward.
    return replace(plan, content=replace(
        plan.content, media_reference=path.resolve().as_uri(), media_sha256=observed["sha256"]))
