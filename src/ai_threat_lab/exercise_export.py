"""Approved, inert local rehearsal assets. No transport or media generation."""

import hashlib
import html
import json
from datetime import datetime, timezone
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path

from .models import ValidationError
from .training_lab import ALLOWED, NOTICE, validate_approval

INTRO = "LOCAL TRAINING SIMULATION. No real information should be entered or requested."


def claim_directory(path):
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise FileExistsError("Output directory already exists; choose a new path")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir(mode=0o700)  # Exclusive claim also rejects a racing directory/symlink.
    return path


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def export_exercise(plan, approval, output, *, now=None):
    current = now if now is not None else datetime.now(timezone.utc)
    validate_approval(plan, approval, current)
    if plan.channel not in ALLOWED:
        raise ValidationError("Unsupported local training channel")
    preview = {"subject": plan.content.subject, "body": plan.content.body}
    if len(json_bytes(preview)) > 64 * 1024:
        raise ValidationError("Local training preview exceeds 64 KiB")
    metadata = {
        "schema_version": 1,
        "mode": "local_rehearsal_assets",
        "channel": plan.channel,
        "plan_digest": plan.digest,
        "approval_notice": "Caller-supplied exact-preview approval, not authenticated identity.",
        "expires_at": plan.scope.expires_at.isoformat(),
        "preview": preview,
        "allowed_actions": sorted(str(a) for a in ALLOWED[plan.channel]),
        "notice": NOTICE,
        "media_notice": "Media references are not opened, downloaded, embedded or generated.",
    }
    page = (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" '
        'content="default-src &#39;none&#39;; base-uri &#39;none&#39;; '
        'form-action &#39;none&#39;">'
        "<title>Local training rehearsal</title><body><h1>Local training rehearsal</h1>"
        f"<p>{html.escape(INTRO)}</p><h2>{html.escape(preview['subject'])}</h2>"
        f"<pre>{html.escape(preview['body'])}</pre>"
        f"<p>{html.escape(NOTICE)}</p></body></html>"
    ).encode("utf-8")
    artifacts = {
        "exercise.json": json_bytes(metadata),
        "preview.html": page,
        "INSTRUCTIONS.txt": (
            INTRO + "\n\nReview exercise.json and preview.html locally.\n"
            "This pack is an inert export, not a dispatch job or executable script.\n"
            "Use training-start / training-run with the original plan and approval for "
            "structured selections. Their scope and expiry are checked again.\n"
            "Do not send the preview or use it to collect real information.\n"
            "Exported files cannot enforce expiry or revocation after copying.\n" + NOTICE + "\n"
        ).encode("utf-8"),
    }
    if plan.channel == "email":
        message = EmailMessage(policy=SMTP)
        message["From"] = "Local Training <exercise@example.invalid>"
        message["To"] = "Local Preview <participant@example.invalid>"
        message["Subject"] = "[LOCAL TRAINING] Inert email preview"
        message["X-AI-Threat-Lab-Mode"] = "local-rehearsal-only"
        message.set_content(INTRO + "\n\n" + preview["subject"] + "\n\n" + preview["body"])
        artifacts["preview.eml"] = message.as_bytes()
    elif plan.channel == "voice":
        artifacts["voice-script.json"] = json_bytes(
            {
                "mode": "text_script_only",
                "opening": preview["body"],
                "identity": "Fictional training coordinator; no real person's voice or identity.",
                "verification_practice": "Use a trusted directory for independent callback.",
                "stop_on": ["participant stop", "real information offered", "scope expiry"],
                "raw_replies": "Not collected; use structured training actions.",
            }
        )
    else:
        artifacts["video-storyboard.json"] = json_bytes(
            {
                "mode": "text_storyboard_only",
                "scenes": [
                    {"caption": "SIMULATION", "text": preview["subject"]},
                    {"caption": "FICTIONAL TRAINING REQUEST", "text": preview["body"]},
                    {"caption": "VERIFY INDEPENDENTLY", "text": "Pause and use a trusted channel."},
                ],
                "media": "No likeness, cloned voice, image, audio or video generated.",
            }
        )
    directory = claim_directory(output)
    # All asset bytes are prepared before claiming the directory. Manifest is written last.
    # A failed write can leave an incomplete pack; there is no resumable dispatch behavior.
    index = {}
    for name, raw in artifacts.items():
        with (directory / name).open("xb") as stream:
            stream.write(raw)
        index[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    manifest = {
        "schema_version": 1,
        "mode": "local_rehearsal_assets",
        "plan_digest": plan.digest,
        "files": index,
        "notice": "Local consistency index, not a signature, dispatch or authenticity proof.",
    }
    with (directory / "manifest.json").open("xb") as stream:
        stream.write(json_bytes(manifest))
    return {
        "output_directory": str(directory.resolve()),
        "channel": plan.channel,
        "files": sorted([*artifacts, "manifest.json"]),
        "notice": NOTICE,
    }
