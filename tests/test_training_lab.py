import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from ai_threat_lab.campaigns import CampaignScope, CampaignService, ContentApproval
from ai_threat_lab.models import ValidationError
from ai_threat_lab.training_lab import LabAction, TrainingLab, render_training_html

NOW = datetime(2026, 10, 18, 12, tzinfo=timezone.utc)


def approved(channel="voice", *, recipient_count=1):
    recipients = tuple(
        f"+1202555010{i}" if channel == "voice" else f"trainee{i}@example.invalid"
        for i in range(recipient_count)
    )
    scope = CampaignScope("training-fixture", "reviewer", recipients, NOW + timedelta(hours=1))
    plan = CampaignService().prepare(
        channel + "_training", scope, recipients, ("TRAINING-ALPHA is invented.",), now=NOW
    )
    return plan, ContentApproval(plan.digest, "reviewer", NOW)


def laboratory(tmp_path, *, clock=lambda: NOW):
    return TrainingLab(tmp_path / "lab.sqlite", clock=clock)


@pytest.mark.parametrize("channel", ["email", "voice", "video"])
def test_start_approved_text_preview_only(tmp_path, channel):
    plan, approval = approved(channel)
    lab = laboratory(tmp_path)
    state = lab.start(plan, approval, "trainee-01")
    assert state["mode"] == "local_text_rehearsal" and state["status"] == "running"
    assert state["preview"]["body"] == plan.content.body
    assert state["plan_digest"] == plan.digest and state["turns"] == 0
    assert state["selected_actions"] == [] and state["allowed_actions"]
    assert lab.get(state["session_id"]) == state
    assert plan.recipients[0] not in json.dumps(state)
    if os.name != "nt":
        assert lab.path.stat().st_mode & 0o777 == 0o600
    lab.path.unlink()


@pytest.mark.parametrize(
    "change",
    [
        {"plan_digest": "wrong"},
        {"approved_by": ""},
        {"approved_by": None},
        {"approved_at": NOW + timedelta(minutes=1)},
        {"approved_at": NOW + timedelta(hours=1)},
        {"approved_at": NOW.replace(tzinfo=None)},
    ],
)
def test_bad_approval_cannot_start(tmp_path, change):
    plan, approval = approved()
    lab = laboratory(tmp_path)
    with pytest.raises(ValidationError):
        lab.start(plan, replace(approval, **change), "trainee-01")
    assert lab.report()["counts"]["sessions"] == 0


def test_expired_or_changed_plan_rejected(tmp_path):
    plan, approval = approved()
    with pytest.raises(ValidationError):
        laboratory(tmp_path, clock=lambda: NOW + timedelta(hours=1)).start(plan, approval, "p1")
    lab = laboratory(tmp_path)
    with pytest.raises(ValidationError):
        lab.start(replace(plan, content=replace(plan.content, body="changed")), approval, "p1")
    with pytest.raises(ValidationError):
        lab.start(None, approval, "p1")
    with pytest.raises(ValidationError):
        lab.start(plan, None, "p1")


@pytest.mark.parametrize(
    "participant", ["", "name@example.com", "+12025550100", "a b", "p" * 65, None, "żółć"]
)
def test_alias_contract_rejects_contact_details(tmp_path, participant):
    with pytest.raises(ValidationError):
        laboratory(tmp_path).start(*approved(), participant)


@pytest.mark.parametrize("index", [-1, 1, True, "0"])
def test_recipient_index_must_select_scoped_recipient(tmp_path, index):
    with pytest.raises(ValidationError):
        laboratory(tmp_path).start(*approved(), "p1", recipient_index=index)


def test_one_session_per_plan_recipient_and_alias(tmp_path):
    plan, approval = approved(recipient_count=2)
    lab = laboratory(tmp_path)
    lab.start(plan, approval, "p1")
    with pytest.raises(ValidationError, match="already"):
        lab.start(plan, approval, "p2")
    with pytest.raises(ValidationError, match="already"):
        lab.start(plan, approval, "p1", recipient_index=1)
    assert lab.start(plan, approval, "p2", recipient_index=1)["participant_id"] == "p2"


@pytest.mark.parametrize(
    "channel,action,outcome,status",
    [
        ("voice", LabAction.REQUEST_VERIFICATION, "verification_selected", "completed"),
        (
            "voice",
            LabAction.SHARE_SYNTHETIC_IDENTIFIER,
            "synthetic_disclosure_selected",
            "completed",
        ),
        ("voice", LabAction.DECLINE, "declined_selected", "completed"),
        ("voice", LabAction.REAL_DATA_OFFERED, "real_data_boundary", "stopped"),
        ("voice", LabAction.STOP, "participant_stop", "stopped"),
        ("voice", LabAction.REPORT, "reporting_selected", "completed"),
        ("email", LabAction.FOLLOW_SYNTHETIC_LINK, "synthetic_interaction_selected", "completed"),
        ("email", LabAction.REPORT, "reporting_selected", "completed"),
        (
            "video",
            LabAction.ACKNOWLEDGE_SYNTHETIC_REQUEST,
            "synthetic_interaction_selected",
            "completed",
        ),
    ],
)
def test_actions_record_selected_outcome_without_live_claims(
    tmp_path, channel, action, outcome, status
):
    lab = laboratory(tmp_path)
    state = lab.start(*approved(channel), "p1")
    result = lab.record(state["session_id"], action, "step1")
    assert result["applied"] and not result["replayed"]
    state = result["session"]
    assert state["outcome"] == outcome and state["status"] == status
    assert state["turns"] == 1 and not state["allowed_actions"]
    assert len(state["selected_actions"]) == 1
    assert "identity_verified" not in json.dumps(state)
    assert not lab.record(state["session_id"], LabAction.STOP, "later")["applied"]


def test_voice_turn_bound_and_resume(tmp_path):
    lab = laboratory(tmp_path)
    state = lab.start(*approved(), "p1")
    identifier = state["session_id"]
    for step in range(2):
        state = laboratory(tmp_path).record(identifier, LabAction.UNKNOWN, f"step{step}")["session"]
        assert state["status"] == "running"
        assert "TRAINING-ALPHA" in state["next_prompt"]
    state = lab.record(identifier, LabAction.UNKNOWN, "step2")["session"]
    assert state["turns"] == 3 and state["outcome"] == "unclassified"
    assert not lab.record(identifier, LabAction.UNKNOWN, "step3")["applied"]


def test_voice_verification_after_unknown_is_not_proof(tmp_path):
    lab = laboratory(tmp_path)
    identifier = lab.start(*approved(), "p1")["session_id"]
    lab.record(identifier, LabAction.UNKNOWN, "step1")
    state = lab.record(identifier, LabAction.REQUEST_VERIFICATION, "step2")["session"]
    assert "not verification proof" in state["guidance"]
    assert "identity_verified" not in json.dumps(lab.report())


@pytest.mark.parametrize(
    "channel,action",
    [
        ("email", LabAction.UNKNOWN),
        ("voice", LabAction.OPEN_PREVIEW),
        ("video", LabAction.FOLLOW_SYNTHETIC_LINK),
        ("email", LabAction.SHARE_SYNTHETIC_IDENTIFIER),
    ],
)
def test_action_channel_scope(tmp_path, channel, action):
    lab = laboratory(tmp_path)
    identifier = lab.start(*approved(channel), "p1")["session_id"]
    with pytest.raises(ValidationError):
        lab.record(identifier, action, "step1")
    assert lab.get(identifier)["turns"] == 0


def test_no_raw_responses_and_idempotency_conflicts(tmp_path):
    lab = laboratory(tmp_path)
    identifier = lab.start(*approved("email"), "p1")["session_id"]
    with pytest.raises(ValidationError):
        lab.record(identifier, "SECRET_RAW_RESPONSE", "step1")
    with pytest.raises(ValidationError):
        lab.record(identifier, LabAction.REPORT, "address@example.com")
    first = lab.record(identifier, LabAction.OPEN_PREVIEW, "step1")
    second = laboratory(tmp_path).record(identifier, LabAction.OPEN_PREVIEW, "step1")
    assert second["replayed"] and not second["applied"]
    assert second["session"] == first["session"]
    with pytest.raises(ValidationError, match="different"):
        lab.record(identifier, LabAction.REPORT, "step1")
    with pytest.raises(ValidationError, match="already"):
        lab.record(identifier, LabAction.OPEN_PREVIEW, "step2")
    lab.record(identifier, LabAction.REPORT, "step2")
    assert (
        lab.record(identifier, LabAction.OPEN_PREVIEW, "step1")["session"]["status"] == "completed"
    )


def test_expiry_is_applied_before_actions_and_committed(tmp_path):
    lab = laboratory(tmp_path)
    identifier = lab.start(*approved(), "p1")["session_id"]
    later = laboratory(tmp_path, clock=lambda: NOW + timedelta(hours=1))
    result = later.record(identifier, LabAction.SHARE_SYNTHETIC_IDENTIFIER, "late")
    assert not result["applied"] and result["session"]["status"] == "expired"
    assert result["session"]["turns"] == 0
    assert lab.get(identifier)["status"] == "expired"
    assert later.report()["counts"]["selected_outcomes"] == {"scope_expired": 1}


def test_expiry_does_not_rewrite_finished_sessions(tmp_path):
    lab = laboratory(tmp_path)
    identifier = lab.start(*approved(), "p1")["session_id"]
    lab.record(identifier, LabAction.DECLINE, "step1")
    later = laboratory(tmp_path, clock=lambda: NOW + timedelta(hours=2))
    assert later.get(identifier)["status"] == "completed"
    assert later.report(session_id=identifier)["counts"]["sessions"] == 1


def test_concurrent_same_action_and_start_are_atomic(tmp_path):
    lab = laboratory(tmp_path)
    plan, approval = approved()

    def start(_):
        try:
            return lab.start(plan, approval, "p1")["session_id"]
        except ValidationError:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        starts = list(pool.map(start, range(8)))
    assert sum(s is not None for s in starts) == 1
    identifier = next(s for s in starts if s)
    with ThreadPoolExecutor(max_workers=8) as pool:
        records = list(
            pool.map(lambda _: lab.record(identifier, LabAction.UNKNOWN, "once"), range(8))
        )
    assert sum(r["applied"] for r in records) == 1
    assert lab.get(identifier)["turns"] == 1


def test_aggregate_report_private_preview_omitted_and_html_safe(tmp_path):
    lab = laboratory(tmp_path)
    plan, approval = approved("email")
    content = replace(plan.content, body="PRIVATE_APPROVED_FACT <script>not executed</script>")
    plan = replace(plan, content=content)
    approval = replace(approval, plan_digest=plan.digest)
    identifier = lab.start(plan, approval, "p1")["session_id"]
    lab.record(identifier, LabAction.REPORT, "step1")
    report = lab.report()
    assert "PRIVATE_APPROVED_FACT" not in json.dumps(report)
    assert report["counts"]["sessions"] == 1 and report["follow_up"]
    with sqlite3.connect(lab.path) as db:
        db.execute("UPDATE lab_sessions SET participant=?", ("<script>alert(1)</script>",))
    html = render_training_html(lab.report())
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "default-src 'none'" in html and "<link" not in html and "<iframe" not in html


def test_unknown_and_corrupt_sessions_fail_readably(tmp_path):
    lab = laboratory(tmp_path)
    with pytest.raises(ValidationError):
        lab.get("does-not-exist")
    with pytest.raises(ValidationError):
        lab.get("../../outside")
    identifier = lab.start(*approved(), "p1")["session_id"]
    with sqlite3.connect(lab.path) as db:
        db.execute("UPDATE lab_sessions SET status='invalid'")
    with pytest.raises(ValidationError):
        lab.report()
    with sqlite3.connect(lab.path) as db:
        db.execute("UPDATE lab_sessions SET status='running', preview='invalid-json'")
    with pytest.raises(ValidationError):
        lab.get(identifier)
    for preview in ("[]", '{"subject":1,"body":"x"}', '{"subject":"x"}'):
        with sqlite3.connect(lab.path) as db:
            db.execute("UPDATE lab_sessions SET preview=?", (preview,))
        with pytest.raises(ValidationError):
            lab.get(identifier)


def test_oversized_preview_and_naive_clock_rejected(tmp_path):
    plan, approval = approved()
    plan = replace(plan, content=replace(plan.content, body="x" * 65537))
    approval = replace(approval, plan_digest=plan.digest)
    with pytest.raises(ValidationError, match="64 KiB"):
        laboratory(tmp_path).start(plan, approval, "p1")
    with pytest.raises(ValidationError):
        laboratory(tmp_path, clock=lambda: NOW.replace(tzinfo=None)).report()


def test_db_session_cap(tmp_path):
    lab = laboratory(tmp_path)
    plan, approval = approved()
    lab.start(plan, approval, "p1")
    with sqlite3.connect(lab.path) as db:
        for index in range(999):
            db.execute(
                "INSERT INTO lab_sessions SELECT ?,plan_digest,?,?,scenario,channel,created,"
                "expires,preview,status,outcome,turns FROM lab_sessions LIMIT 1",
                (f"id{index}", f"participant{index}", f"recipient{index}"),
            )
    with pytest.raises(ValidationError, match="1000"):
        lab.start(plan, approval, "p2")


def test_db_symlink_rejected(tmp_path):
    path = tmp_path / "real"
    path.touch()
    link = tmp_path / "linked"
    try:
        link.symlink_to(path)
    except OSError:
        pytest.skip("Symlinks unavailable")
    with pytest.raises(ValidationError):
        TrainingLab(link)


def test_corrupt_running_voice_history(tmp_path):
    lab = laboratory(tmp_path)
    identifier = lab.start(*approved(), "p1")["session_id"]
    lab.record(identifier, LabAction.UNKNOWN, "step1")
    with sqlite3.connect(lab.path) as db:
        db.execute("UPDATE lab_actions SET action='open_preview'")
    with pytest.raises(ValidationError, match="history"):
        lab.get(identifier)


def test_plan_cancellation_is_persistent_and_blocks_future_participants(tmp_path):
    lab = laboratory(tmp_path)
    plan, approval = approved(recipient_count=2)
    identifier = lab.start(plan, approval, "p1")["session_id"]
    result = lab.cancel(plan.digest)
    assert result["cancelled_sessions"] == 1 and not result["already_revoked"]
    assert laboratory(tmp_path).get(identifier)["outcome"] == "operator_cancelled"
    assert not lab.record(identifier, LabAction.SHARE_SYNTHETIC_IDENTIFIER, "after-cancel")[
        "applied"
    ]
    with pytest.raises(ValidationError, match="cancelled"):
        laboratory(tmp_path).start(plan, approval, "p2", recipient_index=1)
    assert lab.cancel(plan.digest)["already_revoked"]
    assert lab.cancel(plan.digest)["cancelled_sessions"] == 0


def test_cancellation_does_not_rewrite_finished_or_expired_results(tmp_path):
    lab = laboratory(tmp_path)
    plan, approval = approved()
    identifier = lab.start(plan, approval, "p1")["session_id"]
    lab.record(identifier, LabAction.DECLINE, "step1")
    assert lab.cancel(plan.digest)["cancelled_sessions"] == 0
    assert lab.get(identifier)["outcome"] == "declined_selected"


@pytest.mark.parametrize("digest", ["", "bad", "a" * 63, "A" * 64, None])
def test_cancellation_digest_validation(tmp_path, digest):
    with pytest.raises(ValidationError):
        laboratory(tmp_path).cancel(digest)
