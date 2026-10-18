"""Approved, local text rehearsals. No networking, raw-response collection or media IO."""

import hashlib
import html
import json
import os
import re
import sqlite3
import uuid
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path

from .campaigns import CampaignPlan, ContentApproval, _utc, _validate_plan
from .models import ValidationError
from .voice_exercise import VoiceExerciseSession, VoiceSignal


class LabAction(StrEnum):
    OPEN_PREVIEW = "open_preview"
    FOLLOW_SYNTHETIC_LINK = "follow_synthetic_link"
    ACKNOWLEDGE_SYNTHETIC_REQUEST = "acknowledge_synthetic_request"
    REQUEST_VERIFICATION = "request_verification"
    REPORT = "report"
    SHARE_SYNTHETIC_IDENTIFIER = "share_synthetic_identifier"
    DECLINE = "decline"
    STOP = "stop"
    REAL_DATA_OFFERED = "real_data_offered"
    UNKNOWN = "unknown"


COMMON = frozenset(
    (
        LabAction.REQUEST_VERIFICATION,
        LabAction.REPORT,
        LabAction.DECLINE,
        LabAction.STOP,
        LabAction.REAL_DATA_OFFERED,
    )
)
ALLOWED = {
    "email": COMMON | {LabAction.OPEN_PREVIEW, LabAction.FOLLOW_SYNTHETIC_LINK},
    "voice": COMMON | {LabAction.SHARE_SYNTHETIC_IDENTIFIER, LabAction.UNKNOWN},
    "video": COMMON | {LabAction.OPEN_PREVIEW, LabAction.ACKNOWLEDGE_SYNTHETIC_REQUEST},
}
GUIDANCE = {
    "reporting_selected": "Practice the organization's approved incident-reporting procedure.",
    "verification_selected": "Practice callback using a previously trusted directory; "
    "selection is not verification proof.",
    "declined_selected": "Practice declining unusual requests and reporting the context.",
    "synthetic_disclosure_selected": "Rehearse verification before disclosing even seemingly minor "
    "internal identifiers.",
    "synthetic_interaction_selected": "Review unexpected links or realistic media through "
    "an independent trusted channel.",
    "unclassified": "Repeat a short guided exercise; no conclusion about real behavior "
    "can be drawn.",
    "participant_stop": "Honor the stop request; no negative personnel conclusion follows.",
    "real_data_boundary": "End the exercise and do not enter, collect or transmit "
    "real information.",
    "operator_cancelled": "The operator cancelled this local plan; "
    "no personnel conclusion follows.",
    "scope_expired": "Obtain a new approved scope before starting another exercise.",
    "in_progress": "Complete or explicitly stop this local rehearsal.",
}
NOTICE = (
    "Local text rehearsal using operator-selected actions, not observed email/call behavior. "
    "No email sent, link visited, call placed or media generated; raw replies are not collected. "
    "Results do not establish identity verification, real susceptibility or staff performance."
)


def opaque(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value):
        raise ValidationError(
            f"{label} must be an opaque 1..64 character ASCII token; no addresses"
        )
    return value


def validate_approval(plan: CampaignPlan, approval: ContentApproval, now: datetime):
    if not isinstance(plan, CampaignPlan) or not isinstance(approval, ContentApproval):
        raise ValidationError("Training needs a validated plan and exact approval")
    _validate_plan(plan, now)
    _utc(approval.approved_at, "approved_at")
    if (
        not isinstance(approval.approved_by, str)
        or not approval.approved_by.strip()
        or approval.plan_digest != plan.digest
        or approval.approved_at > now
        or approval.approved_at >= plan.scope.expires_at
    ):
        raise ValidationError("Approval does not match the preview or its valid time window")


class TrainingLab:
    def __init__(self, path: Path, *, clock=None):
        self.path = Path(path)
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        if self.path.is_symlink():
            raise ValidationError("Training database must not be a symlink")
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if self.path.is_symlink():
                raise ValidationError("Training database must not be a symlink") from None
        else:
            os.close(descriptor)
        with closing(self.connect()) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS lab_sessions (
                id TEXT PRIMARY KEY, plan_digest TEXT NOT NULL, participant TEXT NOT NULL,
                recipient_hash TEXT NOT NULL, scenario TEXT NOT NULL, channel TEXT NOT NULL,
                created TEXT NOT NULL, expires REAL NOT NULL, preview TEXT NOT NULL,
                status TEXT NOT NULL, outcome TEXT NOT NULL, turns INTEGER NOT NULL,
                UNIQUE(plan_digest, participant), UNIQUE(plan_digest, recipient_hash))""")
            db.execute("""CREATE TABLE IF NOT EXISTS lab_actions (
                session_id TEXT NOT NULL, request_id TEXT NOT NULL, action TEXT NOT NULL,
                selected_at TEXT NOT NULL, PRIMARY KEY(session_id,request_id))""")

            db.execute(
                "CREATE TABLE IF NOT EXISTS lab_revocations "
                "(plan_digest TEXT PRIMARY KEY, revoked_at TEXT NOT NULL)"
            )

    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        return db

    def now(self):
        current = self.clock()
        _utc(current, "now")
        return current.astimezone(timezone.utc)

    @staticmethod
    def expire(db, current):
        db.execute(
            "UPDATE lab_sessions SET status='expired',outcome='scope_expired' "
            "WHERE status='running' AND expires<=?",
            (current.timestamp(),),
        )

    @staticmethod
    def row(db, session_id):
        opaque(session_id, "session_id")
        result = db.execute("SELECT * FROM lab_sessions WHERE id=?", (session_id,)).fetchone()
        if result is None:
            raise ValidationError("Training session does not exist")
        if (
            result["channel"] not in ALLOWED
            or result["status"] not in ("running", "completed", "stopped", "expired")
            or result["outcome"] not in GUIDANCE
        ):
            raise ValidationError("Training session state is invalid")
        return result

    @staticmethod
    def snapshot(db, row):
        actions = db.execute(
            "SELECT action,request_id,selected_at FROM lab_actions WHERE session_id=? "
            "ORDER BY rowid",
            (row["id"],),
        ).fetchall()
        try:
            preview = json.loads(row["preview"])
            if not isinstance(preview, dict) or set(preview) != {"subject", "body"}:
                raise ValueError
            if not all(isinstance(v, str) for v in preview.values()):
                raise ValueError
        except (ValueError, TypeError):
            raise ValidationError("Training preview state is invalid") from None
        next_prompt = preview["body"]
        if row["channel"] == "voice" and row["status"] == "running" and actions:
            dialogue = VoiceExerciseSession("local-rehearsal")
            for action in actions:
                if action["action"] != LabAction.UNKNOWN:
                    raise ValidationError("Running voice session has invalid action history")
                next_prompt = dialogue.advance(VoiceSignal.UNKNOWN).text
        return {
            "schema_version": 1,
            "next_prompt": next_prompt,
            "session_id": row["id"],
            "plan_digest": row["plan_digest"],
            "participant_id": row["participant"],
            "scenario_id": row["scenario"],
            "channel": row["channel"],
            "mode": "local_text_rehearsal",
            "status": row["status"],
            "outcome": row["outcome"],
            "turns": row["turns"],
            "preview": preview,
            "expires_at": datetime.fromtimestamp(row["expires"], timezone.utc).isoformat(),
            "selected_actions": [dict(a) for a in actions],
            "allowed_actions": sorted(str(a) for a in ALLOWED[row["channel"]])
            if row["status"] == "running"
            else [],
            "guidance": GUIDANCE[row["outcome"]],
            "notice": NOTICE,
        }

    def start(self, plan, approval, participant_id, *, recipient_index=0):
        current = self.now()
        validate_approval(plan, approval, current)
        opaque(participant_id, "participant_id")
        if type(recipient_index) is not int or not 0 <= recipient_index < len(plan.recipients):
            raise ValidationError("recipient_index must select a recipient from the approved plan")
        # Preview text only. Never open a media reference, phone number, URL or recipient address.
        preview = json.dumps({"subject": plan.content.subject, "body": plan.content.body})
        if len(preview.encode()) > 64 * 1024:
            raise ValidationError("Local training preview exceeds 64 KiB")
        recipient_hash = hashlib.sha256(plan.recipients[recipient_index].encode()).hexdigest()
        identifier = uuid.uuid4().hex
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute(
                "SELECT 1 FROM lab_revocations WHERE plan_digest=?", (plan.digest,)
            ).fetchone():
                raise ValidationError(
                    "This local training plan was cancelled; a new approved plan is required"
                )
            if db.execute("SELECT COUNT(*) FROM lab_sessions").fetchone()[0] >= 1000:
                raise ValidationError("Training database session limit reached (1000)")
            try:
                db.execute(
                    "INSERT INTO lab_sessions VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        identifier,
                        plan.digest,
                        participant_id,
                        recipient_hash,
                        plan.scenario_id,
                        plan.channel,
                        current.isoformat(),
                        plan.scope.expires_at.timestamp(),
                        preview,
                        "running",
                        "in_progress",
                        0,
                    ),
                )
            except sqlite3.IntegrityError:
                raise ValidationError(
                    "This plan/participant or plan/recipient already has a session"
                ) from None
            return self.snapshot(db, self.row(db, identifier))

    def get(self, session_id):
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            self.expire(db, self.now())
            return self.snapshot(db, self.row(db, session_id))

    def record(self, session_id, action: LabAction, request_id):
        if not isinstance(action, LabAction):
            raise ValidationError("Choose a defined LabAction; raw responses are never accepted")
        opaque(request_id, "action_id")
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            current = self.now()
            self.expire(db, current)
            row = self.row(db, session_id)
            previous = db.execute(
                "SELECT action FROM lab_actions WHERE session_id=? AND request_id=?",
                (session_id, request_id),
            ).fetchone()
            if previous is not None:
                if previous[0] != action:
                    raise ValidationError("Action ID was already used for a different selection")
                return {"replayed": True, "applied": False, "session": self.snapshot(db, row)}
            if row["status"] != "running":
                # Commit expiry even when no user action is applied.
                result = self.snapshot(db, row)
                return {"replayed": False, "applied": False, "session": result}
            if action not in ALLOWED[row["channel"]]:
                raise ValidationError("Action does not match the session channel")
            prior_actions = [
                a[0]
                for a in db.execute(
                    "SELECT action FROM lab_actions WHERE session_id=? ORDER BY rowid",
                    (session_id,),
                )
            ]
            if action in prior_actions and action != LabAction.UNKNOWN:
                raise ValidationError(
                    "That selection is already recorded; reuse its action ID for replay"
                )
            status, outcome = self.transition(row["channel"], action, prior_actions)
            db.execute(
                "INSERT INTO lab_actions VALUES(?,?,?,?)",
                (session_id, request_id, str(action), current.isoformat()),
            )
            db.execute(
                "UPDATE lab_sessions SET status=?,outcome=?,turns=turns+1 WHERE id=?",
                (status, outcome, session_id),
            )
            return {
                "replayed": False,
                "applied": True,
                "session": self.snapshot(db, self.row(db, session_id)),
            }

    @staticmethod
    def transition(channel, action, history):
        outcomes = {
            LabAction.REPORT: ("completed", "reporting_selected"),
            LabAction.REQUEST_VERIFICATION: ("completed", "verification_selected"),
            LabAction.DECLINE: ("completed", "declined_selected"),
            LabAction.STOP: ("stopped", "participant_stop"),
            LabAction.REAL_DATA_OFFERED: ("stopped", "real_data_boundary"),
            LabAction.SHARE_SYNTHETIC_IDENTIFIER: ("completed", "synthetic_disclosure_selected"),
        }
        if channel == "voice":
            mapping = {
                LabAction.UNKNOWN: VoiceSignal.UNKNOWN,
                LabAction.REQUEST_VERIFICATION: VoiceSignal.VERIFICATION_REQUESTED,
                LabAction.DECLINE: VoiceSignal.DECLINED,
                LabAction.STOP: VoiceSignal.STOP,
                LabAction.REAL_DATA_OFFERED: VoiceSignal.REAL_DATA_OFFERED,
                LabAction.SHARE_SYNTHETIC_IDENTIFIER: VoiceSignal.SYNTHETIC_INFO_SHARED,
            }
            if action in mapping:
                dialogue = VoiceExerciseSession("local-rehearsal")
                for previous in history:
                    dialogue.advance(mapping[LabAction(previous)])
                turn = dialogue.advance(mapping[action])
                if action == LabAction.UNKNOWN:
                    return (
                        ("completed", "unclassified")
                        if turn.finished
                        else ("running", "in_progress")
                    )
        if action in outcomes:
            return outcomes[action]
        if action in (LabAction.FOLLOW_SYNTHETIC_LINK, LabAction.ACKNOWLEDGE_SYNTHETIC_REQUEST):
            return "completed", "synthetic_interaction_selected"
        return "running", "in_progress"

    def cancel(self, plan_digest):
        if not isinstance(plan_digest, str) or not re.fullmatch(r"[a-f0-9]{64}", plan_digest):
            raise ValidationError("plan_digest must be a lowercase SHA-256 digest")
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            current = self.now()
            self.expire(db, current)
            previous = db.execute(
                "SELECT revoked_at FROM lab_revocations WHERE plan_digest=?", (plan_digest,)
            ).fetchone()
            db.execute(
                "INSERT OR IGNORE INTO lab_revocations VALUES(?,?)",
                (plan_digest, current.isoformat()),
            )
            changed = db.execute(
                "UPDATE lab_sessions SET status='stopped',outcome='operator_cancelled' "
                "WHERE plan_digest=? AND status='running'",
                (plan_digest,),
            ).rowcount
            return {
                "mode": "local_text_rehearsal",
                "plan_digest": plan_digest,
                "cancelled_sessions": changed,
                "already_revoked": previous is not None,
                "notice": "Local rehearsal plan revoked; no external provider was contacted.",
            }

    def report(self, *, session_id=None):
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            self.expire(db, self.now())
            rows = (
                [self.row(db, session_id)]
                if session_id is not None
                else db.execute("SELECT * FROM lab_sessions ORDER BY created,id").fetchall()
            )
            sessions = []
            for row in rows:
                # Validate persisted enums even in the aggregate path.
                checked = self.row(db, row["id"])
                sessions.append(
                    {
                        k: checked[k]
                        for k in (
                            "id",
                            "participant",
                            "plan_digest",
                            "scenario",
                            "channel",
                            "status",
                            "outcome",
                            "turns",
                        )
                    }
                )
            statuses, outcomes = (
                Counter(s["status"] for s in sessions),
                Counter(s["outcome"] for s in sessions),
            )
            return {
                "schema_version": 1,
                "mode": "local_text_rehearsal",
                "sessions": sessions,
                "counts": {
                    "sessions": len(sessions),
                    "statuses": dict(statuses),
                    "selected_outcomes": dict(outcomes),
                },
                "follow_up": [
                    {"outcome": key, "sessions": count, "guidance": GUIDANCE[key]}
                    for key, count in sorted(outcomes.items())
                ],
                "notice": NOTICE,
                "not_checked": [
                    "No real delivery, caller identity, speech or participant behavior "
                    "was observed.",
                    "Selections are local self/operator reports, not personnel evaluation.",
                    "No actual independent verification is proven by choosing that menu option.",
                ],
            }


def render_training_html(report):
    def escaped(value):
        return html.escape(str(value), quote=True)

    rows = "".join(
        "<tr>"
        + "".join(
            f"<td>{escaped(session[key])}</td>"
            for key in ("participant", "channel", "status", "outcome", "turns")
        )
        + "</tr>"
        for session in report["sessions"]
    )
    guidance = "".join(
        f"<li>{escaped(item['outcome'])}: {escaped(item['guidance'])}</li>"
        for item in report["follow_up"]
    )
    gaps = "".join(f"<li>{escaped(item)}</li>" for item in report["not_checked"])
    return (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
        "<title>Local training rehearsal report</title><style>"
        "body{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:1rem}"
        "td,th{border:1px solid #bbb;padding:.6rem;text-align:left}"
        "table{border-collapse:collapse}p{background:#fff3cc;padding:1rem}</style>"
        "<h1>Local text rehearsal</h1><p>" + escaped(report["notice"]) + "</p>"
        "<h2>Selected outcomes</h2><table><tr><th>Participant alias</th><th>Channel</th>"
        "<th>Status</th><th>Selected outcome</th><th>Turns</th></tr>" + rows + "</table>"
        "<h2>Follow-up practice</h2><ul>" + guidance + "</ul>"
        "<h2>Not checked</h2><ul>" + gaps + "</ul></html>"
    )
