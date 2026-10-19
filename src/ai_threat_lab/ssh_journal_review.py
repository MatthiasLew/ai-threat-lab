"""Selected OpenSSH journal JSON records; no journal access or login attempts."""

import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone

from .auth_log_review import Event, capture_lines, inspect_auth_events, read_auth_text
from .contracts import _nonfinite, _pairs
from .models import ValidationError

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
PROCESSES = {"sshd", "sshd-session"}
MESSAGE = re.compile(
    r"(?P<state>Accepted|Failed) "
    r"(?P<method>[a-z][a-z0-9-]{0,31}(?:/[a-z][a-z0-9-]{0,31})?) for "
    r"(?P<invalid>invalid user )?(?P<account>[!-~]{1,99}) from "
    r"(?P<source>[0-9a-fA-F:.]{2,45}) port (?P<port>[0-9]{1,5}) ssh2"
    r"(?:: [ -~]{1,1024})?"
)
NOTICE = (
    "Selected saved single-host OpenSSH journal records only; no login attempts, "
    "journal/account access or network requests. Export metadata is caller-supplied, "
    "not authenticated. No attack, compromise or participant attribution is established."
)


def parse_ssh_journal(source):
    lines = capture_lines(source)
    events, seen, notices = [], set(), set()
    other, noise, duplicates, machine = 0, 0, 0, None
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line, object_pairs_hook=_pairs, parse_constant=_nonfinite)
            if not isinstance(item, dict):
                raise ValueError
            process = item.get("_COMM")
            if process is not None and not isinstance(process, str):
                raise ValueError
            if process not in PROCESSES:
                other += 1
                continue
            host = item.get("_MACHINE_ID")
            if not isinstance(host, str) or not re.fullmatch(r"[a-f0-9]{32}", host):
                raise ValueError
            if machine is not None and host != machine:
                raise ValueError
            machine = host
            raw_time, text = item.get("__REALTIME_TIMESTAMP"), item.get("MESSAGE")
            if (
                not isinstance(raw_time, str)
                or not re.fullmatch(r"[0-9]{1,18}", raw_time)
                or not isinstance(text, str)
                or not re.fullmatch(r"[ -~]*", text)
            ):
                raise ValueError
            # Journal reception time, integer microseconds; never use float epochs/local TZ.
            time = EPOCH + timedelta(microseconds=int(raw_time))
            message = text.removesuffix(" [preauth]")
            match = MESSAGE.fullmatch(message)
            if match is None:
                if text.startswith(("Accepted ", "Failed ")):
                    raise ValueError  # Never silently omit an unsupported terminal outcome.
                noise += 1
                continue
            state, invalid = match["state"], match["invalid"]
            if state == "Accepted" and (invalid or text.endswith(" [preauth]")):
                raise ValueError
            port = int(match["port"])
            if not 1 <= port <= 65535:
                raise ValueError
            address = str(ipaddress.ip_address(match["source"]))
            method = {"password": "password", "publickey": "public_key"}.get(
                match["method"], "unknown"
            )
            identity = (
                time,
                match["account"],
                address,
                "success" if state == "Accepted" else "failure",
                method,
            )
            if identity in seen:
                duplicates += 1
                continue
            seen.add(identity)
            events.append(Event(*identity, number))
        except (ValueError, TypeError, RecursionError, OverflowError):
            raise ValidationError(
                f"Invalid or unsupported SSH journal record on line {number}; values omitted"
            ) from None
    if duplicates:
        notices.add(
            f"Collapsed {duplicates} exact mapped duplicate event(s); "
            "distinct attempts may be undercounted; cursor/replay authenticity unverified."
        )
    if any(a.time > b.time for a, b in zip(events, events[1:])):
        notices.add(
            "Events reordered by journal reception time; original line references retained."
        )
    notices.add(
        f"SSH mapping: selected events={len(events)}; other/missing process rows={other}; "
        f"nonterminal/unrecognized SSH messages={noise}. Omitted rows are not login outcomes."
    )
    events.sort(key=lambda event: (event.time, event.line))
    return events, notices


def inspect_ssh_journal(source, *, policy=None, target="<ssh-journal>"):
    events, notices = parse_ssh_journal(source)
    notices.add(
        "Single declared machine; exact case-sensitive account names and canonical IP literals. "
        "Journal reception time may differ from authentication time; ports, cursors, host ID "
        "and key metadata omitted. Other methods map to unknown, never inferred MFA. "
        "Partial/Postponed and other SSH messages are not terminal authentication outcomes."
    )
    return inspect_auth_events(
        events, notices, policy=policy, target=target, target_kind="ssh_journal", context=NOTICE
    )


def review_ssh_journal_file(path, *, policy=None):
    return inspect_ssh_journal(read_auth_text(path), policy=policy, target=str(path))
