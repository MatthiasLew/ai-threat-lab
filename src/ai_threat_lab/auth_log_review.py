"""Bounded normalized login-event review, without login attempts or raw identity evidence."""

import json
import os
import re
import stat
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from .assessment import AssessmentFinding, AssessmentResult
from .contracts import _nonfinite, _pairs
from .models import ValidationError

MAX_BYTES = 4 * 1024 * 1024
MAX_LINES = 10_000
MAX_LINE = 4096
MAX_FINDINGS = 200
FIELDS = {"timestamp", "account", "source", "outcome", "method"}
METHODS = {"password", "public_key", "mfa", "unknown"}
NOTICE = (
    "Selected normalized login-event patterns only; no login attempts, account access, "
    "network requests, identity attribution or compromise confirmation. "
    "Log authenticity, completeness, clock accuracy and effective defenses unverified."
)
ACTIONS = {
    "auth_repeated_failures": "Review the original events and rate-limiting/MFA controls; "
    "mistyped or stale credentials can also create failure bursts.",
    "auth_password_spray_pattern": "Review password failures across accounts and source context; "
    "shared gateways and monitoring can produce similar patterns.",
    "auth_distributed_failures": "Review failures against the same account from multiple sources; "
    "source identifiers are not reliable actor identities.",
    "auth_success_after_failures": "Verify the successful login independently and inspect session "
    "context; this sequence alone does not establish account compromise.",
}


@dataclass(frozen=True)
class AuthPolicy:
    window_seconds: int = 300
    min_failures: int = 5
    min_accounts: int = 5
    min_sources: int = 3

    def __post_init__(self):
        for value, low, high in (
            (self.window_seconds, 1, 3600),
            (self.min_failures, 3, 100),
            (self.min_accounts, 2, 100),
            (self.min_sources, 2, 100),
        ):
            if type(value) is not int or not low <= value <= high:
                raise ValidationError("Authentication review policy exceeds supported bounds")


@dataclass(frozen=True)
class Event:
    time: datetime
    account: str
    source: str
    outcome: str
    method: str
    line: int


def capture_lines(source):
    if not isinstance(source, str):
        raise ValidationError("Authentication events require UTF-8 JSON Lines text")
    try:
        if len(source.encode("utf-8")) > MAX_BYTES:
            raise ValidationError("Authentication log exceeds the 4 MiB limit")
    except UnicodeError:
        raise ValidationError("Authentication log text encoding unsupported") from None
    lines = source.split("\n")
    # The final newline is a terminator, not another physical input line.
    if lines[-1] == "":
        lines.pop()
    if len(lines) > MAX_LINES:
        raise ValidationError("Authentication log exceeds the 10000-line limit")
    for line in lines:
        if len(line) > MAX_LINE:
            raise ValidationError("Authentication log line exceeds its 4096-character limit")
    return lines


def parse_events(source):
    lines = capture_lines(source)
    events, seen, notices = [], set(), set()
    duplicates = 0
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line, object_pairs_hook=_pairs, parse_constant=_nonfinite)
            if not isinstance(item, dict) or set(item) != FIELDS:
                raise ValueError
            timestamp = item["timestamp"]
            if not isinstance(timestamp, str) or not re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                r"(?:\.[0-9]{1,6})?(?:Z|\+00:00)",
                timestamp,
            ):
                raise ValueError
            time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if time.year < 1970:
                raise ValueError
            for key in ("account", "source"):
                value = item[key]
                if not isinstance(value, str) or not re.fullmatch(r"[!-~]{1,128}", value):
                    raise ValueError
            if item["outcome"] not in ("failure", "success") or item["method"] not in METHODS:
                raise ValueError
            identity = (time, item["account"], item["source"], item["outcome"], item["method"])
            if identity in seen:
                duplicates += 1
                continue
            seen.add(identity)
            events.append(Event(*identity, number))
        except (ValueError, TypeError, RecursionError, OverflowError):
            raise ValidationError(
                f"Invalid normalized authentication event on line {number}; values omitted"
            ) from None
    if duplicates:
        notices.add(
            f"Collapsed {duplicates} exact normalized duplicate event(s); replay unverified."
        )
    if any(a.time > b.time for a, b in zip(events, events[1:])):
        notices.add("Events reordered by declared UTC time; original line references retained.")
    events.sort(key=lambda event: (event.time, event.line))
    return events, notices


class Window:
    def __init__(self):
        self.items = deque()
        self.counts = Counter()

    def prune(self, cutoff):
        while self.items and self.items[0][0] < cutoff:
            _, _, identity = self.items.popleft()
            self.counts[identity] -= 1
            if not self.counts[identity]:
                del self.counts[identity]

    def add(self, event, identity):
        self.items.append((event.time, event.line, identity))
        self.counts[identity] += 1


def inspect_auth_log(source, *, policy=None, target="<authentication-events>"):
    events, notices = parse_events(source)
    return inspect_auth_events(events, notices, policy=policy, target=target)


def inspect_auth_events(
    events,
    notices,
    *,
    policy=None,
    target="<authentication-events>",
    target_kind="authentication_log",
    context=NOTICE,
):
    policy = AuthPolicy() if policy is None else policy
    if not isinstance(policy, AuthPolicy):
        raise ValidationError("Authentication review needs a validated policy")
    notices = set(notices)
    pairs, accounts, sources = defaultdict(Window), defaultdict(Window), defaultdict(Window)
    account_ids, source_ids = {}, {}
    for event in sorted(events, key=lambda e: e.line):
        account_ids.setdefault(event.account, len(account_ids) + 1)
        source_ids.setdefault(event.source, len(source_ids) + 1)
    observed = {}

    def record(check, group, event, count, distinct=0):
        key = (check, group)
        if key not in observed and len(observed) >= MAX_FINDINGS:
            notices.add("Authentication finding limit reached; additional groups omitted.")
            return
        if key not in observed or (count, distinct) > observed[key][:2]:
            observed[key] = (count, distinct, event.line)

    for event in events:
        cutoff = event.time - timedelta(seconds=policy.window_seconds)
        pair = pairs[(event.account, event.source)]
        pair.prune(cutoff)
        if event.outcome == "success":
            # Equal timestamps have no proven event order. Success starts a new pair segment.
            prior = sum(time < event.time for time, _, _ in pair.items)
            if prior >= policy.min_failures:
                record(
                    "auth_success_after_failures",
                    (account_ids[event.account], source_ids[event.source]),
                    event,
                    prior,
                )
            pairs.pop((event.account, event.source), None)
            continue
        pair.add(event, event.method)
        if len(pair.items) >= policy.min_failures:
            record(
                "auth_repeated_failures",
                (account_ids[event.account], source_ids[event.source]),
                event,
                len(pair.items),
            )
        account = accounts[event.account]
        account.prune(cutoff)
        account.add(event, event.source)
        if len(account.items) >= policy.min_failures and len(account.counts) >= policy.min_sources:
            record(
                "auth_distributed_failures",
                (account_ids[event.account],),
                event,
                len(account.items),
                len(account.counts),
            )
        if event.method == "password":
            origin = sources[event.source]
            origin.prune(cutoff)
            origin.add(event, event.account)
            if (
                len(origin.items) >= policy.min_failures
                and len(origin.counts) >= policy.min_accounts
            ):
                record(
                    "auth_password_spray_pattern",
                    (source_ids[event.source],),
                    event,
                    len(origin.items),
                    len(origin.counts),
                )
    findings = []
    for (check, group), (count, distinct, line) in sorted(observed.items()):
        label = (
            f"account group {group[0]}, source group {group[1]}"
            if len(group) == 2
            else f"source group {group[0]}"
            if check == "auth_password_spray_pattern"
            else f"account group {group[0]}"
        )
        findings.append(
            AssessmentFinding(
                check,
                "candidate",
                f"Line {line}; {label}; selected failures={count}; "
                + (f"distinct counterparts={distinct}; " if distinct else "")
                + f"inclusive window={policy.window_seconds}s; "
                f"thresholds failures={policy.min_failures}, "
                f"accounts={policy.min_accounts}, sources={policy.min_sources}. "
                "Group ordinals are local to this capture; identities/timestamps omitted. "
                "Pattern is not attack or compromise proof.",
                ACTIONS[check],
            )
        )
    return AssessmentResult(
        target,
        target_kind,
        "partial",
        tuple(findings),
        (
            context,
            f"Configured policy: inclusive window={policy.window_seconds}s; "
            f"minimum failures={policy.min_failures}; minimum accounts={policy.min_accounts}; "
            f"minimum sources={policy.min_sources}; maximum findings={MAX_FINDINGS}.",
            *sorted(notices),
            f"Reviewed {len(events)} unique normalized event(s); "
            "exact identities are case-sensitive. "
            "No arbitrary provider-format conversion, IP/NAT inference, geo-location, "
            "session/token correlation, password-strength or lockout/MFA effectiveness assessment.",
            "Only declared outcome/method/time is used; missing records are not inferred. "
            "No candidates is not evidence of a secure account or absence of attacks.",
        ),
    )


def read_auth_text(path):
    path = Path(path)
    if path.is_symlink() or getattr(path, "is_junction", lambda: False)() or not path.is_file():
        raise ValidationError("Authentication log must be a regular file without links")
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValidationError("Authentication log must be a regular file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            raw = stream.read(MAX_BYTES + 1)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(raw) > MAX_BYTES:
        raise ValidationError("Authentication log exceeds the 4 MiB limit")
    try:
        source = raw.decode("utf-8-sig")
    except UnicodeError:
        raise ValidationError("Authentication log requires UTF-8 text") from None
    return source


def review_auth_log_file(path, *, policy=None):
    return inspect_auth_log(read_auth_text(path), policy=policy, target=str(path))
