"""Regular bounded saved-report reads with optional aggregate byte accounting."""

import os
import stat
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from .models import ValidationError

_BUDGETS = ContextVar("report_read_budgets", default=())


class ReportReadLimit(ValidationError):
    """An aggregate verification read budget is exhausted, not a corrupt individual run."""


@contextmanager
def report_read_budget(maximum):
    budget = [maximum]
    token = _BUDGETS.set((*_BUDGETS.get(), budget))
    try:
        yield
    finally:
        _BUDGETS.reset(token)


def read_regular(path, maximum, *, limit_message="Report artifact exceeds its byte limit"):
    from .agent_fs import open_pinned_file
    from .dependency_paths import linked

    path = Path(path)
    if linked(path) or (path.exists() and not path.is_file()):
        raise ValidationError("Report artifact must be a regular file without links/junctions")
    with open_pinned_file(path) as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValidationError("Report artifact must be a regular file without links")
        budgets = _BUDGETS.get()
        allowance = min([maximum + 1, *(budget[0] + 1 for budget in budgets)])
        raw = stream.read(allowance)
        after = os.fstat(stream.fileno())
        for budget in budgets:
            budget[0] -= len(raw)
        if any(budget[0] < 0 for budget in budgets):
            raise ReportReadLimit("History verification exceeds its aggregate read-byte limit")
        if len(raw) > maximum:
            raise ValidationError(limit_message)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ):
            raise ValidationError("File changed during read")
        return raw
