"""Regular bounded saved-report reads with optional aggregate byte accounting."""

import os
import stat
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from .dependency_paths import linked
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
    path = Path(path)
    if linked(path) or (path.exists() and not path.is_file()):
        raise ValidationError("Report artifact must be a regular file without links/junctions")
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValidationError("Report artifact must be a regular file without links")
        budgets = _BUDGETS.get()
        allowance = min([maximum + 1, *(budget[0] + 1 for budget in budgets)])
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            raw = stream.read(allowance)
        for budget in budgets:
            budget[0] -= len(raw)
        if any(budget[0] < 0 for budget in budgets):
            raise ReportReadLimit("History verification exceeds its aggregate read-byte limit")
        if len(raw) > maximum:
            raise ValidationError(limit_message)
        return raw
    finally:
        if descriptor is not None:
            os.close(descriptor)
