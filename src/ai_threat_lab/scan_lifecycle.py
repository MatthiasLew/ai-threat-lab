"""Terminal-independent version 1 audit events and cooperative cancellation."""

from contextvars import ContextVar
from dataclasses import asdict, dataclass
from threading import Lock
from typing import Callable


@dataclass(frozen=True)
class ScanEvent:
    schema_version: int
    operation_id: str
    sequence: int
    event: str
    module: str | None = None
    status: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


EventHandler = Callable[[ScanEvent], None]
_current_scan = ContextVar("current_scan", default=None)


def collector_checkpoint():
    """Check the current scan at a file or manifest boundary."""
    control = _current_scan.get()
    if control is not None:
        control._checkpoint()


class ScanCancelled(Exception):
    """Cancellation acknowledged before publication; no new bundle was committed."""


class ScanControl:
    """Single-operation token. Cancellation is accepted only before publication.

    request_cancel is thread-safe. A token cannot be reused across operations.
    Collectors stop at the next checkpoint, not necessarily immediately.
    """

    def __init__(self):
        self._lock = Lock()
        self._requested = False
        self._started = False
        self._closed = False
        self._committing = False

    def request_cancel(self) -> bool:
        with self._lock:
            if self._closed:
                return False
            self._requested = True
            return True

    def _start(self):
        with self._lock:
            if self._started:
                raise ValueError("ScanControl is single-use; create a new token")
            self._started = True

    def _checkpoint(self, *, commit=False):
        with self._lock:
            if self._requested:
                raise ScanCancelled("Audit cancelled before report publication")
            if commit:
                self._committing = True
                self._closed = True

    @property
    def publication_started(self) -> bool:
        with self._lock:
            return self._committing

    def _close(self):
        with self._lock:
            self._closed = True


class EventEmitter:
    """One operation's ordered callback stream, called on the scanning thread.

    Observer exceptions are isolated: a disconnected display must not invalidate
    a completed bundle. Observers should queue events quickly, never block here.
    """

    def __init__(self, operation_id: str, handler: EventHandler | None):
        self.operation_id = operation_id
        self.handler = handler
        self.sequence = 0

    def emit(self, event: str, module: str | None = None, status: str | None = None):
        self.sequence += 1
        if self.handler is not None:
            item = ScanEvent(1, self.operation_id, self.sequence, event, module, status)
            try:
                self.handler(item)
            except Exception:
                # Never include callback exception payloads in reports/events.
                pass
