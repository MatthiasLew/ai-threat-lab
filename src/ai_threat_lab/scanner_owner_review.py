"""In-process owner review contract. No signing or launch capability."""

import time
from dataclasses import dataclass

from .scanner_approval import MAX_APPROVAL_SECONDS
from .scanner_sandbox import ScannerExecutionPlan


@dataclass(frozen=True, slots=True)
class OwnerReviewPrompt:
    plan: ScannerExecutionPlan
    fingerprint: str
    expires_at: int
    _deadline: float

    @classmethod
    def prepare(cls, review):
        return cls(
            review.plan, review.fingerprint(), int(time.time()) + MAX_APPROVAL_SECONDS,
            time.monotonic() + MAX_APPROVAL_SECONDS,
        )

    def record_demo_confirmation(self, review, decision):
        """A demo client may record intent. This value cannot redeem an approval."""
        return (
            decision is True and time.monotonic() < self._deadline
            and review.fingerprint() == self.fingerprint
        )
