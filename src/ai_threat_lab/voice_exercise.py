"""Bounded voice-exercise dialogue policy; speech/telephony remain provider adapters."""

from dataclasses import dataclass
from enum import StrEnum

from .campaigns import TrainingEvent
from .models import ValidationError, require_text


class VoiceSignal(StrEnum):
    UNKNOWN = "unknown"
    VERIFICATION_REQUESTED = "verification_requested"
    IDENTITY_VERIFIED = "identity_verified"
    SYNTHETIC_INFO_SHARED = "synthetic_info_shared"
    REAL_DATA_OFFERED = "real_data_offered"
    DECLINED = "declined"
    STOP = "stop"


@dataclass(frozen=True)
class VoiceTurn:
    text: str
    finished: bool
    event: TrainingEvent | None = None


class VoiceExerciseSession:
    """Accept classified signals, never raw secrets or transcripts. No network or audio IO."""

    def __init__(self, participant_id: str) -> None:
        require_text(participant_id, "participant_id")
        self.participant_id = participant_id
        self._turns = 0
        self._finished = False

    def advance(self, signal: VoiceSignal) -> VoiceTurn:
        if not isinstance(signal, VoiceSignal):
            raise ValidationError("Voice dialogue requires a defined VoiceSignal")
        if self._finished:
            raise ValidationError("Voice exercise already ended")
        self._turns += 1
        if signal in (VoiceSignal.STOP, VoiceSignal.DECLINED, VoiceSignal.REAL_DATA_OFFERED):
            self._finished = True
            event = (
                TrainingEvent(self.participant_id, "declined")
                if signal == VoiceSignal.DECLINED
                else None
            )
            return VoiceTurn(
                "The exercise is ending. Do not share any real information.", True, event
            )
        if signal in (VoiceSignal.VERIFICATION_REQUESTED, VoiceSignal.IDENTITY_VERIFIED):
            self._finished = True
            return VoiceTurn(
                "Please verify through your established channel. The exercise ends here.",
                True,
                TrainingEvent(self.participant_id, "identity_verified")
                if signal == VoiceSignal.IDENTITY_VERIFIED
                else None,
            )
        if signal == VoiceSignal.SYNTHETIC_INFO_SHARED:
            self._finished = True
            return VoiceTurn(
                "The synthetic exercise is complete. No other information is needed.",
                True,
                TrainingEvent(self.participant_id, "synthetic_info_shared"),
            )
        if self._turns >= 3:
            self._finished = True
            return VoiceTurn("The exercise is ending without a classified outcome.", True)
        return VoiceTurn(
            "Only the invented TRAINING-ALPHA identifier is part of this exercise. "
            "Use your usual caller-verification procedure; share no real information.",
            False,
        )
