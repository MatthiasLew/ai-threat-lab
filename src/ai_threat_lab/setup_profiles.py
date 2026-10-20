"""Non-secret optional integration settings checks; never read credential environment values."""

from .avatar_training import AvatarConfig
from .call_training import HOST, CallConfig
from .contracts import read_document
from .smtp_training import SMTPConfig
from .speech_training import SpeechConfig


def integration_profiles(*, smtp_path=None, speech_path=None, avatar_path=None, call_path=None):
    rows = []
    if smtp_path is None:
        rows.append({"id": "smtp", "status": "not_selected",
                     "next_step": "Supply --smtp-config only when preparing fictional delivery."})
    else:
        smtp = SMTPConfig.from_document(read_document(smtp_path))
        rows.append({
            "id": "smtp", "status": "local_configuration_valid", "host": smtp.host,
            "tls_mode": smtp.mode, "timeout_seconds": smtp.timeout,
            "credentials_inspected": False, "live_ready": False,
            "next_step": "Prepare an exact approved email preview, configure credentials "
                         "outside source control, then validate the account "
                         "on a controlled recipient.",
        })
    if speech_path is None:
        rows.append({"id": "speech", "status": "not_selected",
                     "next_step": "Supply --speech-config only when preparing a voice asset."})
    else:
        speech = SpeechConfig.from_document(read_document(speech_path))
        rows.append({
            "id": "speech", "status": "local_configuration_valid", "host": speech.host,
            "voice": speech.voice, "configured_usd_per_million_characters":
                speech.usd_per_million_characters,
            "configured_max_request_usd": speech.max_request_usd,
            "credentials_inspected": False, "live_ready": False,
            "next_step": "Verify the configured price and region, prepare an approved script "
                         "preview, then validate account access, generated audio and billed usage.",
        })
    if avatar_path is None:
        rows.append({"id": "avatar", "status": "not_selected",
                     "next_step": "Supply --avatar-config only when preparing fictional video."})
    else:
        avatar = AvatarConfig.from_document(read_document(avatar_path))
        rows.append({
            "id": "avatar", "status": "local_configuration_valid", "host": avatar.resource_host,
            "voice": avatar.voice, "configured_usd_per_video_minute": avatar.usd_per_video_minute,
            "configured_max_request_estimate_usd": avatar.max_request_estimate_usd,
            "credentials_inspected": False, "live_ready": False,
            "next_step": "Verify avatar resource access and current prices, review the exact "
                         "preview, then validate generated media, download and billed usage.",
        })
    if call_path is None:
        rows.append({"id": "call", "status": "not_selected",
                     "next_step": "Supply --call-config only for approved fictional calls."})
    else:
        call = CallConfig.from_document(read_document(call_path))
        rows.append({
            "id": "call", "status": "local_configuration_valid", "host": HOST,
            "configured_usd_per_minute": call.usd_per_minute,
            "configured_max_request_estimate_usd": call.max_request_estimate_usd,
            "credentials_inspected": False, "live_ready": False,
            "next_step": "Verify account, caller identity, recipient consent, regional permissions "
                         "and prices. Test one approved call, remote stop and billed usage.",
        })
    return rows
