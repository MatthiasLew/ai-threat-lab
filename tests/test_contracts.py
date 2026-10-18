import copy
import json
from datetime import datetime, timedelta, timezone

import pytest

from ai_threat_lab.contracts import (
    MAX_JSON_BYTES,
    approval_from_document,
    approval_to_document,
    config_from_document,
    plan_from_document,
    read_document,
    request_from_document,
    timestamp,
    write_document,
)
from ai_threat_lab.models import ValidationError
from ai_threat_lab.providers import ProviderConfig, ProviderRegistry
from ai_threat_lab.workflows import (
    approve_campaign,
    example_request,
    prepare_campaign,
    simulate_campaign,
)


def ready_plan(scenario="email_training"):
    return prepare_campaign(example_request(scenario), ProviderRegistry(), ProviderConfig())


@pytest.mark.parametrize("scenario", ["email_training", "voice_training", "video_training"])
def test_request_and_preview_roundtrip(scenario, tmp_path):
    request = example_request(scenario)
    path = tmp_path / "Żądanie testowe.json"
    write_document(request, path)
    assert read_document(path) == request
    plan = prepare_campaign(read_document(path), ProviderRegistry(), ProviderConfig())
    restored = plan_from_document(json.loads(write_document(plan)))
    assert restored.digest == plan["plan_digest"]
    assert restored.scenario_id == scenario
    assert restored.scope.recipient_allowlist == restored.recipients


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[]",
        b"null",
        b"1",
        b"\xff",
        b'{"schema_version":1,"schema_version":2}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"nested":{"duplicate":1,"duplicate":2}}',
        b'{"value":' + b"[" * 2000,
    ],
)
def test_malformed_documents_have_readable_errors(raw, tmp_path):
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    with pytest.raises(ValidationError):
        read_document(path)


def test_large_document_and_overwrite_are_rejected(tmp_path):
    path = tmp_path / "large.json"
    path.write_bytes(b" " * (MAX_JSON_BYTES + 1))
    with pytest.raises(ValidationError, match="limit"):
        read_document(path)
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        write_document({"schema_version": 1}, path)
    assert path.read_bytes() == before


@pytest.mark.parametrize("value", [None, "", "tomorrow", "2026-01-01", "2026-01-01T12:00:00", 10])
def test_timestamp_requires_explicit_timezone(value):
    with pytest.raises(ValidationError):
        timestamp(value, "approval time")


@pytest.mark.parametrize("value", ["2026-01-01T10:00:00Z", "2026-01-01T12:00:00+02:00"])
def test_timestamp_preserves_aware_instant(value):
    assert timestamp(value, "time") == datetime(2026, 1, 1, 10, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "change",
    [
        "version_bool",
        "version_old",
        "extra",
        "missing",
        "recipients_string",
        "scope_array",
        "facts_int",
        "empty_role",
    ],
)
def test_invalid_campaign_requests(change):
    value = example_request("email_training")
    if change == "version_bool":
        value["schema_version"] = True
    elif change == "version_old":
        value["schema_version"] = 0
    elif change == "extra":
        value["api_key"] = "must-not-be-accepted"
    elif change == "missing":
        del value["scenario_id"]
    elif change == "recipients_string":
        value["recipients"] = "person@example.invalid"
    elif change == "scope_array":
        value["scope"] = []
    elif change == "facts_int":
        value["approved_facts"] = [1]
    else:
        value["scope"]["authorized_by"] = " "
    with pytest.raises(ValidationError):
        request_from_document(value)


@pytest.mark.parametrize(
    "section,key,new",
    [
        ("content", "body", "Changed text"),
        ("content", "subject", "Changed subject"),
        ("scope", "authorized_by", "Other reviewer"),
        ("scope", "identity_reference", "fictional:other"),
        ("root", "approved_facts", ["Changed fact"]),
        ("root", "recipients", ["other@example.invalid"]),
        ("root", "channel", "voice"),
    ],
)
def test_saved_plan_tampering_is_detected(section, key, new):
    value = ready_plan()
    target = value["plan"] if section == "root" else value["plan"][section]
    target[key] = new
    with pytest.raises(ValidationError, match="digest"):
        plan_from_document(value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("plan_digest", "bad"),
        ("approved_by", ""),
        ("approved_at", "2026-01-01"),
        ("schema_version", False),
    ],
)
def test_approval_schema_rejects_invalid_values(field, value):
    document = approval_to_document(approve_campaign(ready_plan(), "Reviewer"))
    document[field] = value
    with pytest.raises(ValidationError):
        approval_from_document(document)


def test_approval_is_bound_to_exact_plan_and_scope_expiry():
    document = ready_plan()
    approval = approve_campaign(document, "Reviewer")
    assert approval_from_document(approval_to_document(approval)) == approval
    other = ready_plan("voice_training")
    with pytest.raises(ValidationError, match="exact preview"):
        simulate_campaign(other, approval_to_document(approval))
    old = copy.deepcopy(example_request("email_training"))
    old["scope"]["expires_at"] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    with pytest.raises(ValidationError, match="expired"):
        prepare_campaign(old, ProviderRegistry(), ProviderConfig())


def test_complete_persistent_simulation_and_duplicate_refusal(tmp_path):
    document = ready_plan()
    approval = approval_to_document(approve_campaign(document, "Reviewer"))
    path = tmp_path / "ledger.sqlite"
    result = simulate_campaign(document, approval, path)
    assert result["mode"] == "offline_simulation"
    assert {r["status"] for r in result["receipts"]} == {"simulated"}
    with pytest.raises(ValidationError, match="already attempted"):
        simulate_campaign(document, approval, path)


def test_video_stays_preview_only_without_approved_media():
    document = ready_plan("video_training")
    approval = approval_to_document(approve_campaign(document, "Reviewer"))
    with pytest.raises(ValidationError, match="asset"):
        simulate_campaign(document, approval)


@pytest.mark.parametrize(
    "value",
    [
        {"schema_version": True},
        {"schema_version": 9},
        {"schema_version": 1, "api_key": "secret"},
        {"schema_version": 1, "content": ""},
        {"schema_version": 1, "assessment": []},
        {"schema_version": 1, "assessment": {"unknown": "x"}},
        {"schema_version": 1, "assessment": {"website": 1}},
    ],
)
def test_provider_config_rejects_secrets_and_invalid_schema(value):
    with pytest.raises(ValidationError):
        config_from_document(value)
