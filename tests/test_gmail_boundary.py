"""Gmail settings contract, with synthetic tokens and responses only."""

import json

import pytest

from ai_threat_lab.http_client import HttpResponse
from ai_threat_lab.providers import ProviderError
from ai_threat_lab.remote_audit import GmailAudit

TARGET = 'mailbox:user@example.com'
BASE = 'https://gmail.googleapis.com/gmail/v1/users/me'


class HTTP:
    def __init__(self, *documents):
        self.documents = list(documents)
        self.calls = []

    def request(self, url, **kwargs):
        self.calls.append((url, kwargs))
        assert self.documents, 'Unexpected request or retry'
        doc = self.documents.pop(0)
        return (doc if isinstance(doc, HttpResponse)
                else HttpResponse(200, {}, json.dumps(doc).encode()))


@pytest.fixture(autouse=True)
def synthetic_token(monkeypatch):
    monkeypatch.setenv('GMAIL_ACCESS_TOKEN', 'fixture-token')


@pytest.mark.parametrize('identity', [None, 1, True, [], {}, '', 'other@example.com',
                                     'user@example.com\n'])
def test_identity_failure_stops_before_settings(identity):
    http = HTTP({'emailAddress': identity})
    with pytest.raises(ProviderError, match='does not match'):
        GmailAudit(http).assess(TARGET)
    assert len(http.calls) == 1


@pytest.mark.parametrize('token', ['', 'bad token', 'bad\ntoken', 'bad\rtoken',
                                  'bad\ttoken', 'é', '\x7f', 'x' * 4097],
                         ids=[f'token-{i}' for i in range(8)])
def test_token_rejected_before_any_request(token, monkeypatch):
    monkeypatch.setenv('GMAIL_ACCESS_TOKEN', token)
    http = HTTP()
    with pytest.raises(ProviderError) as error:
        GmailAudit(http).assess(TARGET)
    assert not http.calls and 'fixture-token' not in str(error.value)
    if token and len(token) > 20:
        assert token not in str(error.value)


@pytest.mark.parametrize('enabled', [None, 0, 1, 'false', 'true', [], {}])
def test_forwarding_type_is_checked_before_filter_request(enabled):
    http = HTTP({'emailAddress': 'user@example.com'}, {'enabled': enabled})
    with pytest.raises(ProviderError, match='forwarding'):
        GmailAudit(http).assess(TARGET)
    assert len(http.calls) == 2


@pytest.mark.parametrize('filters', [
    {'filter': None}, {'filter': {}}, {'filter': True}, {'filter': [None]},
    {'filter': [1]}, {'filter': [{'action': None}]}, {'filter': [{'action': []}]},
    {'filter': [{'action': {'forward': None}}]}, {'filter': [{'action': {'forward': 1}}]},
    {'filter': [{'action': {'forward': False}}]},
    {'filter': [{'action': {'forward': 'PRIVATE\nADDRESS'}}]},
    {'filter': [{'action': {'forward': 'PRIVATE ADDRESS'}}]},
    {'filter': [{'action': {'forward': 'x' * 1025}}]},
    {'filter': [{}] * 1001}, {'nextPageToken': 'PRIVATE_NEXT'}, {'nextPageToken': 0},
], ids=[f'filters-{i}' for i in range(16)])
def test_malformed_filters_never_become_clean_or_positive_observations(filters):
    http = HTTP({'emailAddress': 'user@example.com'}, {'enabled': True}, filters)
    with pytest.raises(ProviderError) as error:
        GmailAudit(http).assess(TARGET)
    assert 'PRIVATE' not in str(error.value) and len(http.calls) == 3


def test_every_rule_is_validated_even_after_a_positive_rule():
    http = HTTP({'emailAddress': 'user@example.com'}, {'enabled': False},
                {'filter': [{'action': {'forward': 'PRIVATE@example.com'}}, {'action': None}]})
    with pytest.raises(ProviderError):
        GmailAudit(http).assess(TARGET)


@pytest.mark.parametrize('filters', [{}, {'filter': []}, {'filter': [{}]},
    {'filter': [{'action': {}}]}, {'filter': [{'action': {'forward': ''}}]},
    {'filter': [{}] * 1000}],
    ids=['omitted', 'empty', 'no-action', 'empty-action', 'default', 'limit'])
def test_supported_empty_settings(filters):
    http = HTTP({'emailAddress': 'USER@EXAMPLE.COM'}, {'enabled': False}, filters)
    result = GmailAudit(http).assess(TARGET)
    assert result.status == 'partial' and not result.findings and result.not_checked


def test_fixed_read_only_endpoints_headers_and_redacted_findings():
    http = HTTP({'emailAddress': 'user@example.com', 'messagesTotal': 12345},
                {'enabled': True, 'emailAddress': 'PRIVATE_AUTO@example.com'},
                {'filter': [{'criteria': {'query': 'PRIVATE_QUERY'},
                             'action': {'forward': 'PRIVATE_FILTER@example.com'}}]})
    result = GmailAudit(http).assess(TARGET)
    assert {item.check for item in result.findings} == {
        'mailbox_auto_forwarding', 'mailbox_filter_forwarding',
    }
    assert 'PRIVATE' not in str(result) and 'fixture-token' not in str(result)
    assert '12345' not in str(result)
    assert http.calls == [(BASE + path, {'headers': {'Authorization': 'Bearer fixture-token'}})
                          for path in ('/profile', '/settings/autoForwarding', '/settings/filters')]


@pytest.mark.parametrize('stage', [0, 1, 2])
@pytest.mark.parametrize('status', [301, 401, 403, 429, 500])
def test_http_errors_stop_without_retry_or_raw_response(status, stage):
    docs = [{'emailAddress': 'user@example.com'}, {'enabled': False}, {}]
    docs[stage] = HttpResponse(status, {}, b'PRIVATE_ERROR')
    http = HTTP(*docs[:stage + 1])
    with pytest.raises(ProviderError) as error:
        GmailAudit(http).assess(TARGET)
    assert len(http.calls) == stage + 1 and 'PRIVATE_ERROR' not in str(error.value)
