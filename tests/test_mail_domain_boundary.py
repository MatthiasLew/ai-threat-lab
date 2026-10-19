"""Mail DNS boundaries: provider failure must never become missing-policy evidence."""

import json
from urllib.parse import parse_qs, urlsplit

import pytest

from ai_threat_lab.http_client import HttpResponse
from ai_threat_lab.models import ValidationError
from ai_threat_lab.providers import ProviderError
from ai_threat_lab.remote_audit import MailDomainAudit, dns_txt


class Wire:
    def __init__(self, *documents):
        self.documents = list(documents)
        self.calls = []

    def request(self, url, **kwargs):
        self.calls.append((url, kwargs))
        assert self.documents, 'Unexpected query/retry'
        body = self.documents.pop(0)
        return HttpResponse(200, {}, json.dumps(body).encode())


def answer(value='"v=spf1 -all"', **overrides):
    return {"name": "example.com.", "type": 16, "data": value, **overrides}


@pytest.mark.parametrize('document', [
    {}, {"Status": False}, {"Status": True}, {"Status": 0.0}, {"Status": "0"},
    {"Status": 0, "Answer": None}, {"Status": 0, "Answer": {}},
    {"Status": 0, "Answer": [None]}, {"Status": 0, "Answer": [True]},
    {"Status": 0, "Answer": [answer(name=None)]},
    {"Status": 0, "Answer": [answer(type=16.0)]},
    {"Status": 0, "Answer": [answer(type=True)]},
    {"Status": 0, "Answer": [answer(type=0)]},
    {"Status": 0, "Answer": [answer(type=65536)]},
    {"Status": 0, "Answer": [answer(data=None)]},
    {"Status": 0, "Answer": [answer(name='')]},
    {"Status": 0, "Answer": [answer(name='example.com..')]},
    {"Status": 0, "Answer": [answer(name='bad name.example')]},
    {"Status": 0, "Answer": [answer(name='é.example')]},
    {"Status": 0, "Answer": [answer(name='x' * 64 + '.example')]},
    {"Status": 0, "TC": True}, {"Status": 0, "TC": 0},
    {"Status": 3, "Answer": [answer()]},
], ids=lambda value: str(value)[:100])
def test_invalid_response_is_controlled_and_stops_before_next_query(document):
    wire = Wire(document)
    with pytest.raises(ProviderError) as caught:
        MailDomainAudit(wire).assess('mail-domain:example.com')
    assert 'v=spf1' not in str(caught.value)
    assert len(wire.calls) == 1


@pytest.mark.parametrize('question', [None, {}, [], [None], [{}],
    [{"name": "other.example.", "type": 16}],
    [{"name": "example.com.", "type": 16.0}],
    [{"name": None, "type": 16}],
    [{"name": "example.com..", "type": 16}],
    [{"name": "example.com.", "type": 16}] * 2])
def test_question_binding(question):
    wire = Wire({"Status": 0, "Question": question})
    with pytest.raises(ProviderError, match='question'):
        MailDomainAudit(wire).assess('mail-domain:example.com')
    assert len(wire.calls) == 1


def test_fixed_query_names_and_headers_and_case_normalization():
    wire = Wire(
        {"Status": 0, "TC": False, "Question": [{"name": "EXAMPLE.COM.", "type": 16}],
         "Answer": [answer('"v=spf1 " "-all"', name='EXAMPLE.COM.')]},
        {"Status": 0, "Answer": [answer('"v=DMARC1; p=reject;"', name='_dmarc.example.com.')]},
        {"Status": 0, "Answer": [answer('"unrelated TXT"', name='sel._domainkey.example.com.')]},
    )
    result = MailDomainAudit(wire, selector='sel').assess('mail-domain:EXAMPLE.COM')
    assert result.status == 'partial' and not result.findings
    assert any('presence only' in notice for notice in result.not_checked)
    assert len(wire.calls) == 3
    for (url, kwargs), name in zip(wire.calls, (
        'example.com', '_dmarc.example.com', 'sel._domainkey.example.com',
    ), strict=True):
        parts = urlsplit(url)
        assert parts.scheme == 'https' and parts.netloc == 'cloudflare-dns.com'
        assert parts.path == '/dns-query'
        assert parse_qs(parts.query) == {'name': [name], 'type': ['TXT']}
        assert kwargs == {'headers': {'Accept': 'application/dns-json'}}


@pytest.mark.parametrize('kind', [5, 39])
def test_aliases_are_unknown_not_missing_and_are_not_followed(kind):
    wire = Wire({"Status": 0, "Answer": [answer('PRIVATE_ALIAS.example.', type=kind)]})
    with pytest.raises(ProviderError, match='alias') as caught:
        MailDomainAudit(wire).assess('mail-domain:example.com')
    assert 'PRIVATE_ALIAS' not in str(caught.value) and len(wire.calls) == 1


def test_answer_count_bound():
    wire = Wire({"Status": 0, "Answer": [answer()] * 257})
    with pytest.raises(ProviderError):
        MailDomainAudit(wire).assess('mail-domain:example.com')
    wire = Wire({"Status": 0, "Answer": [answer()] * 256}, {"Status": 3})
    result = MailDomainAudit(wire).assess('mail-domain:example.com')
    assert result.findings[0].check == 'spf_record_count'
    assert '256' in result.findings[0].evidence


@pytest.mark.parametrize(('presentation', 'expected'), [
    ('""', ''), (' "v=spf1 "\t"-all" ', 'v=spf1 -all'),
    (r'"v=spf1\032-all"', 'v=spf1 -all'),
    (r'"say \"hello\" \\ ok"', 'say "hello" \\ ok'),
    ('"' + 'x' * 255 + '"', 'x' * 255),
])
def test_dns_quoted_chunks_and_decimal_escapes(presentation, expected):
    assert dns_txt(presentation) == expected


@pytest.mark.parametrize('value', [None, True, 1, [], '', ' ', "'v=spf1 -all'", 'v=spf1 -all',
    '"x""y"', '"x" junk', '"unterminated', '"dangling\\', r'"\1"', r'"\12x"',
    r'"\256"', r'"\000"', r'"\127"', '"x\ny"', '"é"', '"' + 'x' * 256 + '"',
    '"x" ' * 65536, 'x' * 262145,
], ids=[f'unsupported-{i}' for i in range(22)])
def test_unsupported_txt_is_not_silently_reinterpreted(value):
    with pytest.raises(ProviderError):
        dns_txt(value)


@pytest.mark.parametrize('selector', [True, 123, [], {}, '', 'a.b'])
def test_selector_types_fail_before_network(selector):
    wire = Wire()
    with pytest.raises(ValidationError):
        MailDomainAudit(wire, selector=selector)
    assert not wire.calls


def test_derived_dns_name_length_checked_before_any_query():
    wire = Wire()
    domain = '.'.join(['x' * 63] * 3 + ['y' * 50])
    with pytest.raises(ValidationError, match='253'):
        MailDomainAudit(wire, selector='s' * 63).assess('mail-domain:' + domain)
    assert not wire.calls


def policy_result(spf, dmarc):
    wire = Wire(
        {"Status": 0, "Answer": [answer(json.dumps(spf))]},
        {"Status": 0, "Answer": [answer(json.dumps(dmarc), name='_dmarc.example.com.')]},
    )
    return MailDomainAudit(wire).assess('mail-domain:example.com')


def test_spf_version_boundary_and_case_insensitive_all():
    result = policy_result('v=spf10 -all', 'v=DMARC1; p=reject')
    assert [item.check for item in result.findings] == ['spf_record_count']
    result = policy_result('v=spf1 +ALL -all', 'v=DMARC1; p=reject')
    assert [item.check for item in result.findings] == ['weak_spf']


@pytest.mark.parametrize('policy', ['p=none; p=reject', 'p=reject; p=none', 'p=reject; bad',
    'p=reject;;', 'p=REJECT', 'P=reject', 'p=unknown', 'rua=mailto:PRIVATE@example.com'])
def test_ambiguous_dmarc_is_visible_without_raw_policy_disclosure(policy):
    result = policy_result('v=spf1 -all', 'v=DMARC1; ' + policy)
    assert [item.check for item in result.findings] == ['invalid_dmarc']
    assert 'PRIVATE' not in str(result)


@pytest.mark.parametrize("previous_engine", [
    "read-only-pipeline-23", "read-only-pipeline-24", "read-only-pipeline-25",
])
def test_previous_engine_remains_readable_but_not_comparable(tmp_path, previous_engine):
    from ai_threat_lab.scan_bundle import compare_bundles, publish_bundle, read_bundle, scope_digest
    from ai_threat_lab.scan_engine import ScanOptions, ScanService

    result = policy_result('v=spf1 -all', 'v=DMARC1; p=reject')
    ScanService(lambda _: result).run(
        ScanOptions('mail-domain:example.com', network=True, allowed_hosts=('example.com',)),
        tmp_path / 'current',
    )
    current = read_bundle(tmp_path / 'current')
    assert current['manifest']['scope']['engine'] == 'read-only-pipeline-26'
    metadata = dict(current['manifest'])
    metadata['scope'] = {**metadata['scope'], 'engine': previous_engine}
    metadata['scope_digest'] = scope_digest(metadata['scope'])
    artifacts = {name: (tmp_path / 'current' / name).read_bytes() for name in metadata['files']}
    publish_bundle(tmp_path / 'previous', artifacts, metadata)
    previous = read_bundle(tmp_path / 'previous')
    assert previous['manifest']['scope']['engine'] == previous_engine
    assert compare_bundles(previous, current)['comparable'] is False
