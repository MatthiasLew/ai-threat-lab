"""Advisory-cache corruption must not masquerade as an uncached or clean result."""

import json
import sqlite3

import pytest

from ai_threat_lab.dependencies import AdvisoryCache, Dependency, Inventory, OSVAudit
from ai_threat_lab.http_client import HttpResponse
from ai_threat_lab.models import ValidationError
from ai_threat_lab.providers import ProviderError

PACKAGE = Dependency('PyPI', 'fixture', '1.0', ())


@pytest.fixture
def cache(tmp_path):
    return AdvisoryCache(tmp_path / 'cache.sqlite', clock=lambda: 100)


def corrupt(cache, expiry, response):
    with sqlite3.connect(cache.path) as db:
        db.execute('INSERT OR REPLACE INTO advisories VALUES(?,?,?)',
                   (cache.key(PACKAGE), expiry, response))


@pytest.mark.parametrize('expiry', [None, 'bad', b'123', float('inf'), float('-inf'),
                                  float('nan'), -1, 10**12 + 86401])
def test_invalid_stored_expiry_is_controlled(cache, expiry):
    corrupt(cache, expiry, '[]')
    with pytest.raises(ValidationError, match='expiry'):
        cache.get(PACKAGE)


@pytest.mark.parametrize('response', [None, 123, b'[]', '{}', 'null', 'true', '[null]',
    '["../PRIVATE"]', 'not-json', '[' * 1500 + ']' * 1500,
    json.dumps(['OSV-' + str(i) for i in range(1001)]), '"' + 'x' * 262144 + '"'],
    ids=[f'response-{i}' for i in range(12)])
def test_invalid_stored_response_is_controlled_and_redacted(cache, response):
    corrupt(cache, 200, response)
    with pytest.raises(ValidationError) as error:
        cache.get(PACKAGE)
    assert 'PRIVATE' not in str(error.value)


@pytest.mark.parametrize('value', [None, True, '100', -1, float('inf'), float('nan'), 10**1000],
                         ids=['null', 'bool', 'text', 'negative', 'infinity', 'nan', 'huge-int'])
@pytest.mark.parametrize('operation', ['get', 'put'])
def test_invalid_clock_never_creates_or_reuses_a_result(cache, value, operation):
    cache.put(PACKAGE, [])
    cache.clock = lambda: value
    with pytest.raises(ValidationError, match='clock'):
        cache.get(PACKAGE) if operation == 'get' else cache.put(PACKAGE, [])


@pytest.mark.parametrize('value', [None, {}, 'OSV-1', [None], [True], ['../PRIVATE'],
                                 ['x' * 201], ['OSV-1'] * 1001],
                         ids=[f'value-{i}' for i in range(8)])
def test_invalid_write_preserves_previous_valid_result(cache, value):
    cache.put(PACKAGE, ['OSV-existing'])
    with pytest.raises(ValidationError):
        cache.put(PACKAGE, value)
    assert cache.get(PACKAGE) == ['OSV-existing']


def test_normalization_empty_result_expiry_and_legacy_row(cache):
    cache.put(PACKAGE, ['OSV-z', 'OSV-a', 'OSV-z'])
    assert cache.get(PACKAGE) == ['OSV-a', 'OSV-z']
    cache.put(PACKAGE, [])
    assert cache.get(PACKAGE) == []
    cache.clock = lambda: 3700
    assert cache.get(PACKAGE) is None
    corrupt(cache, 4000, '["OSV-legacy"]')
    assert cache.get(PACKAGE) == ['OSV-legacy']


@pytest.mark.parametrize('operation', ['get', 'put'])
def test_removed_database_is_not_recreated(cache, operation):
    cache.path.unlink()
    with pytest.raises(ValidationError, match='Existing'):
        cache.get(PACKAGE) if operation == 'get' else cache.put(PACKAGE, [])
    assert not cache.path.exists()


def test_directory_and_oversize_paths_are_rejected(tmp_path):
    with pytest.raises(ValidationError, match='regular'):
        AdvisoryCache(tmp_path)
    path = tmp_path / 'large.sqlite'
    with path.open('wb') as stream:
        stream.truncate(128 * 1024 * 1024 + 1)
    with pytest.raises(ValidationError, match='128 MiB'):
        AdvisoryCache(path)


def test_path_replacement_is_rechecked_for_each_operation(cache, tmp_path):
    original = tmp_path / 'original.sqlite'
    cache.path.rename(original)
    try:
        cache.path.symlink_to(original)
    except OSError:
        pytest.skip('Symlinks unavailable')
    for operation in ('get', 'put'):
        with pytest.raises(ValidationError, match='links'):
            cache.get(PACKAGE) if operation == 'get' else cache.put(PACKAGE, [])


class HTTP:
    def __init__(self, *pages):
        self.pages = list(pages)
        self.calls = []

    def request(self, url, **kwargs):
        self.calls.append((url, kwargs))
        assert self.pages, 'Unexpected query/retry'
        return HttpResponse(200, {}, json.dumps(self.pages.pop(0)).encode())


def test_multi_step_pagination_cycle_is_rejected_without_caching(cache):
    def page(token):
        return {'results': [{'next_page_token': token}]}
    http = HTTP(page('one'), page('two'), page('one'))
    with pytest.raises(ProviderError, match='repeated'):
        OSVAudit(http, cache=cache).assess(Inventory('fixture', (PACKAGE,), ()))
    assert len(http.calls) == 3 and cache.get(PACKAGE) is None


def test_cached_aggregate_limit_stops_before_any_request(cache):
    second = Dependency('PyPI', 'fixture2', '1.0', ())
    cache.put(PACKAGE, ['OSV-' + str(i) for i in range(600)])
    cache.put(second, ['OSV-' + str(i) for i in range(600)])
    http = HTTP()
    with pytest.raises(ProviderError, match='Cached'):
        OSVAudit(http, cache=cache).assess(Inventory('fixture', (PACKAGE, second), ()))
    assert not http.calls


def test_same_token_for_different_packages_is_not_a_cycle():
    second = Dependency('PyPI', 'fixture2', '1.0', ())
    http = HTTP({'results': [{'next_page_token': 'one'}, {'next_page_token': 'one'}]},
                {'results': [{}, {}]})
    result = OSVAudit(http).assess(Inventory('fixture', (PACKAGE, second), ()))
    assert result['dependency_audit']['complete_queries'] == 2
