"""Installed inventory/OSV/cache acceptance; fake replies, real SQLite, no sockets."""

import io
import json
import socket
import sqlite3
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from ai_threat_lab.cli import main as cli_main
from ai_threat_lab.dependencies import AdvisoryCache, Dependency
from ai_threat_lab.http_client import HttpResponse
from ai_threat_lab.scan_bundle import read_bundle


class HTTP:
    def __init__(self, *pages):
        self.pages = list(pages)
        self.calls = []

    def request(self, url, **kwargs):
        assert url == 'https://api.osv.dev/v1/querybatch'
        assert kwargs['method'] == 'POST'
        assert kwargs['headers'] == {'Content-Type': 'application/json'}
        body = json.loads(kwargs['body'])
        for query in body['queries']:
            assert set(query) <= {'package', 'version', 'page_token'}
            assert query['package']['ecosystem'] == 'PyPI'
            assert query['package']['name'] in ('fixture-a', 'fixture-b')
        assert 'PRIVATE' not in kwargs['body'].decode()
        assert self.pages, 'Unexpected retry or cache miss'
        self.calls.append(body)
        return HttpResponse(200, {}, json.dumps(self.pages.pop(0)).encode())


def blocked(*args, **kwargs):
    raise AssertionError('Dependency acceptance must not use the network')


def command(arguments, client):
    out, err = io.StringIO(), io.StringIO()
    with (patch('ai_threat_lab.integration_cli.PublicHTTPS', return_value=client),
          patch('ai_threat_lab.scan_cli.PublicHTTPS', return_value=client),
          redirect_stdout(out), redirect_stderr(err)):
        status = cli_main(arguments)
    return status, out.getvalue(), err.getvalue()


def main():
    socket.create_connection = blocked
    socket.getaddrinfo = blocked
    with tempfile.TemporaryDirectory(prefix='dependency acceptance ') as directory:
        root = Path(directory)
        project = root / 'local project'
        project.mkdir()
        manifest = project / 'requirements.txt'
        manifest.write_text('fixture-a==1.0\nfixture-b==2.0\n# PRIVATE_SOURCE\n')
        cache_path = root / 'advisory cache.sqlite'
        args = ['audit-deps', str(project), '--network', '--share-packages',
                '--advisory-cache', str(cache_path)]
        http = HTTP({'results': [{'vulns': [{'id': 'OSV-fixture'}],
                                  'next_page_token': 'next'}, {}]},
                    {'results': [{'vulns': [{'id': 'CVE-2099-1234'}]}]})
        status, out, err = command(args, http)
        assert status == 0 and not err and len(http.calls) == 2 and not http.pages
        report = json.loads(out)
        assert len(report['findings']) == 2
        assert report['dependency_audit']['complete_queries'] == 2
        assert http.calls[1]['queries'][0]['page_token'] == 'next'
        cached = HTTP()
        status, out, err = command(args, cached)
        assert status == 0 and not err and not cached.calls
        assert json.loads(out)['dependency_audit']['cache_hits'] == 2
        destination = root / 'saved scan'
        status, out, err = command([
            'scan', str(project), '--network', '--share-packages',
            '--advisory-cache', str(cache_path), '--output-dir', str(destination),
        ], cached)
        assert status == 0 and not err and not cached.calls
        assert json.loads(out)['ai_calls'] == 0
        saved = read_bundle(destination)
        assert saved['manifest']['scope']['engine'] == 'read-only-pipeline-26'
        assert saved['documents']['dependencies.json']['dependency_audit']['cache_hits'] == 2

        negative_controls = 0
        client = HTTP()
        status, out, err = command(['audit-deps', str(project), '--network'], client)
        assert status == 2 and not out and err and not client.calls
        negative_controls += 1
        cache = AdvisoryCache(cache_path)
        package = Dependency('PyPI', 'fixture-a', '1.0', ())
        with sqlite3.connect(cache_path) as db:
            db.execute('UPDATE advisories SET expires=? WHERE key=?',
                       (float('inf'), cache.key(package)))
        status, out, err = command(args, client)
        assert status == 2 and not out and 'expiry' in err and not client.calls
        negative_controls += 1
        manifest.write_text('fixture-a==1.0\n')
        cycle = HTTP(*({'results': [{'next_page_token': token}]} for token in ('a', 'b', 'a')))
        status, out, err = command([
            'audit-deps', str(project), '--network', '--share-packages',
        ], cycle)
        assert status == 3 and not out and 'repeated' in err and len(cycle.calls) == 3
        negative_controls += 1
        malformed = HTTP({'results': [None]})
        status, out, err = command([
            'audit-deps', str(project), '--network', '--share-packages',
        ], malformed)
        assert status == 3 and not out and err and len(malformed.calls) == 1
        negative_controls += 1
    print(json.dumps({'status': 'passed', 'positive_requests': 2,
                      'negative_controls': negative_controls, 'cached_workflows': 2,
                      'live_requests': 0, 'ai_calls': 0}))


if __name__ == '__main__':
    main()
