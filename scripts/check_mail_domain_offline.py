"""Installed mail-domain CLI acceptance: synthetic DNS only, sockets blocked."""

import io
import json
import socket
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from ai_threat_lab.cli import main as cli_main
from ai_threat_lab.http_client import HttpResponse
from ai_threat_lab.scan_bundle import read_bundle

TARGET = 'mail-domain:fixture.example'


def blocked(*args, **kwargs):
    raise AssertionError('Mail-domain acceptance must not use the network')


class SyntheticDNS:
    def __init__(self, failure=None):
        self.failure = failure
        self.calls = []

    def request(self, url, **kwargs):
        parts = urlsplit(url)
        assert parts.scheme == 'https' and parts.netloc == 'cloudflare-dns.com'
        assert parts.path == '/dns-query'
        assert kwargs == {'headers': {'Accept': 'application/dns-json'}}
        query = parse_qs(parts.query)
        name = query['name'][0]
        assert query == {'name': [name], 'type': ['TXT']}
        assert name in ('fixture.example', '_dmarc.fixture.example',
                        'sel._domainkey.fixture.example')
        assert name not in self.calls, 'No retry/recursive lookup allowed'
        self.calls.append(name)
        records = {
            'fixture.example': '"v=spf1 " "-all"',
            '_dmarc.fixture.example': '"v=DMARC1; p=reject; rua=mailto:PRIVATE@example.com"',
            'sel._domainkey.fixture.example': '"v=DKIM1; p=PRIVATE_KEY"',
        }
        body = self.failure if self.failure is not None else {
            'Status': 0, 'TC': False, 'Question': [{'name': name + '.', 'type': 16}],
            'Answer': [{'name': name + '.', 'type': 16, 'data': records[name]}],
        }
        assert len(self.calls) <= 3
        return HttpResponse(200, {}, json.dumps(body).encode())


def command(args, client):
    stdout, stderr = io.StringIO(), io.StringIO()
    with (patch('ai_threat_lab.integration_cli.PublicHTTPS', return_value=client) as factory,
          redirect_stdout(stdout), redirect_stderr(stderr)):
        status = cli_main(args)
    return status, stdout.getvalue(), stderr.getvalue(), factory


def main():
    socket.create_connection = blocked
    socket.getaddrinfo = blocked
    common = [TARGET, '--network', '--allow-host', 'fixture.example']
    with tempfile.TemporaryDirectory(prefix='mail domain acceptance ') as directory:
        client = SyntheticDNS()
        destination = Path(directory) / 'saved scan'
        status, out, err, factory = command([
            'scan', *common, '--dkim-selector', 'sel', '--output-dir', str(destination),
        ], client)
        factory.assert_called_once_with(['cloudflare-dns.com'], max_requests=3)
        assert status == 0 and not err
        assert json.loads(out)['ai_calls'] == 0
        saved = read_bundle(destination)
        assert saved['manifest']['scope']['engine'] == 'read-only-pipeline-28'
        assert saved['documents']['assessment.json']['status'] == 'partial'
        assert 'PRIVATE' not in json.dumps(saved)
        assert len(client.calls) == 3

        client = SyntheticDNS()
        status, out, err, _ = command(['audit', *common], client)
        assert status == 0 and not err and len(client.calls) == 2
        result = json.loads(out)
        assert not result['findings'] and any('not checked' in x for x in result['not_checked'])

        scope_rejections = 0
        for flags in ([], ['--network'], ['--network', '--allow-host', 'other.example']):
            client = SyntheticDNS()
            status, out, err, factory = command(['audit', TARGET, *flags], client)
            assert status == 2 and not out and err
            factory.assert_not_called()
            assert not client.calls
            scope_rejections += 1

        negative_controls = 0
        for body in ({'Status': False}, {'Status': 2}, {'Status': 0, 'TC': True},
                     {'Status': 0, 'Answer': None}, {'Status': 0, 'Question': []}):
            client = SyntheticDNS(failure=body)
            status, out, err, _ = command(['audit', *common], client)
            assert status == 3 and not out and 'Integration error:' in err
            assert len(client.calls) == 1
            negative_controls += 1
        client = SyntheticDNS(failure={'Status': 2})
        failed = Path(directory) / 'failed scan'
        status, out, err, _ = command(['scan', *common, '--output-dir', str(failed)], client)
        assert status == 3 and json.loads(out)['failed_modules']
        saved = read_bundle(failed)
        assert saved['documents']['assessment.json']['status'] == 'not_configured'
        assert saved['documents']['assessment.json']['findings'] == []
        negative_controls += 1
    print(json.dumps({'status': 'passed', 'positive_requests': 5,
                      'scope_rejections': scope_rejections, 'negative_controls': negative_controls,
                      'live_requests': 0, 'ai_calls': 0}))


if __name__ == '__main__':
    main()
