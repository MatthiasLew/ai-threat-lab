"""Installed Gmail settings acceptance using synthetic tokens and blocked sockets."""

import io
import json
import os
import socket
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from ai_threat_lab.cli import main as cli_main
from ai_threat_lab.http_client import HttpResponse
from ai_threat_lab.scan_bundle import read_bundle

TARGET = 'mailbox:fixture@example.com'
BASE = 'https://gmail.googleapis.com/gmail/v1/users/me'
TOKEN = 'offline-fixture-token'
FLAGS = [TARGET, '--network', '--allow-host', 'gmail.googleapis.com']


def blocked(*args, **kwargs):
    raise AssertionError('Gmail acceptance must not contact the network')


class HTTP:
    def __init__(self, documents=None):
        self.documents = list(documents if documents is not None else [
            {'emailAddress': 'fixture@example.com'},
            {'enabled': True, 'emailAddress': 'PRIVATE_AUTO@example.com'},
            {'filter': [{'criteria': {'query': 'PRIVATE_QUERY'},
                         'action': {'forward': 'PRIVATE_FILTER@example.com'}}]},
        ])
        self.calls = []

    def request(self, url, **kwargs):
        assert len(self.calls) < 3 and self.documents
        assert url == BASE + ('/profile', '/settings/autoForwarding', '/settings/filters')[
            len(self.calls)
        ]
        assert kwargs == {'headers': {'Authorization': 'Bearer ' + TOKEN}}
        self.calls.append(url)
        body = self.documents.pop(0)
        return HttpResponse(200, {}, json.dumps(body).encode())


def command(arguments, client):
    out, err = io.StringIO(), io.StringIO()
    with (patch('ai_threat_lab.integration_cli.PublicHTTPS', return_value=client) as factory,
          redirect_stdout(out), redirect_stderr(err)):
        status = cli_main(arguments)
    return status, out.getvalue(), err.getvalue(), factory


def main():
    socket.create_connection = blocked
    socket.getaddrinfo = blocked
    os.environ['GMAIL_ACCESS_TOKEN'] = TOKEN
    with tempfile.TemporaryDirectory(prefix='gmail acceptance ') as folder:
        destination = Path(folder) / 'saved scan'
        client = HTTP()
        status, out, err, factory = command([
            'scan', *FLAGS, '--output-dir', str(destination),
        ], client)
        assert status == 0 and not err and len(client.calls) == 3
        factory.assert_called_once_with(['gmail.googleapis.com'], max_requests=3)
        assert json.loads(out)['ai_calls'] == 0
        saved = read_bundle(destination)
        assessment = saved['documents']['assessment.json']
        assert assessment['status'] == 'partial' and len(assessment['findings']) == 2
        assert saved['manifest']['scope']['engine'] == 'read-only-pipeline-26'
        assert all(value not in json.dumps(saved) for value in ('PRIVATE_', TOKEN))

        client = HTTP([{'emailAddress': 'fixture@example.com'}, {'enabled': False}, {}])
        status, out, err, _ = command(['audit', *FLAGS], client)
        assert status == 0 and not err and not json.loads(out)['findings']
        assert len(client.calls) == 3

        scope_rejections = 0
        for flags in ([], ['--network'], ['--network', '--allow-host', 'other.example']):
            client = HTTP()
            status, out, err, factory = command(['audit', TARGET, *flags], client)
            assert status == 2 and not out and err and not client.calls
            factory.assert_not_called()
            scope_rejections += 1
        negative_controls = 0
        documents = [
            [{'emailAddress': None}], [{'emailAddress': 'other@example.com'}],
            [{'emailAddress': 'fixture@example.com'}, {'enabled': 0}],
            [{'emailAddress': 'fixture@example.com'}, {'enabled': False}, {'filter': [None]}],
            [{'emailAddress': 'fixture@example.com'}, {'enabled': True},
             {'filter': [{'action': {'forward': 'PRIVATE@example.com'}}, {'action': None}]}],
        ]
        for records in documents:
            client = HTTP(records)
            status, out, err, _ = command(['audit', *FLAGS], client)
            assert status == 3 and not out and 'Integration error:' in err
            assert 'PRIVATE' not in err and TOKEN not in err and len(client.calls) == len(records)
            negative_controls += 1
        for token in ('', 'invalid token'):
            os.environ['GMAIL_ACCESS_TOKEN'] = token
            client = HTTP()
            status, out, err, _ = command(['audit', *FLAGS], client)
            assert status == 3 and not out and err and not client.calls
            negative_controls += 1
        os.environ['GMAIL_ACCESS_TOKEN'] = TOKEN
        failed = Path(folder) / 'failed scan'
        client = HTTP([{'emailAddress': 'other@example.com'}])
        status, out, err, _ = command(['scan', *FLAGS, '--output-dir', str(failed)], client)
        assert status == 3 and json.loads(out)['failed_modules'] == ['target_assessment']
        failed_assessment = read_bundle(failed)['documents']['assessment.json']
        assert failed_assessment['status'] == 'not_configured'
        assert not failed_assessment['findings']
        negative_controls += 1
    print(json.dumps({'status': 'passed', 'positive_requests': 6, 'scope_rejections': 3,
                      'negative_controls': negative_controls, 'live_requests': 0, 'ai_calls': 0}))


if __name__ == '__main__':
    main()
