"""Saved credentials survive storage problems and malformed API requests."""
import json
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from server import settings
from server.app import create_app
from server.config import Config
from tests.test_http import _LiveServer


class SettingsStorageHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ws = Path(self.temp.name)
        settings.set_key(self.ws, 'virustotal', 'synthetic-virus-total-value')
        settings.set_key(self.ws, 'abuseipdb', 'synthetic-abuse-value')
        self.target = settings.path(self.ws)
        self.original = self.target.read_bytes()
        self.server = _LiveServer(create_app(Config(workspace=self.ws, token='synthetic-local-token')))
        self.base = self.server.start()
        self.addCleanup(self.server.stop)

    def request(self, method, path, body=None):
        req = urllib.request.Request(self.base + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Content-Type': 'application/json', 'X-Token': 'synthetic-local-token'})
        try:
            response = urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            return response.status, json.loads(response.read())

    def test_key_deletion_requires_an_explicit_empty_value(self):
        self.assertEqual(422, self.request('POST', '/api/settings/key', {'service': 'virustotal'})[0])
        self.assertEqual(self.original, self.target.read_bytes())
        self.assertEqual(200, self.request('POST', '/api/settings/key', {'service': 'virustotal', 'key': ''})[0])
        data = settings.load(self.ws)
        self.assertFalse(data['keys']['virustotal'])
        self.assertTrue(data['keys']['abuseipdb'])

    def test_malformed_credential_requests_do_not_echo_submitted_secrets(self):
        marker = 'synthetic-validation-secret'
        requests = [('/api/settings/key', 'POST', {'service': 'virustotal', 'legacy_key': marker}),
                    ('/api/settings/key', 'POST', {'service': 'virustotal', 'key': [marker]}),
                    ('/api/opencti/settings', 'PATCH', {'token': [marker]})]
        for path, method, data in requests:
            with self.subTest(path=path):
                status, result = self.request(method, path, data)
                self.assertEqual(422, status)
                self.assertNotIn(marker, json.dumps(result))
                self.assertEqual(self.original, self.target.read_bytes())

    def test_unreadable_settings_are_unavailable_not_empty_and_writes_stop(self):
        read_text = Path.read_text
        def unreadable(path, *args, **kwargs):
            if path == self.target:
                raise PermissionError('private-diagnostic-marker')
            return read_text(path, *args, **kwargs)
        with patch.object(Path, 'read_text', unreadable):
            calls = [('GET', '/api/settings', None),
                     ('POST', '/api/settings/enrichment-ack', {'accepted': True}),
                     ('POST', '/api/settings/key', {'service': 'virustotal', 'key': 'synthetic-new-key'}),
                     ('POST', '/api/settings/detection', {'indirect_php': True}),
                     ('PATCH', '/api/opencti/settings', {'sample_uploads': True})]
            for method, path, body in calls:
                with self.subTest(path=path):
                    status, result = self.request(method, path, body)
                    self.assertEqual(503, status)
                    self.assertNotIn('private-diagnostic-marker', json.dumps(result))
                    self.assertNotIn('synthetic-new-key', json.dumps(result))
                    self.assertEqual(self.original, self.target.read_bytes())
        status, result = self.request('GET', '/api/settings')
        self.assertEqual(200, status)
        self.assertTrue(result['services']['virustotal']['configured'])
        self.assertNotIn('synthetic-virus-total-value', json.dumps(result))

    def test_corrupt_settings_are_preserved_until_repaired(self):
        broken = b'{"keys":{"virustotal":"synthetic-private"'
        self.target.write_bytes(broken)
        self.assertEqual(503, self.request('GET', '/api/settings')[0])
        self.assertEqual(503, self.request('POST', '/api/settings/enrichment-ack', {'accepted': True})[0])
        self.assertEqual(broken, self.target.read_bytes())
        self.target.write_bytes(self.original)
        self.assertTrue(self.request('GET', '/api/settings')[1]['services']['virustotal']['configured'])

    def test_unknown_integration_secrets_are_preserved_but_never_published(self):
        data = settings.load(self.ws)
        data['opencti']['future_secret'] = 'synthetic-future-secret'
        data['opencti']['timeout'] = {'private': 'synthetic-invalid-timeout'}
        self.target.write_text(json.dumps(data), encoding='utf-8')
        status, result = self.request('GET', '/api/settings')
        self.assertEqual(200, status)
        self.assertEqual(30, result['opencti']['timeout'])
        self.assertNotIn('synthetic-future-secret', json.dumps(result))
        self.assertNotIn('synthetic-invalid-timeout', json.dumps(result))
        settings.set_ack(self.ws, True)
        self.assertEqual('synthetic-future-secret', json.loads(self.target.read_text())['opencti']['future_secret'])
