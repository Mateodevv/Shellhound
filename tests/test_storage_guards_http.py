"""Storage failures must not become editable empty libraries or case profiles."""
import json
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from server import patterns, workspace
from server.app import create_app
from server.config import Config
from tests.test_http import _LiveServer


class StorageGuardsHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ws = Path(self.temp.name)
        self.case = workspace.create_case(self.ws, 'Saved case', reference='SYN-001',
                                          notes='Saved notes')
        self.other = workspace.create_case(self.ws, 'Other case')
        self.entry = patterns.add(self.ws, ['/synthetic-review'], name='Saved pattern')
        self.library = patterns.library_path(self.ws)
        self.identity = self.case / workspace.CASE_FILE
        self.server = _LiveServer(create_app(Config(workspace=self.ws, token='synthetic-local-token')))
        self.base = self.server.start()
        self.addCleanup(self.server.stop)

    def request(self, method, path, body=None):
        request = urllib.request.Request(self.base + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Content-Type': 'application/json', 'X-Token': 'synthetic-local-token'})
        try:
            response = urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            return response.status, json.loads(response.read())

    def unavailable(self, target):
        read_text = Path.read_text

        def read(path, *args, **kwargs):
            if path == target:
                raise PermissionError('private-storage-diagnostic-marker')
            return read_text(path, *args, **kwargs)

        return patch.object(Path, 'read_text', read)

    def assert_unavailable(self, result):
        status, body = result
        self.assertEqual(503, status)
        self.assertNotIn('private-storage-diagnostic-marker', json.dumps(body))

    def test_library_read_failure_blocks_api_edits_and_retry_recovers(self):
        original = self.library.read_bytes()
        with self.unavailable(self.library):
            self.assert_unavailable(self.request('GET', '/api/patterns'))
            self.assert_unavailable(self.request('POST', '/api/patterns',
                                                {'pattern': '/another-synthetic', 'name': 'New pattern'}))
            self.assertEqual(original, self.library.read_bytes())
        status, result = self.request('GET', '/api/patterns')
        self.assertEqual(200, status)
        self.assertIn(self.entry['id'], [row['id'] for row in result['patterns']])

    def test_case_read_failure_isolated_from_other_cases_and_cannot_be_saved(self):
        original = self.identity.read_bytes()
        with self.unavailable(self.identity):
            status, state = self.request('GET', '/api/state')
            self.assertEqual(200, status)
            unavailable = next(row for row in state['cases'] if row['slug'] == self.case.name)
            self.assertFalse(unavailable['metadata_available'])
            self.assertFalse(unavailable.get('profile_revision'))
            self.assertIn(self.other.name, [row['slug'] for row in state['cases']])
            self.assert_unavailable(self.request('GET', '/api/cases/' + self.case.name))
            self.assert_unavailable(self.request('PATCH', '/api/cases/' + self.case.name,
                                                {'notes': 'A new draft'}))
            self.assertEqual(original, self.identity.read_bytes())
        status, info = self.request('GET', '/api/cases/' + self.case.name)
        self.assertEqual(200, status)
        self.assertEqual(('Saved case', 'SYN-001', 'Saved notes'),
                         (info['name'], info['reference'], info['notes']))

    def test_corrupt_files_are_preserved_and_never_appear_empty(self):
        for target, route, method, payload in [
            (self.library, '/api/patterns', 'POST', {'pattern': '/another-synthetic'}),
            (self.identity, '/api/cases/' + self.case.name, 'PATCH', {'name': 'New draft'}),
        ]:
            with self.subTest(route=route):
                original = target.read_bytes()
                broken = b'{"private-storage-marker":'
                target.write_bytes(broken)
                self.assert_unavailable(self.request('GET', route))
                self.assert_unavailable(self.request(method, route, payload))
                self.assertEqual(broken, target.read_bytes())
                target.write_bytes(original)
