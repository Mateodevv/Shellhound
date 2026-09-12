"""Case-scoped marker writes and stable timeline navigation over real HTTP."""
import json
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from server import db, workspace
from server.app import create_app
from server.config import Config
from tests.test_http import _LiveServer


class FirstSignApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='marker api ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = Config(workspace=self.root / 'cases', token='test-token')
        self.case = workspace.create_case(self.config.workspace, 'Marker case')
        self.other = workspace.create_case(self.config.workspace, 'Other case')
        self.events = [{
            'id': f'event-{i}', 'at': 1800000000 + i, 'epoch': 1800000000 + i,
            'kind': 'erfolg', 'title': f'Harmless observation {i}', 'detail': 'Test context',
            'source': 'log', 'artifact': f'/evidence/item-{i}.txt', 'artifact_kind': 'file',
            'artifact_rel': f'item-{i}.txt', 'ip': '', 'severity': 1,
            'first_sign_eligible': True, 'first_sign_selectable': True, 'first_sign_basis': 'request',
        } for i in range(205)]
        self.chain = {
            'events': self.events, 'confirmed': 205, 'gaps': [], 'undated': [],
            'span': {'first': 1800000000, 'last': 1800000204},
            'event_span': {'first': 1800000000, 'last': 1800000204},
            'total_events': 205, 'truncated': False, 'offsets': {'logs': 0, 'dump': 0},
            'tz_mode': 'utc', 'zone': 'UTC', 'tz_offsets': ['UTC'], 'tz_mixed': False,
        }
        def build(case, *args, **kwargs):
            if Path(case) == self.other:
                return {**self.chain, 'events': [], 'confirmed': 0, 'total_events': 0}
            return {**self.chain, 'events': list(self.events)}
        self.patcher = patch('server.app.case_chain', side_effect=build)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.server = _LiveServer(create_app(self.config))
        self.addCleanup(self.server.stop)
        self.base = self.server.start()

    def call(self, suffix, body=None, token=True, slug=None):
        url = f'{self.base}/api/cases/{slug or self.case.name}/{suffix}'
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['X-Token'] = self.config.token
        request = urllib.request.Request(url, headers=headers,
            data=json.dumps(body).encode() if body is not None else None,
            method='POST' if body is not None else 'GET')
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)

    def test_jump_opens_containing_page_in_both_orders_and_missing_event_is_explicit(self):
        for order, offset in [('asc', 160), ('desc', 0)]:
            status, result = self.call(f'chain?focus=event-173&order={order}')
            self.assertEqual(200, status)
            self.assertEqual(offset, result['offset'])
            self.assertTrue(result['focus_found'])
            self.assertIn('event-173', [event['id'] for event in result['events']])
            self.assertEqual(205, result['total_events'])
        status, result = self.call('chain?focus=gone')
        self.assertEqual(200, status)
        self.assertFalse(result['focus_found'])
        self.assertEqual(0, result['offset'])
        self.assertIsNone(self.call('chain?offset=80')[1]['focus_found'])

    def test_override_persists_is_case_scoped_and_can_restore_automatic(self):
        status, result = self.call('first-sign', {'event_id': 'event-173', 'note': 'Reviewed context'})
        self.assertEqual(200, status)
        self.assertEqual('manual', result['mode'])
        self.assertTrue(result['earlier_candidate'])
        self.assertEqual('event-173', self.call('first-sign')[1]['event']['id'])
        self.assertEqual('Reviewed context', self.call('first-sign')[1]['note'])
        self.assertEqual('no_confirmed', self.call('first-sign', slug=self.other.name)[1]['state'])
        status, reset = self.call('first-sign', {'event_id': None})
        self.assertEqual(200, status)
        self.assertEqual('automatic', reset['mode'])
        self.assertEqual('event-0', reset['event']['id'])

    def test_invalid_or_revoked_event_cannot_overwrite_saved_choice(self):
        self.call('first-sign', {'event_id': 'event-173', 'note': 'Keep this'})
        self.events[5]['first_sign_selectable'] = False
        for event_id in ('not-in-case', 'event-5'):
            status, _ = self.call('first-sign', {'event_id': event_id, 'note': 'Should not save'})
            self.assertEqual(409, status)
        self.assertEqual('Keep this', self.call('first-sign')[1]['note'])
        self.events[173]['first_sign_selectable'] = False
        result = self.call('first-sign')[1]
        self.assertEqual('stale_override', result['state'])
        self.assertEqual('event-173', result['event']['id'])
        self.assertEqual('Keep this', result['note'])

    def test_authentication_input_validation_and_unknown_cases(self):
        self.assertEqual(401, self.call('first-sign', token=False)[0])
        self.assertEqual(401, self.call('first-sign', {'event_id': None}, token=False)[0])
        self.assertEqual(422, self.call('first-sign', {})[0])
        self.assertEqual(422, self.call('first-sign', {'event_id': 'event-1', 'note': 'n' * 2001})[0])
        self.assertEqual(404, self.call('first-sign', slug='missing-case')[0])
        self.assertEqual(409, self.call('first-sign', {'event_id': 'event-1'}, slug=self.other.name)[0])

    def test_save_rebuilds_evidence_after_reserving_case_transaction(self):
        original = db.connect
        writes = []
        def traced(path):
            conn = original(path)
            conn.set_trace_callback(lambda query: writes.append(query.split()[0].upper()))
            return conn
        def build(*args, **kwargs):
            self.assertIn('BEGIN', writes)
            self.assertIsNone(kwargs['event_cap'])
            return {**self.chain, 'events': self.events}
        with patch('server.app.db.connect', side_effect=traced), patch('server.app.case_chain', side_effect=build):
            self.assertEqual(200, self.call('first-sign', {'event_id': 'event-1'})[0])
        self.assertIn('COMMIT', writes)
