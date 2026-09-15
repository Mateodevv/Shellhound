"""Dashboard facts and offline demo creation against real evidence and HTTP."""
import json
import tempfile
import unittest
import urllib.request
import urllib.error
from pathlib import Path
from server import db, file_classifications, workspace
from server.casework.testcase import generate
from server.casework.incident_summary import summarize
from server.chain import case_chain
from server.engines import logindex
from server.app import create_app
from server.config import Config
from tests.test_http import _LiveServer


class IncidentDashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = generate(self.root)

    def summary(self):
        return summarize(self.case, case_chain(self.case, event_cap=None))

    def test_demo_is_repeatable_and_does_not_overwrite_cases(self):
        again = generate(self.root)
        self.assertNotEqual(self.case, again)
        self.assertEqual(9, logindex.overview(self.case)['lines'])
        self.assertEqual(9, logindex.overview(again)['lines'])
        self.assertTrue(logindex.status(self.case, [str(self.case / 'training-evidence/access.log')])['fresh'])
        for path in (self.case / 'training-evidence/webroot').rglob('*'):
            if path.is_file():
                text = path.read_text(encoding='utf-8')
                self.assertNotIn('<?', text)
                self.assertIn('SYNTHETIC TRAINING FILE', text)

    def test_confirmed_only_not_all_log_clients_or_file_times(self):
        from datetime import datetime, timezone
        result = self.summary()
        self.assertEqual(1, result['attacker_ips'])
        self.assertEqual(1, result['malware_files'])
        for key, minute in [('first_action', 0), ('last_action', 4)]:
            expected = int(datetime(2026, 9, 8, 9, minute, tzinfo=timezone.utc).timestamp())
            self.assertEqual(expected, result[key])
        overview = logindex.overview(self.case)
        self.assertLess(overview['first_epoch'], result['first_action'])
        self.assertGreater(overview['last_epoch'], result['last_action'])

    def test_multilabel_file_counted_once_and_dismissal_clears_summary(self):
        conn = db.connect(self.case)
        file = str(self.case / 'training-evidence/webroot/uploads/training-shell.php')
        file_classifications.store(conn, file, ['webshell', 'malware', 'backdoor'], 'confirmed')
        conn.commit()
        self.assertEqual(1, self.summary()['malware_files'])
        conn.execute("UPDATE findings SET triage='dismissed'")
        conn.commit()
        conn.close()
        self.assertEqual({'first_action': None, 'last_action': None, 'attacker_ips': 0, 'malware_files': 0}, self.summary())

    def test_stale_log_does_not_claim_current_action_times(self):
        path = self.case / 'training-evidence/access.log'
        path.write_text(path.read_text(encoding='utf-8') + '\n', encoding='utf-8')
        result = self.summary()
        self.assertIsNone(result['first_action'])
        self.assertIsNone(result['last_action'])

    def test_latest_successful_file_request_without_confirmed_client(self):
        conn = db.connect(self.case)
        conn.execute("UPDATE findings SET triage='new' WHERE artifact_kind='client'")
        conn.commit()
        conn.close()
        result = self.summary()
        self.assertEqual(0, result['attacker_ips'])
        self.assertEqual(120, result['last_action'] - result['first_action'])

    def test_http_requires_token_and_returns_openable_case(self):
        config = Config(workspace=self.root, token='synthetic-test-token')
        server = _LiveServer(create_app(config))
        self.addCleanup(server.stop)
        base = server.start()
        def request(token):
            return urllib.request.Request(base + '/api/testcase', data=b'{}',
                headers={'Content-Type': 'application/json', **({'X-Token': config.token} if token else {})})
        before = len(workspace.list_cases(self.root))
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request(False))
        self.assertIn(error.exception.code, (401, 403))
        error.exception.close()
        self.assertEqual(before, len(workspace.list_cases(self.root)))
        with urllib.request.urlopen(request(True), timeout=20) as response:
            created = json.load(response)
        with urllib.request.urlopen(urllib.request.Request(base + '/api/cases/' + created['slug'] + '/dashboard', headers={'X-Token': config.token})) as response:
            data = json.load(response)
        self.assertEqual(1, data['incident_summary']['attacker_ips'])
