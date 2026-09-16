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
        self.case = generate(self.root, analyse=False)

    def analyse_and_review(self):
        # Analyst decisions belong to the test scenario, never to the generator.
        logindex.build(self.case, [str(self.case / 'training-evidence/access.log')])
        conn = db.connect(self.case)
        file = str(self.case / 'training-evidence/webroot/uploads/training-shell.xml.php')
        db.upsert_finding(conn, 'webshell', db.SEV_HIGH, 'Test marker', 'file', file, rule_id='test.marker')
        db.upsert_finding(conn, 'analyst', db.SEV_HIGH, 'Test client', 'client', '192.0.2.14', rule_id='test.client')
        file_classifications.store(conn, file, ['webshell'], 'confirmed')
        conn.execute("UPDATE findings SET triage='confirmed',triaged_at=? WHERE artifact IN (?,?)", (db.now(), file, '192.0.2.14'))
        conn.commit()
        conn.close()

    def summary(self):
        return summarize(self.case, case_chain(self.case, event_cap=None))

    def test_demo_is_repeatable_and_does_not_overwrite_cases(self):
        again = generate(self.root, analyse=False)
        self.assertNotEqual(self.case, again)
        for case in (self.case, again):
            conn = db.connect(case)
            for table in ('findings', 'iocs', 'ioc_assessments'):
                self.assertEqual(0, conn.execute(f'SELECT count(*) FROM {table}').fetchone()[0])
            self.assertEqual({'webroot', 'access_logs', 'sql_dump'}, {r[0] for r in conn.execute('SELECT kind FROM evidence')})
            conn.close()
            self.assertFalse(logindex.status(case, [])['exists'])
        for path in (self.case / 'training-evidence/webroot').rglob('*'):
            if path.is_file():
                text = path.read_text(encoding='utf-8')
                self.assertTrue(text.strip())

    def test_demo_matches_bundled_jce_pattern_without_creating_findings(self):
        from server import patterns
        logindex.build(self.case, [str(self.case / 'training-evidence/access.log')])
        pattern = next(p for p in patterns.bundled() if p['id'] == 'joomla-jce-rce')
        conn = db.connect(self.case)
        before = conn.execute('SELECT count(*) FROM findings').fetchone()[0]
        result = logindex.match_rule(self.case, pattern['rule'])
        self.assertGreater(result['hits'], 0)
        self.assertEqual(1, result['clients_total'])
        self.assertEqual(before, conn.execute('SELECT count(*) FROM findings').fetchone()[0])
        conn.close()

    def test_confirmed_only_not_all_log_clients_or_file_times(self):
        self.analyse_and_review()
        from datetime import datetime, timezone
        result = self.summary()
        self.assertEqual(1, result['attacker_ips'])
        self.assertEqual(1, result['malware_files'])
        for key, minute in [('first_action', 0), ('last_action', 4)]:
            expected = int(datetime(2026, 9, 9, 9, minute, tzinfo=timezone.utc).timestamp())
            self.assertEqual(expected, result[key])
        overview = logindex.overview(self.case)
        self.assertGreaterEqual(overview['last_epoch'] - overview['first_epoch'], 2 * 86400)
        self.assertLess(overview['first_epoch'], result['first_action'])
        self.assertGreater(overview['last_epoch'], result['last_action'])

    def test_multilabel_file_counted_once_and_dismissal_clears_summary(self):
        self.analyse_and_review()
        conn = db.connect(self.case)
        file = str(self.case / 'training-evidence/webroot/uploads/training-shell.xml.php')
        file_classifications.store(conn, file, ['webshell', 'malware', 'backdoor'], 'confirmed')
        conn.commit()
        self.assertEqual(1, self.summary()['malware_files'])
        conn.execute("UPDATE findings SET triage='dismissed'")
        conn.commit()
        conn.close()
        self.assertEqual({'first_action': None, 'last_action': None,
                          'last_action_event_id': None, 'attacker_ips': 0,
                          'confirmed_ips': 0, 'pending_ips': 0,
                          'malware_files': 0, 'pending_malware_files': 0}, self.summary())

    def test_stale_log_does_not_claim_current_action_times(self):
        self.analyse_and_review()
        path = self.case / 'training-evidence/access.log'
        path.write_text(path.read_text(encoding='utf-8') + '\n', encoding='utf-8')
        result = self.summary()
        self.assertIsNone(result['first_action'])
        self.assertIsNone(result['last_action'])

    def test_latest_successful_file_request_without_confirmed_client(self):
        self.analyse_and_review()
        conn = db.connect(self.case)
        conn.execute("UPDATE findings SET triage='new' WHERE artifact_kind='client'")
        conn.commit()
        conn.close()
        result = self.summary()
        self.assertEqual(0, result['attacker_ips'])
        self.assertEqual(120, result['last_action'] - result['first_action'])
        chain = case_chain(self.case, event_cap=None)
        anchor = next(event for event in chain['events']
                      if event['id'] == result['last_action_event_id'])
        self.assertEqual(result['last_action'], anchor['epoch'])

    def test_files_produce_reviewable_findings_only_after_analysis(self):
        from server.engines import webshell
        root = self.case / 'training-evidence/webroot'
        hits, skipped, inert = webshell.scan_file(str(root / 'uploads/training-shell.xml.php'), root=str(root))
        self.assertTrue(any(hit[0] == 'webshell.double_ext' for hit in hits))
        self.assertIsNone(skipped)

    def test_sql_dump_can_be_scanned_without_analyst_decisions(self):
        from server.engines import sqldump
        sqldump.scan(self.case, [str(self.case / 'training-evidence/training-wordpress.sql')])
        conn = db.connect(self.case)
        self.assertGreater(conn.execute('SELECT count(*) FROM db_tables').fetchone()[0], 0)
        self.assertEqual(0, conn.execute("SELECT count(*) FROM findings WHERE triage!='new'").fetchone()[0])
        conn.close()

    def test_default_demo_is_analysed_with_cms_but_no_decisions(self):
        case = generate(self.root)
        conn = db.connect(case)
        self.assertGreater(conn.execute('SELECT count(*) FROM findings').fetchone()[0], 0)
        self.assertEqual(0, conn.execute("SELECT count(*) FROM findings WHERE triage!='new'").fetchone()[0])
        self.assertEqual(0, conn.execute('SELECT count(*) FROM iocs').fetchone()[0])
        self.assertEqual(1, conn.execute('SELECT count(*) FROM cms_installs').fetchone()[0])
        self.assertEqual(3, conn.execute('SELECT count(*) FROM cms_items').fetchone()[0])
        self.assertGreater(conn.execute('SELECT count(*) FROM db_tables').fetchone()[0], 0)
        conn.close()
        self.assertTrue(logindex.status(case, [str(case / 'training-evidence/access.log')])['fresh'])

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
        self.assertEqual(0, data['incident_summary']['attacker_ips'])
