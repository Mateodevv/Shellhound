"""Dashboard review counts and their links share the grouped Findings scope."""
import unittest

from server import db, file_classifications
from server.app import create_app
from server.chain import case_chain
from server.config import Config
from tests import test_backups as backup_fixtures


class BackupDashboardCountsTests(unittest.TestCase):
    def setUp(self):
        self.fixture = backup_fixtures.BackupTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.conn = self.fixture.conn
        self.fixture.populate()
        app = create_app(Config(workspace=self.fixture.case.parent, token='synthetic-token'))
        endpoints = {route.path: route.endpoint for route in app.routes if hasattr(route, 'endpoint')}
        self.dashboard = endpoints['/api/cases/{slug}/dashboard']
        self.findings = endpoints['/api/cases/{slug}/findings']

    def prepare(self, states):
        for root, state in zip(self.fixture.roots, states):
            path = str(root / 'same.txt')
            db.upsert_finding(self.conn, 'webshell', 1, 'Harmless marker observation', 'file', path,
                              rule_id='synthetic.observation')
            self.conn.execute('UPDATE findings SET triage=? WHERE artifact=?', (state, path))
        self.fixture.prepare()

    def overview(self):
        self.conn.commit()
        return self.dashboard(self.fixture.case.name, lang='en', tz='utc')

    def list(self, **filters):
        return self.findings(self.fixture.case.name, group_backups=True, **filters)

    def test_identical_copies_count_once_in_overview_and_linked_groups(self):
        self.prepare(['confirmed'] * 3)
        result = self.overview()
        confirmed = self.list(hide_triage='new,reviewed,dismissed')
        self.assertEqual(result['triage'], {'confirmed': 1})
        self.assertEqual(result['triage']['confirmed'], confirmed['total'])
        self.assertEqual(result['severity'], {1: 1})
        self.assertEqual(result['confirmed_kinds'], {'file': 1})
        self.assertEqual(result['confirmed_severity'], {1: 1})
        self.assertEqual(len(result['confirmed_artifacts']), 1)
        self.assertEqual(len(result['notable_artifacts']), 1)
        top = result['top_findings']['groups'][0]
        self.assertEqual((top['confirmed'], top['awaiting_review'], top['kinds']), (1, 0, {'file': 1}))
        self.assertEqual(self.list(category=top['category'], hide_triage='dismissed')['total'], 1)
        summary = result['incident_summary']
        self.assertEqual((summary['malware_files'], summary['pending_malware_files']), (1, 0))
        self.assertEqual(self.list(summary_group='malware_files', hide_triage='new,reviewed,dismissed')['total'], 1)
        self.assertTrue(result['has_confirmed_findings'])
        # Physical observations still retain all three evidence copies.
        chain = case_chain(self.fixture.case, lang='en', tz_mode='utc', event_cap=None)
        self.assertEqual(result['chronology']['total_events'], chain['total_events'])
        observed = {row['artifact'] for row in chain['events'] if row['artifact_kind'] == 'file'}
        self.assertEqual(observed, {str(root / 'same.txt') for root in self.fixture.roots})
        self.assertEqual(len(result['evidence']), 3)

    def test_conflicting_group_is_pending_without_retracting_compromise(self):
        self.prepare(['confirmed', 'dismissed', 'reviewed'])
        result = self.overview()
        pending = self.list(hide_triage='confirmed,dismissed')
        self.assertEqual(result['triage'], {'new': 1})
        self.assertEqual(pending['total'], result['triage']['new'])
        self.assertTrue(pending['artifacts'][0]['review_conflict'])
        self.assertEqual(pending['artifacts'][0]['backup_count'], 3)
        self.assertEqual(self.list(hide_triage='new,reviewed,dismissed')['total'], 0)
        self.assertEqual(result['confirmed_kinds'], {})
        self.assertEqual(result['confirmed_severity'], {})
        self.assertEqual(result['confirmed_artifacts'], [])
        self.assertTrue(result['has_confirmed_findings'])
        top = result['top_findings']['groups'][0]
        self.assertEqual((top['confirmed'], top['awaiting_review']), (0, 1))
        summary = result['incident_summary']
        self.assertEqual((summary['malware_files'], summary['pending_malware_files']), (0, 1))
        self.assertEqual(self.list(summary_group='malware_files', hide_triage='confirmed,dismissed')['total'], 1)

    def test_changed_content_remains_a_separate_finding_version(self):
        (self.fixture.roots[2] / 'same.txt').write_text('Different harmless version\n', encoding='utf-8')
        self.prepare(['confirmed'] * 3)
        result = self.overview()
        self.assertEqual(result['triage'], {'confirmed': 2})
        self.assertEqual(result['confirmed_kinds'], {'file': 2})
        self.assertEqual(result['incident_summary']['malware_files'], 2)
        self.assertEqual(self.list(summary_group='malware_files')['total'], 2)

    def test_a_supporting_copy_can_qualify_group_without_overriding_explicit_classes(self):
        self.prepare(['confirmed'] * 3)
        file_classifications.store(self.conn, str(self.fixture.roots[0] / 'same.txt'), [], 'confirmed')
        result = self.overview()
        self.assertEqual(result['incident_summary']['malware_files'], 1)
        group = self.list(summary_group='malware_files')
        self.assertEqual(group['total'], 1)
        self.assertEqual(group['artifacts'][0]['backup_count'], 3)
        self.assertEqual(len(group['findings']), 3)
        for root in self.fixture.roots:
            file_classifications.store(self.conn, str(root / 'same.txt'), [], 'confirmed')
        result = self.overview()
        self.assertEqual(result['incident_summary']['malware_files'], 0)
        self.assertEqual(self.list(summary_group='malware_files')['total'], 0)


if __name__ == '__main__':
    unittest.main()
