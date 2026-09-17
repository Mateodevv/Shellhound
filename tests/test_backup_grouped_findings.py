"""Logical backup review units retain their decisions and backing evidence."""
import unittest
from unittest.mock import patch

from server import db
from server.app import create_app
from server.artifacts import review_progress
from server.config import Config
from tests import test_backups as backup_fixtures


class GroupedBackupFindingsTests(unittest.TestCase):
    def setUp(self):
        self.fixture = backup_fixtures.BackupTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.conn = self.fixture.conn
        self.fixture.populate()
        app = create_app(Config(workspace=self.fixture.case.parent, token='synthetic-token'))
        self.endpoint = next(route.endpoint for route in app.routes
                             if route.path == '/api/cases/{slug}/findings')

    def results(self, **filters):
        self.conn.commit()
        return self.endpoint(self.fixture.case.name, **filters)

    def test_triage_filter_cannot_hide_a_conflicting_copy(self):
        for root, state in zip(self.fixture.roots, ('confirmed', 'dismissed', 'reviewed')):
            self.fixture.finding(root / 'same.txt', state)
        self.fixture.prepare()
        result = self.results(group_backups=True, hide_triage='dismissed')
        self.assertEqual(result['total'], 1)
        row = result['artifacts'][0]
        self.assertEqual((row['triage'], row['backup_count'], row['review_conflict']), ('new', 3, True))
        self.assertEqual(len(result['findings']), 3)
        self.assertEqual({f['triage'] for f in result['findings']}, {'confirmed', 'dismissed', 'reviewed'})
        self.assertEqual(result['counts']['triage'], {'new': 1})
        self.assertEqual(result['counts']['source'], {'analyst': 1})
        self.assertEqual(review_progress(self.conn), {'total': 1, 'reviewed': 0, 'remaining': 1, 'skipped': 0})

    def test_source_and_search_select_complete_groups(self):
        for root, source in zip(self.fixture.roots, ('analyst', 'yara', 'webshell')):
            db.upsert_finding(self.conn, source, 1, 'Harmless source observation', 'file',
                              str(root / 'same.txt'), rule_id=source + '.synthetic')
        self.fixture.prepare()
        for filters in ({'source': 'yara'}, {'search': 'copy 2'}):
            with self.subTest(filters=filters):
                result = self.results(group_backups=True, **filters)
                self.assertEqual(result['total'], 1)
                self.assertEqual(result['artifacts'][0]['backup_count'], 3)
                self.assertEqual({f['source'] for f in result['findings']}, {'analyst', 'yara', 'webshell'})
                self.assertEqual(result['counts']['source'], {'analyst': 1, 'yara': 1, 'webshell': 1})

    def test_unreviewed_and_reviewed_facets_remain_distinct(self):
        for root in self.fixture.roots:
            self.fixture.finding(root / 'same.txt', 'reviewed')
        self.fixture.prepare()
        result = self.results(group_backups=True, hide_triage='new')
        self.assertEqual(result['total'], 1)
        self.assertEqual(result['artifacts'][0]['triage'], 'reviewed')
        self.assertEqual(review_progress(self.conn)['skipped'], 1)
        result = self.results(group_backups=True, hide_triage='reviewed')
        self.assertEqual(result['total'], 0)

    def test_legacy_api_retains_occurrence_counts_and_decisions(self):
        for root, state in zip(self.fixture.roots, ('confirmed', 'dismissed', 'reviewed')):
            self.fixture.finding(root / 'same.txt', state)
        self.fixture.prepare()
        result = self.results(hide_triage='dismissed')
        self.assertEqual(result['total'], 2)
        self.assertEqual({row['triage'] for row in result['artifacts']}, {'confirmed', 'reviewed'})
        self.assertEqual(result['counts']['total'], 3)
        self.assertEqual(result['counts']['source'], {'analyst': 3})

    def test_complete_groups_are_selected_before_pagination(self):
        for index in range(211):
            for root in self.fixture.roots:
                path = root / f'ordinary-{index:03}.txt'
                path.write_text(f'Harmless content version {index}\n', encoding='utf-8')
                self.fixture.finding(path)
        self.fixture.prepare()
        result = self.results(group_backups=True, limit=5, offset=205)
        self.assertEqual(result['total'], 211)
        self.assertEqual(len(result['artifacts']), 5)
        self.assertEqual(len(result['findings']), 15)
        self.assertEqual([row['artifact'].split('ordinary-')[-1] for row in result['artifacts']],
                         [f'{index:03}.txt' for index in range(205, 210)])
        self.assertTrue(all(row['backup_count'] == 3 for row in result['artifacts']))

    def test_muted_counts_are_logical_units_without_losing_decisions(self):
        for root in self.fixture.roots:
            self.fixture.finding(root / 'same.txt')
        self.fixture.prepare()
        with patch('server.app.ruleswitch.disabled_ids', return_value={'analyst.synthetic'}):
            result = self.results(group_backups=True)
            self.assertEqual((result['total'], result['muted_hidden']), (0, 1))
            self.conn.execute('UPDATE findings SET triage=? WHERE artifact=?',
                              ('confirmed', str(self.fixture.roots[0] / 'same.txt')))
            result = self.results(group_backups=True)
            self.assertEqual((result['total'], result['muted_hidden']), (1, 0))
            self.assertEqual(len(result['findings']), 3)


if __name__ == '__main__':
    unittest.main()
