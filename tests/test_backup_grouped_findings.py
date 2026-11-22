"""Logical backup review units retain their decisions and backing evidence."""
import unittest
from unittest.mock import patch

from server import backups, db
from server.app import create_app
from server.artifacts import counts, grouped_review_artifacts, review_progress
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

    def test_scan_publishing_during_grouping_reaches_the_next_page_refresh(self):
        for root in self.fixture.roots:
            self.fixture.finding(root / 'same.txt')
        self.fixture.prepare()

        def publish_after_grouping(conn, rows):
            grouped = grouped_review_artifacts(conn, rows)
            self.fixture.finding(self.fixture.roots[0] / 'new-file.txt')
            self.conn.commit()
            return grouped

        with patch('server.artifacts.grouped_review_artifacts', side_effect=publish_after_grouping):
            first = self.results(group_backups=True)
        self.assertEqual((first['total'], first['counts']['total'], first['findings_total']), (1, 1, 3))
        later = self.results(group_backups=True)
        self.assertEqual((later['total'], later['counts']['total'], later['findings_total']), (2, 2, 4))

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

    def test_grouping_is_shared_with_global_counts_even_when_rules_are_muted(self):
        for root in self.fixture.roots:
            self.fixture.finding(root / 'same.txt')
        self.fixture.prepare()
        with patch('server.app.ruleswitch.disabled_ids', return_value={'analyst.synthetic'}), \
             patch('server.backups.grouping', wraps=backups.grouping) as grouping:
            result = self.results(group_backups=True)
        self.assertEqual(grouping.call_count, 1)
        self.assertEqual((result['total'], result['muted_hidden']), (0, 1))
        self.assertEqual(result['counts']['total'], 1)
        self.assertEqual(result['counts']['triage'], {'new': 1})
        self.assertEqual(result['counts']['source'], {'analyst': 1})

    def test_grouped_page_builds_the_categorized_artifact_view_once(self):
        for root in self.fixture.roots:
            self.fixture.finding(root / 'same.txt')
        self.fixture.prepare()
        connect = db.connect
        queries = []

        def traced_connect(*args, **kwargs):
            conn = connect(*args, **kwargs)
            conn.set_trace_callback(queries.append)
            return conn

        with patch('server.app.db.connect', side_effect=traced_connect):
            result = self.results(group_backups=True, limit=1)
        self.assertEqual(result['total'], 1)
        self.assertEqual(len(result['findings']), 3)
        self.assertEqual(sum('WITH leaders AS' in query for query in queries), 1)

    def test_muted_severity_still_contributes_to_confirmed_group_and_facets(self):
        for root in self.fixture.roots:
            path = str(root / 'same.txt')
            db.upsert_finding(self.conn, 'webshell', 0, 'High observation', 'file', path,
                              rule_id='synthetic.muted')
            db.upsert_finding(self.conn, 'yara', 2, 'Low observation', 'file', path,
                              rule_id='synthetic.live')
            self.conn.execute('UPDATE findings SET triage=? WHERE artifact=?', ('confirmed', path))
        self.fixture.prepare()
        with patch('server.app.ruleswitch.disabled_ids', return_value={'synthetic.muted'}):
            result = self.results(group_backups=True, source='yara')
            hidden = self.results(group_backups=True, hide_severity='0')
        with patch('server.app.ruleswitch.disabled_ids', return_value=set()):
            unmuted = self.results(group_backups=True, source='yara')
        self.assertEqual(result['total'], 1)
        self.assertEqual(result['artifacts'][0]['worst'], 0)
        self.assertEqual(result['artifacts'][0]['active'], 3)
        self.assertEqual(result['counts']['severity'], {0: 1})
        self.assertEqual(result['counts']['source'], {'webshell': 1, 'yara': 1})
        self.assertEqual(result['counts']['triage'], {'confirmed': 1})
        self.assertEqual(unmuted['artifacts'][0]['active'], 6)
        self.assertEqual(result['counts'], unmuted['counts'])
        self.assertEqual(result['counts'], counts(self.conn))
        self.assertEqual(hidden['total'], 0)


if __name__ == '__main__':
    unittest.main()
