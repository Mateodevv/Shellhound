"""Harmless current-version scan proofs, independent of folder timestamps."""
import hashlib
import json
import sqlite3
import unittest
from contextlib import closing
from types import SimpleNamespace
from unittest.mock import patch

from server import backups, db, file_scan_receipts
from server.engines import webshell, yarascan
from tests import test_backups as backup_fixtures


class FileScanReceiptTests(unittest.TestCase):
    def setUp(self):
        self.fixture = backup_fixtures.BackupTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.fixture.populate()
        self.conn = self.fixture.conn
        self.path = self.fixture.roots[0] / 'same.txt'
        self.fixture.prepare()

    def history(self, name='same.txt'):
        return backups.history(self.conn, self.fixture.site, name)['entries'][0]

    def scan(self, **kwargs):
        self.conn.commit()
        return webshell.scan(self.fixture.case, [str(root) for root in self.fixture.roots], **kwargs)

    def test_legacy_folder_receipt_does_not_cover_a_file(self):
        self.conn.execute('UPDATE evidence SET scanned_at=?', (db.now(),))
        self.assertEqual(self.history()['scan_state'], 'not_analyzed')

    def test_case_upgrade_does_not_manufacture_file_receipts(self):
        self.conn.execute('DROP TABLE file_scan_receipts')
        self.conn.execute("UPDATE meta SET value='21' WHERE key='schema_version'")
        self.conn.execute('UPDATE evidence SET scanned_at=?', (db.now(),))
        self.conn.commit()
        with closing(db.connect(self.fixture.case)) as conn:
            self.assertEqual(db.one(conn, "SELECT value FROM meta WHERE key='schema_version'")['value'],
                             str(db.CASE_SCHEMA_VERSION))
            self.assertEqual(db.rows(conn, 'SELECT * FROM file_scan_receipts'), [])
            self.assertEqual(backups.history(conn, self.fixture.site, 'same.txt')['entries'][0]['scan_state'], 'not_analyzed')

    def test_success_indexes_every_unflagged_file_and_survives_reopen(self):
        self.scan()
        with closing(db.connect(self.fixture.case)) as conn:
            indexed = db.one(conn, 'SELECT * FROM content_files WHERE artifact=?', (str(self.path),))
            receipt = db.one(conn, 'SELECT * FROM file_scan_receipts WHERE artifact=?', (str(self.path),))
            self.assertEqual(indexed['sha256'], hashlib.sha256(self.path.read_bytes()).hexdigest())
            self.assertEqual(indexed['marker'], receipt['marker'])
            self.assertEqual(len(db.rows(conn, 'SELECT * FROM file_scan_receipts')),
                             sum(len(list(root.glob('*'))) for root in self.fixture.roots))
            self.assertEqual(backups.history(conn, self.fixture.site, 'same.txt')['entries'][0]['scan_state'], 'no_detections')

    def test_added_or_changed_file_requires_its_own_current_version_scan(self):
        self.scan()
        self.path.write_text('Different harmless text\n', encoding='utf-8')
        (self.fixture.roots[0] / 'added.txt').write_text('Later harmless file\n', encoding='utf-8')
        self.fixture.prepare()
        self.assertEqual(self.history()['scan_state'], 'not_analyzed')
        self.assertEqual(self.history('added.txt')['scan_state'], 'not_analyzed')
        self.scan()
        self.assertEqual(self.history()['scan_state'], 'no_detections')
        self.assertEqual(self.history('added.txt')['scan_state'], 'no_detections')

    def test_skip_with_unchanged_metadata_invalidates_previous_receipt(self):
        self.scan()
        with patch.object(webshell, 'scan_file', return_value=([], 'synthetic read error', None)):
            self.scan()
        self.assertIsNone(db.one(self.conn, 'SELECT * FROM file_scan_receipts WHERE artifact=?', (str(self.path),)))
        self.assertEqual(self.history()['scan_state'], 'not_analyzed')

    def test_all_scheduled_file_engines_need_matching_receipts(self):
        self.scan()
        attempt = {'engines': {'webshell': {'state': 'complete'}, 'yara': {'state': 'complete'}}}
        self.conn.execute('UPDATE evidence SET stats=?', (json.dumps({'last_attempt': attempt}),))
        self.assertEqual(self.history()['scan_state'], 'not_analyzed')
        self.conn.commit()
        fake_rules = SimpleNamespace(match=lambda **kwargs: [])
        with patch.object(yarascan, '_compile', return_value=(fake_rules, [], 1)):
            yarascan.scan(self.fixture.case, [str(root) for root in self.fixture.roots], workspace=self.fixture.root)
        self.assertEqual(self.history()['scan_state'], 'no_detections')
        attempt['engines']['yara']['state'] = 'failed'
        self.conn.execute('UPDATE evidence SET stats=?', (json.dumps({'last_attempt': attempt}),))
        self.assertEqual(self.history()['scan_state'], 'not_analyzed')

    def test_analyst_verdict_is_not_a_scanner_detection(self):
        self.scan()
        db.upsert_finding(self.conn, 'webshell', 1, 'Harmless inherited verdict', 'file', str(self.path),
                          engine='content_assessment', rule_id='analyst.content_assessment')
        self.assertEqual(self.history()['scan_state'], 'no_detections')

    def test_no_custom_yara_rules_does_not_create_an_unexamined_engine_gap(self):
        self.scan()
        attempt = {'engines': {'webshell': {'state': 'complete'},
                               'yara': {'state': 'complete', 'stats': {'rules': 0}}}}
        self.conn.execute('UPDATE evidence SET stats=?', (json.dumps({'last_attempt': attempt}),))
        self.assertEqual(self.history()['scan_state'], 'no_detections')

    def test_matching_scan_detection_requires_current_manifest(self):
        path = self.fixture.roots[0] / 'ordinary.php'
        path.write_text('Harmless detector marker\n', encoding='utf-8')
        self.fixture.prepare()
        with patch.object(webshell, '_yara_findings', return_value=[('fixture.marker', 1, 'Harmless marker', 1, 'marker')]):
            self.scan()
        self.assertEqual(self.history('ordinary.php')['scan_state'], 'detections')
        path.write_text('Changed harmless marker\n', encoding='utf-8')
        stale = self.history('ordinary.php')
        self.assertTrue(stale['stale'])
        self.assertEqual(stale['scan_state'], 'not_analyzed')
        self.assertIsNone(stale['finding'])

    def test_mutation_during_matching_never_records_a_success(self):
        path = self.fixture.roots[0] / 'ordinary.php'
        path.write_text('Initial harmless marker\n', encoding='utf-8')
        def changed(_raw, _kind):
            path.write_text('New harmless marker\n', encoding='utf-8')
            return []
        with patch.object(webshell, '_yara_findings', side_effect=changed):
            stats = self.scan()
        self.assertEqual(stats['file_skips'], 1)
        self.assertIsNone(db.one(self.conn, 'SELECT * FROM file_scan_receipts WHERE artifact=?', (str(path),)))
        self.assertIsNone(db.one(self.conn, 'SELECT * FROM content_files WHERE artifact=?', (str(path),)))

    def test_cancelled_inflight_file_has_no_success_receipt(self):
        path = self.fixture.roots[0] / 'ordinary.php'
        path.write_text('Harmless cancellation marker\n', encoding='utf-8')
        ctx = SimpleNamespace(stopped=False, progress=lambda *args: None)
        ctx.cancelled = lambda: ctx.stopped
        def stopped(_raw, _kind):
            ctx.stopped = True
            return []
        with patch.object(webshell, '_yara_findings', side_effect=stopped):
            self.scan(ctx=ctx)
        self.assertIsNone(db.one(self.conn, 'SELECT * FROM file_scan_receipts WHERE artifact=?', (str(path),)))

    def test_read_mutation_is_rejected_instead_of_indexing_new_bytes(self):
        original = file_scan_receipts.os.fstat
        calls = 0
        def mutating_stat(handle):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.path.write_text('Replacement harmless content\n', encoding='utf-8')
            return original(handle)
        with patch.object(file_scan_receipts.os, 'fstat', side_effect=mutating_stat):
            with self.assertRaisesRegex(ValueError, 'changed'):
                file_scan_receipts.read_file(str(self.path))

    def test_full_hash_read_stops_between_chunks_when_cancelled(self):
        self.path.write_bytes(b'Harmless bytes' * 100000)
        checks = 0
        def cancelled():
            nonlocal checks
            checks += 1
            return checks > 1
        with self.assertRaisesRegex(ValueError, 'cancelled'):
            file_scan_receipts.read_file(str(self.path), keep_content=False, cancelled=cancelled)
        self.assertEqual(checks, 2)

    def test_clean_file_receipt_reads_cannot_upgrade_a_stale_parallel_writer_snapshot(self):
        original = db.one
        conflicts = []
        self.conn.commit()
        with closing(db.connect(self.fixture.case)) as sibling:
            sibling.execute('PRAGMA busy_timeout=0')
            def parallel_commit(conn, sql, params=()):
                result = original(conn, sql, params)
                if sql == 'SELECT * FROM content_inheritance WHERE artifact=?':
                    # This is exactly the SELECT between an empty DELETE
                    # executemany and the content-index INSERT. A sibling
                    # commit here would make a deferred snapshot stale.
                    try:
                        sibling.execute("INSERT OR REPLACE INTO meta VALUES ('parallel-fixture', '1')")
                        sibling.commit()
                        conflicts.append(False)
                    except sqlite3.OperationalError as error:
                        sibling.rollback()
                        if getattr(error, 'sqlite_errorcode', None) != sqlite3.SQLITE_BUSY:
                            raise
                        conflicts.append(True)
                return result
            with patch.object(db, 'one', side_effect=parallel_commit):
                self.scan()
                fake_rules = SimpleNamespace(match=lambda **kwargs: [])
                with patch.object(yarascan, '_compile', return_value=(fake_rules, [], 1)):
                    yarascan.scan(self.fixture.case, [str(root) for root in self.fixture.roots],
                                  workspace=self.fixture.root)
        self.assertTrue(conflicts)
        self.assertTrue(all(conflicts))
        self.assertEqual(self.history()['scan_state'], 'no_detections')


if __name__ == '__main__':
    unittest.main()
