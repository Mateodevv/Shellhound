import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from server import db, workspace
from server.integrations.opencti import matches
from server.integrations.opencti.client import OpenCTIError


class Context:
    def cancelled(self):
        return False

    def progress(self, *args):
        pass


class MatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = workspace.create_case(self.root / 'cases', 'Case', 'CASE-1')
        self.config = {'url': 'https://cti.example.test', 'token': 'token', 'ingester_id': ''}
        self.client = MagicMock()
        self.client.case_matches.return_value = {'known': True, 'cases': [{'id': 'case-1', 'name': 'Other', 'url': 'https://evil.test'}], 'truncated': False}
        self.settings = patch('server.integrations.opencti.matches.settings.opencti_config', side_effect=lambda _: dict(self.config))
        self.factory = patch('server.integrations.opencti.matches.OpenCTIClient', return_value=self.client)
        self.settings.start()
        self.factory.start()
        self.addCleanup(self.settings.stop)
        self.addCleanup(self.factory.stop)

    def finding(self, artifact, kind, triage='new'):
        conn = db.connect(self.case)
        conn.execute("INSERT INTO findings(fingerprint,source,severity,rule,artifact_kind,artifact,created,last_seen,triage) VALUES (?,?,?,?,?,?,?,?,?)",
                     (artifact, 'logs', 1, 'rule', kind, artifact, db.now(), db.now(), triage))
        conn.commit()
        conn.close()

    def test_lookup_is_saved_locally_and_scoped_to_connection_and_case(self):
        result = matches.lookup(self.root, self.case, 'ip', '2001:0db8::1')
        self.assertEqual('2001:db8::1', result['value'])
        self.assertEqual('https://cti.example.test/dashboard/id/case-1', result['cases'][0]['url'])
        self.assertEqual(result, matches.saved(self.root, self.case, 'ip', '2001:db8::1'))
        self.client.case_matches.assert_called_once_with('ip', '2001:db8::1', exclude_reference='CASE-1')
        self.config['token'] = 'different'
        self.assertIsNone(matches.saved(self.root, self.case, 'ip', '2001:db8::1'))

    def test_imported_malformed_results_are_not_shown_and_reference_is_scoped(self):
        matches.lookup(self.root, self.case, 'ip', '192.0.2.1')
        conn = db.connect(self.case)
        conn.execute("UPDATE opencti_case_matches SET payload=?", (json.dumps({'known': False, 'truncated': False, 'checked_at': 'now', 'cases': [{'id': 'x', 'name': 'Injected'}]}),))
        conn.commit()
        conn.close()
        self.assertIsNone(matches.saved(self.root, self.case, 'ip', '192.0.2.1'))
        matches.lookup(self.root, self.case, 'ip', '192.0.2.1')
        with patch('server.integrations.opencti.matches._reference', return_value='OTHER-CASE'):
            self.assertIsNone(matches.saved(self.root, self.case, 'ip', '192.0.2.1'))

    def test_scan_deduplicates_without_reading_evidence_or_mutating_triage(self):
        self.finding('2001:db8::1', 'client')
        self.finding('2001:0db8::1', 'client')
        self.finding('missing.php', 'file')
        self.finding('dismissed.php', 'file', 'dismissed')
        conn = db.connect(self.case)
        before = db.rows(conn, 'SELECT artifact,triage FROM findings ORDER BY artifact')
        conn.close()
        stats = matches.scan(self.root, self.case, Context(), expected_authority=matches.authority(self.root))
        self.assertEqual((1, 1, 1, 1, 1), (stats['total'], stats['checked'], stats['known'], stats['linked'], stats['missing_hashes']))
        self.assertTrue(stats['partial'])
        conn = db.connect(self.case)
        self.assertEqual(before, db.rows(conn, 'SELECT artifact,triage FROM findings ORDER BY artifact'))
        self.assertEqual([], db.rows(conn, 'SELECT * FROM iocs'))
        conn.close()
        self.client.case_matches.assert_called_once()

    def test_failed_request_is_partial_and_queued_destination_is_pinned(self):
        self.finding('192.0.2.1', 'client')
        token = matches.authority(self.root)
        self.config['url'] = 'https://other.example.test'
        with self.assertRaises(ValueError):
            matches.scan(self.root, self.case, Context(), expected_authority=token)
        self.client.case_matches.assert_not_called()
        self.client.case_matches.side_effect = OpenCTIError('private text', code='authentication')
        result = matches.scan(self.root, self.case, Context(), expected_authority=matches.authority(self.root))
        self.assertEqual((0, 1, True), (result['checked'], result['failed'], result['partial']))
        self.assertNotIn('private text', json.dumps(result))

    def test_conflicting_stored_hashes_are_not_sent(self):
        self.finding('first.php', 'file')
        conn = db.connect(self.case)
        conn.execute('INSERT INTO content_files VALUES (?,?,?,?,?)', ('first.php', 'a' * 64, 10, 'marker', db.now()))
        conn.execute("UPDATE findings SET engine='webshell' WHERE artifact='first.php'")
        conn.execute('INSERT INTO file_scan_receipts VALUES (?,?,?,?,?,?,?)', ('webshell', 'first.php', 'b' * 64, 'marker', 0, db.now(), 0))
        conn.commit()
        conn.close()
        result = matches.scan(self.root, self.case, Context(), expected_authority=matches.authority(self.root))
        self.assertEqual((0, 1, True), (result['total'], result['missing_hashes'], result['partial']))
        self.client.case_matches.assert_not_called()

    def test_skipped_file_never_uses_legacy_or_retained_content(self):
        self.finding('first.php', 'file')
        conn = db.connect(self.case)
        conn.execute("UPDATE findings SET engine='webshell' WHERE artifact='first.php'")
        conn.execute('INSERT INTO content_files VALUES (?,?,?,?,?)', ('first.php', 'a' * 64, 10, 'marker', db.now()))
        conn.execute("INSERT OR REPLACE INTO meta VALUES ('webshell_hashes',?)", (json.dumps({'first.php': 'a' * 64}),))
        conn.execute("INSERT INTO skipped(source,path,reason) VALUES ('webshell','first.php','unreadable')")
        conn.commit()
        conn.close()
        result = matches.scan(self.root, self.case, Context(), expected_authority=matches.authority(self.root))
        self.assertEqual((0, 1, True), (result['total'], result['missing_hashes'], result['partial']))
        self.client.case_matches.assert_not_called()

    def test_later_content_index_skip_invalidates_old_receipt(self):
        self.finding('first.php', 'file')
        conn = db.connect(self.case)
        conn.execute("UPDATE findings SET engine='webshell' WHERE artifact='first.php'")
        conn.execute('INSERT INTO content_files VALUES (?,?,?,?,?)', ('first.php', 'a' * 64, 10, 'marker', db.now()))
        conn.execute('INSERT INTO file_scan_receipts VALUES (?,?,?,?,?,?,?)', ('webshell', 'first.php', 'a' * 64, 'marker', 0, db.now(), 1))
        conn.execute("INSERT INTO job_skips(job_id,ordinal,path,reason,category,root) VALUES (2,0,'first.php','unreadable','file','')")
        conn.commit()
        conn.close()
        result = matches.scan(self.root, self.case, Context(), expected_authority=matches.authority(self.root))
        self.assertEqual((0, 1), (result['total'], result['missing_hashes']))
        self.client.case_matches.assert_not_called()

    def test_single_lookup_does_not_return_result_after_connection_or_case_change(self):
        def change(*args, **kwargs):
            self.config['token'] = 'new-token'
            return {'known': True, 'cases': [], 'truncated': False}
        self.client.case_matches.side_effect = change
        with self.assertRaises(ValueError):
            matches.lookup(self.root, self.case, 'ip', '192.0.2.1')
        self.assertIsNone(matches.saved(self.root, self.case, 'ip', '192.0.2.1'))
        self.client.case_matches.side_effect = lambda *args, **kwargs: {'known': True, 'cases': [], 'truncated': False}
        with patch('server.integrations.opencti.matches._reference', side_effect=['CASE-1', 'CASE-2']):
            with self.assertRaises(ValueError):
                matches.lookup(self.root, self.case, 'ip', '192.0.2.1')

    def test_rejects_zone_ids_and_malformed_known(self):
        with self.assertRaises(ValueError):
            matches.lookup(self.root, self.case, 'ip', 'fe80::1%eth0')
        self.client.case_matches.return_value = {'known': None, 'cases': [], 'truncated': False}
        with self.assertRaises(OpenCTIError):
            matches.lookup(self.root, self.case, 'ip', '192.0.2.1')
        self.assertIsNone(matches.saved(self.root, self.case, 'ip', '192.0.2.1'))

    def test_auth_error_stops_batch_and_programming_error_propagates(self):
        self.finding('192.0.2.1', 'client')
        self.finding('192.0.2.2', 'client')
        self.client.case_matches.side_effect = OpenCTIError('private', code='authentication')
        result = matches.scan(self.root, self.case, Context(), expected_authority=matches.authority(self.root))
        self.assertEqual((1, True), (result['failed'], result['partial']))
        self.assertIn('token', result['reason'])
        self.client.case_matches.assert_called_once()
        self.client.case_matches.side_effect = RuntimeError('unexpected programming error')
        with self.assertRaises(RuntimeError):
            matches.scan(self.root, self.case, Context(), expected_authority=matches.authority(self.root))

    def test_scan_uses_stored_hashes_once_and_distinguishes_unlinked(self):
        self.finding('first.php', 'file')
        self.finding('second.php', 'file')
        conn = db.connect(self.case)
        digest = 'a' * 64
        for name in ('first.php', 'second.php'):
            conn.execute("UPDATE findings SET engine='webshell' WHERE artifact=?", (name,))
            conn.execute('INSERT INTO content_files VALUES (?,?,?,?,?)', (name, digest, 10, 'marker', db.now()))
            conn.execute('INSERT INTO file_scan_receipts VALUES (?,?,?,?,?,?,?)', ('webshell', name, digest, 'marker', 0, db.now(), 0))
        conn.commit()
        conn.close()
        self.client.case_matches.return_value = {'known': True, 'cases': [], 'truncated': False}
        result = matches.scan(self.root, self.case, Context(), expected_authority=matches.authority(self.root))
        self.assertEqual((1, 1, 1, 0, False), (result['total'], result['checked'], result['known'], result['linked'], result['partial']))
        self.client.case_matches.assert_called_once_with('hash', digest, exclude_reference='CASE-1')

    def test_log_finding_can_share_valid_scanner_receipt(self):
        self.finding('mixed.php', 'file')
        self.finding('log-only.php', 'file')
        conn = db.connect(self.case)
        conn.execute("UPDATE findings SET engine='logs' WHERE artifact IN ('mixed.php','log-only.php')")
        conn.execute("INSERT INTO findings(fingerprint,source,severity,rule,artifact_kind,artifact,created,last_seen,engine) VALUES ('scanner','webshell',1,'rule','file','mixed.php',?,?,'webshell')", (db.now(), db.now()))
        for name in ('mixed.php', 'log-only.php'):
            conn.execute('INSERT INTO file_scan_receipts VALUES (?,?,?,?,?,?,?)', ('webshell', name, 'a' * 64, 'marker', 0, db.now(), 0))
        conn.commit()
        conn.close()
        result = matches.scan(self.root, self.case, Context(), expected_authority=matches.authority(self.root))
        self.assertEqual((1, 1, 0, False), (result['total'], result['checked'], result['missing_hashes'], result['partial']))
        self.client.case_matches.assert_called_once_with('hash', 'a' * 64, exclude_reference='CASE-1')

    def test_missing_live_scanner_receipt_is_not_replaced_by_other_scanner(self):
        self.finding('mixed.php', 'file')
        conn = db.connect(self.case)
        conn.execute("UPDATE findings SET engine='webshell' WHERE artifact='mixed.php'")
        conn.execute('INSERT INTO file_scan_receipts VALUES (?,?,?,?,?,?,?)', ('yarascan', 'mixed.php', 'a' * 64, 'marker', 0, db.now(), 0))
        conn.commit()
        conn.close()
        result = matches.scan(self.root, self.case, Context(), expected_authority=matches.authority(self.root))
        self.assertEqual((0, 1), (result['total'], result['missing_hashes']))
        self.client.case_matches.assert_not_called()

    def test_changed_connection_stops_remaining_requests(self):
        self.finding('192.0.2.1', 'client')
        self.finding('192.0.2.2', 'client')
        def change(*args, **kwargs):
            self.config['token'] = 'new-token'
            return {'known': False, 'cases': [], 'truncated': False}
        self.client.case_matches.side_effect = change
        result = matches.scan(self.root, self.case, Context(), expected_authority=matches.authority(self.root))
        self.assertEqual((2, 1, True), (result['total'], result['checked'], result['partial']))
        self.client.case_matches.assert_called_once()
        self.assertIsNone(matches.saved(self.root, self.case, 'ip', '192.0.2.1'))
