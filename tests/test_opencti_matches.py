import json
import tempfile
import threading
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

    def test_newer_clean_receipt_does_not_prove_a_previous_scan_finding(self):
        self.finding('changed.php', 'file')
        conn = db.connect(self.case)
        try:
            with conn:
                conn.execute("UPDATE findings SET engine='webshell', seen_run=1 WHERE artifact='changed.php'")
                conn.execute('INSERT INTO file_scan_receipts VALUES (?,?,?,?,?,?,?)',
                             ('webshell', 'changed.php', 'a' * 64, 'old', 1, db.now(), 1))
            db.complete_run(conn, 'webshell', 1)
            # A full scan can commit examined bytes before its final retirement marker.
            with conn:
                conn.execute('INSERT OR REPLACE INTO file_scan_receipts VALUES (?,?,?,?,?,?,?)',
                             ('webshell', 'changed.php', 'b' * 64, 'new', 2, db.now(), 2))
                conn.execute('INSERT INTO content_files VALUES (?,?,?,?,?)',
                             ('changed.php', 'b' * 64, 10, 'new', db.now()))
            authority = matches.authority(self.root)
            pending = matches.scan(self.root, self.case, Context(), expected_authority=authority)
            self.assertEqual((0, 1), (pending['checked'], pending['missing_hashes']))
            self.client.case_matches.assert_not_called()
            with conn:
                conn.execute("UPDATE findings SET seen_run=2 WHERE artifact='changed.php'")
            reproduced = matches.scan(self.root, self.case, Context(), expected_authority=authority)
            self.assertEqual((1, 0), (reproduced['checked'], reproduced['missing_hashes']))
            self.client.case_matches.assert_called_once_with('hash', 'b' * 64, exclude_reference='CASE-1')
        finally:
            conn.close()

    def test_changed_connection_stops_remaining_requests(self):
        self.finding('192.0.2.1', 'client')
        self.finding('192.0.2.2', 'client')
        def change(*args, **kwargs):
            self.config['token'] = 'new-token'
            return {'known': False, 'cases': [], 'truncated': False}
        self.client.case_matches.side_effect = change
        result = matches.scan(self.root, self.case, Context(), expected_authority=matches.authority(self.root))
        self.assertEqual((2, 0, True), (result['total'], result['checked'], result['partial']))
        self.client.case_matches.assert_called_once()
        self.assertIsNone(matches.saved(self.root, self.case, 'ip', '192.0.2.1'))

    def test_auto_skips_successful_unknown_and_manual_refresh_checks_again(self):
        self.finding('192.0.2.1', 'client')
        self.config['auto_match'] = True
        self.client.case_matches.return_value = {'known': False, 'cases': [], 'truncated': False}
        authority = matches.authority(self.root)
        first = matches.scan(self.root, self.case, Context(), expected_authority=authority, only_new=True)
        second = matches.scan(self.root, self.case, Context(), expected_authority=authority, only_new=True)
        self.assertEqual((1, 0), (first['checked'], first['skipped']))
        self.assertEqual((0, 1), (second['checked'], second['skipped']))
        matches.scan(self.root, self.case, Context(), expected_authority=authority)
        self.assertEqual(2, self.client.case_matches.call_count)
        self.config['auto_match'] = False
        with self.assertRaises(ValueError):
            matches.scan(self.root, self.case, Context(), expected_authority=authority, only_new=True)
        matches.lookup(self.root, self.case, 'ip', '192.0.2.1')

    def test_cached_sweep_uses_one_bulk_read_and_no_client(self):
        for value in ('192.0.2.1', '192.0.2.2'):
            self.finding(value, 'client')
            matches.lookup(self.root, self.case, 'ip', value)
        self.config['auto_match'] = True
        self.client.reset_mock()
        with patch('server.integrations.opencti.matches.saved', side_effect=AssertionError('per-value cache read')), \
                patch('server.integrations.opencti.matches.OpenCTIClient', side_effect=AssertionError('unneeded client')):
            result = matches.scan(self.root, self.case, Context(), expected_authority=matches.authority(self.root), only_new=True)
        self.assertEqual((2, 0, 2), (result['total'], result['checked'], result['skipped']))

    def test_log_observation_must_itself_be_visible(self):
        self.finding('shared.php', 'file')
        conn = db.connect(self.case)
        for fp, ip, triage, rule in (('dismissed', '192.0.2.1', 'dismissed', ''),
                                      ('muted', '192.0.2.2', 'new', 'muted.rule'),
                                      ('visible', '192.0.2.3', 'new', '')):
            conn.execute('INSERT INTO findings(fingerprint,source,severity,rule,rule_id,artifact_kind,artifact,created,last_seen,triage) VALUES (?,?,?,?,?,?,?,?,?,?)',
                         (fp, 'logs', 1, 'rule', rule, 'file', 'shared.php', db.now(), db.now(), triage))
            conn.execute('INSERT INTO log_observations VALUES (?,?,?,?)', (fp, fp, 'source', json.dumps({'ip': ip})))
        conn.commit()
        conn.close()
        with patch('server.integrations.opencti.matches.ruleswitch.disabled_ids', return_value={'muted.rule'}):
            matches.scan(self.root, self.case, Context(), expected_authority=matches.authority(self.root))
        self.client.case_matches.assert_called_once_with('ip', '192.0.2.3', exclude_reference='CASE-1')

    def test_auto_waiting_on_manual_check_stops_when_cancelled(self):
        self.finding('192.0.2.1', 'client')
        self.config['auto_match'] = True
        entered, release, cancelled = threading.Event(), threading.Event(), threading.Event()
        class Stoppable(Context):
            def cancelled(self):
                return cancelled.is_set()
        def response(*args, **kwargs):
            entered.set()
            self.assertTrue(release.wait(5))
            return {'known': False, 'cases': [], 'truncated': False}
        self.client.case_matches.side_effect = response
        authority = matches.authority(self.root)
        manual = threading.Thread(target=lambda: matches.lookup(self.root, self.case, 'ip', '192.0.2.1'))
        results = []
        automatic = threading.Thread(target=lambda: results.append(matches.scan(self.root, self.case, Stoppable(), expected_authority=authority, only_new=True)))
        manual.start()
        self.assertTrue(entered.wait(5))
        automatic.start()
        cancelled.set()
        automatic.join(2)
        release.set()
        manual.join(5)
        self.assertFalse(automatic.is_alive() or manual.is_alive())
        self.assertTrue(results[0]['cancelled'])
        self.client.case_matches.assert_called_once()

    def test_auto_stops_without_saving_when_disabled_during_request(self):
        self.finding('192.0.2.1', 'client')
        self.finding('192.0.2.2', 'client')
        self.config['auto_match'] = True
        def disable(*args, **kwargs):
            self.config['auto_match'] = False
            return {'known': False, 'cases': [], 'truncated': False}
        self.client.case_matches.side_effect = disable
        result = matches.scan(self.root, self.case, Context(), expected_authority=matches.authority(self.root), only_new=True)
        self.assertEqual((0, True), (result['checked'], result['partial']))
        self.assertIsNone(matches.saved(self.root, self.case, 'ip', '192.0.2.1'))
        self.client.case_matches.assert_called_once()

    def test_concurrent_auto_checks_share_success_and_manual_runs_after(self):
        self.finding('192.0.2.1', 'client')
        self.config['auto_match'] = True
        entered, release = threading.Event(), threading.Event()
        def response(*args, **kwargs):
            entered.set()
            self.assertTrue(release.wait(5))
            return {'known': False, 'cases': [], 'truncated': False}
        self.client.case_matches.side_effect = response
        authority = matches.authority(self.root)
        results = []
        def run_auto():
            results.append(matches.scan(self.root, self.case, Context(), expected_authority=authority, only_new=True))
        first = threading.Thread(target=run_auto)
        second = threading.Thread(target=run_auto)
        first.start()
        self.assertTrue(entered.wait(5))
        second.start()
        release.set()
        first.join(5)
        second.join(5)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertEqual([0, 1], sorted(r['checked'] for r in results))
        self.client.case_matches.assert_called_once()

    def test_manual_refresh_cannot_be_overwritten_by_an_older_auto_request(self):
        self.finding('192.0.2.1', 'client')
        self.config['auto_match'] = True
        entered, release = threading.Event(), threading.Event()
        def response(*args, **kwargs):
            if not entered.is_set():
                entered.set()
                self.assertTrue(release.wait(5))
                return {'known': False, 'cases': [], 'truncated': False}
            return {'known': True, 'cases': [], 'truncated': False}
        self.client.case_matches.side_effect = response
        authority = matches.authority(self.root)
        automatic = threading.Thread(target=lambda: matches.scan(self.root, self.case, Context(), expected_authority=authority, only_new=True))
        manual = threading.Thread(target=lambda: matches.lookup(self.root, self.case, 'ip', '192.0.2.1'))
        automatic.start()
        self.assertTrue(entered.wait(5))
        manual.start()
        release.set()
        automatic.join(5)
        manual.join(5)
        self.assertFalse(automatic.is_alive() or manual.is_alive())
        self.assertTrue(matches.saved(self.root, self.case, 'ip', '192.0.2.1')['known'])
        self.assertEqual(2, self.client.case_matches.call_count)

    def test_auto_checks_hash_when_missing_receipt_becomes_available(self):
        self.finding('first.php', 'file')
        self.config['auto_match'] = True
        conn = db.connect(self.case)
        conn.execute("UPDATE findings SET engine='webshell' WHERE artifact='first.php'")
        conn.commit()
        conn.close()
        authority = matches.authority(self.root)
        first = matches.scan(self.root, self.case, Context(), expected_authority=authority, only_new=True)
        self.assertEqual((0, 1), (first['checked'], first['missing_hashes']))
        conn = db.connect(self.case)
        conn.execute('INSERT INTO file_scan_receipts VALUES (?,?,?,?,?,?,?)', ('webshell', 'first.php', 'a' * 64, 'marker', 0, db.now(), 0))
        conn.commit()
        conn.close()
        second = matches.scan(self.root, self.case, Context(), expected_authority=authority, only_new=True)
        self.assertEqual((1, 0), (second['checked'], second['missing_hashes']))
        self.client.case_matches.assert_called_once()

    def test_log_observation_ip_is_included_for_live_finding(self):
        self.finding('observation', 'log_observation')
        conn = db.connect(self.case)
        conn.execute('INSERT INTO log_observations VALUES (?,?,?,?)', ('event', 'observation', 'source', json.dumps({'ip': '192.0.2.7', 'raw': '192.0.2.8'})))
        conn.commit()
        conn.close()
        matches.scan(self.root, self.case, Context(), expected_authority=matches.authority(self.root))
        self.client.case_matches.assert_called_once_with('ip', '192.0.2.7', exclude_reference='CASE-1')
