"""Case-matching notices follow committed findings and scan proofs."""
from contextlib import closing
from pathlib import Path
import tempfile
import unittest

from server import db, file_scan_receipts
from server.log_evidence import _save_finding


class FindingCommitTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.case = Path(scratch.name)
        self.conn = db.connect(self.case)
        self.addCleanup(self.conn.close)
        self.notices = []

    def subscribe(self, callback=None):
        unsubscribe = db.subscribe_finding_changes(callback or self.notices.append)
        self.addCleanup(unsubscribe)
        return unsubscribe

    def finding(self, client='192.0.2.34', **kwargs):
        return db.upsert_finding(self.conn, 'logs', db.SEV_MEDIUM, 'Fixture request',
                                 'client', client, **kwargs)

    def test_commits_notify_once_and_only_after_changes_can_be_read(self):
        def verify(case):
            with closing(db.connect(case)) as other:
                self.notices.append((case, other.execute("SELECT COUNT(*) FROM findings").fetchone()[0]))

        self.subscribe(verify)
        self.finding()
        self.finding('192.0.2.35')
        self.assertEqual(self.notices, [])
        self.conn.commit()
        self.assertEqual(self.notices, [(self.case, 2)])
        self.finding()
        self.conn.commit()
        self.assertEqual(len(self.notices), 1)
        with self.conn:
            self.finding(evidence='A different request excerpt')
        self.assertEqual(self.notices, [(self.case, 2), (self.case, 2)])

    def test_rollbacks_close_and_unrelated_writes_do_not_notify(self):
        self.subscribe()
        self.finding()
        self.conn.rollback()
        with self.assertRaises(RuntimeError):
            with self.conn:
                self.finding()
                raise RuntimeError('abort write')
        self.conn.execute('SELECT * FROM findings').fetchall()
        with self.conn:
            self.conn.execute("INSERT INTO jobs(kind,created) VALUES('logindex',?)", (db.now(),))
            self.conn.execute("INSERT INTO opencti_case_matches VALUES('cti','ref','ip','192.0.2.34','{}')")
            db.upsert_finding(self.conn, 'sqldb', 0, 'Fixture row', 'table', 'articles')
            self.finding('example.test')
        self.finding()
        self.conn.close()
        self.assertEqual(self.notices, [])

    def test_activation_can_observe_a_transaction_already_writing(self):
        self.finding()
        unsubscribe = self.subscribe()
        self.conn.commit()
        self.assertEqual(self.notices, [self.case])
        unsubscribe()
        with self.conn:
            self.finding('192.0.2.35')
        self.assertEqual(self.notices, [self.case])

    def test_listener_failure_does_not_change_successful_commit(self):
        def broken(_):
            raise RuntimeError('observer stopped')

        self.subscribe(broken)
        self.subscribe()
        with self.conn:
            self.finding()
        self.assertEqual(self.notices, [self.case])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0], 1)

    def test_new_file_proof_notifies_when_a_findings_row_already_exists(self):
        self.subscribe()
        path = self.case / 'fixture.txt'
        path.write_text('test fixture', encoding='utf-8')
        _, proof = file_scan_receipts.read_file(path)
        with self.conn:
            file_scan_receipts.record(self.conn, 'webshell', str(path), 1, proof)
        self.assertEqual(self.notices, [])
        with self.conn:
            file_scan_receipts.invalidate(self.conn, 'webshell', str(path))
        with self.conn:
            db.upsert_finding(self.conn, 'analyst', 1, 'Review fixture', 'file', str(path))
        with self.conn:
            file_scan_receipts.record(self.conn, 'webshell', str(path), 2, proof)
        self.assertEqual(self.notices, [self.case, self.case])
        file_scan_receipts.record(self.conn, 'yarascan', str(path), 3, proof)
        self.conn.rollback()
        self.conn.commit()
        self.assertEqual(len(self.notices), 2)

    def test_explicit_log_ips_notify_on_add_or_change(self):
        self.subscribe()
        event = {'id': 'log-observation-fixture', 'source_id': 'example',
                 'source_name': 'fixture.log', 'line': 1, 'raw': 'FTP transfer',
                 'detection': False, 'artifact': '', 'ip': ''}
        with self.conn:
            _save_finding(self.conn, event, manual=True)
        self.assertEqual(self.notices, [])
        event['ip'] = '192.0.2.36'
        with self.conn:
            _save_finding(self.conn, event, manual=True)
        self.assertEqual(self.notices, [self.case])
        with self.conn:
            _save_finding(self.conn, event, manual=True)
        self.assertEqual(self.notices, [self.case])

    def test_restore_and_reappearing_findings_notify_after_commit(self):
        self.subscribe()
        with self.conn:
            self.finding(engine='logindex', run=1)
        db.complete_run(self.conn, 'logindex', 2)
        with self.conn:
            self.finding(engine='logindex', run=3)
        with self.conn:
            self.conn.execute("UPDATE findings SET triage='dismissed'")
            db.mark_finding_triage_changed(self.conn, '192.0.2.34', 'client', 'dismissed')
        with self.conn:
            self.conn.execute("UPDATE findings SET triage='new'")
            db.mark_finding_triage_changed(self.conn, '192.0.2.34', 'client', 'new')
        self.assertEqual(self.notices, [self.case, self.case, self.case])

    def test_retirement_can_release_a_current_receipt_for_another_finding(self):
        self.subscribe()
        path = self.case / 'fixture.txt'
        path.write_text('test fixture', encoding='utf-8')
        _, proof = file_scan_receipts.read_file(path)
        with self.conn:
            db.upsert_finding(self.conn, 'webshell', 1, 'Old detection', 'file', str(path),
                              engine='webshell', run=1)
            db.upsert_finding(self.conn, 'analyst', 1, 'Current observation', 'file', str(path))
            file_scan_receipts.record(self.conn, 'webshell', str(path), 2, proof)
        self.notices.clear()
        db.complete_file_scan(self.conn, 'webshell', 2)
        self.assertEqual(self.notices, [self.case])
