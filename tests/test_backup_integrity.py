"""Content assessments stay bound to verified bytes and preserve analyst work."""
import json
from contextlib import closing
import unittest
from unittest.mock import patch

from server import backups, db, file_classifications
from server import workspace
from server.artifacts import ART_SQL
from tests import test_backups as backup_fixtures


class BackupIntegrityTests(unittest.TestCase):
    def test_archive_import_retains_backup_identity_and_content_provenance(self):
        self.prepare_decisions()
        digest, _ = self.decide('confirmed', ['malware'])
        self.conn.close()
        archive, _ = workspace.archive_case(self.fixture.root / 'cases', self.fixture.case)
        restored = workspace.import_archive(self.fixture.root / 'restored cases', archive)
        with closing(db.connect(restored['dir'])) as conn:
            self.assertEqual(len(backups.settings(conn)['snapshots']), 3)
            self.assertEqual(backups.assessment(conn, digest)['state'], 'confirmed')
            self.assertEqual(db.one(conn, 'SELECT sha256 FROM content_inheritance WHERE artifact=?', (self.copy,))['sha256'], digest)
            self.assertEqual(backups.history(conn, self.fixture.site, 'same.txt')['entries'][1]['finding']['triage'], 'confirmed')
    def setUp(self):
        self.fixture = backup_fixtures.BackupTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.conn = self.fixture.conn
        self.fixture.populate()
        self.origin = str(self.fixture.roots[0] / 'same.txt')
        self.copy = str(self.fixture.roots[1] / 'same.txt')

    def row(self, artifact):
        return db.one(self.conn, f'WITH art AS ({ART_SQL}) SELECT * FROM art WHERE artifact=?', (artifact,))

    def decide(self, state, classes=None):
        digest = backups.assess_content(self.conn, self.origin, state, 'Harmless analyst assessment', classes)
        self.conn.execute('UPDATE findings SET triage=? WHERE artifact=?', (state, self.origin))
        result = backups.inherit_all(self.conn)
        self.conn.commit()
        return digest, result

    def prepare_decisions(self, copy_state='new', copy_note='Original occurrence note'):
        self.fixture.finding(self.origin)
        self.fixture.finding(self.copy, copy_state)
        self.conn.execute('UPDATE findings SET triage_note=? WHERE artifact=?', (copy_note, self.copy))
        self.fixture.prepare()

    def test_changed_content_restores_previous_decision_and_keeps_hash_history(self):
        self.prepare_decisions('reviewed')
        digest, _ = self.decide('confirmed', ['webshell'])
        self.assertEqual(self.row(self.copy)['triage'], 'confirmed')
        (self.fixture.roots[1] / 'same.txt').write_text('Changed harmless content\n', encoding='utf-8')
        self.fixture.prepare()
        restored = self.row(self.copy)
        self.assertEqual((restored['triage'], restored['triage_note']), ('reviewed', 'Original occurrence note'))
        self.assertFalse(self.conn.execute('SELECT 1 FROM content_inheritance WHERE artifact=?', (self.copy,)).fetchone())
        self.assertEqual(backups.assessment(self.conn, digest)['state'], 'confirmed')
        self.assertNotEqual(db.one(self.conn, 'SELECT sha256 FROM content_files WHERE artifact=?', (self.copy,))['sha256'], digest)
        self.assertTrue(self.conn.execute("SELECT 1 FROM triage_events WHERE artifact=? AND note LIKE 'Content changed%'", (self.copy,)).fetchone())

    def test_withdrawn_shared_assessment_restores_prior_review_and_note(self):
        self.prepare_decisions('reviewed')
        digest, _ = self.decide('confirmed', ['malware'])
        _, result = self.decide('new')
        self.assertIn(self.copy, result['applied'])
        self.assertEqual((self.row(self.copy)['triage'], self.row(self.copy)['triage_note']),
                         ('reviewed', 'Original occurrence note'))
        self.assertEqual(backups.assessment(self.conn, digest)['state'], 'new')
        self.assertFalse(self.conn.execute('SELECT 1 FROM content_inheritance WHERE artifact=?', (self.copy,)).fetchone())
        self.assertEqual(self.conn.execute('SELECT count(*) FROM content_assessment_history WHERE sha256=?', (digest,)).fetchone()[0], 2)

    def test_corrected_classification_updates_inherited_confirmations(self):
        self.prepare_decisions()
        self.decide('confirmed', ['webshell'])
        self.assertEqual(file_classifications.saved(self.conn, self.copy), ['webshell'])
        self.decide('confirmed', ['malware'])
        self.assertEqual(file_classifications.saved(self.conn, self.copy), ['malware'])
        self.assertEqual(self.row(self.copy)['triage'], 'confirmed')
        # Explicitly empty is a real analyst classification choice.
        self.decide('confirmed', [])
        self.assertEqual(file_classifications.saved(self.conn, self.copy), [])

    def test_omitted_classifications_preserve_an_existing_origin_classification(self):
        self.prepare_decisions()
        file_classifications.store(self.conn, self.origin, ['backdoor'], 'new')
        self.decide('confirmed')
        self.assertEqual(file_classifications.saved(self.conn, self.copy), ['backdoor'])

    def test_independent_same_verdict_is_never_converted_to_inheritance(self):
        self.prepare_decisions('confirmed', 'Independent analyst decision')
        self.decide('confirmed', ['malware'])
        self.assertFalse(self.conn.execute('SELECT 1 FROM content_inheritance WHERE artifact=?', (self.copy,)).fetchone())
        _, result = self.decide('dismissed')
        self.assertIn(self.copy, result['conflicts'])
        row = self.row(self.copy)
        self.assertEqual((row['triage'], row['triage_note']), ('confirmed', 'Independent analyst decision'))

    def test_explicit_occurrence_override_survives_later_hash_decisions(self):
        self.prepare_decisions()
        digest, _ = self.decide('confirmed')
        self.conn.execute('INSERT INTO content_exceptions VALUES (?,?)', (self.copy, digest))
        self.conn.execute('UPDATE findings SET triage=?,triage_note=? WHERE artifact=?',
                          ('dismissed', 'This occurrence has a different context', self.copy))
        self.decide('new')
        self.assertEqual((self.row(self.copy)['triage'], self.row(self.copy)['triage_note']),
                         ('dismissed', 'This occurrence has a different context'))

    def test_changed_copy_retains_an_independent_confirmation_as_historical(self):
        self.fixture.finding(self.origin)
        self.fixture.prepare()
        digest, _ = self.decide('confirmed', ['malware'])
        # This copy was introduced through content inheritance. The analyst
        # subsequently confirmed this occurrence independently of the hash.
        self.conn.execute('INSERT INTO content_exceptions VALUES (?,?)', (self.copy, digest))
        self.conn.execute('UPDATE findings SET triage_note=? WHERE artifact=?',
                          ('Independent occurrence confirmation', self.copy))
        self.conn.commit()
        (self.fixture.roots[1] / 'same.txt').write_text('Different harmless replacement\n', encoding='utf-8')
        self.fixture.prepare()
        historical = self.row(self.copy)
        self.assertEqual(historical['findings'], 0)
        self.assertEqual(historical['triage'], 'confirmed')
        self.assertEqual(historical['triage_note'], 'Independent occurrence confirmation')

    def test_accepted_size_skip_is_not_mislabelled_as_no_detections(self):
        self.fixture.prepare()
        receipt = json.dumps({'last_attempt': {'run_id': 'synthetic-run', 'status': 'complete'}})
        self.conn.execute('UPDATE evidence SET scanned_at=?,stats=?', (db.now(), receipt))
        job = self.conn.execute("INSERT INTO jobs(kind,state,created,run_id) VALUES ('webshell','done',?,'synthetic-run')", (db.now(),)).lastrowid
        self.conn.execute('INSERT INTO job_skips(job_id,ordinal,path,reason,category,root) VALUES (?,0,?,?,?,?)',
                          (job, self.origin, 'File exceeds configured size limit', 'file', str(self.fixture.roots[0])))
        self.conn.execute('INSERT INTO skip_reviews(job_id,ordinal,outcome_job_id,accepted_at) VALUES (?,0,0,?)', (job, db.now()))
        entries = backups.history(self.conn, self.fixture.site, 'same.txt')['entries']
        self.assertEqual(entries[0]['scan_state'], 'not_analyzed')
        self.assertEqual(entries[1]['scan_state'], 'no_detections')
        retry = self.conn.execute("INSERT INTO jobs(kind,state,created,scan_context) VALUES ('webshell','done',?,?)",
                                  (db.now(), json.dumps({'parent_job_id': job, 'mode': 'retry'}))).lastrowid
        self.conn.execute("INSERT INTO file_scan_results(job_id,ordinal,status,reason) VALUES (?,0,'resolved','')", (retry,))
        self.assertEqual(backups.history(self.conn, self.fixture.site, 'same.txt')['entries'][0]['scan_state'], 'no_detections')

    def test_cancelled_inventory_keeps_old_generation_and_retry_publishes_new(self):
        self.fixture.prepare()
        sid = self.fixture.ids[0]
        before = db.one(self.conn, 'SELECT generation FROM backup_snapshots WHERE id=?', (sid,))['generation']
        extra = self.fixture.roots[0] / 'added-later.txt'
        extra.write_text('Harmless later addition\n', encoding='utf-8')

        class CancelOnProgress:
            stopped = False

            def cancelled(self):
                return self.stopped

            def phase_progress(self, *args):
                self.stopped = True

            def detailed_skip(self, *args, **kwargs):
                pass

        result = backups.build(self.fixture.case, CancelOnProgress(), [sid])
        self.assertTrue(result['cancelled'])
        retained = db.one(self.conn, 'SELECT generation,state FROM backup_snapshots WHERE id=?', (sid,))
        self.assertEqual(retained, {'generation': before, 'state': 'stale'})
        self.assertFalse(self.conn.execute('SELECT 1 FROM backup_files WHERE generation=? AND relative_path=?', (before, extra.name)).fetchone())
        result = backups.build(self.fixture.case, snapshot_ids=[sid])
        self.assertEqual(result['failed_sources'], 0)
        after = db.one(self.conn, 'SELECT generation,state FROM backup_snapshots WHERE id=?', (sid,))
        self.assertNotEqual(after['generation'], before)
        self.assertEqual(after['state'], 'ready')
        self.assertTrue(self.conn.execute('SELECT 1 FROM backup_files WHERE generation=? AND relative_path=?', (after['generation'], extra.name)).fetchone())

    def test_per_file_hash_failure_is_visible_and_successful_retry_replaces_it(self):
        self.fixture.prepare()
        original = backups.hash_file

        def unreadable(path, ctx=None):
            if str(path) == self.origin:
                raise PermissionError('Synthetic read failure')
            return original(path, ctx)

        with patch.object(backups, 'hash_file', side_effect=unreadable):
            backups.build(self.fixture.case, snapshot_ids=[self.fixture.ids[0]])
        row = backups.history(self.conn, self.fixture.site, 'same.txt')['entries'][0]
        self.assertEqual(row['snapshot']['state'], 'partial')
        self.assertEqual(row['file']['state'], 'unavailable')
        self.assertEqual(row['file']['sha256'], '')
        backups.build(self.fixture.case, snapshot_ids=[self.fixture.ids[0]])
        row = backups.history(self.conn, self.fixture.site, 'same.txt')['entries'][0]
        self.assertEqual(row['snapshot']['state'], 'ready')
        self.assertEqual(row['file']['state'], 'ready')
        self.assertEqual(len(row['file']['sha256']), 64)

    def test_removed_registration_or_reused_id_cannot_reactivate_old_root(self):
        self.fixture.prepare()
        sid = self.fixture.ids[2]
        original = db.one(self.conn, 'SELECT * FROM backup_snapshots WHERE id=?', (sid,))
        self.conn.execute('DELETE FROM evidence WHERE id=?', (original['evidence_id'],))
        self.conn.commit()
        removed = next(s for s in backups.settings(self.conn)['snapshots'] if s['id'] == sid)
        self.assertFalse(removed['available'])
        unrelated = self.fixture.root / 'Unrelated source'
        unrelated.mkdir()
        new_id = self.conn.execute("INSERT INTO evidence(kind,path,added) VALUES ('webroot',?,?)", (str(unrelated), db.now())).lastrowid
        self.assertEqual(new_id, original['evidence_id'])
        self.conn.commit()
        result = backups.build(self.fixture.case, snapshot_ids=[sid])
        self.assertEqual(result['failed_sources'], 1)
        after = db.one(self.conn, 'SELECT generation FROM backup_snapshots WHERE id=?', (sid,))
        self.assertEqual(after['generation'], original['generation'])
        self.assertFalse(next(s for s in backups.settings(self.conn)['snapshots'] if s['id'] == sid)['available'])


if __name__ == '__main__':
    unittest.main()
