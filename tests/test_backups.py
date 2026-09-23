"""Website backup histories use harmless text, distinct content and explicit decisions."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from server import backups, db, workspace


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='backup comparison ')
        self.root = Path(self.temp.name)
        self.case = workspace.create_case(self.root / 'cases', 'Synthetic backups')
        self.conn = db.connect(self.case)
        self.site = backups.save_site(self.conn, 'Example website', 'UTC')
        self.roots = []
        self.ids = []
        for n in (1, 2, 3):
            root = self.root / f'copy {n}' / 'site'
            root.mkdir(parents=True)
            self.roots.append(root)
            eid = self.conn.execute("INSERT INTO evidence(kind,path,added) VALUES ('webroot',?,?)", (str(root), db.now())).lastrowid
            self.ids.append(backups.save_snapshot(self.conn, site_id=self.site, evidence_id=eid, root=str(root), label=f'Week {n}', captured_at=f'2026-09-{n:02}T12:00:00Z', completeness='complete'))
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        self.temp.cleanup()

    def populate(self):
        for root in self.roots:
            (root / 'same.txt').write_text('Shared harmless fixture\n', encoding='utf-8')
        (self.roots[0] / 'changed.txt').write_text('Earlier ordinary text\n', encoding='utf-8')
        (self.roots[1] / 'changed.txt').write_text('Later ordinary text\n', encoding='utf-8')
        (self.roots[2] / 'new.txt').write_text('Only in third backup\n', encoding='utf-8')

    def prepare(self):
        self.conn.commit()
        result = backups.build(self.case)
        self.assertEqual(result['failed_sources'], 0)

    def finding(self, path, decision='new'):
        db.upsert_finding(self.conn, 'analyst', 1, 'Synthetic observation', 'file', str(path), rule_id='analyst.synthetic')
        self.conn.execute('UPDATE findings SET triage=? WHERE artifact=?', (decision, str(path)))

    def test_history_includes_unflagged_alternatives_and_absence(self):
        self.populate()
        self.finding(self.roots[1] / 'changed.txt')
        self.prepare()
        result = backups.compare(self.conn, self.site)
        self.assertEqual([r['path'] for r in result['rows']], ['changed.txt'])
        entries = result['rows'][0]['entries']
        self.assertNotEqual(entries[0]['file']['sha256'], entries[1]['file']['sha256'])
        self.assertEqual(entries[2]['status'], 'not_present')
        changes = backups.compare(self.conn, self.site, 'changes')
        self.assertEqual({r['path'] for r in changes['rows']}, {'changed.txt', 'new.txt'})

    def test_identical_hash_assessment_reaches_other_paths_but_preserves_conflicts(self):
        self.populate()
        other = self.roots[1] / 'renamed.txt'
        other.write_bytes((self.roots[0] / 'same.txt').read_bytes())
        self.finding(self.roots[0] / 'same.txt', 'confirmed')
        self.finding(self.roots[2] / 'same.txt', 'dismissed')
        self.prepare()
        digest = backups.assess_content(self.conn, str(self.roots[0] / 'same.txt'), 'confirmed', 'Synthetic content decision', ['malware'])
        result = backups.inherit_all(self.conn)
        self.assertIn(str(other), result['applied'])
        self.assertIn(str(self.roots[2] / 'same.txt'), result['conflicts'])
        self.assertEqual(db.one(self.conn, 'SELECT triage FROM findings WHERE artifact=?', (str(other),))['triage'], 'confirmed')
        self.assertEqual(backups.assessment(self.conn, digest)['classifications'], ['malware'])
        self.assertFalse(self.conn.execute('SELECT 1 FROM content_inheritance WHERE artifact=?', (str(self.roots[1] / 'changed.txt'),)).fetchone())

    def test_grouping_retains_changed_versions_and_deduplicates_before_limit(self):
        self.populate()
        for root in self.roots:
            self.finding(root / 'same.txt')
        self.finding(self.roots[0] / 'changed.txt')
        self.finding(self.roots[1] / 'changed.txt')
        self.prepare()
        from server.artifacts import ART_SQL
        groups = backups.group_rows(self.conn, db.rows(self.conn, f'WITH art AS ({ART_SQL}) SELECT * FROM art'))
        self.assertEqual(len(groups), 3, [(Path(r['artifact']).name, r['backup_count'], r['version_key']) for r in groups])
        self.assertEqual(sorted(r['backup_count'] for r in groups), [1, 1, 3])

    def test_diff_is_inert_and_rejects_changed_evidence(self):
        self.populate()
        self.prepare()
        result = backups.file_diff(self.conn, self.ids[0], self.ids[1], 'changed.txt')
        self.assertTrue(any(line == '-Earlier ordinary text' for line in result['lines']))
        self.assertTrue(any(line == '+Later ordinary text' for line in result['lines']))
        (self.roots[1] / 'changed.txt').write_text('Changed after inventory\n')
        with self.assertRaisesRegex(backups.BackupError, 'changed'):
            backups.file_diff(self.conn, self.ids[0], self.ids[1], 'changed.txt')

    def test_failed_discovery_retains_previous_generation(self):
        self.populate()
        self.prepare()
        original = db.one(self.conn, 'SELECT generation FROM backup_snapshots WHERE id=?', (self.ids[0],))['generation']
        def failure(_root, _ctx, errors):
            errors.append(('folder', 'Cannot enumerate'))
            return iter(())
        with patch.object(backups, '_walk', failure):
            result = backups.build(self.case, snapshot_ids=[self.ids[0]])
        self.assertEqual(result['failed_sources'], 1)
        saved = db.one(self.conn, 'SELECT * FROM backup_snapshots WHERE id=?', (self.ids[0],))
        self.assertEqual(saved['generation'], original)
        self.assertEqual(saved['state'], 'stale')

    def test_root_fence_and_unrelated_websites(self):
        with self.assertRaises(backups.BackupError):
            backups.save_snapshot(self.conn, site_id=self.site, evidence_id=1, root=str(self.root), label='Outside')
        self.populate()
        self.prepare()
        other_site = backups.save_site(self.conn, 'Different site')
        self.conn.execute('UPDATE backup_snapshots SET site_id=? WHERE id=?', (other_site, self.ids[1]))
        with self.assertRaises(backups.BackupError):
            backups.file_diff(self.conn, self.ids[0], self.ids[1], 'same.txt')


if __name__ == '__main__':
    unittest.main()
