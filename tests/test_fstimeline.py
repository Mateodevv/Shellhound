# tests/test_fstimeline.py
"""When the webroot was touched -- a lead, never a proof.

The assertions that matter here are the ones about restraint. This module
reads the very thing the rest of the toolkit refuses to trust, so the tests
have to hold it to what it promised: no findings, no severity, nothing in the
chronology, and no ranking of clusters by suspicion.
"""
import os
import tempfile
import unittest
from pathlib import Path

from server import db, fstimeline

DEPLOY = 1780000000
INTRUSION = DEPLOY + 30 * 86400


class ClusterTests(unittest.TestCase):

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix="shellhound-fs-"))
        self.root = Path(tempfile.mkdtemp(prefix="shellhound-fsroot-"))
        db.connect(self.case).close()
        conn = db.connect(self.case)
        try:
            conn.execute("INSERT INTO evidence (kind, path, added) "
                         "VALUES ('webroot', ?, ?)", (str(self.root), db.now()))
            conn.commit()
        finally:
            conn.close()

    def _make(self, rel, when):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("<?php", encoding="utf-8")
        os.utime(path, (when, when))
        return str(path.resolve())

    def _confirm(self, path):
        conn = db.connect(self.case)
        try:
            db.upsert_finding(conn, "webshell", 0, "eval on input", "file",
                              path, evidence="x")
            conn.execute("UPDATE findings SET triage = 'confirmed' "
                         "WHERE artifact = ?", (path,))
            conn.commit()
        finally:
            conn.close()

    def _two_bursts(self):
        for i in range(12):
            self._make(f"core{i}.php", DEPLOY + i)
        shell = self._make("images/kb-media.php", INTRUSION)
        self._make("images/helper.php", INTRUSION + 8)
        self._make("images/.htaccess", INTRUSION + 19)
        return shell

    def test_files_written_together_form_one_burst(self):
        self._two_bursts()
        out = fstimeline.clusters(self.case)
        self.assertTrue(out["checked"])
        self.assertEqual(2, len(out["clusters"]))
        self.assertEqual([12, 3], [c["count"] for c in out["clusters"]])

    def test_bursts_are_ordered_by_time_not_by_suspicion(self):
        """Ranking clusters would be exactly the verdict this module refuses
        to give."""
        self._confirm(self._two_bursts())
        out = fstimeline.clusters(self.case)
        starts = [c["from"] for c in out["clusters"]]
        self.assertEqual(starts, sorted(starts))
        self.assertEqual(0, out["clusters"][0]["confirmed"],
                         "the tied burst was moved to the front")

    def test_a_burst_says_whether_the_case_already_confirmed_something_in_it(self):
        """The one piece of interpretation: the OTHER files in that burst
        were written in the same minute as something known to belong here."""
        shell = self._two_bursts()
        self._confirm(shell)
        out = fstimeline.clusters(self.case)
        tied = [c for c in out["clusters"] if c["confirmed"]]
        self.assertEqual(1, len(tied))
        self.assertEqual(3, tied[0]["count"])
        marked = [f for f in tied[0]["files"] if f["confirmed"]]
        self.assertEqual([shell], [f["path"] for f in marked])

    def test_a_lone_file_is_not_a_burst(self):
        self._make("only.php", DEPLOY)
        self._make("far.php", DEPLOY + 99999)
        self.assertEqual([], fstimeline.clusters(self.case)["clusters"])

    def test_cache_churn_is_out_by_default_and_available_on_request(self):
        """A cache rewrites itself constantly and would be the largest
        cluster in every case."""
        self._two_bursts()
        for i in range(40):
            self._make(f"cache/c{i}.php", INTRUSION + 200 + i)
        quiet = fstimeline.clusters(self.case)
        noisy = fstimeline.clusters(self.case, include_noise=True)
        self.assertEqual(2, len(quiet["clusters"]))
        self.assertEqual(3, len(noisy["clusters"]))
        self.assertGreater(noisy["files"], quiet["files"])

    def test_no_webroot_says_so_rather_than_returning_nothing(self):
        bare = Path(tempfile.mkdtemp(prefix="shellhound-fsbare-"))
        db.connect(bare).close()
        out = fstimeline.clusters(bare)
        self.assertFalse(out["checked"])
        self.assertEqual("nowebroot", out["reason"])

    # --- the promises -------------------------------------------------------

    def test_nothing_is_written_to_the_case(self):
        """No findings, no severity, nothing to triage. This reads."""
        self._confirm(self._two_bursts())
        conn = db.connect(self.case)
        try:
            before = conn.execute("SELECT count(*) FROM findings").fetchone()[0]
        finally:
            conn.close()
        fstimeline.clusters(self.case)
        conn = db.connect(self.case)
        try:
            after = conn.execute("SELECT count(*) FROM findings").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(before, after)

    def test_no_cluster_carries_a_severity(self):
        self._two_bursts()
        for c in fstimeline.clusters(self.case)["clusters"]:
            self.assertNotIn("severity", c)
            self.assertNotIn("worst", c)

    def test_the_chronology_never_sees_any_of_this(self):
        """The chain is measured time only. An mtime is not a measurement of
        when something happened -- it is a measurement of what a file system
        currently claims."""
        from server.chain import case_chain
        self._confirm(self._two_bursts())
        chain = case_chain(self.case)
        for event in chain["events"]:
            self.assertIn(event["source"], ("log", "dump"))


if __name__ == "__main__":
    unittest.main()
