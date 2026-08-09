import json
import shutil
import tempfile
import unittest
from pathlib import Path

from server import correlation, db, workspace


class CrossCaseIocTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="shellhound-correlation-"))
        self.current = workspace.create_case(self.root, "Current")
        self.other = workspace.create_case(self.root, "Earlier", reference="IR-41")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    @staticmethod
    def add(case_dir, value, kind, tags=("analyst",), note=""):
        conn = db.connect(case_dir)
        try:
            db.add_ioc(conn, value, kind, tags, note=note, origin="test")
            conn.commit()
        finally:
            conn.close()

    def test_only_ioc_box_entries_match_and_hashes_are_case_insensitive(self):
        digest = "A" * 64
        self.add(self.current, digest, "hash")
        self.add(self.other, digest.lower(), "hash", note="seen before")
        conn = db.connect(self.other)
        try:
            db.upsert_finding(conn, "logs", db.SEV_HIGH, "raw finding",
                              "client", "203.0.113.99")
            conn.commit()
        finally:
            conn.close()

        out = correlation.compare(self.root, self.current.name)
        self.assertEqual(1, out["matched_iocs"])
        self.assertEqual("Earlier", out["entries"][0]["matches"][0]["name"])
        self.assertEqual("IR-41", out["entries"][0]["matches"][0]["reference"])
        self.assertNotIn("203.0.113.99", json.dumps(out))
        self.assertNotIn(str(self.root), json.dumps(out))

    def test_paths_remain_case_sensitive(self):
        self.add(self.current, "Images/Shell.php", "path")
        self.add(self.other, "images/shell.php", "path")
        self.assertEqual([], correlation.compare(self.root, self.current.name)["entries"])

    def test_a_broken_other_case_is_skipped_without_hiding_the_count(self):
        broken = workspace.create_case(self.root, "Broken")
        db.case_db_path(broken).write_bytes(b"not sqlite")
        self.add(self.current, "evil.example", "domain")
        out = correlation.compare(self.root, self.current.name)
        self.assertEqual(2, out["cases_scanned"])
        self.assertEqual(1, out["cases_skipped"])


if __name__ == "__main__":
    unittest.main()
