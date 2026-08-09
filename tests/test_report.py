import shutil
import tempfile
import unittest
from pathlib import Path

from server import case_report, db, workspace


class HtmlReportTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="shellhound-report-"))
        self.case = workspace.create_case(
            self.root, "Case <script>alert(1)</script>",
            notes="Analyst <b>note</b>")
        self.evidence = self.root / "analyst-secret-layout" / "webroot"
        conn = db.connect(self.case)
        try:
            conn.execute(
                "INSERT INTO evidence (kind, path, added, label, files, bytes) "
                "VALUES (?,?,?,?,?,?)",
                ("webroot", str(self.evidence), db.now(), "Production", 3, 1200))
            artifact = self.evidence / "images" / "shell.php"
            db.upsert_finding(conn, "webshell", db.SEV_HIGH,
                              "Suspicious <rule>", "file", str(artifact),
                              evidence="not exported")
            conn.execute(
                "UPDATE findings SET triage='confirmed', triage_note=?, "
                "triaged_at=?", ("Checked <manually>", db.now()))
            path_id = db.add_ioc(conn, str(artifact), "path", ["confirmed"],
                                 origin=f"from {self.evidence}")
            hash_id = db.add_ioc(conn, "a" * 64, "hash", ["confirmed"])
            db.link_iocs(conn, hash_id, path_id, "hash-of")
            conn.commit()
        finally:
            conn.close()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_report_is_self_contained_escaped_and_drops_host_paths(self):
        html = case_report.render(self.case, "en", "utc")
        self.assertTrue(html.startswith("<!doctype html>"))
        self.assertIn("Content-Security-Policy", html)
        self.assertIn("Case &lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("Analyst &lt;b&gt;note&lt;/b&gt;", html)
        self.assertIn("images/shell.php", html)
        self.assertIn("a" * 64, html)
        self.assertNotIn(str(self.evidence), html)
        self.assertNotIn("not exported", html)

    def test_bytes_and_digest_are_stable_for_one_render(self):
        body, digest = case_report.render_bytes(self.case, "de", "log")
        self.assertEqual(64, len(digest))
        self.assertIn(b"Fallbericht", body)


if __name__ == "__main__":
    unittest.main()
