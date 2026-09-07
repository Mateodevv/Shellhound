"""Per-job skip history must survive retries, failures and database upgrades."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from server import db, workspace
from server.app import create_app
from server.config import Config
from server.engines import webshell
from server.jobs import JobManager


class JobSkipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = Config(workspace=self.root / "workspace", token="test")
        self.case = workspace.create_case(self.config.workspace, "Synthetic")
        self.manager = JobManager()
        app = create_app(self.config)
        self.details = next(r.endpoint for r in app.routes
                            if getattr(r, "path", "") == "/api/cases/{slug}/jobs/{job_id}/skipped")

    def tearDown(self):
        self.manager.pool.shutdown(wait=True)
        self.temp.cleanup()

    def run_job(self, fn):
        job = self.manager.submit(self.case, "webshell", fn)
        self.assertEqual([], self.manager.wait_for(self.case, [job], timeout=10))
        return job

    def test_scan_records_path_reason_and_retry_keeps_history(self):
        evidence = self.root / "Evidence # ä"
        evidence.mkdir()
        target = evidence / "large.php"
        target.write_text("synthetic fixture", encoding="utf-8")
        with patch.object(webshell, "scan_file", return_value=([], "too large", None)):
            first = self.run_job(lambda ctx: webshell.scan(self.case, [str(evidence)], ctx))
        with patch.object(webshell, "scan_file", return_value=([], None, None)):
            second = self.run_job(lambda ctx: webshell.scan(self.case, [str(evidence)], ctx))
        self.assertEqual({"items": [{"path": str(target), "reason": "too large"}],
                          "total": 1, "recorded": True}, self.details(self.case.name, first))
        self.assertEqual({"items": [], "total": 0, "recorded": True},
                         self.details(self.case.name, second))

    def test_failed_job_keeps_details_and_pages_without_polling_payload_growth(self):
        def fail(ctx):
            for i in range(205):
                ctx.skip(f"file-{i}.php", "unreadable")
            raise ValueError("synthetic failure")
        job = self.run_job(fail)
        self.assertEqual(200, len(self.details(self.case.name, job, limit=10000)["items"]))
        tail = self.details(self.case.name, job, offset=200)
        self.assertEqual(205, tail["total"])
        self.assertEqual(5, len(tail["items"]))
        self.assertEqual("file-200.php", tail["items"][0]["path"])
        conn = db.connect(self.case)
        try:
            row = db.one(conn, "SELECT state, stats FROM jobs WHERE id = ?", (job,))
            self.assertEqual("failed", row["state"])
            self.assertEqual({"skip_details": 205}, json.loads(row["stats"]))
        finally:
            conn.close()

    def test_legacy_job_does_not_borrow_current_case_skips(self):
        conn = db.connect(self.case)
        try:
            conn.execute("INSERT INTO jobs (kind, created, stats) VALUES ('webshell', ?, ?)",
                         (db.now(), '{"skipped":1}'))
            conn.execute("INSERT INTO skipped (source, path, reason) VALUES ('webshell','other.php','new scan')")
            conn.commit()
        finally:
            conn.close()
        self.assertEqual({"items": [], "total": 0, "recorded": False}, self.details(self.case.name, 1))
        with self.assertRaises(HTTPException) as err:
            self.details(self.case.name, 999)
        self.assertEqual(404, err.exception.status_code)

    def test_version_ten_upgrade_creates_skip_history(self):
        conn = db.connect(self.case)
        conn.execute("DROP TABLE job_skips")
        conn.execute("UPDATE meta SET value = '10' WHERE key = 'schema_version'")
        conn.commit()
        conn.close()
        conn = db.connect(self.case)
        try:
            self.assertEqual(0, conn.execute("SELECT count(*) FROM job_skips").fetchone()[0])
        finally:
            conn.close()
