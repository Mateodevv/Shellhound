import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from server import db, log_evidence, workspace
import server.app as app_module
from server.app import create_app
from server.config import Config
from server.engines import logindex
from server.jobs import CaseBusy


LINE = '192.0.2.7 - - [14/Sep/2026:10:02:03 +0000] "GET /marker HTTP/1.1" 200 42 "-" "sqlmap"\n'


class Context:
    def cancelled(self): return False
    def progress(self, *args): pass
    def phase_progress(self, *args): pass
    def detailed_skip(self, *args, **kwargs): pass


class LogReindexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = Config(workspace=self.root / "workspace", token="test-token")
        self.case = workspace.create_case(self.config.workspace, "First")
        self.other = workspace.create_case(self.config.workspace, "Second")
        app = create_app(self.config)
        self.reindex = next(route.endpoint for route in app.routes
                            if getattr(route, "path", "") == "/api/cases/{slug}/access/reindex")

    def register(self, kind, name, case=None):
        path = self.root / name
        path.write_text(LINE, encoding="utf-8")
        with closing(db.connect(case or self.case)) as conn:
            conn.execute("INSERT INTO evidence(kind,path,added,scanned_at) VALUES (?,?,?,?)",
                         (kind, str(path), db.now(), db.now()))
            conn.commit()
        return path

    def schedule(self):
        queued = []
        def submit(_case, kind, fn, **kwargs):
            queued.append((kind, fn))
            return len(queued)
        with patch.object(app_module.manager, "submit", side_effect=submit):
            result = self.reindex(self.case.name)
        return result, queued

    def run_jobs(self, queued):
        with patch.object(app_module.errorlog, "scan", return_value={}), \
             patch.object(app_module.sigmascan, "scan", return_value={}):
            for _, fn in queued:
                fn(Context())

    def test_reindex_selects_all_registered_logs_only(self):
        first = self.register("access_logs", "one.log")
        second = self.register("logs", "two.log")
        self.register("webroot", "webroot.txt")
        self.register("sql_dump", "dump.sql")
        _, queued = self.schedule()
        self.assertEqual(["index_logs", "sigma", "log_events"], [kind for kind, _ in queued])
        with patch.object(logindex, "build", return_value={"partial": False}) as build:
            queued[0][1](Context())
        self.assertEqual({str(first), str(second)}, set(build.call_args.args[1]))

    def test_no_access_logs_and_busy_are_rejected(self):
        with self.assertRaises(HTTPException) as error:
            self.reindex(self.case.name)
        self.assertEqual(400, error.exception.status_code)
        self.register("access_logs", "one.log")
        with patch.object(app_module.manager, "case_operation", side_effect=CaseBusy("busy")):
            with self.assertRaises(HTTPException) as error:
                self.reindex(self.case.name)
        self.assertEqual(409, error.exception.status_code)

    def test_partial_warning_retry_preserves_triage_and_other_case(self):
        path = self.register("access_logs", "one.log")
        other_path = self.register("access_logs", "other.log", self.other)
        logindex.build(self.other, [str(other_path)])
        logindex.build(self.case, [str(path)])
        with closing(db.connect(self.case)) as conn:
            conn.execute("UPDATE findings SET triage='confirmed', triage_note='reviewed'")
            conn.commit()
            self.assertTrue(conn.execute("SELECT 1 FROM findings").fetchone())
        with closing(db.connect(self.other)) as conn:
            before = conn.execute("SELECT fingerprint,triage,seen_run FROM findings").fetchall()

        class BrokenReader:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def __iter__(self):
                yield LINE
                raise OSError("private error")

        _, queued = self.schedule()
        with patch.object(logindex, "_is_log_text", return_value=True), \
             patch.object(logindex.accesslog, "sniff_error_log", return_value=False), \
             patch.object(logindex, "open_text_auto", return_value=BrokenReader()):
            self.run_jobs(queued)
        source = log_evidence.source_status(self.case)[0]
        self.assertEqual("failed", source["state"])
        self.assertFalse(source["fresh"])
        self.assertIn("incomplete", source["warning"])
        self.assertNotIn("private error", source["warning"])
        _, retry = self.schedule()
        self.run_jobs(retry)
        source = log_evidence.source_status(self.case)[0]
        self.assertEqual("ready", source["state"])
        self.assertTrue(source["fresh"])
        self.assertEqual("", source["warning"])
        with closing(db.connect(self.case)) as conn:
            self.assertEqual(("confirmed", "reviewed"), tuple(conn.execute(
                "SELECT triage,triage_note FROM findings").fetchone()))
        with closing(db.connect(self.other)) as conn:
            self.assertEqual([tuple(row) for row in before], [tuple(row) for row in conn.execute(
                "SELECT fingerprint,triage,seen_run FROM findings")])
