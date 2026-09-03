"""Incremental analysis keeps old evidence authoritative and scopes new work."""
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from server import db, workspace
import server.app as app_module
from server.app import create_app
from server.config import Config
from server.engines import cmsinventory, sqldump, webshell


class _Context:
    def __init__(self, cancelled=False):
        self._cancelled = cancelled

    def cancelled(self):
        return self._cancelled

    def progress(self, *_args, **_kwargs):
        pass


class IncrementalSchedulingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = Config(workspace=self.root / "workspace", token="test-token")
        self.case_dir = workspace.create_case(self.config.workspace, "Synthetic")
        self.slug = self.case_dir.name
        app = create_app(self.config)
        self.analyze = next(
            route.endpoint for route in app.routes
            if getattr(route, "path", "") == "/api/cases/{slug}/analyze")
        self.dashboard = next(route.endpoint for route in app.routes
                              if getattr(route, "path", "") == "/api/cases/{slug}/dashboard")

    def tearDown(self):
        self.temp.cleanup()

    def _register(self, kind, name, scanned=True, file=False):
        path = self.root / "evidence" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if file:
            path.write_text("-- synthetic SQL\n", encoding="utf-8")
        else:
            path.mkdir(parents=True, exist_ok=True)
        conn = db.connect(self.case_dir)
        try:
            cur = conn.execute(
                "INSERT INTO evidence (kind, path, added, scanned_at) VALUES (?,?,?,?)",
                (kind, str(path), db.now(), db.now() if scanned else ""))
            conn.commit()
            return cur.lastrowid, path
        finally:
            conn.close()

    def _schedule(self, mode="new", body=True):
        queued = []

        def submit(_case_dir, kind, fn, **_kwargs):
            queued.append((kind, fn))
            return len(queued)

        request_body = SimpleNamespace(mode=mode) if body else None
        with patch.object(app_module.manager, "submit", side_effect=submit):
            result = self.analyze(self.slug, request_body)
        return result, queued

    def test_bodyless_request_remains_a_full_run(self):
        self._register("access_logs", "logs")
        self._register("webroot", "site")
        self._register("sql_dump", "database.sql", file=True)

        _result, queued = self._schedule(body=False)

        self.assertEqual(
            ["index_logs", "errorlog", "sigma", "webshell", "cms", "sqldb"],
            [kind for kind, _fn in queued])

    def test_new_logs_rebuild_all_logs_but_queue_no_file_or_sql_engine(self):
        _old_id, old_logs = self._register("access_logs", "logs-old")
        new_id, new_logs = self._register("access_logs", "logs-new", scanned=False)
        self._register("webroot", "site")
        self._register("sql_dump", "database.sql", file=True)

        _result, queued = self._schedule()
        self.assertEqual(["index_logs", "errorlog", "sigma"],
                         [kind for kind, _fn in queued])

        index_job = queued[0][1]
        with patch.object(app_module.logindex, "build",
                          return_value={"files": 2, "partial": False}) as build:
            index_job(_Context())
        self.assertEqual({str(old_logs), str(new_logs)}, set(build.call_args.args[1]))
        self.assertFalse(self._scanned_at(new_id))
        with patch.object(app_module.errorlog, "scan", return_value={}), \
                patch.object(app_module.sigmascan, "scan", return_value={}):
            queued[1][1](_Context())
            self.assertFalse(self._scanned_at(new_id))
            queued[2][1](_Context())
        conn = db.connect(self.case_dir)
        try:
            row = db.one(conn, "SELECT scanned_at FROM evidence WHERE id = ?", (new_id,))
            self.assertTrue(row["scanned_at"])
        finally:
            conn.close()

    def test_new_webroot_queues_only_file_inventory_and_log_correlation(self):
        self._register("access_logs", "logs")
        self._register("webroot", "site-old")
        new_id, _new = self._register("webroot", "site-new", scanned=False)
        self._register("sql_dump", "database.sql", file=True)

        _result, queued = self._schedule()
        self.assertEqual(["webshell", "cms", "errorlog"],
                         [kind for kind, _fn in queued])

        shell_job = queued[0][1]
        with patch.object(app_module.webshell, "scan", return_value={"scanned": 1}) as scan:
            shell_job(_Context(cancelled=True))
        self.assertFalse(self._scanned_at(new_id))
        self.assertFalse(scan.call_args.kwargs["authoritative"])

        with patch.object(app_module.webshell, "scan", side_effect=OSError("synthetic failure")):
            with self.assertRaises(OSError):
                shell_job(_Context())
        self.assertFalse(self._scanned_at(new_id))

    def _scanned_at(self, evidence_id):
        conn = db.connect(self.case_dir)
        try:
            return db.one(conn, "SELECT scanned_at FROM evidence WHERE id = ?",
                          (evidence_id,))["scanned_at"]
        finally:
            conn.close()

    def test_webroot_receipt_waits_for_cms_and_yara_in_any_completion_order(self):
        new_id, _ = self._register("webroot", "new-site", scanned=False)
        for order in (("webshell", "cms", "yara"), ("yara", "cms", "webshell")):
            with self.subTest(order=order):
                with patch.object(app_module.yarascan, "status", return_value={"rules": 1}):
                    _, queued = self._schedule(mode="all")
                jobs = dict(queued)
                with patch.object(app_module.webshell, "scan", return_value={"scanned": 1}), \
                        patch.object(app_module.cmsinventory, "scan", return_value={"installs": 1}), \
                        patch.object(app_module.yarascan, "scan", return_value={"rules": 1}), \
                        patch.object(app_module.db, "now", return_value="new-receipt"):
                    before = self._scanned_at(new_id)
                    jobs[order[0]](_Context())
                    jobs[order[1]](_Context())
                    self.assertEqual(before, self._scanned_at(new_id))
                    jobs[order[2]](_Context())
                self.assertEqual("new-receipt", self._scanned_at(new_id))

    def test_failed_or_cancelled_secondary_engine_keeps_incremental_retry_available(self):
        new_id, _ = self._register("webroot", "new-site", scanned=False)
        for engine in ("cms", "yara"):
            for failure in ("exception", "cancelled", "partial"):
                with self.subTest(engine=engine, failure=failure):
                    with patch.object(app_module.yarascan, "status", return_value={"rules": 1}):
                        _, queued = self._schedule()
                    with patch.object(app_module.webshell, "scan", return_value={}), \
                            patch.object(app_module.cmsinventory, "scan", return_value={}), \
                            patch.object(app_module.yarascan, "scan", return_value={}):
                        for kind, fn in queued:
                            if kind != engine:
                                fn(_Context())
                                continue
                            module = app_module.cmsinventory if kind == "cms" else app_module.yarascan
                            if failure == "exception":
                                with patch.object(module, "scan", side_effect=OSError("synthetic failure")):
                                    with self.assertRaises(OSError):
                                        fn(_Context())
                            elif failure == "cancelled":
                                fn(_Context(cancelled=True))
                            else:
                                with patch.object(module, "scan", return_value={"broken_rules": 1}):
                                    fn(_Context())
                    self.assertFalse(self._scanned_at(new_id))
        # A fresh manual retry succeeds; old successes do not create a receipt alone.
        _, retry = self._schedule()
        with patch.object(app_module.webshell, "scan", return_value={}), \
                patch.object(app_module.cmsinventory, "scan", return_value={}):
            for _, fn in retry:
                fn(_Context())
        self.assertTrue(self._scanned_at(new_id))

    def test_new_webroot_waits_for_error_log_correlation(self):
        self._register("access_logs", "logs")
        new_id, _ = self._register("webroot", "new-site", scanned=False)
        _, queued = self._schedule()
        with patch.object(app_module.webshell, "scan", return_value={}), \
                patch.object(app_module.cmsinventory, "scan", return_value={}):
            queued[0][1](_Context())
            queued[1][1](_Context())
        self.assertFalse(self._scanned_at(new_id))
        with patch.object(app_module.errorlog, "scan", return_value={}):
            queued[2][1](_Context(cancelled=True))
        self.assertFalse(self._scanned_at(new_id))
        self._schedule()  # Still retryable.

    def test_log_receipt_rejects_failed_dependent_engine_or_partial_index(self):
        new_id, _ = self._register("access_logs", "new-logs", scanned=False)
        for partial in (False, True):
            _, queued = self._schedule()
            with patch.object(app_module.logindex, "build", return_value={"partial": partial}), \
                    patch.object(app_module.errorlog, "scan", return_value={}), \
                    patch.object(app_module.sigmascan, "scan", side_effect=OSError("synthetic failure")):
                queued[0][1](_Context())
                queued[1][1](_Context())
                if partial:
                    self.assertTrue(queued[2][1](_Context())["skipped"])
                else:
                    with self.assertRaises(OSError):
                        queued[2][1](_Context())
            self.assertFalse(self._scanned_at(new_id))
        self._schedule()

    def test_sql_partial_scan_does_not_mark_dump_complete(self):
        new_id, _ = self._register("sql_dump", "new.sql", scanned=False, file=True)
        _, queued = self._schedule()
        with patch.object(app_module.sqldump, "scan", return_value={"skipped": 1}):
            queued[0][1](_Context())
        self.assertFalse(self._scanned_at(new_id))

    def test_access_logs_can_complete_without_optional_webroot_correlations(self):
        new_id, _ = self._register("access_logs", "logs-only", scanned=False)
        _, queued = self._schedule()
        with patch.object(app_module.logindex, "build", return_value={"lines": 1}), \
                patch.object(app_module.errorlog, "scan", return_value={"skipped": 1}), \
                patch.object(app_module.sigmascan, "scan", return_value={}):
            for _, fn in queued:
                fn(_Context())
        self.assertTrue(self._scanned_at(new_id))
        conn = db.connect(self.case_dir)
        try:
            conn.execute("INSERT INTO jobs (kind, state, created, stats) VALUES (?,?,?,?)",
                         ("errorlog", "done", db.now(), '{"skipped":1}'))
            conn.commit()
        finally:
            conn.close()
        self.assertTrue(self.dashboard(self.slug, "en", "UTC")["analysis_complete"])

    def test_parallel_completion_writes_one_receipt(self):
        from server.analysis import AnalysisReceipts
        from unittest.mock import Mock
        mark = Mock()
        tasks = [(kind, lambda _ctx: {}, ("webroot",)) for kind in ("webshell", "cms", "yara")]
        receipt = AnalysisReceipts(tasks, {"webroot": [{"id": 1}]}, mark)
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = [pool.submit(receipt.wrap(kind, fn), _Context()) for kind, fn, _ in tasks]
            for result in futures:
                result.result(timeout=5)
        mark.assert_called_once()
        self.assertEqual([1], mark.call_args.args[0])
        self.assertEqual({"webshell", "cms", "yara"}, set(mark.call_args.args[1]["engines"]))

    def test_dashboard_requires_receipts_and_successful_latest_engine_results(self):
        new_id, _ = self._register("webroot", "site", scanned=False)
        self.assertFalse(self.dashboard(self.slug, "en", "UTC")["analysis_complete"])
        conn = db.connect(self.case_dir)
        try:
            conn.execute("UPDATE evidence SET scanned_at = ? WHERE id = ?", (db.now(), new_id))
            conn.commit()
            self.assertTrue(self.dashboard(self.slug, "en", "UTC")["analysis_complete"])
            for state, stats in (("failed", {}), ("cancelled", {}), ("running", {}),
                                 ("done", {"skipped": 1}), ("done", {})):
                with self.subTest(state=state, stats=stats):
                    conn.execute("DELETE FROM jobs")
                    conn.execute("INSERT INTO jobs (kind, state, created, stats) VALUES (?,?,?,?)",
                                 ("cms", state, db.now(), json.dumps(stats)))
                    # An unrelated later success must not hide the failed CMS scan.
                    conn.execute("INSERT INTO jobs (kind, state, created, stats) VALUES (?,?,?,?)",
                                 ("sqldb", "done", db.now(), "{}"))
                    conn.commit()
                    self.assertEqual(state == "done" and not stats,
                                     self.dashboard(self.slug, "en", "UTC")["analysis_complete"])
        finally:
            conn.close()

    def test_overlapping_new_root_is_refused_before_a_job_is_created(self):
        _old_id, old = self._register("webroot", "site")
        nested = old / "nested"
        nested.mkdir()
        conn = db.connect(self.case_dir)
        try:
            conn.execute(
                "INSERT INTO evidence (kind, path, added, scanned_at) VALUES (?,?,?, '')",
                ("webroot", str(nested), db.now()))
            conn.commit()
        finally:
            conn.close()

        with patch.object(app_module.manager, "submit") as submit:
            with self.assertRaises(HTTPException) as raised:
                self.analyze(self.slug, SimpleNamespace(mode="new"))
        self.assertEqual(409, raised.exception.status_code)
        self.assertIn("full reanalysis", raised.exception.detail)
        submit.assert_not_called()


class PartialEngineMergeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.case_dir = workspace.create_case(self.root / "workspace", "Merge")

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def _shell(root, name):
        path = root / "images" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("<?php echo 1;\n", encoding="utf-8")
        return path

    @staticmethod
    def _wordpress(root, version):
        version_file = root / "wp-includes" / "version.php"
        version_file.parent.mkdir(parents=True, exist_ok=True)
        version_file.write_text(f"<?php $wp_version = '{version}';\n", encoding="utf-8")

    def test_partial_file_scan_merges_hashes_and_keeps_prior_decisions_live(self):
        old_root, new_root = self.root / "old-site", self.root / "new-site"
        old_file = self._shell(old_root, "old.jpg.php")
        new_file = self._shell(new_root, "new.jpg.php")
        webshell.scan(self.case_dir, [str(old_root)])
        conn = db.connect(self.case_dir)
        try:
            conn.execute("UPDATE findings SET triage = 'confirmed', triage_note = 'synthetic review'")
            conn.execute("INSERT INTO skipped (source, path, reason) VALUES ('webshell', ?, 'old')",
                         (str(old_root / "unreadable.php"),))
            marker = db.one(conn, "SELECT value FROM meta WHERE key = 'engine_done:webshell'")["value"]
            conn.commit()
        finally:
            conn.close()

        webshell.scan(self.case_dir, [str(new_root)], authoritative=False)

        conn = db.connect(self.case_dir)
        try:
            hashes = json.loads(db.one(
                conn, "SELECT value FROM meta WHERE key = 'webshell_hashes'")["value"])
            self.assertEqual({str(old_file.resolve()), str(new_file.resolve())}, set(hashes))
            self.assertEqual(marker, db.one(
                conn, "SELECT value FROM meta WHERE key = 'engine_done:webshell'")["value"])
            old_rows = db.rows(conn, "SELECT triage, triage_note FROM findings WHERE artifact = ?",
                               (str(old_file.resolve()),))
            self.assertTrue(old_rows)
            self.assertEqual({("confirmed", "synthetic review")},
                             {(row["triage"], row["triage_note"]) for row in old_rows})
            self.assertEqual(1, conn.execute(
                "SELECT count(*) FROM skipped WHERE source='webshell' AND reason='old'").fetchone()[0])
        finally:
            conn.close()

    def test_partial_cms_and_sql_inventory_preserve_previous_sources(self):
        old_site, new_site = self.root / "old-cms", self.root / "new-cms"
        self._wordpress(old_site, "6.4.1")
        self._wordpress(new_site, "6.5.2")
        cmsinventory.scan(self.case_dir, [str(old_site)])
        cmsinventory.scan(self.case_dir, [str(new_site)], authoritative=False)

        old_dump, new_dump = self.root / "old.sql", self.root / "new.sql"
        statement = "CREATE TABLE `sample` (`id` int); INSERT INTO `sample` VALUES (1);\n"
        old_dump.write_text(statement, encoding="utf-8")
        new_dump.write_text(statement.replace("sample", "sample_two"), encoding="utf-8")
        sqldump.scan(self.case_dir, [str(old_dump)])
        conn = db.connect(self.case_dir)
        try:
            marker = db.one(conn, "SELECT value FROM meta WHERE key = 'engine_done:sqldump'")["value"]
        finally:
            conn.close()
        sqldump.scan(self.case_dir, [str(new_dump)], authoritative=False)

        conn = db.connect(self.case_dir)
        try:
            self.assertEqual({str(old_site), str(new_site)}, {
                row["root"] for row in db.rows(conn, "SELECT root FROM cms_installs")})
            self.assertEqual({str(old_dump.resolve()), str(new_dump.resolve())}, {
                row["path"] for row in db.rows(conn, "SELECT path FROM db_dumps")})
            self.assertEqual(marker, db.one(
                conn, "SELECT value FROM meta WHERE key = 'engine_done:sqldump'")["value"])
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
