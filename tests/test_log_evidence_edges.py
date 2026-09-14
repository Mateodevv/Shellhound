"""Log-source lifecycle regressions using harmless, local-only evidence."""
import json
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from server import db, log_evidence as logs, log_parsers as parsers, workspace
from server.artifacts import ART_SQL
from server.analysis import refresh_receipts
from server.engines import errorlog, logindex
from server.engines.fsutil import canonical_file


FTP = "Mon Sep 14 10:02:03 2026 1 192.0.2.7 42 /srv/site/marker.txt b _ i r demo ftp 0 * c\n"
ERROR = "[Mon Sep 14 10:02:03 2026] [php:error] PHP Fatal error: harmless marker in /srv/site/marker.php on line 2\n"
ACCESS = '192.0.2.7 - - [14/Sep/2026:10:02:03 +0000] "GET /marker.txt HTTP/1.1" 200 42 "-" "Synthetic review client"\n'


class _Context:
    def __init__(self):
        self.stopped = False

    def cancelled(self):
        return self.stopped

    def phase_progress(self, *_args, **_kwargs):
        pass

    def detailed_skip(self, *_args, **_kwargs):
        pass


class LogEvidenceEdgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="log lifecycle ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ws = self.root / "workspace"
        self.case = workspace.create_case(self.ws, "Log lifecycle")
        self.sources = self.root / "sources"
        self.sources.mkdir()

    def register(self, kind, path):
        conn = db.connect(self.case)
        try:
            conn.execute("INSERT INTO evidence(kind,path,added) VALUES (?,?,?)",
                         (kind, str(path), db.now()))
            conn.commit()
        finally:
            conn.close()

    def source(self, filename):
        return next(source for source in logs.inventory(self.case, persist=True)
                    if Path(source["path"]).name == filename)

    def findings(self, case=None):
        conn = db.connect(case or self.case)
        try:
            return db.rows(conn, "SELECT * FROM findings ORDER BY id")
        finally:
            conn.close()

    def confirm(self):
        conn = db.connect(self.case)
        try:
            conn.execute("UPDATE findings SET triage='confirmed',triage_note='Reviewed source entry'")
            conn.commit()
        finally:
            conn.close()

    def analyze_endpoint(self):
        from server.app import create_app
        from server.config import Config
        app = create_app(Config(workspace=self.ws, token="synthetic-review-token"))
        return next(route.endpoint for route in app.routes
                    if getattr(route, "path", "") == "/api/cases/{slug}/analyze")

    def wait_for_jobs(self, jobs):
        from server.jobs import manager
        remaining = manager.wait_for(self.case, jobs, timeout=5)
        if remaining:
            for job in remaining:
                manager.cancel(self.case, job)
            manager.wait_for(self.case, remaining, timeout=2)
        self.assertEqual(remaining, [], "Synthetic analysis did not finish")

    def receipt(self):
        conn = db.connect(self.case)
        try:
            refresh_receipts(conn)
            conn.commit()
            item = db.one(conn, "SELECT scanned_at,stats FROM evidence WHERE kind='logs'")
            return item["scanned_at"], json.loads(item["stats"])["last_attempt"]
        finally:
            conn.close()

    def test_retrying_one_error_source_preserves_other_sources_support(self):
        webroot = self.root / "webroot"
        webroot.mkdir()
        (webroot / "marker.php").write_text("Harmless marker", encoding="utf-8")
        self.register("webroot", webroot)
        self.register("logs", self.sources)
        (self.sources / "a-error.log").write_text(ERROR, encoding="utf-8")
        second = self.sources / "b-error.log"
        second.write_text(ERROR.replace("10:02:03", "11:02:03"), encoding="utf-8")
        for source in logs.inventory(self.case, persist=True):
            logs.configure(self.case, source["id"],
                           {"server_root": "/srv/site", "webroot": str(webroot)})
        logs.build(self.case)
        self.confirm()
        second.write_text("[Mon Sep 14 11:02:03 2026] [info] Ordinary marker\n", encoding="utf-8")
        logs.build(self.case, source_ids=[self.source(second.name)["id"]])
        conn = db.connect(self.case)
        try:
            artifacts = db.rows(conn, f"WITH art AS ({ART_SQL}) SELECT * FROM art")
            self.assertEqual(len(artifacts), 1)
            self.assertEqual(artifacts[0]["findings"], 1)
            self.assertEqual(artifacts[0]["retired"], 1)
            self.assertEqual(artifacts[0]["triage"], "confirmed")
        finally:
            conn.close()

    def test_cancelling_mid_source_keeps_previous_events_and_decisions(self):
        path = self.sources / "ftp.log"
        path.write_text(FTP, encoding="utf-8")
        self.register("logs", path)
        logs.build(self.case)
        previous = logs.search(self.case)["rows"][0]
        logs.apply(self.case, [previous])
        self.confirm()
        path.write_text(FTP.replace("10:02:03", "11:02:03") + FTP, encoding="utf-8")
        ctx = _Context()
        original_records = parsers.records

        def cancel_after_first_record(*args, **kwargs):
            for position, event in enumerate(original_records(*args, **kwargs)):
                if position == 1:
                    ctx.stopped = True
                yield event

        with patch.object(parsers, "records", cancel_after_first_record):
            logs.build(self.case, ctx)
        self.assertTrue(ctx.cancelled())
        rows = logs.search(self.case)["rows"]
        self.assertEqual([row["id"] for row in rows], [previous["id"]])
        self.assertFalse(rows[0]["fresh"])
        self.assertEqual(logs.source_status(self.case)[0]["state"], "cancelled")
        self.assertEqual(self.findings()[0]["triage"], "confirmed")
        logs.build(self.case)
        self.assertEqual(logs.search(self.case)["total"], 2)
        self.assertTrue(all(row["fresh"] for row in logs.search(self.case)["rows"]))
        self.assertEqual(self.findings()[0]["triage_note"], "Reviewed source entry")

    def test_failed_source_keeps_history_without_blocking_other_sources(self):
        self.register("logs", self.sources)
        good = self.sources / "a-scan.txt"
        failing = self.sources / "b-scan.txt"
        good.write_text("/srv/first.txt: Synthetic.Demo FOUND\n", encoding="utf-8")
        failing.write_text("/srv/second.txt: Synthetic.Demo FOUND\n", encoding="utf-8")
        logs.build(self.case)
        self.confirm()
        previous = {event["source_id"]: event for event in logs.search(self.case)["rows"]}
        sid = self.source(failing.name)["id"]
        good.write_text("/srv/third.txt: Synthetic.Demo FOUND\n", encoding="utf-8")
        failing.write_bytes(b"\x00unsupported binary content")
        result = logs.build(self.case)
        self.assertEqual(result["files"], 1)
        self.assertEqual(result["failed_sources"], 1)
        rows = logs.search(self.case)["rows"]
        preserved = next(event for event in rows if event["source_id"] == sid)
        self.assertEqual(preserved["id"], previous[sid]["id"])
        self.assertFalse(preserved["fresh"])
        self.assertTrue(next(event for event in rows if event["source_id"] != sid)["fresh"])
        failing.write_text("/srv/second.txt: Synthetic.Demo FOUND\n", encoding="utf-8")
        self.assertEqual(logs.build(self.case, source_ids=[sid])["failed_sources"], 0)
        self.assertTrue(all(event["fresh"] for event in logs.search(self.case)["rows"]))
        self.assertEqual(next(row for row in self.findings() if row["artifact"] ==
                             "log-observation:" + previous[sid]["id"])["triage"], "confirmed")

    def test_empty_recognized_report_and_unknown_text_are_distinct(self):
        self.register("logs", self.sources)
        (self.sources / "empty-scan.txt").write_text("", encoding="utf-8")
        (self.sources / "notes.txt").write_text("Host maintenance note\n", encoding="utf-8")
        empty = self.source("empty-scan.txt")
        logs.configure(self.case, empty["id"], {"format": "clamav"})
        result = logs.build(self.case)
        self.assertEqual(result["failed_sources"], 0)
        sources = {Path(row["path"]).name: row for row in logs.source_status(self.case)}
        self.assertEqual(sources["empty-scan.txt"]["stats"].get("events", 0), 0)
        self.assertEqual(sources["empty-scan.txt"]["family"], "malware")
        self.assertFalse(sources["empty-scan.txt"]["warning"])
        self.assertTrue(sources["notes.txt"]["warning"])
        event = logs.search(self.case)["rows"][0]
        self.assertEqual(event["family"], "text")
        self.assertFalse(event["parsed"])
        self.assertIsNone(event["epoch"])
        self.assertEqual(self.findings(), [])

    def test_archive_preserves_source_settings_and_review_without_derived_index(self):
        path = self.sources / "notes.txt"
        path.write_text("Host maintenance note\n", encoding="utf-8")
        self.register("logs", path)
        sid = self.source(path.name)["id"]
        options = {"format": "text", "timezone": "UTC", "label": "Host notes"}
        logs.configure(self.case, sid, options)
        logs.build(self.case)
        event = logs.search(self.case)["rows"][0]
        logs.apply(self.case, [event], "Retain this source reference")
        self.confirm()
        logs.accept_warning(self.case, sid)
        archive, _ = workspace.archive_case(self.ws, self.case)
        with zipfile.ZipFile(archive) as zipped:
            names = zipped.namelist()
            self.assertIn(db.CASE_DB, names)
            self.assertFalse(any(Path(name).name.startswith(logs.INDEX_NAME) for name in names))
        restored = Path(workspace.import_archive(self.root / "restored", archive)["dir"])
        source = logs.source_status(restored)[0]
        self.assertEqual(source["id"], sid)
        self.assertTrue(all(source["settings"][key] == value for key, value in options.items()))
        self.assertFalse(source["fresh"])
        self.assertTrue(source["accepted"])
        stored = self.findings(restored)[0]
        self.assertEqual(stored["triage"], "confirmed")
        self.assertEqual(stored["triage_note"], "Reviewed source entry")
        conn = db.connect(restored)
        try:
            snapshot = logs.saved_for_artifact(conn, stored["artifact"])[0]
        finally:
            conn.close()
        self.assertEqual(snapshot["id"], event["id"])
        self.assertEqual(snapshot["source_name"], "Host notes")
        self.assertEqual(snapshot["raw"], "Host maintenance note")
        with self.assertRaises(logs.LogEvidenceError):
            logs.context(restored, event["id"])
        logs.build(restored)
        self.assertEqual(logs.context(restored, event["id"])["event"]["id"], event["id"])
        self.assertEqual(len(self.findings(restored)), 1)
        self.assertEqual(self.findings(restored)[0]["triage"], "confirmed")

    def test_format_change_requires_reanalysis_and_preserves_manual_decision(self):
        path = self.sources / "ftp.log"
        path.write_text(FTP, encoding="utf-8")
        self.register("logs", path)
        sid = self.source(path.name)["id"]
        logs.configure(self.case, sid, {"format": "xferlog", "timezone": "UTC"})
        logs.build(self.case)
        previous = logs.search(self.case)["rows"][0]
        logs.apply(self.case, [previous])
        self.confirm()
        logs.configure(self.case, sid, {"format": "text", "timezone": "UTC"})
        with self.assertRaises(logs.LogEvidenceError):
            logs.context(self.case, previous["id"])
        with self.assertRaises(logs.LogEvidenceError):
            logs.apply(self.case, [previous])
        logs.build(self.case)
        current = logs.search(self.case)["rows"][0]
        self.assertEqual(current["family"], "text")
        self.assertEqual(current["id"], previous["id"])
        self.assertNotEqual(current["fingerprint"], previous["fingerprint"])
        self.assertIsNone(current["epoch"])
        self.assertEqual(self.findings()[0]["triage"], "confirmed")

    def test_legacy_access_index_remains_fresh_until_inventory_migration(self):
        access = self.sources / "access.log"
        access.write_text(ACCESS, encoding="utf-8")
        (self.sources / "error.log").write_text(ERROR, encoding="utf-8")
        self.register("access_logs", self.sources)
        targets = logs.access_targets(self.case)
        self.assertEqual(targets, [str(self.sources)])
        logindex.build(self.case, targets)
        self.assertTrue(logindex.status(self.case, logs.access_targets(self.case))["fresh"])
        notes = self.root / "notes.txt"
        notes.write_text("Host maintenance note\n", encoding="utf-8")
        self.register("logs", notes)
        self.assertEqual([canonical_file(path) for path in logs.access_targets(self.case)],
                         [canonical_file(access)])
        self.assertFalse(logindex.status(self.case, logs.access_targets(self.case))["fresh"])
        logindex.build(self.case, logs.access_targets(self.case))
        self.assertTrue(logindex.status(self.case, logs.access_targets(self.case))["fresh"])
        notes.write_text("Updated maintenance note\n", encoding="utf-8")
        self.assertTrue(logindex.status(self.case, logs.access_targets(self.case))["fresh"])
        self.assertEqual(logindex.access_search(self.case)["total"], 1)

    def test_cancelled_queued_access_index_releases_dependent_jobs(self):
        import server.app as app_module
        path = self.sources / "access.log"
        path.write_text(ACCESS, encoding="utf-8")
        self.register("logs", path)
        analyze = self.analyze_endpoint()
        queued, events = {}, []
        real_event = threading.Event

        def track_event():
            event = real_event()
            events.append(event)
            return event

        def submit(_case, kind, fn, **kwargs):
            queued[kind] = (fn, kwargs)
            return len(queued)

        with patch.object(app_module.manager, "submit", side_effect=submit), \
                patch.object(app_module.threading, "Event", side_effect=track_event):
            analyze(self.case.name, SimpleNamespace(mode="all"))
        queued["index_logs"][1]["on_cancel"]()
        ctx = _Context()
        results = {}

        def run_dependents():
            try:
                results["sigma"] = queued["sigma"][0](ctx)
                results["logs"] = queued["log_events"][0](ctx)
            except Exception as exc:
                results["error"] = type(exc).__name__

        worker = threading.Thread(target=run_dependents, daemon=True)
        with patch.object(app_module.sigmascan, "scan") as scan:
            try:
                worker.start()
                worker.join(2)
                completed = not worker.is_alive()
            finally:
                # A regression must fail without leaving a test thread behind.
                ctx.stopped = True
                for event in events:
                    event.set()
                worker.join(2)
            self.assertTrue(completed, "Cancellation left a dependent job waiting indefinitely")
            self.assertNotIn("error", results)
            self.assertIn("logs", results)
            self.assertEqual(results["sigma"]["reason"], "log index build did not complete")
            scan.assert_not_called()

    def test_correcting_text_to_access_can_complete_full_analysis(self):
        path = self.sources / "access.log"
        path.write_text(ACCESS, encoding="utf-8")
        self.register("logs", path)
        sid = self.source(path.name)["id"]
        logs.configure(self.case, sid, {"format": "text"})
        analyze = self.analyze_endpoint()
        first = analyze(self.case.name, SimpleNamespace(mode="all"))
        self.wait_for_jobs([job["job"] for job in first["started"]])
        self.assertEqual(self.receipt()[1]["status"], "complete_with_warnings")
        logs.configure(self.case, sid, {"format": "access"})
        second = analyze(self.case.name, SimpleNamespace(mode="all"))
        self.wait_for_jobs([job["job"] for job in second["started"]])
        scanned, attempt = self.receipt()
        self.assertTrue(scanned)
        self.assertEqual(attempt["status"], "complete")
        self.assertTrue(logindex.status(self.case, logs.access_targets(self.case))["fresh"])
        self.assertEqual(logindex.access_search(self.case)["total"], 1)

    def test_text_retry_cannot_certify_changed_access_evidence(self):
        from server.jobs import manager
        access = self.sources / "access.log"
        access.write_text(ACCESS, encoding="utf-8")
        (self.sources / "notes.txt").write_text("Host maintenance note\n", encoding="utf-8")
        self.register("logs", self.sources)
        analyze = self.analyze_endpoint()
        initial = analyze(self.case.name, SimpleNamespace(mode="all"))
        self.wait_for_jobs([job["job"] for job in initial["started"]])
        self.assertTrue(self.receipt()[0])
        access.write_text(ACCESS + ACCESS.replace("10:02:03", "11:02:03"), encoding="utf-8")
        sid = self.source("notes.txt")["id"]
        job = manager.submit(self.case, "log_events", lambda ctx: logs.build(self.case, ctx, [sid]),
                             scan_context={"mode": "log_retry"})
        self.wait_for_jobs([job])
        self.assertFalse(logindex.status(self.case, logs.access_targets(self.case))["fresh"])
        scanned, attempt = self.receipt()
        self.assertFalse(scanned)
        self.assertEqual(attempt["status"], "partial")
        self.assertEqual(attempt["engines"]["index_logs"]["state"], "partial")
        repaired = analyze(self.case.name, SimpleNamespace(mode="all"))
        self.wait_for_jobs([job["job"] for job in repaired["started"]])
        self.assertTrue(self.receipt()[0])
        self.assertEqual(logindex.access_search(self.case)["total"], 2)

    def test_only_complete_general_log_pass_retires_legacy_error_support(self):
        webroot = self.root / "webroot"
        webroot.mkdir()
        target = webroot / "marker.php"
        target.write_text("Harmless marker", encoding="utf-8")
        self.register("webroot", webroot)
        self.register("access_logs", self.sources)
        path = self.sources / "error.log"
        path.write_text(ERROR, encoding="utf-8")
        errorlog.scan(self.case, [str(self.sources)], workspace=self.ws)
        self.assertEqual(len(self.findings()), 1)
        self.confirm()
        notes = self.root / "notes.txt"
        notes.write_text("Host maintenance note\n", encoding="utf-8")
        self.register("logs", notes)
        path.write_text("[Mon Sep 14 10:02:03 2026] [info] Ordinary marker\n", encoding="utf-8")

        def legacy_counts():
            conn = db.connect(self.case)
            try:
                return db.one(conn, f"WITH art AS ({ART_SQL}) SELECT findings,retired,triage FROM art")
            finally:
                conn.close()

        sid = self.source("notes.txt")["id"]
        logs.build(self.case, source_ids=[sid])
        self.assertEqual(legacy_counts()["findings"], 1)
        notes.write_bytes(b"\x00unsupported binary content")
        self.assertEqual(logs.build(self.case)["failed_sources"], 1)
        self.assertEqual(legacy_counts()["findings"], 1)
        notes.write_text("Host maintenance note\n", encoding="utf-8")
        self.assertEqual(logs.build(self.case)["failed_sources"], 0)
        self.assertEqual(legacy_counts(), {"findings": 0, "retired": 1, "triage": "confirmed"})
