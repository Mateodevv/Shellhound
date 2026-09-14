"""Harmless local log evidence: formats, source identity and analyst decisions."""
import gzip
import bz2
import json
import lzma
import os
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from server import db, log_evidence as logs, log_parsers as parsers, workspace
from server.chain import case_chain


FTP = 'Mon Sep 14 10:02:03 2026 1 2001:db8::7 42 /srv/site/marker.txt b _ i r demo ftp 0 * c\n'
NATIVE = 'Mon Sep 14 10:02:03 2026 [pid 123] [demo] OK UPLOAD: Client "192.0.2.7", "/srv/site/marker.txt", 42 bytes\n'


class ParserTests(unittest.TestCase):
    def test_nginx_multiline_and_compressed_text_variants(self):
        line = '2026/09/14 10:02:03 [error] 123#123: *4 Ordinary diagnostic, client: 192.0.2.8, server: example.test\n  Continued diagnostic\n'
        with tempfile.TemporaryDirectory(prefix="log formats ") as directory:
            for suffix, compress in (("gz", gzip.compress), ("bz2", bz2.compress), ("xz", lzma.compress)):
                path = Path(directory) / ("error.log." + suffix)
                path.write_bytes(compress(line.encode("utf-8")))
                self.assertEqual(parsers.detect(list(parsers.text_lines(path, preview=True)))["format"], "nginx_error")
                events = list(parsers.records(path, "nginx_error", "UTC"))
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["ip"], "192.0.2.8")
                self.assertEqual(events[0]["line_end"], 2)
                self.assertIsNotNone(events[0]["epoch"])

    def test_transfer_formats_and_clock_uncertainty(self):
        for fmt, line in (("xferlog", FTP), ("vsftpd", NATIVE)):
            event = parsers.parse_line(fmt, line)
            self.assertEqual(event["operation"], "upload")
            self.assertEqual(event["outcome"], "success")
            self.assertEqual(event["path"], "/srv/site/marker.txt")
            self.assertIsNone(parsers.timestamp(event["raw_time"]))
            self.assertEqual(parsers.timestamp(event["raw_time"], "+02:00"), 1789372923)

    def test_scan_limits_are_not_malware(self):
        self.assertTrue(parsers.parse_line("clamav", "/srv/marker.txt: Synthetic.Demo FOUND")["detection"])
        self.assertFalse(parsers.parse_line("clamav", "/srv/marker.txt: Heuristics.Limits.Exceeded.MaxFileSize FOUND")["detection"])
        self.assertEqual(parsers.parse_line("clamav", "Scanned files: 4")["operation"], "scan_summary")

    def test_reported_cleanup_errors_and_scan_dates_remain_distinct(self):
        for action in ("Removed.", "moved to '/quarantine/marker.txt'", "copied to '/quarantine/marker.txt'"):
            event = parsers.parse_line("clamav", "C:/site/marker.txt: " + action)
            self.assertEqual(event["outcome"], "reported_action")
            self.assertFalse(event["detection"])
            self.assertEqual(event["path"], "C:/site/marker.txt")
        self.assertEqual(parsers.parse_line("clamav", "ERROR: Cannot read source")["outcome"], "error")
        summary = parsers.parse_line("clamav", "End Date: 2026:09:14 08:02:03")
        self.assertEqual(summary["time_meaning"], "scan")
        self.assertEqual(parsers.timestamp(summary["raw_time"], "UTC"), 1789372923)
        self.assertFalse(summary["detection"])

    def test_unknown_and_mixed_formats(self):
        self.assertEqual(parsers.detect([(1, "ordinary text")])["format"], "text")
        result = parsers.detect([(1, FTP), (2, NATIVE)])
        self.assertTrue(result["ambiguous"])
        self.assertEqual(result["format"], "text")

    def test_utc_and_explicit_offset(self):
        self.assertEqual(parsers.timestamp("2026-09-14T10:02:03+02:00"), parsers.timestamp("2026-09-14T08:02:03Z"))
        self.assertIsNone(parsers.timestamp("not a date", "UTC"))


class LogEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="log evidence ")
        self.root = Path(self.temp.name)
        self.case = workspace.create_case(self.root / "workspace", "Log review")
        self.sources = self.root / "logs"
        self.sources.mkdir()
        self.register("logs", self.sources)

    def tearDown(self):
        self.temp.cleanup()

    def register(self, kind, path):
        conn = db.connect(self.case)
        conn.execute("INSERT INTO evidence(kind,path,added) VALUES (?,?,?)", (kind, str(path), db.now()))
        conn.commit()
        conn.close()

    def test_import_select_retry_and_stale_context(self):
        path = self.sources / "ftp.log"
        path.write_text(FTP, encoding="utf-8")
        source = logs.inventory(self.case, persist=True)[0]
        logs.configure(self.case, source["id"], {"timezone": "UTC"})
        self.assertEqual(logs.build(self.case)["events"], 1)
        event = logs.search(self.case)["rows"][0]
        result = logs.apply(self.case, [event], "Review this transfer")
        self.assertEqual(result["added"], 1)
        logs.apply(self.case, [event], "Review this transfer")
        conn = db.connect(self.case)
        self.assertEqual(conn.execute("SELECT count(*) FROM findings").fetchone()[0], 1)
        conn.execute("UPDATE findings SET triage='confirmed'")
        conn.commit()
        conn.close()
        logs.build(self.case)
        self.assertEqual(logs.search(self.case)["rows"][0]["id"], event["id"])
        self.assertTrue(logs.context(self.case, event["id"])["lines"])
        path.write_text(FTP.replace("10:02:03", "11:02:03"), encoding="utf-8")
        with self.assertRaises(logs.LogEvidenceError):
            logs.context(self.case, event["id"])

    def test_malware_report_unmatched_path_and_warning_acceptance(self):
        (self.sources / "scan.txt").write_text("/srv/marker.txt: Synthetic.Demo FOUND\n", encoding="utf-8")
        (self.sources / "notes.txt").write_text("An observation for manual review\n", encoding="utf-8")
        logs.build(self.case)
        conn = db.connect(self.case)
        findings = db.rows(conn, "SELECT * FROM findings")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["artifact_kind"], "log_observation")
        self.assertEqual(findings[0]["triage"], "new")
        conn.close()
        self.assertEqual(logs.warning_counts(self.case), (1, 0))
        source = next(s for s in logs.source_status(self.case) if s["warning"])
        logs.accept_warning(self.case, source["id"])
        self.assertEqual(logs.warning_counts(self.case), (0, 1))
        Path(source["path"]).write_text("Changed observation\n", encoding="utf-8")
        self.assertEqual(logs.warning_counts(self.case), (1, 0))

    def test_mapping_respects_existing_decision_and_earliest_upload(self):
        webroot = self.root / "webroot"
        webroot.mkdir()
        target = webroot / "marker.txt"
        target.write_text("Harmless marker", encoding="utf-8")
        self.register("webroot", webroot)
        (self.sources / "ftp.log").write_text(FTP + FTP.replace("10:02:03", "09:02:03"), encoding="utf-8")
        source = logs.inventory(self.case, persist=True)[0]
        logs.configure(self.case, source["id"], {"server_root": "/srv/site", "webroot": str(webroot), "timezone": "UTC"})
        conn = db.connect(self.case)
        db.upsert_finding(conn, "analyst", db.SEV_MEDIUM, "Manual marker review", "file", str(target))
        conn.execute("UPDATE findings SET triage='confirmed'")
        conn.commit()
        conn.close()
        logs.build(self.case)
        conn = db.connect(self.case)
        self.assertEqual({r[0] for r in conn.execute("SELECT triage FROM findings")}, {"confirmed"})
        conn.close()
        events = [e for e in case_chain(self.case)["events"] if e["kind"] == "log-observation"]
        self.assertTrue(events)
        self.assertTrue(all(e["first_sign_eligible"] for e in events))

    def test_failed_source_does_not_replace_old_events_and_can_retry(self):
        path = self.sources / "ftp.log"
        path.write_text(FTP, encoding="utf-8")
        logs.build(self.case)
        with patch.object(parsers, "MAX_LINE", 5):
            stats = logs.build(self.case)
        self.assertEqual(stats["failed_sources"], 1)
        self.assertFalse(logs.search(self.case)["rows"][0]["fresh"])
        self.assertEqual(logs.build(self.case)["events"], 1)
        self.assertTrue(logs.search(self.case)["rows"][0]["fresh"])

    def test_rotations_overlap_pagination_and_no_basename_match(self):
        with gzip.open(self.sources / "ftp.log.gz", "wt", encoding="utf-8") as stream:
            stream.write(FTP * 205)
        self.register("logs", self.sources / "ftp.log.gz")
        self.assertEqual(len(logs.inventory(self.case)), 1)
        logs.build(self.case)
        first = logs.search(self.case, {"limit": 200})
        self.assertEqual(first["total"], 205)
        self.assertEqual(len(logs.search(self.case, {"offset": first["next_offset"]})["rows"]), 5)
        self.assertTrue(all(not e["artifact"] for e in first["rows"]))

    def test_multiline_context_and_credentials(self):
        path = self.sources / "errors.log"
        path.write_text("[Mon Sep 14 10:02:03 2026] [php:error] A harmless warning\n  continuation token=private-value\n", encoding="utf-8")
        logs.build(self.case)
        event = logs.search(self.case)["rows"][0]
        self.assertEqual(event["line_end"], 2)
        self.assertNotIn("private-value", event["raw"])
        self.assertNotIn("private-value", json.dumps(logs.context(self.case, event["id"])))

    def test_error_detection_without_a_webroot_keeps_working_source_navigation(self):
        (self.sources / "errors.log").write_text(
            "[Mon Sep 14 10:02:03 2026] [php:error] Harmless diagnostic in /srv/site/marker.php on line 7\n",
            encoding="utf-8")
        with patch.object(logs.errorlog, "_INTERESTING", re.compile("Harmless")):
            logs.build(self.case)
        conn = db.connect(self.case)
        finding = db.one(conn, "SELECT * FROM findings")
        self.assertIsNotNone(finding)
        self.assertEqual(finding["artifact_kind"], "log_observation")
        self.assertIsNone(finding["line"])
        observation = logs.saved_for_artifact(conn, finding["artifact"])[0]
        conn.close()
        self.assertFalse(logs.context(self.case, observation["id"])["event"]["artifact_available"])
        self.assertEqual(observation["source_name"], "errors.log")

    def test_publication_failure_preserves_previous_generation(self):
        path = self.sources / "scan.log"
        path.write_text("/srv/marker.txt: Synthetic.Demo FOUND\n", encoding="utf-8")
        logs.build(self.case)
        old = logs.search(self.case)["rows"][0]["id"]
        path.write_text("/srv/another.txt: Synthetic.Demo FOUND\n", encoding="utf-8")
        with patch.object(logs, "_save_finding", side_effect=sqlite3.OperationalError("simulated write failure")):
            self.assertEqual(logs.build(self.case)["failed_sources"], 1)
        self.assertEqual(logs.search(self.case)["rows"][0]["id"], old)

    def test_clock_preserving_change_cannot_supply_first_sign(self):
        path = self.sources / "ftp.log"
        path.write_text(FTP, encoding="utf-8")
        sid = logs.inventory(self.case, persist=True)[0]["id"]
        logs.configure(self.case, sid, {"timezone": "UTC"})
        logs.build(self.case)
        event = logs.search(self.case)["rows"][0]
        logs.apply(self.case, [event])
        conn = db.connect(self.case)
        conn.execute("UPDATE findings SET triage='confirmed'")
        conn.commit()
        conn.close()
        original = path.stat()
        path.write_text(FTP.replace("10:02:03", "09:02:03"), encoding="utf-8")
        os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
        self.assertFalse(logs.timeline_events(self.case)[0]["fresh"])

    def test_bulk_selection_hashes_each_source_once(self):
        (self.sources / "ftp.log").write_text(FTP * 3, encoding="utf-8")
        logs.build(self.case)
        events = logs.search(self.case)["rows"]
        with patch.object(logs, "fingerprint", wraps=logs.fingerprint) as hashes:
            logs.apply(self.case, events)
        self.assertEqual(hashes.call_count, 1)

    def test_saved_context_deduplicates_and_rejects_another_generation(self):
        path = self.sources / "scan.log"
        path.write_text("/srv/marker.txt: Synthetic.Demo FOUND\n", encoding="utf-8")
        logs.build(self.case)
        event = logs.search(self.case)["rows"][0]
        artifact = logs.apply(self.case, [event])["artifacts"][0]
        conn = db.connect(self.case)
        self.assertEqual(len(logs.saved_for_artifact(conn, artifact)), 1)
        conn.close()
        path.write_text("/srv/marker.txt: Synthetic.Demo FOUND\nScanned files: 1\n", encoding="utf-8")
        logs.build(self.case)
        current = logs.search(self.case, {"id": event["id"]})["rows"][0]
        self.assertNotEqual(current["fingerprint"], event["fingerprint"])
        with self.assertRaises(logs.LogEvidenceError):
            logs.context(self.case, event["id"], event["fingerprint"])
        self.assertTrue(logs.context(self.case, current["id"], current["fingerprint"])["lines"])

    def test_report_uses_source_reference_and_escaped_saved_observation(self):
        from server import case_report
        (self.sources / "notes.txt").write_text("A harmless <em>marker</em> observation\n", encoding="utf-8")
        logs.build(self.case)
        event = logs.search(self.case)["rows"][0]
        logs.apply(self.case, [event], "Analyst context")
        conn = db.connect(self.case)
        conn.execute("UPDATE findings SET triage='confirmed'")
        conn.commit()
        conn.close()
        report = case_report.render(self.case)
        self.assertIn("notes.txt:1", report)
        self.assertIn("&lt;em&gt;marker&lt;/em&gt;", report)
        self.assertNotIn("<em>marker</em>", report)
        self.assertIn("1 are not automatically analyzed", report)

    def test_scan_summary_time_is_not_an_automatic_compromise_anchor(self):
        (self.sources / "scan.log").write_text("End Date: 2026:09:14 08:02:03\n", encoding="utf-8")
        sid = logs.inventory(self.case, persist=True)[0]["id"]
        logs.configure(self.case, sid, {"timezone": "UTC"})
        logs.build(self.case)
        logs.apply(self.case, logs.search(self.case)["rows"])
        conn = db.connect(self.case)
        conn.execute("UPDATE findings SET triage='confirmed'")
        conn.commit()
        conn.close()
        events = [e for e in case_chain(self.case)["events"] if e["kind"] == "log-observation"]
        self.assertEqual(len(events), 1)
        self.assertFalse(events[0]["first_sign_eligible"])

    def test_clock_correction_is_applied_once_to_search_and_timeline(self):
        (self.sources / "ftp.log").write_text(FTP, encoding="utf-8")
        sid = logs.inventory(self.case, persist=True)[0]["id"]
        logs.configure(self.case, sid, {"timezone": "+02:00"})
        logs.build(self.case)
        original = logs.search(self.case)["rows"][0]
        logs.apply(self.case, [original])
        conn = db.connect(self.case)
        conn.execute("UPDATE findings SET triage='confirmed'")
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES ('clock_offsets',?)", (json.dumps({"logs": 1800}),))
        conn.commit()
        conn.close()
        corrected = original["epoch"] + 1800
        event = logs.search(self.case, {"from_epoch": corrected, "to_epoch": corrected})["rows"][0]
        self.assertEqual(event["epoch"], corrected)
        self.assertEqual(event["recorded_epoch"], original["epoch"])
        chain_event = next(e for e in case_chain(self.case)["events"] if e["id"] == event["timeline_id"])
        self.assertEqual(chain_event["epoch"], corrected)
        self.assertTrue(chain_event["first_sign_eligible"])

    def test_mapping_does_not_move_an_existing_analyst_decision(self):
        webroot = self.root / "webroot"
        webroot.mkdir()
        (webroot / "marker.txt").write_text("Ordinary marker", encoding="utf-8")
        self.register("webroot", webroot)
        (self.sources / "scan.log").write_text("/srv/site/marker.txt: Synthetic.Demo FOUND\n", encoding="utf-8")
        logs.build(self.case)
        conn = db.connect(self.case)
        conn.execute("UPDATE findings SET triage='confirmed',triage_note='Analyst note'")
        conn.commit()
        conn.close()
        sid = logs.inventory(self.case)[0]["id"]
        logs.configure(self.case, sid, {"server_root": "/srv/site", "webroot": str(webroot)})
        logs.build(self.case)
        conn = db.connect(self.case)
        findings = db.rows(conn, "SELECT * FROM findings")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["triage"], "confirmed")
        self.assertEqual(findings[0]["triage_note"], "Analyst note")
        conn.close()

    def test_case_http_registration_analysis_and_log_only_completion(self):
        from server.app import create_app
        from server.config import Config
        from server.jobs import manager
        from tests.test_http import _LiveServer, request
        path = self.sources / "ftp.log"
        path.write_text(FTP, encoding="utf-8")
        server = _LiveServer(create_app(Config(workspace=self.root / "workspace", token="synthetic-test-token")))
        base = f"/api/cases/{self.case.name}"
        def call(method, route, body=None):
            status, _, raw = request(method, base + route, body, token="synthetic-test-token")
            self.assertEqual(status, 200, raw[:1000])
            return json.loads(raw)
        try:
            with patch("tests.test_http.BASE", server.start()):
                call("POST", "/log-sources/preview", {"path": str(path)})
                call("POST", "/log-sources/register", {"path": str(path), "timezone": "UTC"})
                response = call("POST", "/analyze", {"mode": "all"})
                manager.wait_for(self.case, [s["job"] for s in response["started"]])
                result = call("POST", "/log-events/search", {})
                self.assertEqual(result["total"], 1)
                event = result["rows"][0]
                call("POST", "/log-events/apply", {"selections": [{"id": event["id"], "fingerprint": event["fingerprint"]}]})
                artifacts = call("GET", "/findings")["artifacts"]
                self.assertEqual(artifacts[0]["display_name"], "ftp.log:1")
                self.assertTrue(call("GET", "/dashboard")["analysis_complete"])
                source = call("GET", "/log-sources")["sources"][0]
                call("PATCH", "/log-sources/" + source["id"], {"timezone": "+02:00"})
                self.assertFalse(call("GET", "/dashboard")["analysis_complete"])
                retry = call("POST", "/log-sources/analyze", {"source_ids": [source["id"]]})
                manager.wait_for(self.case, [retry["job"]])
                self.assertTrue(call("GET", "/dashboard")["analysis_complete"])
                (self.sources / "another.log").write_text(NATIVE, encoding="utf-8")
                retry = call("POST", "/log-sources/analyze", {"source_ids": [source["id"]]})
                manager.wait_for(self.case, [retry["job"]])
                self.assertFalse(call("GET", "/dashboard")["analysis_complete"], "A scoped retry cannot certify a new sibling source")
        finally:
            server.stop()
