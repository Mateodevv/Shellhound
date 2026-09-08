"""File warnings and retries must preserve unexamined evidence and decisions."""
import itertools
import builtins
import json
import os
import tempfile
import tracemalloc
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from server import db
from server.engines import fsutil, webshell, yarascan
from server.engines.scan_limits import MAX_OVERRIDE_SCAN_BYTES


class RecordingContext:
    def __init__(self):
        self.events = []
        self.skips = []
        self.results = []
        self.stop = False

    def cancelled(self):
        return self.stop

    def phase_progress(self, fraction, message, phase, completed=None, total=None):
        self.events.append((phase, completed, total, message))

    def detailed_skip(self, path, reason, category="file", root=""):
        self.skips.append((path, reason, category, root))

    def file_result(self, path, root, status, reason=""):
        self.results.append((path, root, status, reason))


class FileScanRetryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.site = self.root / "Evidence with spaces"
        self.site.mkdir()
        self.first = self.site / "first.php"
        self.second = self.site / "second.php"
        self.first.write_text("<?php echo 'ordinary page';", encoding="utf-8")
        self.second.write_text("<?php echo 'another ordinary page';", encoding="utf-8")
        self.ws = self.root / "workspace"
        (self.ws / "yara").mkdir(parents=True)
        (self.ws / "yara" / "synthetic.yar").write_text(
            'rule synthetic { strings: $s = "synthetic-marker" condition: $s }',
            encoding="utf-8")

    def seed(self, engine):
        case = self.root / ("case-" + engine)
        case.mkdir()
        conn = db.connect(case)
        source = "yara" if engine == "yarascan" else engine
        run = db.begin_run(conn, engine)
        for path in (self.first, self.second):
            db.upsert_finding(conn, source, 0, "Previous synthetic finding", "file", str(path),
                              engine=engine, run=run)
            conn.execute("INSERT INTO skipped(source,path,reason) VALUES (?,?,?)",
                         (source, str(path), "previous read failure"))
            if engine == "webshell":
                conn.execute("INSERT INTO inert_php(path,reason) VALUES (?,?)",
                             (str(path), "previous stub observation"))
        conn.execute("UPDATE findings SET triage='confirmed', triage_note='Analyst note'")
        conn.execute("INSERT OR REPLACE INTO meta VALUES ('webshell_hashes', ?)",
                     (json.dumps({str(self.first): "first-digest", str(self.second): "second-digest"}),))
        db.complete_run(conn, engine, run)
        conn.close()
        return case, run

    def findings(self, case):
        conn = db.connect(case)
        try:
            rows = db.rows(conn,
                f"SELECT f.*, {db.LIVE_PREDICATE} AS live FROM findings f {db.RETIRE_JOIN}")
            return {Path(row["artifact"]).name: row for row in rows}
        finally:
            conn.close()

    def run_scan(self, engine, case, ctx=None, files=None):
        case.mkdir(exist_ok=True)
        module = webshell if engine == "webshell" else yarascan
        return module.scan(case, [str(self.site)], workspace=self.ws, ctx=ctx,
                           file_targets=files, authoritative=files is None)

    def targets(self, *paths):
        return [{"path": str(path), "root": str(self.site)} for path in paths]

    def test_skipped_files_keep_prior_findings_then_successful_retry_retires_only_that_file(self):
        for engine in ("webshell", "yarascan"):
            with self.subTest(engine=engine):
                case, initial_run = self.seed(engine)
                self.first.write_bytes(b"x" * (webshell.MAX_CONTENT_SCAN_BYTES + 1))
                ctx = RecordingContext()
                stats = self.run_scan(engine, case, ctx)
                self.assertEqual(1, stats["file_skips"])
                self.assertNotIn("partial", stats)
                rows = self.findings(case)
                self.assertTrue(rows[self.first.name]["live"])
                self.assertFalse(rows[self.second.name]["live"])
                self.assertEqual("Analyst note", rows[self.first.name]["triage_note"])
                self.assertEqual(("file", str(self.site)), ctx.skips[0][2:])
                if engine == "webshell":
                    conn = db.connect(case)
                    self.assertEqual({str(self.first): "first-digest"}, json.loads(db.one(
                        conn, "SELECT value FROM meta WHERE key='webshell_hashes'")["value"]))
                    self.assertEqual([str(self.first)], [r[0] for r in conn.execute(
                        "SELECT path FROM inert_php")])
                    conn.close()
                self.first.write_text("<?php echo 'ordinary';", encoding="utf-8")
                retry_ctx = RecordingContext()
                stats = self.run_scan(engine, case, retry_ctx, self.targets(self.first))
                self.assertEqual(1, stats["scanned"])
                self.assertEqual("resolved", retry_ctx.results[0][2])
                rows = self.findings(case)
                self.assertFalse(rows[self.first.name]["live"])
                self.assertEqual("confirmed", rows[self.first.name]["triage"])
                self.assertEqual("Analyst note", rows[self.first.name]["triage_note"])

    def test_retry_commits_before_resolution_and_preserves_unrelated_state(self):
        for engine in ("webshell", "yarascan"):
            with self.subTest(engine=engine):
                case, run = self.seed(engine)
                ctx = RecordingContext()

                def committed_result(path, root, status, reason=""):
                    rows = self.findings(case)  # independent DB connection
                    self.assertFalse(rows[self.first.name]["live"])
                    self.assertTrue(rows[self.second.name]["live"])
                    ctx.results.append(status)

                ctx.file_result = committed_result
                stats = self.run_scan(engine, case, ctx, self.targets(self.first))
                self.assertEqual(1, stats["scanned"])
                self.assertEqual(["resolved"], ctx.results)
                conn = db.connect(case)
                try:
                    self.assertEqual(str(run), db.one(conn,
                        "SELECT value FROM meta WHERE key=?", ("engine_done:" + engine,))["value"])
                    self.assertEqual([str(self.second)], [r[0] for r in conn.execute(
                        "SELECT path FROM skipped WHERE source=?",
                        ("yara" if engine == "yarascan" else engine,))])
                    if engine == "webshell":
                        self.assertEqual({str(self.second): "second-digest"}, json.loads(db.one(
                            conn, "SELECT value FROM meta WHERE key='webshell_hashes'")["value"]))
                finally:
                    conn.close()

    def test_cancelled_retry_preserves_unvisited_files_but_keeps_committed_success(self):
        for engine in ("webshell", "yarascan"):
            with self.subTest(engine=engine):
                case, _run = self.seed(engine)
                ctx = RecordingContext()
                record = ctx.file_result

                def stop_after_file(*args, **kwargs):
                    record(*args, **kwargs)
                    ctx.stop = True

                ctx.file_result = stop_after_file
                stats = self.run_scan(engine, case, ctx, self.targets(self.first, self.second))
                self.assertEqual(1, stats["scanned"])
                self.assertEqual(1, len(ctx.results))
                rows = self.findings(case)
                self.assertFalse(rows[self.first.name]["live"])
                self.assertTrue(rows[self.second.name]["live"])

    def test_retry_preserves_original_root_for_location_rules(self):
        nested = self.site / "uploads" / "nested" / "page.php"
        nested.parent.mkdir(parents=True)
        nested.write_text("<?php echo $_GET['name'];", encoding="utf-8")
        case = self.root / "location-case"
        case.mkdir()
        stats = webshell.scan(case, [], file_targets=self.targets(nested))
        self.assertEqual(1, stats["scanned"])
        conn = db.connect(case)
        self.assertTrue(db.one(conn, "SELECT 1 FROM findings WHERE rule_id='webshell.upload_php'"))
        conn.close()

    def test_all_skipped_files_remain_warnings_and_missing_retries_stay_unresolved(self):
        for path in (self.first, self.second):
            path.write_bytes(b"x" * (webshell.MAX_CONTENT_SCAN_BYTES + 1))
        for engine in ("webshell", "yarascan"):
            with self.subTest(engine=engine):
                case, _run = self.seed(engine)
                stats = self.run_scan(engine, case)
                self.assertEqual(2, stats["file_skips"])
                self.assertNotIn("partial", stats)
                self.assertTrue(all(row["live"] for row in self.findings(case).values()))
                self.first.unlink()
                ctx = RecordingContext()
                stats = self.run_scan(engine, case, ctx, self.targets(self.first))
                self.assertEqual(1, stats["file_skips"])
                self.assertEqual("skipped", ctx.results[0][2])
                self.assertTrue(self.findings(case)[self.first.name]["live"])
                self.first.write_bytes(b"x" * (webshell.MAX_CONTENT_SCAN_BYTES + 1))

    def test_retry_never_traverses_a_replacement_directory_or_an_outside_root(self):
        self.first.unlink()
        self.first.mkdir()
        (self.first / "new.php").write_text("synthetic", encoding="utf-8")
        outside = self.root / "outside.php"
        outside.write_text("synthetic", encoding="utf-8")
        for engine in ("webshell", "yarascan"):
            with self.subTest(engine=engine):
                case, _run = self.seed(engine)
                ctx = RecordingContext()
                with patch.object(fsutil.os, "scandir", side_effect=AssertionError("must not walk")):
                    stats = self.run_scan(engine, case, ctx, self.targets(self.first, outside))
                self.assertEqual(1, stats["scanned"])
                self.assertEqual(1, stats["file_skips"])
                self.assertTrue(stats["partial"])
                self.assertEqual(1, stats["discovery_errors"])
                self.assertEqual({"file", "discovery"}, {entry[2] for entry in ctx.skips})
                self.assertEqual("skipped", ctx.results[0][2])

    def test_discovery_emits_live_counts_before_scanning(self):
        for i in range(8):
            (self.site / f"extra-{i}.txt").write_text("ordinary", encoding="utf-8")
        for engine in ("webshell", "yarascan"):
            with self.subTest(engine=engine):
                ctx = RecordingContext()
                case = self.root / engine
                scan_dir = fsutil.os.scandir

                def observed_walk(path):
                    self.assertEqual("discovering", ctx.events[-1][0])
                    return scan_dir(path)

                with patch.object(fsutil.os, "scandir", side_effect=observed_walk), \
                        patch.object(fsutil.time, "monotonic", side_effect=itertools.count(step=0.11)):
                    stats = self.run_scan(engine, case, ctx)
                counts = [n for phase, n, total, _msg in ctx.events
                          if phase == "discovering" and total is None]
                self.assertEqual(10, stats["scanned"])
                self.assertTrue(any(0 < count < 10 for count in counts))
                scanning = [event for event in ctx.events if event[0] == "scanning"]
                self.assertEqual(10, scanning[0][2])
                self.assertEqual("finalizing", ctx.events[-1][0])

    def directory_alias(self, link, target):
        if os.name == "nt":
            import _winapi
            _winapi.CreateJunction(str(target), str(link))
            self.addCleanup(link.rmdir)
        else:
            link.symlink_to(target, target_is_directory=True)
            self.addCleanup(link.unlink)

    def test_directory_alias_keeps_location_finding_and_analyst_decision(self):
        uploads = self.site / "uploads"
        uploads.mkdir()
        sample = uploads / "sample.php"
        # An inert token exercises the location heuristic without a payload.
        sample.write_text("file_put_contents(", encoding="utf-8")
        case = self.root / "alias-case"
        self.run_scan("webshell", case)
        conn = db.connect(case)
        try:
            original = db.one(conn, "SELECT id FROM findings WHERE rule_id='webshell.upload_php'")
            self.assertIsNotNone(original)
            conn.execute("UPDATE findings SET triage='confirmed', triage_note='Keep this decision' WHERE id=?",
                         (original["id"],))
            conn.commit()
        finally:
            conn.close()
        self.directory_alias(self.site / "z-cache", uploads)
        stats = self.run_scan("webshell", case)
        self.assertEqual(4, stats["scanned"])
        self.assertEqual(0, stats["skipped"])
        conn = db.connect(case)
        try:
            finding = db.one(conn, f"SELECT f.*, {db.LIVE_PREDICATE} AS live FROM findings f "
                             f"{db.RETIRE_JOIN} WHERE f.id=?", (original["id"],))
            self.assertTrue(finding["live"])
            self.assertEqual("confirmed", finding["triage"])
            self.assertEqual("Keep this decision", finding["triage_note"])
        finally:
            conn.close()

    def test_overlapping_roots_preserve_distinct_location_contexts(self):
        uploads = self.site / "uploads"
        uploads.mkdir()
        sample = uploads / "sample.php"
        sample.write_text("ordinary marker", encoding="utf-8")
        files = fsutil.discover_scan_files(
            [str(uploads), str(self.site), str(self.site)], fsutil.ScanProgress(None), {})
        contexts = [root for path, root in files if path == str(sample)]
        self.assertCountEqual([str(uploads), str(self.site)], contexts)
        self.assertEqual(4, len(files))

    def test_directory_cycles_stop_and_external_aliases_remain_discovery_errors(self):
        uploads = self.site / "uploads"
        uploads.mkdir()
        sample = uploads / "sample.php"
        sample.write_text("ordinary marker", encoding="utf-8")
        self.directory_alias(self.site / "z-cache", uploads)
        self.directory_alias(uploads / "back", self.site)
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "outside.php").write_text("ordinary marker", encoding="utf-8")
        self.directory_alias(self.site / "external", outside)
        ctx = RecordingContext()
        stats = {}
        # Fail promptly if a regression follows the cycle indefinitely.
        checks = itertools.count()
        def cancelled():
            self.assertLess(next(checks), 100)
            return False
        ctx.cancelled = cancelled
        files = fsutil.discover_scan_files([str(self.site)], fsutil.ScanProgress(ctx), stats)
        self.assertCountEqual(
            [str(self.first), str(self.second), str(sample), str(self.site / "z-cache" / "sample.php")],
            [path for path, _root in files])
        self.assertTrue(stats["partial"])
        self.assertEqual(1, stats["discovery_errors"])
        self.assertEqual("discovery", ctx.skips[0][2])

    def test_cancellation_during_discovery_does_not_change_saved_results(self):
        for engine in ("webshell", "yarascan"):
            with self.subTest(engine=engine):
                case, run = self.seed(engine)
                ctx = RecordingContext()
                record = ctx.phase_progress

                def cancel_during_discovery(*args, **kwargs):
                    record(*args, **kwargs)
                    if ctx.events[-1][0] == "discovering" and ctx.events[-1][1] >= 1:
                        ctx.stop = True

                ctx.phase_progress = cancel_during_discovery
                with patch.object(fsutil.time, "monotonic", side_effect=itertools.count()):
                    stats = self.run_scan(engine, case, ctx)
                self.assertEqual(0, stats["scanned"])
                self.assertTrue(all(row["live"] for row in self.findings(case).values()))
                conn = db.connect(case)
                self.assertEqual(str(run), db.one(conn,
                    "SELECT value FROM meta WHERE key='scan_seq'")["value"])
                conn.close()

    def test_unreadable_subdirectory_is_incomplete_and_preserves_unvisited_findings(self):
        inaccessible = self.site / "unreadable"
        inaccessible.mkdir()
        scan_dir = fsutil.os.scandir

        def fail_one_directory(path):
            if fsutil.canonical_file(path) == fsutil.canonical_file(inaccessible):
                raise PermissionError("synthetic permission failure")
            return scan_dir(path)

        for engine in ("webshell", "yarascan"):
            with self.subTest(engine=engine):
                case, run = self.seed(engine)
                ctx = RecordingContext()
                with patch.object(fsutil.os, "scandir", side_effect=fail_one_directory):
                    stats = self.run_scan(engine, case, ctx)
                self.assertTrue(stats["partial"])
                self.assertEqual(1, stats["discovery_errors"])
                self.assertEqual(0, stats["file_skips"])
                self.assertEqual("discovery", ctx.skips[0][2])
                self.assertTrue(all(row["live"] for row in self.findings(case).values()))
                conn = db.connect(case)
                self.assertEqual(str(run), db.one(conn,
                    "SELECT value FROM meta WHERE key=?", ("engine_done:" + engine,))["value"])
                conn.close()

    def test_yara_broken_rules_do_not_retire_findings_or_resolve_retry_warnings(self):
        (self.ws / "yara" / "broken.yar").write_text("not a yara rule", encoding="utf-8")
        case, _run = self.seed("yarascan")
        ctx = RecordingContext()
        stats = self.run_scan("yarascan", case, ctx)
        self.assertEqual(1, stats["broken_rules"])
        self.assertEqual(0, stats["file_skips"])
        self.assertTrue(all(row["live"] for row in self.findings(case).values()))
        self.assertEqual("rule", ctx.skips[0][2])
        retry_ctx = RecordingContext()
        stats = self.run_scan("yarascan", case, retry_ctx, self.targets(self.first))
        self.assertEqual(0, stats["scanned"])
        self.assertEqual([], retry_ctx.results)

    def test_missing_evidence_root_is_a_discovery_failure(self):
        missing = self.root / "missing root"
        for engine in ("webshell", "yarascan"):
            with self.subTest(engine=engine):
                case, run = self.seed(engine)
                module = webshell if engine == "webshell" else yarascan
                stats = module.scan(case, [str(missing)], workspace=self.ws)
                self.assertTrue(stats["partial"])
                self.assertEqual(1, stats["discovery_errors"])
                self.assertEqual(0, stats["scanned"])
                self.assertTrue(all(row["live"] for row in self.findings(case).values()))

    def test_timeout_is_a_file_warning_but_unexpected_engine_errors_propagate(self):
        case = self.root / "timeout-case"
        case.mkdir()
        ctx = RecordingContext()
        with patch.object(webshell, "scan_file", side_effect=webshell.yara.TimeoutError("timeout")):
            stats = webshell.scan(case, [], ctx=ctx, file_targets=self.targets(self.first))
        self.assertEqual(1, stats["file_skips"])
        self.assertEqual("skipped", ctx.results[0][2])
        with patch.object(webshell, "scan_file", side_effect=RuntimeError("engine failure")):
            with self.assertRaisesRegex(RuntimeError, "engine failure"):
                webshell.scan(case, [], file_targets=self.targets(self.first))
        for error in (yarascan.yara.TimeoutError("timeout"), RuntimeError("engine failure")):
            with self.subTest(error=type(error).__name__):
                def fail_match(data, timeout):
                    self.assertEqual(20, timeout)
                    raise error

                with patch.object(yarascan, "_compile",
                                  return_value=(SimpleNamespace(match=fail_match), [], 1)):
                    if isinstance(error, RuntimeError):
                        with self.assertRaisesRegex(RuntimeError, "engine failure"):
                            self.run_scan("yarascan", case, files=self.targets(self.first))
                    else:
                        stats = self.run_scan("yarascan", case, files=self.targets(self.first))
                        self.assertEqual(1, stats["file_skips"])

    def test_explicit_size_override_scans_the_selected_file_past_the_default_limit(self):
        payload = b"shellhound synthetic-marker"
        benign_rules = webshell.yara.compile(source='''
            rule benign_size_fixture {
                meta:
                    id = "webshell.synthetic_size"
                    severity = "high"
                    name = "Benign size fixture"
                strings: $s = "synthetic-marker"
                condition: $s
            }
        ''')
        self.first.write_bytes(b" " * webshell.MAX_CONTENT_SCAN_BYTES + payload)
        self.second.write_bytes(self.first.read_bytes())
        size = self.first.stat().st_size
        for engine in ("webshell", "yarascan"):
            with self.subTest(engine=engine):
                case, _run = self.seed(engine)
                default_stats = self.run_scan(engine, case)
                self.assertEqual(2, default_stats["file_skips"])
                files = self.targets(self.first)
                files[0]["max_bytes"] = size
                ctx = RecordingContext()
                with patch.object(webshell.bundled_rules, "compiled", return_value=benign_rules):
                    stats = self.run_scan(engine, case, ctx, files)
                self.assertEqual(1, stats["scanned"])
                self.assertEqual(0, stats["file_skips"])
                self.assertGreater(stats["findings"], 0)
                self.assertEqual("resolved", ctx.results[0][2])
                conn = db.connect(case)
                try:
                    found = db.rows(conn, "SELECT artifact, rule FROM findings WHERE rule != ?",
                                    ("Previous synthetic finding",))
                    self.assertEqual({str(self.first)}, {row["artifact"] for row in found})
                    expected = ("Benign size fixture"
                                if engine == "webshell" else "YARA: synthetic")
                    self.assertIn(expected, {row["rule"] for row in found})
                finally:
                    conn.close()
                self.assertTrue(self.findings(case)[self.second.name]["live"])
                # A one-file choice never changes the next normal scan's ceiling.
                self.assertEqual(2, self.run_scan(engine, case)["file_skips"])

    def test_large_file_match_locations_and_snippets_use_bounded_memory(self):
        benign_rules = webshell.yara.compile(source='''
            rule benign_location_fixture {
                meta:
                    id = "webshell.synthetic_location"
                    severity = "high"
                    name = "Benign location fixture"
                strings: $s = "harmless-marker"
                condition: $s
            }
        ''')
        newline_count = 1024 * 1024
        first_line = b" \t harmless-marker and harmless-marker \r\n"
        long_line = ("\u2003" * (1024 * 1024) + "é" * 170 + " harmless-marker ").encode()
        raw = b"\n" * newline_count + first_line + long_line
        with patch.object(webshell.bundled_rules, "compiled", return_value=benign_rules):
            tracemalloc.start()
            try:
                findings = list(webshell._yara_findings(raw, "content"))
                _current, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
        self.assertEqual([newline_count + 1, newline_count + 2], [row[3] for row in findings])
        self.assertEqual("harmless-marker and harmless-marker", findings[0][4])
        self.assertEqual("é" * 160 + "…", findings[1][4])
        # The input is allocated before tracing. An index of every newline or
        # decoding the multi-megabyte line would exceed this allowance.
        self.assertLess(peak, 1024 * 1024)

    def test_bounded_snippets_preserve_whitespace_and_utf8_truncation(self):
        samples = (
            "\u2003" * 3000 + "é" * 160 + "\u2003" * 3000,
            " \t " + "é" * 160 + " " * 10000 + "end",
            "a" * 159 + "\u2003" * 10000 + "end",
            "\u2003" * 3000 + "ordinary text" + " \t\r",
            "\u2003" * 3000,
        )
        for sample in samples:
            with self.subTest(length=len(sample)):
                stripped = sample.strip()
                expected = stripped if len(stripped) <= 160 else stripped[:160] + "…"
                self.assertEqual(expected, webshell._line_snippet(sample.encode(), 0))
        malformed = b" " * 4095 + b"\xf0\x9f" + b" harmless-marker "
        self.assertEqual(malformed.decode("utf-8", errors="replace").strip(),
                         webshell._line_snippet(malformed, 0))

    def test_size_override_detects_growth_after_stat_and_preserves_prior_results(self):
        for engine in ("webshell", "yarascan"):
            with self.subTest(engine=engine):
                self.first.write_bytes(b"x" * (webshell.MAX_CONTENT_SCAN_BYTES + 1))
                size = self.first.stat().st_size
                case, _run = self.seed(engine)
                files = self.targets(self.first)
                files[0]["max_bytes"] = size
                module = webshell if engine == "webshell" else yarascan

                def grow_before_read(path, mode="r", *args, **kwargs):
                    if mode == "rb" and fsutil.canonical_file(path) == fsutil.canonical_file(self.first):
                        with builtins.open(path, "ab") as writer:
                            writer.write(b"x")
                    return builtins.open(path, mode, *args, **kwargs)

                ctx = RecordingContext()
                with patch.object(module, "open", side_effect=grow_before_read, create=True):
                    stats = self.run_scan(engine, case, ctx, files)
                self.assertEqual(1, stats["file_skips"])
                self.assertIn("grew beyond", ctx.skips[0][1])
                self.assertEqual("skipped", ctx.results[0][2])
                self.assertTrue(self.findings(case)[self.first.name]["live"])
                self.assertEqual("Analyst note", self.findings(case)[self.first.name]["triage_note"])

    def test_size_override_memory_failure_is_a_warning_and_preserves_prior_results(self):
        for engine in ("webshell", "yarascan"):
            with self.subTest(engine=engine):
                case, _run = self.seed(engine)
                files = self.targets(self.first)
                files[0]["max_bytes"] = webshell.MAX_CONTENT_SCAN_BYTES + 1
                module = webshell if engine == "webshell" else yarascan

                def fail_file_read(path, mode="r", *args, **kwargs):
                    if mode == "rb" and fsutil.canonical_file(path) == fsutil.canonical_file(self.first):
                        raise MemoryError("synthetic allocation failure")
                    return builtins.open(path, mode, *args, **kwargs)

                ctx = RecordingContext()
                with patch.object(module, "open", side_effect=fail_file_read, create=True):
                    stats = self.run_scan(engine, case, ctx, files)
                self.assertEqual(1, stats["file_skips"])
                self.assertIn("not enough memory", ctx.skips[0][1])
                self.assertEqual("skipped", ctx.results[0][2])
                self.assertTrue(self.findings(case)[self.first.name]["live"])
                self.assertEqual("Analyst note", self.findings(case)[self.first.name]["triage_note"])

    def test_invalid_override_cannot_trigger_an_unbounded_scan(self):
        for engine in ("webshell", "yarascan"):
            for value in (True, "10485760", 0, -1, MAX_OVERRIDE_SCAN_BYTES + 1):
                with self.subTest(engine=engine, value=value):
                    files = self.targets(self.first)
                    files[0]["max_bytes"] = value
                    with self.assertRaisesRegex(ValueError, "selected-file scan limit"):
                        self.run_scan(engine, self.root / "invalid-limits", files=files)


if __name__ == "__main__":
    unittest.main()
