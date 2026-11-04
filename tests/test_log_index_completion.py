import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from server import db
from server.engines import logindex


LINE = '203.0.113.5 - - [06/Jan/2026:08:00:00 +0200] "GET /a HTTP/1.1" 200 12 "-" "curl"\n'
SCANNER = LINE.replace('"curl"', '"sqlmap"')


class IndexCompletionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.case = Path(self.temp.name, "case")
        self.case.mkdir()
        self.log = Path(self.temp.name, "access.log")
        self.log.write_text(SCANNER, encoding="utf-8")
        db.connect(self.case).close()

    def build(self, **kwargs):
        return logindex.build(self.case, [str(self.log)], **kwargs)

    def test_read_error_retains_fragment_counts_and_prior_findings_then_retry(self):
        self.build()
        with closing(db.connect(self.case)) as conn:
            done = conn.execute("SELECT value FROM meta WHERE key='engine_done:logindex'").fetchone()[0]
            self.assertTrue(conn.execute("SELECT 1 FROM findings WHERE engine='logindex'").fetchone())

        class BrokenReader:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def __iter__(self):
                yield LINE
                yield LINE
                yield "unrecognized\n"
                raise OSError("secret diagnostic")

        with patch.object(logindex, "_is_log_text", return_value=True), \
             patch.object(logindex.accesslog, "sniff_error_log", return_value=False), \
             patch.object(logindex, "open_text_auto", return_value=BrokenReader()), \
             patch.object(logindex, "_BATCH", 2):
            stats = self.build()
        self.assertTrue(stats["partial"])
        self.assertEqual((2, 1, 1), (stats["lines"], stats["unparsed"], stats["skipped"]))
        with closing(sqlite3.connect(db.log_db_path(self.case))) as conn:
            self.assertEqual((2, 1, "read error"), conn.execute(
                "SELECT lines,unparsed,skipped_reason FROM sources").fetchone())
            self.assertEqual(2, conn.execute("SELECT count(*) FROM requests").fetchone()[0])
        with closing(db.connect(self.case)) as conn:
            self.assertEqual(done, conn.execute("SELECT value FROM meta WHERE key='engine_done:logindex'").fetchone()[0])
        for targets in (None, [str(self.log)]):
            state = logindex.status(self.case, targets)
            self.assertTrue(state["partial"])
            self.assertFalse(state["fresh"])
        with self.assertRaises(logindex.StaleHuntIndex):
            logindex.index_snapshot(self.case)
        self.assertFalse(self.build()["partial"])
        self.assertTrue(logindex.status(self.case, [str(self.log)])["fresh"])

    def test_cancellation_on_final_source_and_unparsed_lines(self):
        class Context:
            def __init__(self): self.stop = False
            def cancelled(self): return self.stop
            def progress(self, *args): pass

        for lines in ([LINE], ["unrecognized\n"] * 1001):
            ctx = Context()
            class Reader:
                def __enter__(self): return self
                def __exit__(self, *args): pass
                def __iter__(self):
                    for line in lines:
                        ctx.stop = True
                        yield line

            with patch.object(logindex, "_is_log_text", return_value=True), \
                 patch.object(logindex.accesslog, "sniff_error_log", return_value=False), \
                 patch.object(logindex, "open_text_auto", return_value=Reader()):
                stats = self.build(ctx=ctx)
            self.assertTrue(stats["partial"])
            self.assertFalse(logindex.status(self.case)["fresh"])
            if len(lines) > 1:
                self.assertEqual(999, stats["unparsed"])

    def test_permission_error_during_preflight_is_incomplete(self):
        self.build()
        with closing(db.connect(self.case)) as conn:
            done = conn.execute("SELECT value FROM meta WHERE key='engine_done:logindex'").fetchone()[0]
            self.assertTrue(conn.execute("SELECT 1 FROM findings WHERE engine='logindex'").fetchone())
        with patch.object(logindex, "open", create=True, side_effect=PermissionError("private detail")):
            stats = self.build()
        self.assertTrue(stats["partial"])
        self.assertEqual(1, stats["skipped"])
        self.assertFalse(logindex.status(self.case, [str(self.log)])["fresh"])
        with closing(sqlite3.connect(db.log_db_path(self.case))) as conn:
            self.assertEqual("read error", conn.execute("SELECT skipped_reason FROM sources").fetchone()[0])
        with closing(db.connect(self.case)) as conn:
            self.assertEqual(done, conn.execute("SELECT value FROM meta WHERE key='engine_done:logindex'").fetchone()[0])
            self.assertTrue(conn.execute("SELECT 1 FROM findings WHERE engine='logindex'").fetchone())

    def test_old_schema_requires_rebuild_and_deliberate_skip_stays_fresh(self):
        self.log.write_bytes(b"\x00\x01\x02")
        stats = self.build()
        self.assertEqual(1, stats["skipped"])
        self.assertTrue(logindex.status(self.case, [str(self.log)])["fresh"])
        with closing(sqlite3.connect(db.log_db_path(self.case))) as conn:
            conn.execute("UPDATE meta SET value='12' WHERE key='schema'")
            conn.commit()
        self.assertFalse(logindex.status(self.case)["fresh"])
        with self.assertRaises(logindex.StaleHuntIndex):
            logindex.index_snapshot(self.case)
        self.build()
        self.assertTrue(logindex.status(self.case)["fresh"])
