# tests/test_coverage.py
"""What the logs do NOT cover.

Every test builds a log with a KNOWN defect and asserts that it is found --
and, just as importantly, that a clean log stays quiet. A tamper detector
that fires on ordinary data is worse than none: it teaches the analyst to
ignore it.
"""
import tempfile
import time
import unittest
from pathlib import Path

from server import coverage, db
from server.engines import logindex

BASE = 1780000000


def line(epoch, path="/index.php", ip="203.0.113.5"):
    stamp = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime(epoch))
    return f'{ip} - - [{stamp}] "GET {path} HTTP/1.1" 200 12 "-" "curl"\n'


class QuietWindowTests(unittest.TestCase):

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix="shellhound-cov-"))
        self.logs = Path(tempfile.mkdtemp(prefix="shellhound-covlogs-"))
        db.connect(self.case).close()

    def _index(self, text, name="access.log"):
        (self.logs / name).write_text(text, encoding="utf-8")
        logindex.build(self.case, [str(self.logs)])

    def test_a_hole_far_beyond_the_logs_own_rhythm_is_reported(self):
        rows = [line(BASE + i * 5) for i in range(100)]
        rows += [line(BASE + 4 * 3600 + i * 5) for i in range(100)]
        self._index("".join(rows))
        out = coverage.quiet_windows(self.case)
        self.assertTrue(out["checked"])
        self.assertEqual(1, len(out["windows"]))
        self.assertGreater(out["windows"][0]["seconds"], 3 * 3600)

    def test_a_steady_log_reports_nothing(self):
        """The guard against a detector that cries wolf."""
        rows = [line(BASE + i * 5) for i in range(400)]
        self._index("".join(rows))
        out = coverage.quiet_windows(self.case)
        self.assertTrue(out["checked"])
        self.assertEqual([], out["windows"])

    def test_the_threshold_follows_the_log_not_a_fixed_number(self):
        """A server with a request every two seconds and one with three a
        day cannot share a threshold."""
        rows = [line(BASE + i * 5) for i in range(200)]
        self._index("".join(rows))
        out = coverage.quiet_windows(self.case)
        self.assertEqual(5, out["median_gap"])
        self.assertGreaterEqual(out["threshold"], coverage.QUIET_MIN_SECONDS)

    def test_too_little_data_says_so_instead_of_claiming_no_holes(self):
        """"No holes" on twelve lines would be a statement the data cannot
        support."""
        self._index("".join(line(BASE + i * 5) for i in range(12)))
        out = coverage.quiet_windows(self.case)
        self.assertFalse(out["checked"])
        self.assertEqual([], out["windows"])

    def test_no_index_is_not_a_clean_bill(self):
        bare = Path(tempfile.mkdtemp(prefix="shellhound-covbare-"))
        db.connect(bare).close()
        self.assertFalse(coverage.quiet_windows(bare)["checked"])


class FileAnomalyTests(unittest.TestCase):

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix="shellhound-cova-"))
        self.logs = Path(tempfile.mkdtemp(prefix="shellhound-covalogs-"))
        db.connect(self.case).close()

    def _index(self):
        logindex.build(self.case, [str(self.logs)])

    def _by_name(self):
        return {a["name"]: a for a in coverage.file_anomalies(self.case)}

    def test_a_head_cut_mid_record_is_reported(self):
        """Rotation cuts on line boundaries. A head that starts mid-line
        means the beginning was removed."""
        rows = ['5 "-" "curl"\n'] + [line(BASE + i * 5) for i in range(60)]
        (self.logs / "cut.log").write_text("".join(rows), encoding="utf-8")
        self._index()
        self.assertTrue(self._by_name()["cut.log"]["truncated"])

    def test_timestamps_stepping_backwards_are_counted(self):
        rows = [line(BASE + i * 5) for i in range(40)]
        rows.append(line(BASE - 500))
        rows += [line(BASE + 500 + i * 5) for i in range(20)]
        (self.logs / "spliced.log").write_text("".join(rows), encoding="utf-8")
        self._index()
        self.assertGreaterEqual(self._by_name()["spliced.log"]["backwards"], 1)

    def test_a_clean_file_produces_no_anomaly(self):
        rows = [line(BASE + i * 5) for i in range(60)]
        (self.logs / "clean.log").write_text("".join(rows), encoding="utf-8")
        self._index()
        self.assertEqual({}, self._by_name())

    def test_notes_are_produced_for_what_was_found(self):
        rows = ['5 "-" "curl"\n'] + [line(BASE + i * 5) for i in range(60)]
        (self.logs / "cut.log").write_text("".join(rows), encoding="utf-8")
        self._index()
        notes = coverage.report(self.case)["notes"]
        self.assertTrue(notes)
        self.assertTrue(any("cut.log" in n for n in notes))

    def test_the_notes_follow_the_language(self):
        rows = ['5 "-" "curl"\n'] + [line(BASE + i * 5) for i in range(60)]
        (self.logs / "cut.log").write_text("".join(rows), encoding="utf-8")
        self._index()
        self.assertNotEqual(coverage.report(self.case, "en")["notes"],
                            coverage.report(self.case, "de")["notes"])

    def test_coverage_produces_no_findings(self):
        """None of this proves tampering. A quiet window can be a maintenance
        night. It belongs in the gaps, not in the work list."""
        rows = ['5 "-" "curl"\n'] + [line(BASE + i * 5) for i in range(60)]
        (self.logs / "cut.log").write_text("".join(rows), encoding="utf-8")
        self._index()
        coverage.report(self.case)
        conn = db.connect(self.case)
        try:
            n = conn.execute("SELECT count(*) FROM findings "
                             "WHERE source = 'coverage'").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(0, n)


class ChainIntegrationTests(unittest.TestCase):

    def test_the_notes_reach_the_chronology_gaps(self):
        case = Path(tempfile.mkdtemp(prefix="shellhound-covchain-"))
        logs = Path(tempfile.mkdtemp(prefix="shellhound-covchainlogs-"))
        db.connect(case).close()
        rows = ['5 "-" "curl"\n'] + [line(BASE + i * 5) for i in range(60)]
        (logs / "cut.log").write_text("".join(rows), encoding="utf-8")
        logindex.build(case, [str(logs)])

        from server.chain import case_chain
        gaps = case_chain(case)["gaps"]
        self.assertTrue(any("cut.log" in g for g in gaps),
                        "a coverage note did not reach the chronology")


if __name__ == "__main__":
    unittest.main()
