# tests/test_coverage.py
"""What the logs do NOT cover.

Every test builds a log with a KNOWN defect and asserts that it is found --
and, just as importantly, that a clean log stays quiet. A tamper detector
that fires on ordinary data is worse than none: it teaches the analyst to
ignore it.
"""
import os
import re
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from server import coverage, db
from server.engines import logindex

BASE = 1780000000


def line(epoch, path="/index.php", ip="203.0.113.5", offset="+0000"):
    """One access-log line. `epoch` is UTC; `offset` is what the server wrote,
    so the stamp is shifted into that offset the way a real log is."""
    sign = 1 if offset[0] == "+" else -1
    shift = sign * (int(offset[1:3]) * 3600 + int(offset[3:5]) * 60)
    stamp = time.strftime("%d/%b/%Y:%H:%M:%S ", time.gmtime(epoch + shift))
    return (f'{ip} - - [{stamp}{offset}] "GET {path} HTTP/1.1" 200 12 '
            f'"-" "curl"\n')


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

    def test_a_timestamp_stepping_backwards_is_not_an_anomaly(self):
        """This used to be reported as tampering, and it was wrong in
        principle rather than merely noisy.

        Apache and Nginx write the line when a request COMPLETES, and the
        timestamp in it is when the request STARTED. A request that took
        three seconds is therefore written after a faster one that began
        later, and carries a lower stamp. On any server with concurrent
        requests that happens constantly, so the check was measuring normal
        operation and calling it evidence."""
        rows = [line(BASE + i * 5) for i in range(40)]
        rows.append(line(BASE - 500))
        rows += [line(BASE + 500 + i * 5) for i in range(20)]
        (self.logs / "concurrent.log").write_text("".join(rows), encoding="utf-8")
        self._index()
        self.assertEqual({}, self._by_name())

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
    """Coverage stands ABOVE the chronology, not inside it.

    It used to be folded into the chain's `gaps`, which put the same
    sentences on screen twice once the block above existed. The two answer
    different questions and each says its own thing once: coverage says how
    much of the period the logs could describe at all, `gaps` says what the
    chain itself cannot show."""

    def _case(self):
        case = Path(tempfile.mkdtemp(prefix="shellhound-covchain-"))
        logs = Path(tempfile.mkdtemp(prefix="shellhound-covchainlogs-"))
        db.connect(case).close()
        rows = ['5 "-" "curl"\n'] + [line(BASE + i * 5) for i in range(60)]
        (logs / "cut.log").write_text("".join(rows), encoding="utf-8")
        logindex.build(case, [str(logs)])
        return case

    def test_the_note_is_reported_by_coverage(self):
        notes = coverage.report(self._case())["notes"]
        self.assertTrue(any("cut.log" in n for n in notes),
                        "coverage did not report the truncated file")

    def test_it_is_not_repeated_in_the_chronology_gaps(self):
        from server.chain import case_chain
        gaps = case_chain(self._case())["gaps"]
        self.assertFalse(any("cut.log" in g for g in gaps),
                         "the coverage note is on screen twice")

    def test_the_chain_keeps_the_gaps_only_it_knows(self):
        """Removing the coverage notes must not have emptied `gaps`: the
        statements the chronology makes about itself still belong there."""
        from server.chain import case_chain
        self.assertTrue(case_chain(self._case())["gaps"])


class DashboardOrderTests(unittest.TestCase):
    """Where the two coverage blocks sit on the page.

    This is a layout decision with a forensic reason, so it is guarded like
    one. Both blocks describe the LOGS -- the chart the period they cover,
    the notes what is missing from it -- and both must be read before the
    chronology, which is assembled out of those same logs. An analyst who
    reads the sequence first and learns only afterwards that fourteen hours
    are absent has already formed the wrong picture.

    A source-text check, because the ordering lives in JSX and there is no
    frontend test runner here. Crude, but it fails when someone moves a
    block, which is the entire point."""

    SOURCE = (Path(__file__).resolve().parents[1]
              / "web" / "src" / "views" / "Dashboard.tsx")

    def setUp(self):
        self.text = self.SOURCE.read_text(encoding="utf-8")

    def _at(self, needle):
        i = self.text.find(needle)
        self.assertNotEqual(-1, i, f"{needle} is gone from the dashboard")
        return i

    def test_the_chart_comes_before_the_chronology(self):
        self.assertLess(self._at("<TimelineChart"), self._at("<CaseChain"))

    def test_the_gap_notes_come_before_the_chronology(self):
        self.assertLess(self._at("<LogCoverage"), self._at("<CaseChain"))

    def test_the_chart_comes_before_the_gaps_it_has_holes_in(self):
        """Period first, then what is missing from it. The other way round
        names holes in something the reader has not been shown yet."""
        self.assertLess(self._at("<TimelineChart"), self._at("<LogCoverage"))

    def test_both_stand_after_the_artifact_tiles(self):
        """The tiles are the case at a glance and stay at the top."""
        self.assertLess(self._at("dashboard.artifacts'"),
                        self._at("<TimelineChart"))


class MeasuredNumbersTests(unittest.TestCase):
    """The numbers this module COMPUTES, not the fact that it answered.

    A mutation run over coverage.py left 144 of 250 mutants alive, and they
    were not scattered. The fixtures fed this module logs with one uniform
    gap between requests and then asserted only coarse facts -- did it check,
    how many windows, roughly how long. Every arithmetic step in between
    could be changed without a single test objecting: the median summed
    instead of averaged, the hours multiplied instead of divided, the window
    boundaries taken from the wrong pair.

    So these state the numbers. Each fixture has an answer that can be worked
    out by hand and written into the assertion, which is the only thing that
    makes an arithmetic test worth having.
    """

    def test_the_median_of_an_odd_number_of_gaps(self):
        self.assertEqual(5, coverage._median([1, 5, 100]))

    def test_the_median_of_an_even_number_of_gaps_is_the_average(self):
        """The branch a uniform fixture never reaches. Summed instead of
        averaged, the yardstick doubles -- and every threshold derived from
        it doubles with it, which is the whole quiet-window mechanism."""
        self.assertEqual(7.5, coverage._median([1, 5, 10, 100]))
        self.assertEqual(3, coverage._median([2, 4]))

    def test_the_median_ignores_the_order_it_is_given(self):
        self.assertEqual(coverage._median([100, 1, 5]),
                         coverage._median([1, 5, 100]))

    def test_no_gaps_is_zero_rather_than_an_error(self):
        self.assertEqual(0, coverage._median([]))


class ThresholdTests(unittest.TestCase):
    """How long a silence has to be before it is worth mentioning.

    Two arms, and there was a fixture for neither. The RHYTHM arm -- the
    median times QUIET_FACTOR -- only decides anything on a log whose own
    pace is slow, and every fixture was busy enough that the absolute floor
    won instead. The FLOOR only decides anything on a fast log, and the one
    test that named it asserted `threshold >= QUIET_MIN_SECONDS`, which stays
    true when the constant itself is changed to zero.
    """

    def _case(self, spacing, count, hole=0):
        case = Path(tempfile.mkdtemp(prefix="shellhound-thr-"))
        logs = Path(tempfile.mkdtemp(prefix="shellhound-thrlogs-"))
        self.addCleanup(shutil.rmtree, case, True)
        self.addCleanup(shutil.rmtree, logs, True)
        db.connect(case).close()
        rows, when = [], BASE
        for i in range(count):
            rows.append(line(when))
            when += spacing + (hole if i == count // 2 else 0)
        (logs / "access.log").write_text("".join(rows), encoding="utf-8")
        logindex.build(case, [str(logs)])
        return case

    def test_a_slow_log_is_measured_by_its_own_rhythm(self):
        """One request an hour is a quiet server, not a server standing
        still. Sixty times its median puts the threshold at sixty hours, so
        its ordinary hourly intervals say nothing -- with the rhythm arm
        broken the floor takes over and every one of them is reported as a
        window somebody may have removed."""
        out = coverage.quiet_windows(self._case(3600, 80))
        self.assertEqual(3600, out["median_gap"])
        self.assertEqual(3600 * coverage.QUIET_FACTOR, out["threshold"])
        self.assertEqual([], out["windows"],
                         "an hourly rhythm was reported as holes in itself")

    def test_a_busy_log_is_held_to_the_absolute_floor(self):
        """A request every five seconds makes sixty medians five minutes, and
        a five-minute threshold turns every maintenance pause into a finding.
        The floor is what stops that, and nothing measured it."""
        out = coverage.quiet_windows(self._case(5, 200))
        self.assertEqual(5, out["median_gap"])
        self.assertEqual(coverage.QUIET_MIN_SECONDS, out["threshold"])

    def test_a_ten_minute_pause_on_a_busy_log_is_not_a_finding(self):
        """The floor as behaviour rather than as a number: ten minutes is a
        deploy, a restart, a backup window."""
        self.assertEqual([], coverage.quiet_windows(
            self._case(5, 200, hole=600))["windows"])

    def test_an_hour_long_pause_on_a_busy_log_is_a_finding(self):
        """The guard against a floor raised until nothing fires at all."""
        self.assertEqual(1, len(coverage.quiet_windows(
            self._case(5, 200, hole=3600))["windows"]))


class ReportedWindowTests(unittest.TestCase):
    """WHICH holes are shown, and WHERE each one starts and ends.

    The list is capped at six and sorted longest first, and nothing checked
    either. With the sort reversed the block showed the six SHORTEST holes
    while the total still said nineteen, so an analyst read "the longest
    silence is one hour" with a nineteen-hour hole in the data. And the
    boundaries came out of a zip of three sequences that nothing pinned: one
    step out of line and a four-hour silence is reported between one instant
    and itself.
    """

    @classmethod
    def setUpClass(cls):
        cls.case = Path(tempfile.mkdtemp(prefix="shellhound-win-"))
        logs = Path(tempfile.mkdtemp(prefix="shellhound-winlogs-"))
        cls._dirs = [cls.case, logs]
        db.connect(cls.case).close()
        # Holes of 1 h, 2 h ... 9 h in ASCENDING order, so the longest arrive
        # last: a sort that does nothing looks correct when the input happens
        # to be sorted already.
        rows, when, cls.expected = [], BASE, []
        for hours in range(1, 10):
            for _ in range(40):
                rows.append(line(when))
                when += 5
            # The silence runs from the LAST request before it to the FIRST
            # one after it, so it is five seconds longer than the hole itself.
            cls.expected.append((when - 5, when + hours * 3600))
            when += hours * 3600
        for _ in range(40):
            rows.append(line(when))
            when += 5
        (logs / "access.log").write_text("".join(rows), encoding="utf-8")
        logindex.build(cls.case, [str(logs)])
        cls.out = coverage.quiet_windows(cls.case)

    @classmethod
    def tearDownClass(cls):
        for directory in cls._dirs:
            shutil.rmtree(directory, ignore_errors=True)

    def test_every_hole_is_counted(self):
        self.assertEqual(9, self.out["total"])

    def test_only_the_cap_is_shown(self):
        self.assertEqual(coverage._MAX_QUIET, len(self.out["windows"]))

    def test_the_ones_shown_are_the_longest(self):
        """Not any six. A cap that keeps the small ones hides the finding and
        leaves a total that reads as if everything were present."""
        self.assertEqual([9, 8, 7, 6, 5, 4],
                         [round(w["seconds"] / 3600)
                          for w in self.out["windows"]])

    def test_a_window_spans_the_two_requests_it_sits_between(self):
        """`from` is the last request before the silence, `to` the first one
        after it -- not one instant printed twice, and not a pair one step
        out of line."""
        longest = self.out["windows"][0]
        want_from, want_to = self.expected[-1]
        self.assertEqual(want_from, longest["from"])
        self.assertEqual(want_to, longest["to"])
        self.assertEqual(longest["to"] - longest["from"], longest["seconds"])

    def test_every_window_moves_forwards(self):
        for window in self.out["windows"]:
            self.assertLess(window["from"], window["to"], window)

    def test_the_one_line_summary_counts_the_measurement(self):
        """The cap is there so a screen stays readable. It has no business
        changing a number.

        `notes` carries one sentence per window SHOWN -- six of them here,
        nine measured. The summary counted the sentences, so on a real case
        with fourteen holes the evidence view said six, and six is the number
        a reader carries into the report."""
        note = coverage.evidence_note(self.case)
        self.assertIn("9", note)
        self.assertNotIn("6 ", note)

    def test_the_note_list_itself_stays_capped(self):
        """The other half: the count grows, the list does not. Nine sentences
        on the evidence card would be the thing the cap exists to prevent."""
        report = coverage.report(self.case)
        self.assertEqual(coverage._MAX_QUIET, len(report["notes"]))


class StaleMtimeTests(unittest.TestCase):
    """A file written BEFORE the last thing written into it.

    Not one test in this repository built such a file, so the whole detection
    could be hard-coded to False with all four hundred and eighty-one tests
    still green: one of the three measurements this module documents, switched
    off in silence.

    It is also the measurement that ACCUSES, so it is tested from both sides.
    A forged file has to be caught, and an honest one must not be called
    forged -- the second is the half that matters more.
    """

    def _case(self, mtime_offset):
        case = Path(tempfile.mkdtemp(prefix="shellhound-stale-"))
        logs = Path(tempfile.mkdtemp(prefix="shellhound-stalelogs-"))
        self.addCleanup(shutil.rmtree, case, True)
        self.addCleanup(shutil.rmtree, logs, True)
        db.connect(case).close()
        path = logs / "access.log"
        path.write_text("".join(line(BASE + i * 5) for i in range(61)),
                        encoding="utf-8")
        # BEFORE the build. The index records the mtime it saw while reading,
        # so a file touched afterwards is not the file the index describes --
        # and the check compares the two as they were AT INDEX TIME.
        stamp = BASE + 60 * 5 + mtime_offset
        os.utime(path, (stamp, stamp))
        logindex.build(case, [str(logs)])
        return case

    def test_a_file_written_before_its_own_last_entry_is_reported(self):
        found = coverage.file_anomalies(self._case(-3600))
        self.assertEqual(1, len(found))
        self.assertTrue(found[0]["stale_mtime"])

    def test_a_file_written_after_its_last_entry_is_not(self):
        self.assertEqual([], coverage.file_anomalies(self._case(3600)))

    def test_a_file_written_in_the_same_second_is_not(self):
        """A log is written the moment its last line is, so equality is the
        NORMAL case. An accusation triggered by it would fire on every
        healthy file in every case."""
        self.assertEqual([], coverage.file_anomalies(self._case(0)))

    def test_the_accusation_is_made_only_where_it_is_true(self):
        """Negating one condition attached a forgery accusation to a merely
        TRUNCATED file. Saying that about an honest file is the one thing
        this module's docstring rules out.

        The file has to be truncated, because that is what puts it in the
        anomaly list in the first place: a file with nothing wrong with it is
        never looked at, so the wrong note cannot be seen on one."""
        case = Path(tempfile.mkdtemp(prefix="shellhound-honest-"))
        logs = Path(tempfile.mkdtemp(prefix="shellhound-honestlogs-"))
        self.addCleanup(shutil.rmtree, case, True)
        self.addCleanup(shutil.rmtree, logs, True)
        db.connect(case).close()
        path = logs / "cut.log"
        path.write_text('5 "-" "curl"\n' + "".join(
            line(BASE + i * 5) for i in range(61)), encoding="utf-8")
        stamp = BASE + 60 * 5 + 3600           # written well after its last line
        os.utime(path, (stamp, stamp))
        logindex.build(case, [str(logs)])

        found = coverage.file_anomalies(case)
        self.assertEqual(1, len(found))
        self.assertTrue(found[0]["truncated"])
        self.assertFalse(found[0]["stale_mtime"])
        notes = coverage.report(case, "en")["notes"]
        self.assertTrue([n for n in notes if "cut.log" in n], notes)
        self.assertFalse([n for n in notes if "BEFORE" in n], notes)


class NoteNumberTests(unittest.TestCase):
    """The sentences, read as sentences.

    The note tests checked that a filename appears in one and that English
    and German differ. Nothing read the NUMBER inside, so the hours could be
    multiplied instead of divided and the block would report a silence of
    fifty million hours with the suite still green.
    """

    def _case(self):
        case = Path(tempfile.mkdtemp(prefix="shellhound-note-"))
        logs = Path(tempfile.mkdtemp(prefix="shellhound-notelogs-"))
        self.addCleanup(shutil.rmtree, case, True)
        self.addCleanup(shutil.rmtree, logs, True)
        db.connect(case).close()
        rows, when = [], BASE
        for _ in range(60):
            rows.append(line(when))
            when += 5
        when += 4 * 3600                      # a four-hour hole, exactly
        for _ in range(60):
            rows.append(line(when))
            when += 5
        (logs / "access.log").write_text("".join(rows), encoding="utf-8")
        logindex.build(case, [str(logs)])
        return case

    def test_the_note_states_the_length_in_hours(self):
        notes = coverage.report(self._case(), "en")["notes"]
        self.assertTrue(notes)
        self.assertIn("4.0 h", notes[0], notes[0])

    def test_the_note_names_both_ends_of_the_silence(self):
        """Two different timestamps. One instant printed twice is the shape
        the boundary defect produced, and it reads perfectly."""
        note = coverage.report(self._case(), "en")["notes"][0]
        stamps = re.findall(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", note)
        self.assertEqual(2, len(stamps), note)
        self.assertNotEqual(stamps[0], stamps[1], note)


class CoverageZoneTests(unittest.TestCase):
    """Which offset the reported times are labelled with.

    One offset may be named; several may not, because naming one of them is
    wrong by an hour for the rest. And a case whose logs were never indexed
    has to answer "nothing measured" rather than raise: `GET /coverage` sits
    on the dashboard, and an exception there is a card that fails to load.
    """

    def _case(self, offsets):
        case = Path(tempfile.mkdtemp(prefix="shellhound-covtz-"))
        logs = Path(tempfile.mkdtemp(prefix="shellhound-covtzlogs-"))
        self.addCleanup(shutil.rmtree, case, True)
        self.addCleanup(shutil.rmtree, logs, True)
        db.connect(case).close()
        rows, when = [], BASE
        for offset in offsets:
            for _ in range(60):
                rows.append(line(when, offset=offset))
                when += 5
        (logs / "access.log").write_text("".join(rows), encoding="utf-8")
        logindex.build(case, [str(logs)])
        return case

    def test_one_offset_is_carried(self):
        self.assertEqual(7200, coverage.report(self._case(["+0200"]))["tz"])

    def test_several_offsets_name_none(self):
        """A log straddling a daylight-saving change carries two. Stamping
        the windows with one of them asserts a single unambiguous zone for
        times that are a mixture of both."""
        self.assertEqual(
            0, coverage.report(self._case(["+0100", "+0200"]))["tz"])

    def test_a_case_without_an_index_answers_instead_of_raising(self):
        case = Path(tempfile.mkdtemp(prefix="shellhound-covnone-"))
        self.addCleanup(shutil.rmtree, case, True)
        db.connect(case).close()
        out = coverage.report(case)
        self.assertEqual(0, out["tz"])
        self.assertFalse(out["quiet"]["checked"])
        self.assertEqual([], out["notes"])


if __name__ == "__main__":
    unittest.main()
