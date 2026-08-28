# tests/test_chain.py
"""The chronology and the artifact aggregate.

Both used to live inside `create_app` and could only be reached through an
HTTP route; as modules they can be asserted on directly. The chain is the one
piece of narrative the server writes, and its rules are the kind that fail
quietly: an artifact that vanishes from the story, a gap that is bridged
instead of named, a clock offset that is applied but not reported.
"""
import json
import os
import unittest

from server import artifacts, db
from server.chain import EVENT_CAP, case_chain, clock_offsets, stamp_to_local
from server.engines import logindex, webshell
from tests.fixtures import Evidence, register


class ChainTests(unittest.TestCase):
    """One analysed case for the whole class -- the chain only reads."""

    @classmethod
    def setUpClass(cls):
        cls.ev = Evidence().build()
        conn = db.connect(cls.ev.case_dir)
        register(conn, cls.ev)
        conn.close()
        webshell.scan(cls.ev.case_dir, [str(cls.ev.webroot)])
        logindex.build(cls.ev.case_dir, [str(cls.ev.logs)])

    @classmethod
    def tearDownClass(cls):
        cls.ev.cleanup()

    def setUp(self):
        conn = db.connect(self.ev.case_dir)
        try:
            conn.execute("UPDATE findings SET triage = 'new'")
            conn.execute("DELETE FROM meta WHERE key = 'clock_offsets'")
            conn.commit()
        finally:
            conn.close()

    def _confirm_all(self):
        conn = db.connect(self.ev.case_dir)
        try:
            conn.execute("UPDATE findings SET triage = 'confirmed'")
            conn.commit()
        finally:
            conn.close()

    # --- what the chain is allowed to say -----------------------------------

    def test_nothing_confirmed_says_so_and_stays_empty(self):
        out = case_chain(self.ev.case_dir)
        self.assertEqual([], out["events"])
        self.assertEqual(0, out["confirmed"])
        self.assertTrue(out["gaps"], "an empty chain has to explain itself")

    def test_confirmed_artifacts_produce_dated_events(self):
        self._confirm_all()
        out = case_chain(self.ev.case_dir)
        self.assertGreater(out["confirmed"], 0)
        self.assertTrue(out["events"], "confirmed artifacts produced no event")
        for e in out["events"]:
            self.assertIsInstance(e["at"], int)
            self.assertIn(e["source"], ("log", "dump", "filesystem"),
                          "every line has to name where its time comes from")

    def test_events_are_ordered(self):
        self._confirm_all()
        times = [e["at"] for e in case_chain(self.ev.case_dir)["events"]]
        self.assertEqual(times, sorted(times))

    def test_every_confirmed_artifact_is_accounted_for(self):
        """The rule that matters: a decision of the analyst must never
        quietly disappear. Either the artifact is dated in the chain, or it
        stands under `undated` with a reason."""
        self._confirm_all()
        out = case_chain(self.ev.case_dir)
        conn = db.connect(self.ev.case_dir)
        try:
            confirmed = {r["artifact"] for r in db.rows(
                conn, f"WITH art AS ({artifacts.ART_SQL}) "
                      f"SELECT artifact FROM art WHERE triage = 'confirmed'")}
        finally:
            conn.close()
        dated = {e["artifact"] for e in out["events"] if e["artifact"]}
        undated = {u["artifact"] for u in out["undated"]}
        self.assertEqual(set(), confirmed - dated - undated,
                         "a confirmed artifact appears nowhere in the chain")
        for u in out["undated"]:
            self.assertTrue(u["why"].strip(),
                            "an undated artifact without a reason is a gap")

    def test_a_successful_file_request_remains_a_log_observation(self):
        """Filesystem metadata must not weaken the stronger access proof."""
        self._confirm_all()
        out = case_chain(self.ev.case_dir)
        successes = [e for e in out["events"] if e["kind"] == "erfolg"]
        self.assertTrue(successes, "no file was dated by a successful request")
        self.assertTrue(all(e["source"] == "log" for e in successes))

    def test_confirmed_webshell_adds_filesystem_times_but_not_access_time(self):
        shell = str(self.ev.webroot /
                    "wp-content/uploads/2026/01/kb-media.php")
        measured_mtime = 1_700_000_123
        before = os.stat(shell)
        try:
            os.utime(shell, (before.st_atime, measured_mtime))
            conn = db.connect(self.ev.case_dir)
            try:
                conn.execute("UPDATE findings SET triage = 'confirmed' "
                             "WHERE artifact = ? AND source = 'webshell'",
                             (shell,))
                conn.commit()
            finally:
                conn.close()

            events = [e for e in case_chain(
                self.ev.case_dir, tz_mode="utc", event_cap=None)["events"]
                if e["artifact"] == shell and e["source"] == "filesystem"]
            self.assertTrue(events, "confirmed webshell has no filesystem time")
            modified = [e for e in events
                        if e["kind"] == "datei-geaendert"]
            self.assertEqual([measured_mtime], [e["at"] for e in modified])
            self.assertFalse(any("access" in e["kind"] for e in events))
            self.assertTrue(all("evidence copy" in e["detail"].lower()
                                for e in events))
        finally:
            os.utime(shell, ns=(before.st_atime_ns, before.st_mtime_ns))

    def test_manual_webshell_verdict_also_adds_filesystem_times(self):
        path = str(self.ev.webroot / "wp-includes/functions.php")
        conn = db.connect(self.ev.case_dir)
        fingerprint = ""
        try:
            fingerprint = db.upsert_finding(
                conn, "analyst", db.SEV_HIGH, "Manual file review", "file",
                path, evidence="Analyst classified the file as a webshell.",
                rule_id="analyst.file_review")
            conn.execute("UPDATE findings SET triage = 'confirmed' "
                         "WHERE fingerprint = ?", (fingerprint,))
            conn.commit()
        finally:
            conn.close()
        try:
            events = case_chain(
                self.ev.case_dir, tz_mode="utc", event_cap=None)["events"]
            self.assertTrue(any(e["artifact"] == path
                                and e["source"] == "filesystem"
                                and e["kind"] == "datei-geaendert"
                                for e in events))
        finally:
            conn = db.connect(self.ev.case_dir)
            try:
                conn.execute("DELETE FROM findings WHERE fingerprint = ?",
                             (fingerprint,))
                conn.commit()
            finally:
                conn.close()

    # --- the clock offset ---------------------------------------------------

    def test_clock_offset_moves_the_events_and_is_reported(self):
        self._confirm_all()
        before = case_chain(self.ev.case_dir)
        conn = db.connect(self.ev.case_dir)
        try:
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('clock_offsets', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (json.dumps({"logs": 3600, "dump": 0}),))
            conn.commit()
        finally:
            conn.close()
        after = case_chain(self.ev.case_dir)

        log_before = [e["at"] for e in before["events"] if e["source"] == "log"]
        log_after = [e["at"] for e in after["events"] if e["source"] == "log"]
        self.assertEqual([t + 3600 for t in log_before], log_after)
        self.assertEqual(3600, after["offsets"]["logs"])
        self.assertTrue(
            any("3600" in g or "1 " in g for g in after["gaps"]) or
            len(after["gaps"]) > len(before["gaps"]),
            "a set offset has to be reported among the limitations")

    def test_clock_offsets_survive_a_broken_meta_row(self):
        conn = db.connect(self.ev.case_dir)
        try:
            conn.execute("INSERT INTO meta (key, value) VALUES "
                         "('clock_offsets', 'not json') "
                         "ON CONFLICT(key) DO UPDATE SET value = excluded.value")
            conn.commit()
            self.assertEqual({"logs": 0, "dump": 0}, clock_offsets(conn))
        finally:
            conn.close()

    # --- the language -------------------------------------------------------

    def test_the_prose_follows_the_language(self):
        self._confirm_all()
        en = case_chain(self.ev.case_dir, "en")
        de = case_chain(self.ev.case_dir, "de")
        self.assertEqual([e["at"] for e in en["events"]],
                         [e["at"] for e in de["events"]],
                         "the measured times must not depend on the language")
        self.assertNotEqual(en["gaps"], de["gaps"])

    # --- the small pieces ---------------------------------------------------

    def test_stamp_to_local_reads_the_forms_a_dump_writes(self):
        self.assertIsNotNone(stamp_to_local("2026-07-08 03:17:00"))
        self.assertIsNotNone(stamp_to_local("2026-07-08T03:17:00"))
        self.assertIsNotNone(stamp_to_local("2026-07-08"))
        self.assertIsNone(stamp_to_local(""))
        self.assertIsNone(stamp_to_local("0000-00-00 00:00:00"))

    def test_event_cap_is_reported_not_silently_applied(self):
        self.assertGreater(EVENT_CAP, 0)
        self._confirm_all()
        out = case_chain(self.ev.case_dir)
        self.assertLessEqual(len(out["events"]), EVENT_CAP)
        if out["truncated"]:
            self.assertTrue(out["gaps"], "a truncated chain has to say so")


class ArtifactTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ev = Evidence().build()
        conn = db.connect(cls.ev.case_dir)
        register(conn, cls.ev)
        conn.close()
        webshell.scan(cls.ev.case_dir, [str(cls.ev.webroot)])

    @classmethod
    def tearDownClass(cls):
        cls.ev.cleanup()

    def test_counts_are_artifacts_not_findings(self):
        conn = db.connect(self.ev.case_dir)
        try:
            counts = artifacts.counts(conn)
            distinct = conn.execute(
                "SELECT count(DISTINCT artifact) FROM findings").fetchone()[0]
            findings = conn.execute(
                "SELECT count(*) FROM findings").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(distinct, counts["total"])
        self.assertLessEqual(counts["total"], findings)

    def test_confirmed_wins_over_dismissed_within_one_artifact(self):
        """One real hit makes the artifact real; dismissed only counts when
        it is unanimous. Legacy cases triaged per finding stay readable."""
        conn = db.connect(self.ev.case_dir)
        try:
            target = conn.execute(
                "SELECT artifact FROM findings GROUP BY artifact "
                "HAVING count(*) > 1 LIMIT 1").fetchone()
            if target is None:
                self.skipTest("no artifact with several findings in the fixture")
            name = target[0]
            conn.execute("UPDATE findings SET triage = 'dismissed' "
                         "WHERE artifact = ?", (name,))
            conn.execute("UPDATE findings SET triage = 'confirmed' "
                         "WHERE rowid = (SELECT rowid FROM findings "
                         "WHERE artifact = ? LIMIT 1)", (name,))
            conn.commit()
            state = db.one(
                conn, f"WITH art AS ({artifacts.ART_SQL}) "
                      f"SELECT triage FROM art WHERE artifact = ?", (name,))
            self.assertEqual("confirmed", state["triage"])

            conn.execute("UPDATE findings SET triage = 'dismissed' "
                         "WHERE artifact = ?", (name,))
            conn.commit()
            state = db.one(
                conn, f"WITH art AS ({artifacts.ART_SQL}) "
                      f"SELECT triage FROM art WHERE artifact = ?", (name,))
            self.assertEqual("dismissed", state["triage"])
        finally:
            conn.close()

    def test_uri_path_drops_query_and_case(self):
        self.assertEqual("/a/b.php", artifacts.uri_path("/A/B.php?x=1"))
        self.assertEqual("/a/b.php", artifacts.uri_path("  /a/b.php#frag "))
        self.assertEqual("", artifacts.uri_path(None))

    def test_web_path_is_relative_to_the_evidence_root(self):
        conn = db.connect(self.ev.case_dir)
        try:
            rows = db.rows(conn, "SELECT DISTINCT artifact FROM findings "
                                 "WHERE artifact_kind = 'file'")
            self.assertTrue(rows, "the fixture flagged no file")
            for r in rows:
                rel = artifacts.web_path(conn, r["artifact"])
                self.assertFalse(rel.startswith("/"))
                self.assertNotIn(":", rel, "a drive letter leaked into the path")
                self.assertEqual(rel, rel.lower())
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
