# tests/test_chain_boundaries.py
"""Where the chronology draws its lines.

WHY THIS FILE EXISTS. A mutation run over `server/chain.py` planted 431
changes and the suite killed 248 of them: 183 survived, 42 percent. The
survivors were not spread evenly. Eleven lines carried more than half of
them, and every one of those lines is an INEQUALITY or a single comparison
-- the account window, the offset that labels the span, the direction of the
clock sentence, the threshold that decides whether a gap is named.

That is the shape of defect this module is worst at showing. `case_chain`
returns something plausible for almost any input, so a test that only checks
"there are events, and they are ordered" passes while a boundary is off by
one second, an offset is applied in one place and not the other, or a
sentence names the wrong direction. Nothing here asserts that the chronology
works; each test names ONE edge and stands on it from both sides.
"""
import json
import unittest
from datetime import datetime, timezone

from server import db
from server.chain import case_chain, offset_label, stamp_to_local
from server.engines import logindex, webshell
from tests.fixtures import Evidence, register


def stamp(at):
    """The inverse of `stamp_to_local`: a dump writes wall clock, no zone."""
    return datetime.fromtimestamp(int(at), tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S")


class AccountWindowTests(unittest.TestCase):
    """An account belongs to the case if it was created while the log ran.

    The comparison is `window_first <= at <= window_last`, and both ends are
    meant to be INCLUSIVE: an account registered in the same second as the
    first log line is the most interesting one there is, and dropping it
    because the boundary was written `<` would be silent. Every mutant that
    turned either `<=` into `<`, `==`, `!=` or a reversed comparison survived
    the old suite.
    """

    @classmethod
    def setUpClass(cls):
        cls.ev = Evidence().build()
        conn = db.connect(cls.ev.case_dir)
        register(conn, cls.ev)
        conn.close()
        webshell.scan(cls.ev.case_dir, [str(cls.ev.webroot)])
        logindex.build(cls.ev.case_dir, [str(cls.ev.logs)])
        overview = logindex.overview(cls.ev.case_dir) or {}
        cls.first = int(overview["first_epoch"])
        cls.last = int(overview["last_epoch"])

    @classmethod
    def tearDownClass(cls):
        cls.ev.cleanup()

    def setUp(self):
        conn = db.connect(self.ev.case_dir)
        try:
            conn.execute("UPDATE findings SET triage = 'confirmed'")
            conn.execute("DELETE FROM db_accounts")
            conn.execute("DELETE FROM meta WHERE key = 'clock_offsets'")
            conn.commit()
        finally:
            conn.close()

    def _account(self, registered, login="probe", admin=0, last_login=""):
        conn = db.connect(self.ev.case_dir)
        try:
            conn.execute(
                "INSERT INTO db_accounts (dump_id, cms, tbl, user_id, login, "
                "email, registered, hash_type, admin, last_login, blocked, "
                "sessions) VALUES (1, 'joomla', 'users', 1, ?, '', ?, '', ?, "
                "?, 0, 0)", (login, registered, admin, last_login))
            conn.commit()
        finally:
            conn.close()

    def _logins(self, lang="en"):
        return [e["title"] for e in case_chain(self.ev.case_dir, lang)["events"]
                if e["kind"] == "konto"]

    def _offset(self, logs=0, dump=0):
        conn = db.connect(self.ev.case_dir)
        try:
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('clock_offsets', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (json.dumps({"logs": logs, "dump": dump}),))
            conn.commit()
        finally:
            conn.close()

    def test_the_first_second_of_the_log_is_inside_the_window(self):
        self._account(stamp(self.first), login="onTheEdge")
        self.assertTrue(any("onTheEdge" in title for title in self._logins()))

    def test_one_second_before_the_log_is_outside(self):
        self._account(stamp(self.first - 1), login="tooEarly")
        self.assertEqual([], self._logins())

    def test_the_last_second_of_the_log_is_inside_the_window(self):
        self._account(stamp(self.last), login="onTheLateEdge")
        self.assertTrue(any("onTheLateEdge" in t for t in self._logins()))

    def test_one_second_after_the_log_is_outside(self):
        self._account(stamp(self.last + 1), login="tooLate")
        self.assertEqual([], self._logins())

    def test_an_unreadable_registration_date_is_not_an_event(self):
        """`registered` comes out of a dump and may be anything. It must not
        become a chronology entry at an invented time."""
        self._account("0000-00-00 00:00:00", login="broken")
        self.assertEqual([], self._logins())

    def test_an_admin_account_is_marked_and_weighs_more(self):
        self._account(stamp(self.first + 60), login="planted", admin=1)
        events = [e for e in case_chain(self.ev.case_dir)["events"]
                  if e["kind"] == "konto"]
        self.assertEqual(1, len(events))
        self.assertEqual(db.SEV_HIGH, events[0]["severity"])
        self.assertNotIn("planted", events[0]["title"].replace("planted", "", 1),
                         "the login is named exactly once")

    def test_an_ordinary_account_does_not_weigh_as_much_as_an_admin(self):
        self._account(stamp(self.first + 60), login="ordinary", admin=0)
        events = [e for e in case_chain(self.ev.case_dir)["events"]
                  if e["kind"] == "konto"]
        self.assertEqual(db.SEV_MEDIUM, events[0]["severity"])

    def test_a_last_login_inside_the_window_is_appended(self):
        self._account(stamp(self.first + 60), login="returns",
                      last_login=stamp(self.first + 120))
        detail = [e["detail"] for e in case_chain(self.ev.case_dir)["events"]
                  if e["kind"] == "konto"][0]
        self.assertIn(stamp(self.first + 120), detail)

    def test_a_last_login_outside_the_window_is_left_off(self):
        """The registration is inside the case, the later login is not.
        Printing it anyway would put a time in the paragraph that the log
        cannot speak about at all."""
        self._account(stamp(self.first + 60), login="returnsLater",
                      last_login=stamp(self.last + 86400))
        detail = [e["detail"] for e in case_chain(self.ev.case_dir)["events"]
                  if e["kind"] == "konto"][0]
        self.assertNotIn(stamp(self.last + 86400), detail)

    def test_the_dump_offset_moves_the_account_and_the_window_stays_put(self):
        """Two clocks, two corrections. The log offset moves the window, the
        dump offset moves the account -- and an account one hour before the
        log start belongs to the case once the dump clock is known to run an
        hour slow. Nothing in the old suite set the dump offset at all."""
        self._account(stamp(self.first - 3600), login="slowClock")
        self.assertEqual([], self._logins())
        self._offset(dump=3600)
        self.assertTrue(any("slowClock" in t for t in self._logins()))

    def test_the_window_does_not_move_with_the_display_mode(self):
        """`utc` and `log` change what the reader SEES. The dump timestamps
        are naive wall clock and follow no mode, so a display toggle deciding
        whether an account is part of the story would be absurd."""
        self._account(stamp(self.first), login="atTheEdge")
        self._account(stamp(self.last), login="atTheOtherEdge")
        for mode in ("log", "utc"):
            got = [e["title"] for e in
                   case_chain(self.ev.case_dir, tz_mode=mode)["events"]
                   if e["kind"] == "konto"]
            self.assertEqual(2, len(got), mode)


class SpanLabelTests(unittest.TestCase):
    """Which offset the chronology puts on the log period.

    ONE offset in the logs may be named. Two or more may not: labelling the
    whole span with one of them is wrong by the difference for the rest, and
    wrong in the way nobody checks. `len(tz_offsets) == 1` is the entire
    rule, and every mutant that turned it into `>=`, `<=`, `>` or `<`
    survived.
    """

    def test_one_offset_in_the_logs_labels_the_span(self):
        from tests.fixtures_hostile import HostileEvidence
        ev = HostileEvidence(offset="+0200")
        try:
            ev.build()
            ev.analyse()
            out = case_chain(ev.case_dir)
            self.assertEqual([7200],
                             (logindex.overview(ev.case_dir) or {})["tz_offsets"])
            self.assertIn(offset_label(7200), json.dumps(out))
        finally:
            ev.cleanup()

    def test_two_offsets_are_not_reduced_to_one(self):
        """A server that ran through a DST change writes two, and an Austrian
        log crosses +0100/+0200 twice a year. Naming either one would be a
        guess wearing the clothes of a measurement -- so the span falls back
        to UTC and says it has no single zone.

        The assertion is on the SPAN, not on the label: `span_tz` also shifts
        `span["first"]`/`span["last"]`, and a mutant that let one of two
        offsets through moved those by an hour while `zone` stayed empty --
        no label anywhere was wrong, only every time under it."""
        from tests.fixtures_hostile import HostileEvidence
        ev = HostileEvidence(offset="+0100", second_offset="+0200")
        try:
            ev.build()
            ev.analyse()
            overview = logindex.overview(ev.case_dir) or {}
            self.assertEqual([3600, 7200], sorted(overview["tz_offsets"]))
            out = case_chain(ev.case_dir)
            self.assertEqual(int(overview["first_epoch"]), out["span"]["first"],
                             "the span was shifted by an offset that is only "
                             "one of several")
            self.assertEqual("", out["zone"])
            self.assertTrue(out["tz_mixed"])
        finally:
            ev.cleanup()


class ClockSentenceTests(unittest.TestCase):
    """The sentence that reports a corrected clock.

    It carries a DIRECTION and an AMOUNT, and both come from one number:
    `off > 0` decides forward or backward, `abs(off) / 3600` the hours. A
    mutant that flips the comparison produces a sentence that is grammatical,
    plausible and says the opposite -- the worst kind, because nothing looks
    broken.
    """

    @classmethod
    def setUpClass(cls):
        cls.ev = Evidence().build()
        conn = db.connect(cls.ev.case_dir)
        register(conn, cls.ev)
        conn.execute("UPDATE findings SET triage = 'confirmed'")
        conn.commit()
        conn.close()
        webshell.scan(cls.ev.case_dir, [str(cls.ev.webroot)])
        logindex.build(cls.ev.case_dir, [str(cls.ev.logs)])

    @classmethod
    def tearDownClass(cls):
        cls.ev.cleanup()

    def _gaps(self, logs, lang="en"):
        conn = db.connect(self.ev.case_dir)
        try:
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('clock_offsets', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (json.dumps({"logs": logs, "dump": 0}),))
            conn.commit()
        finally:
            conn.close()
        return " ".join(case_chain(self.ev.case_dir, lang)["gaps"])

    def test_a_clock_set_forward_is_not_reported_as_set_back(self):
        """Asserting only that the two sentences DIFFER is no test at all: a
        mutant that swaps the comparison keeps them different and reverses
        both. The words have to be named."""
        forward, back = self._gaps(3600), self._gaps(-3600)
        self.assertIn("forward", forward)
        self.assertNotIn("back", forward)
        self.assertIn("back", back)
        self.assertNotIn("forward", back)

    def test_the_amount_is_the_size_of_the_correction_not_its_sign(self):
        """`abs(off) / 3600`. Without the `abs` the sentence reads "the clock
        was set -1 hours back" -- and "-1" contains "1", so a test looking
        for the digit passes on it."""
        self.assertIn("1 ", self._gaps(3600))
        self.assertIn("1 ", self._gaps(-3600))
        self.assertNotIn("-1", self._gaps(-3600))
        self.assertIn("2 ", self._gaps(7200))
        self.assertIn("1.5", self._gaps(5400))

    def test_no_correction_says_nothing_about_a_clock(self):
        quiet = self._gaps(0)
        self.assertNotIn("hour", quiet.lower())


class CraftedFactTests(unittest.TestCase):
    """Two rules whose edge no realistic fixture reaches.

    An INFO alert that also carries a TIME, and a file requested exactly
    once. Both are ordinary in the field and neither occurs in the sample
    case -- the sample's one INFO alert has no epoch, so the `not a["epoch"]`
    half of the condition hides whether the severity half works at all. A
    mutant flipping the severity comparison therefore survived while being
    genuinely wrong.

    So the facts are handed in directly. That is not a shortcut around the
    engine: what is under test is the RULE in `chain.py`, and the engine has
    its own tests for producing those facts.
    """

    @classmethod
    def setUpClass(cls):
        cls.ev = Evidence().build()
        conn = db.connect(cls.ev.case_dir)
        register(conn, cls.ev)
        conn.close()
        webshell.scan(cls.ev.case_dir, [str(cls.ev.webroot)])
        logindex.build(cls.ev.case_dir, [str(cls.ev.logs)])
        conn = db.connect(cls.ev.case_dir)
        conn.execute("UPDATE findings SET triage = 'confirmed'")
        conn.commit()
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.ev.cleanup()

    def _with_facts(self, build):
        """Run the chain with `chain_facts` replaced by what `build` returns,
        seeded from the real ones so every other artifact still resolves."""
        from unittest.mock import patch
        real = logindex.chain_facts
        captured = {}

        def fake(case_dir, leaves=(), ips=()):
            facts = real(case_dir, leaves=leaves, ips=ips)
            captured["files"] = facts["files"]
            build(facts)
            return facts

        with patch.object(logindex, "chain_facts", fake):
            return case_chain(self.ev.case_dir)

    def test_an_info_alert_is_not_a_chronology_entry(self):
        """INFO is the level for "worth knowing, proves nothing" -- a scanner
        user agent, say. Ordering it into the chain would put a line into the
        story that carries no claim, and the reader has no way to tell that
        from the lines that do."""
        def add_alerts(facts):
            for actor in facts["clients"].values():
                actor["alerts"] = [
                    {"severity": db.SEV_INFO, "epoch": actor["first_epoch"],
                     "detail": "UA: some-scanner/1.0", "example": "/"},
                    {"severity": db.SEV_HIGH, "epoch": actor["first_epoch"],
                     "detail": "carries a claim", "example": "/x"},
                ]
                break

        out = self._with_facts(add_alerts)
        titles = [e["title"] for e in out["events"] if e["kind"] == "alarm"]
        self.assertIn("carries a claim", titles)
        self.assertNotIn("UA: some-scanner/1.0", titles)

    def test_a_file_requested_once_gets_no_second_last_access_line(self):
        """First and last request are the same moment. A "last access" event
        beside the first one would be the same fact printed twice, and a
        chronology that repeats itself reads like two separate observations."""
        def single_hit(facts):
            for name, hits in facts["files"].items():
                if not hits:
                    continue
                first = hits[0]
                at = first["first_epoch"] or 1767582000
                facts["files"][name] = [dict(first, first_epoch=at,
                                             last_epoch=at, first_ok=at,
                                             hits=1, ok_hits=1)]

        out = self._with_facts(single_hit)
        for kind in ("erfolg", "letzter-zugriff"):
            self.assertEqual(
                sorted(e["at"] for e in out["events"]
                       if e["kind"] == kind and e["artifact_kind"] == "file"),
                sorted({e["at"] for e in out["events"]
                        if e["kind"] == kind and e["artifact_kind"] == "file"}),
                f"{kind} appears twice for the same moment")
        files = {e["artifact"] for e in out["events"]
                 if e["artifact_kind"] == "file"}
        for artifact in files:
            kinds = [e["kind"] for e in out["events"]
                     if e["artifact"] == artifact]
            self.assertNotIn("letzter-zugriff", kinds,
                             "a single request produced a last-access line")


class GapThresholdTests(unittest.TestCase):
    """Two sentences that appear only at a boundary.

    "The chronology begins at the start of the log" is true when the first
    event sits within a minute of the first log line -- meaning the log
    probably does not reach back far enough to show the beginning. The
    threshold is `< 60`, and every mutant that changed the number survived.
    """

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

    def test_a_case_with_nothing_confirmed_explains_itself(self):
        conn = db.connect(self.ev.case_dir)
        conn.execute("UPDATE findings SET triage = 'new'")
        conn.commit()
        conn.close()
        out = case_chain(self.ev.case_dir)
        self.assertEqual([], out["events"])
        self.assertTrue(out["gaps"])

    def test_confirmed_files_without_a_success_are_named(self):
        """A confirmed file the log never answered with a 2xx has no date.
        Saying nothing would leave it out of the story silently; the gap list
        is where it goes instead."""
        conn = db.connect(self.ev.case_dir)
        conn.execute("UPDATE findings SET triage = 'confirmed'")
        conn.commit()
        conn.close()
        out = case_chain(self.ev.case_dir)
        self.assertTrue(out["events"])
        listed = {u["artifact"] for u in out["undated"]}
        for event in out["events"]:
            self.assertNotIn(event["artifact"], listed,
                             "an artifact cannot be dated and undated at once")
        for entry in out["undated"]:
            self.assertTrue(entry["why"], "an undated artifact needs a reason")


if __name__ == "__main__":
    unittest.main()
