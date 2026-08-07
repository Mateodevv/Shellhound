# tests/test_laws.py
"""Statements that have to hold for EVERY case, checked on every hostile shape.

An example test says "this input gives that answer". A law says "whatever the
input, these two answers stand in this relation" -- and that is worth more,
because the fifty-five bugs that got through the example suite were not wrong
answers to the example. They were right answers to the one shape everybody
tested on: one log, one dump, lower-case paths and an offset of zero, where
adding the offset twice is the same as adding it once.

So every test here is a loop over `hostile_shapes()` with a subTest naming the
shape, and every assertion is a relation rather than a value:

  1. Switching the display clock moves timestamps and nothing else -- above
     all it does not decide WHICH facts belong to the case.
  2. Running a scan again changes nothing.
  3. A filter never returns what it was told to hide.
  4. A reported number describes what actually comes back, or says that it
     does not.

The fifth class defends the fixtures themselves: an axis that turns out to
build the same evidence as the control is a test that proves nothing, and a
file made of loops over those shapes would then be four laws' worth of green
resting on twelve copies of one case.
"""
import hashlib
import itertools
import unittest
from datetime import timedelta

from server import db
from server.artifacts import MUTED_CLAUSE, art_sql
from server.chain import case_chain
from server.engines import logindex, sqldump, webshell
from tests.fixtures_hostile import BASE, VISITOR, hostile_shapes, line


def offset_seconds(text):
    """`+0530` as seconds. The fixture writes the offset into the log; this
    reads it back, so a shape's declared axis can be checked against what the
    index actually made of it."""
    sign = -1 if text.startswith("-") else 1
    return sign * (int(text[1:3]) * 3600 + int(text[3:5]) * 60)


def event_key(event):
    """What an event IS, with the time left out.

    Everything here is a statement about the case: which artifact, what kind
    of thing happened to it, how bad, out of which evidence. The moment is the
    only part a display mode is allowed to touch, so it is exactly the part
    this key drops.
    """
    return (event["kind"], event["title"], event["artifact"],
            event["artifact_kind"], event["source"], event["severity"])


def artifact_rows(conn, muted=(), hide_severity=(), hide_triage=(),
                  hide_source=(), kind=""):
    """The artifact list the way `app.findings_list` builds it.

    Composed from `art_sql` and `MUTED_CLAUSE` rather than from a copy of
    them: a guard that re-types the SQL it is guarding passes against a broken
    server. The filters are the chips -- they HIDE, they do not select, and
    several of them stack.
    """
    where, params = [], []
    if hide_severity:
        where.append(f"worst NOT IN ({','.join('?' * len(hide_severity))})")
        params += [int(s) for s in hide_severity]
    if hide_triage:
        where.append(f"triage NOT IN ({','.join('?' * len(hide_triage))})")
        params += list(hide_triage)
    if hide_source:
        where.append(f"source NOT IN ({','.join('?' * len(hide_source))})")
        params += list(hide_source)
    if kind:
        where.append("artifact_kind = ?")
        params.append(kind)
    where.append(MUTED_CLAUSE)
    return [dict(r) for r in conn.execute(
        f"WITH art AS ({art_sql(muted)}) SELECT * FROM art "
        f"WHERE {' AND '.join(where)}", params).fetchall()]


class ShapeCases:
    """One built case per shape, shared by the tests of one class.

    Building twelve cases costs a fraction of a second, but doing it once per
    test method rather than once per class multiplies that by every law in the
    file for no gain. The tests only read from what `setUpClass` leaves them;
    where one of them has to add evidence it builds its own copy, because a
    case handed on between tests in a changed state makes the result depend on
    the order the runner picked.
    """

    confirm = True

    @classmethod
    def setUpClass(cls):
        cls.cases = {}
        for shape in hostile_shapes():
            cls.cases[shape.name] = shape.build().analyse(confirm=cls.confirm)

    @classmethod
    def tearDownClass(cls):
        for evidence in cls.cases.values():
            evidence.cleanup()


class ClockSwitchLaw(ShapeCases, unittest.TestCase):
    """THE TIME SWITCHER ONLY MOVES CLOCKS.

    `tz_mode` is a display toggle: log time or UTC. It may change what a
    moment is called and nothing else. The release just fixed got this wrong
    in both halves. The harmless half showed a timestamp shifted twice, an
    hour or two out. The serious half was that the window used to decide which
    accounts fall inside the period of the case followed the display mode
    while the dump timestamps did not, so switching the toggle added and
    dropped accounts at the edges -- a button in the interface deciding which
    facts belong to an incident.

    None of it was visible at offset zero, where a shift of two hours and a
    shift of none are the same number.
    """

    def chains(self, name):
        case = self.cases[name].case_dir
        return case_chain(case, tz_mode="log"), case_chain(case, tz_mode="utc")

    def test_the_switch_changes_no_event(self):
        """The set of events must be identical in both modes.

        This is the assertion that matters most, so it stands on its own: as
        long as both modes tell the same story, a wrong timestamp is a reading
        error, whereas an event that exists in one mode and not the other is
        the case itself changing under a display setting.
        """
        for shape in hostile_shapes():
            with self.subTest(shape=shape.name):
                log, utc = self.chains(shape.name)
                self.assertEqual(
                    sorted(event_key(e) for e in log["events"]),
                    sorted(event_key(e) for e in utc["events"]),
                    "the chronology holds different events depending on "
                    "which clock the reader chose")

    def test_the_switch_changes_no_account(self):
        """The accounts in the chronology, and their timestamps, must not move.

        A dump timestamp is a naive wall-clock reading in the database
        server's own frame; there is no offset to apply to it without
        inventing one. So an account event is the one thing in the chronology
        that must be bit-for-bit identical in both modes -- both which
        accounts are there and when they were created.
        """
        for shape in hostile_shapes():
            with self.subTest(shape=shape.name):
                log, utc = self.chains(shape.name)

                def accounts(chain):
                    return sorted((e["title"], e["at"], e["severity"])
                                  for e in chain["events"]
                                  if e["source"] == "dump")

                self.assertEqual(accounts(log), accounts(utc),
                                 "a display toggle moved the accounts of the "
                                 "case, or changed which ones it holds")

    def test_the_switch_changes_no_undecided_remainder(self):
        """A confirmed artifact the chain cannot date is listed instead of
        dropped, and that list is a statement about the case rather than about
        the clock. If it grew or shrank with the toggle, the chronology would
        be hiding a decision of the analyst in one mode and showing it in the
        other."""
        for shape in hostile_shapes():
            with self.subTest(shape=shape.name):
                log, utc = self.chains(shape.name)
                self.assertEqual(
                    sorted(u["artifact"] for u in log["undated"]),
                    sorted(u["artifact"] for u in utc["undated"]),
                    "the list of undatable artifacts followed the clock")
                self.assertEqual(log["confirmed"], utc["confirmed"])
                self.assertEqual(log["truncated"], utc["truncated"])

    def test_only_the_clock_moves(self):
        """Every log-borne event shifts by ONE amount, and that amount is an
        offset the logs actually carry.

        A chronology is read as a sequence, so two events an analyst compares
        have to be in the same frame. If one event moves by two hours and the
        next by none, the order on screen is no longer the order of the
        incident -- and the reader has no way to tell, because the times carry
        no zone of their own.

        The amount also has to be an offset that appears in the evidence.
        Zero, on a log written at -05:00, is not a reading of that log; it is
        the absence of one.
        """
        for shape in hostile_shapes():
            with self.subTest(shape=shape.name):
                log, utc = self.chains(shape.name)
                case = self.cases[shape.name].case_dir
                index = logindex.overview(case) or {}
                carried = {int(o) for o in (index.get("tz_offsets") or [])}
                by_key = {}
                for event in utc["events"]:
                    by_key.setdefault(event_key(event), []).append(event["at"])
                shifts = set()
                for event in log["events"]:
                    if event["source"] != "log":
                        continue
                    times = sorted(by_key.get(event_key(event), []))
                    self.assertTrue(times, "an event exists only in log time")
                    # Duplicates of one key can only be paired by order, and
                    # they can only be ordered by time -- which is sound while
                    # the law holds and is what the law is about.
                    shifts.add(event["at"] - times[0])
                self.assertLessEqual(
                    len(shifts), 1,
                    f"the chronology mixes frames: log events moved by "
                    f"{sorted(shifts)} seconds when the clock was switched")
                self.assertTrue(
                    shifts <= carried,
                    f"the events were shifted by {sorted(shifts)}, which is "
                    f"not an offset these logs carry ({sorted(carried)})")


class ScanIdempotenceLaw(unittest.TestCase):
    """EVERY SCAN IS IDEMPOTENT.

    A case is re-scanned all the time: evidence arrives late, a rule is
    switched on, a run was cancelled. The second run has to leave the case as
    the first one did, or the numbers in the report depend on how often
    somebody pressed the button.

    The two-dumps shape is the one that matters. With a single dump SQLite
    hands the re-inserted row the same id, so deleting the children by the NEW
    id happened to hit the right rows; with two dumps it does not, the old
    accounts stay behind without a dump, and the chronology -- which does not
    join `db_dumps` -- read the same account twice.
    """

    def snapshot(self, case_dir):
        """Everything a second run could disturb, with the row ids left out:
        an id is an implementation detail, but a duplicated or orphaned row is
        a wrong answer."""
        conn = db.connect(case_dir)
        try:
            def fetch(sql):
                return sorted(tuple(r) for r in conn.execute(sql).fetchall())

            orphan_accounts = conn.execute(
                "SELECT count(*) FROM db_accounts a "
                "LEFT JOIN db_dumps d ON d.id = a.dump_id "
                "WHERE d.id IS NULL").fetchone()[0]
            orphan_tables = conn.execute(
                "SELECT count(*) FROM db_tables t "
                "LEFT JOIN db_dumps d ON d.id = t.dump_id "
                "WHERE d.id IS NULL").fetchone()[0]
            return {
                "findings": fetch("SELECT fingerprint FROM findings"),
                "accounts": fetch(
                    "SELECT cms, tbl, user_id, login, email, registered, "
                    "hash_type, admin, last_login FROM db_accounts"),
                "tables": fetch(
                    "SELECT name, columns, rows, bytes, col_list "
                    "FROM db_tables"),
                "dumps": fetch("SELECT path, statements, size, cms, kind "
                               "FROM db_dumps"),
                "orphan_accounts": orphan_accounts,
                "orphan_tables": orphan_tables,
            }
        finally:
            conn.close()

    def test_running_every_engine_again_changes_nothing(self):
        for shape in hostile_shapes():
            with self.subTest(shape=shape.name):
                evidence = shape.build()
                try:
                    conn = db.connect(evidence.case_dir)
                    evidence.register(conn)
                    conn.close()
                    rounds = []
                    for _ in range(3):
                        webshell.scan(evidence.case_dir,
                                      [str(evidence.webroot)])
                        logindex.build(evidence.case_dir,
                                       evidence.log_targets)
                        sqldump.scan(evidence.case_dir,
                                     evidence.dump_targets)
                        rounds.append(self.snapshot(evidence.case_dir))
                    first, second, third = rounds
                    self.assertEqual(first, second,
                                     "the second run left a different case "
                                     "behind than the first")
                    # The THIRD run, because a defect that alternates between
                    # two states passes a comparison of two runs.
                    self.assertEqual(first, third,
                                     "the case drifts with every re-scan")
                    for number, state in enumerate(rounds, start=1):
                        self.assertEqual(
                            0, state["orphan_accounts"],
                            f"run {number} left accounts behind whose dump is "
                            f"gone; the chronology does not join db_dumps and "
                            f"would read them as extra accounts")
                        self.assertEqual(
                            0, state["orphan_tables"],
                            f"run {number} left tables behind whose dump is "
                            f"gone")
                    # Idempotence over an empty case is not idempotence.
                    self.assertTrue(first["findings"])
                    self.assertTrue(first["accounts"])
                finally:
                    evidence.cleanup()


class FilterLaw(ShapeCases, unittest.TestCase):
    """A FILTER NEVER RETURNS WHAT IT HIDES.

    The chips in the work list hide a class of artifact and bring it back on
    the next click. `MUTED_CLAUSE` is AND-ed onto them, and because SQL binds
    AND tighter than OR it was, without its brackets, read as
    `(chips AND active > 0) OR triage != 'new'`: every DECIDED artifact walked
    past every chip. Asking for the confirmed ones to be hidden returned them,
    which is the one thing a filter must never do -- an analyst who has hidden
    a class reasonably believes what is left does not contain it.

    Decided artifacts are therefore in every shape here. A case where
    everything is still `new` cannot see this at all.
    """

    confirm = False

    #: Filters are chips: single, stacked, and stacked across dimensions.
    COMBOS = [
        {"hide_severity": ("0",)},
        {"hide_severity": ("0", "1")},
        {"hide_severity": ("1", "2", "3")},
        {"hide_triage": ("confirmed",)},
        {"hide_triage": ("new", "reviewed")},
        {"hide_triage": ("dismissed",)},
        {"hide_source": ("webshell",)},
        {"hide_source": ("logs", "sqldb")},
        {"kind": "file"},
        {"kind": "client"},
        {"kind": "table"},
        {"hide_severity": ("0",), "hide_triage": ("confirmed",)},
        {"hide_severity": ("1",), "kind": "file"},
        {"hide_triage": ("dismissed",), "kind": "client"},
        {"hide_severity": ("0", "1"), "hide_triage": ("confirmed", "reviewed"),
         "kind": "file"},
        {"hide_severity": ("2", "3"), "hide_source": ("sqldb",),
         "hide_triage": ("new",)},
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        for evidence in cls.cases.values():
            conn = db.connect(evidence.case_dir)
            # The scan only produces high and medium findings, so the low and
            # informational chips would hide nothing and prove nothing. Two
            # artifacts are added to fill the scale out.
            db.upsert_finding(conn, "logs", db.SEV_LOW, "law.low", "client",
                              "198.51.100.7", line=0, evidence="x",
                              rule_id="law.low")
            db.upsert_finding(conn, "logs", db.SEV_INFO, "law.info", "client",
                              "198.51.100.8", line=0, evidence="y",
                              rule_id="law.info")
            conn.commit()
            # A spread of decisions rather than one state everywhere: the
            # defect this defends against was invisible while an artifact was
            # still `new`, and equally invisible when they all were.
            artifacts = [r["artifact"] for r in conn.execute(
                "SELECT DISTINCT artifact FROM findings ORDER BY artifact")]
            for position, artifact in enumerate(artifacts):
                state = db.TRIAGE_STATES[position % len(db.TRIAGE_STATES)]
                conn.execute("UPDATE findings SET triage = ? "
                             "WHERE artifact = ?", (state, artifact))
            conn.commit()
            conn.close()

    def test_no_filter_returns_what_it_hides(self):
        for shape in hostile_shapes():
            with self.subTest(shape=shape.name):
                conn = db.connect(self.cases[shape.name].case_dir)
                try:
                    everything = artifact_rows(conn)
                    self.assertTrue(everything, "nothing to filter")
                    for combo in self.COMBOS:
                        got = artifact_rows(conn, **combo)
                        for row in got:
                            self.assertNotIn(
                                str(row["worst"]),
                                combo.get("hide_severity", ()),
                                f"{combo} returned a severity it hid")
                            self.assertNotIn(
                                row["triage"], combo.get("hide_triage", ()),
                                f"{combo} returned a triage state it hid")
                            self.assertNotIn(
                                row["source"], combo.get("hide_source", ()),
                                f"{combo} returned a source it hid")
                            if combo.get("kind"):
                                self.assertEqual(
                                    combo["kind"], row["artifact_kind"],
                                    f"{combo} returned another kind")
                        self.assertLessEqual(
                            {r["artifact"] for r in got},
                            {r["artifact"] for r in everything},
                            f"{combo} invented an artifact")
                finally:
                    conn.close()

    def test_every_filter_had_something_to_hide(self):
        """The law above is satisfied trivially by a filter that returns
        nothing, so this checks the other side: for each combination, the
        unfiltered list really did hold at least one artifact of the class
        that was hidden. Without it, a query that broke and returned an empty
        result would read as a filter working perfectly.
        """
        for shape in hostile_shapes():
            with self.subTest(shape=shape.name):
                conn = db.connect(self.cases[shape.name].case_dir)
                try:
                    everything = artifact_rows(conn)
                    for combo in self.COMBOS:
                        sevs = combo.get("hide_severity", ())
                        hidden = [
                            r for r in everything
                            if str(r["worst"]) in sevs
                            or r["triage"] in combo.get("hide_triage", ())
                            or r["source"] in combo.get("hide_source", ())
                            or (combo.get("kind")
                                and r["artifact_kind"] != combo["kind"])]
                        self.assertTrue(
                            hidden,
                            f"{combo} hid nothing in this case, so the test "
                            f"above proved nothing about it")
                finally:
                    conn.close()

    def test_a_muted_rule_does_not_widen_a_filter(self):
        """The same law with rules switched off.

        `MUTED_CLAUSE` only bites once a rule is actually muted -- with none
        muted, `active > 0` is true for everything and the clause cannot
        misbehave. So the combinations run a second time against a workspace
        that has switched off every rule of one artifact, which is the state
        in which the clause was written to do something.
        """
        for shape in hostile_shapes():
            with self.subTest(shape=shape.name):
                conn = db.connect(self.cases[shape.name].case_dir)
                try:
                    victim = conn.execute(
                        "SELECT artifact FROM findings WHERE rule_id != '' "
                        "ORDER BY artifact LIMIT 1").fetchone()
                    self.assertIsNotNone(victim)
                    muted = tuple(r[0] for r in conn.execute(
                        "SELECT DISTINCT rule_id FROM findings "
                        "WHERE artifact = ? AND rule_id != ''",
                        (victim["artifact"],)).fetchall())
                    self.assertTrue(muted)
                    for combo in self.COMBOS:
                        for row in artifact_rows(conn, muted=muted, **combo):
                            self.assertNotIn(
                                str(row["worst"]),
                                combo.get("hide_severity", ()),
                                f"{combo} with muted rules returned a "
                                f"severity it hid")
                            self.assertNotIn(
                                row["triage"], combo.get("hide_triage", ()),
                                f"{combo} with muted rules returned a triage "
                                f"state it hid")
                            if combo.get("kind"):
                                self.assertEqual(
                                    combo["kind"], row["artifact_kind"],
                                    f"{combo} with muted rules returned "
                                    f"another kind")
                finally:
                    conn.close()


class ReportedNumberLaw(ShapeCases, unittest.TestCase):
    """A REPORTED NUMBER DESCRIBES WHAT COMES BACK, OR SAYS IT DOES NOT.

    The pattern hunt exists for mass exploitation, so its headline figure --
    how many clients hit this path -- is the number that goes into the report.
    It used to be `len()` of a list capped at two hundred, so a campaign with
    three thousand addresses was reported as two hundred, and the only
    truncation flag in the result tracked a different cap entirely. Nothing on
    screen said the number was a page count.

    Below two hundred clients none of this is visible, which is why the
    many-clients shape exists.
    """

    confirm = False

    #: Every shape's log carries this, and the many-clients shapes carry it
    #: two hundred and fifty times.
    CAMPAIGN = "com_jce"
    #: A path every shape's log holds, from a handful of clients.
    COMMON = "index.php"

    def test_the_cap_changes_the_list_and_never_the_number(self):
        """Asking for fewer rows must not change what the case reports.

        The list is a page and the totals describe the whole result, so
        raising the limit may only lengthen the list. A total that moves with
        the page size is a total of the page.
        """
        for shape in hostile_shapes():
            with self.subTest(shape=shape.name):
                case = self.cases[shape.name].case_dir
                for pattern in (self.CAMPAIGN, self.COMMON):
                    whole = logindex.match_pattern(case, pattern, limit=10000)
                    page = logindex.match_pattern(case, pattern, limit=200)
                    self.assertEqual(
                        whole["clients_total"], page["clients_total"],
                        f"'{pattern}': the client count moved with the page "
                        f"size, so it counts the page")
                    self.assertEqual(
                        len(whole["clients"]), whole["clients_total"],
                        f"'{pattern}': the uncapped list and the reported "
                        f"total disagree")
                    self.assertEqual(whole["uri_total"], page["uri_total"])
                    self.assertEqual(whole["hits"], page["hits"])
                    self.assertEqual(whole["ok_clients"], page["ok_clients"])

    def test_a_shortened_client_list_says_so(self):
        """When the list is shorter than the total, the result has to admit
        it. A caller cannot compare the two itself without knowing which
        limit was used, and the interface prints the number beside the list.
        """
        for shape in hostile_shapes():
            with self.subTest(shape=shape.name):
                case = self.cases[shape.name].case_dir
                for pattern in (self.CAMPAIGN, self.COMMON):
                    got = logindex.match_pattern(case, pattern, limit=200)
                    short = len(got["clients"]) < got["clients_total"]
                    self.assertEqual(
                        short, bool(got.get("clients_truncated")),
                        f"'{pattern}': {len(got['clients'])} of "
                        f"{got['clients_total']} clients came back and the "
                        f"result says truncated="
                        f"{got.get('clients_truncated')}")

    def test_the_many_client_shapes_really_exceed_the_cap(self):
        """The shape that carries 250 clients has to report 250 and hand back
        200, or the two tests above are running below the cap and checking
        nothing. This is the assertion that makes them mean something."""
        seen = 0
        for shape in hostile_shapes():
            if not shape.options.get("many_clients"):
                continue
            with self.subTest(shape=shape.name):
                seen += 1
                got = logindex.match_pattern(
                    self.cases[shape.name].case_dir, self.CAMPAIGN, limit=200)
                self.assertEqual(shape.options["many_clients"],
                                 got["clients_total"],
                                 "the campaign clients were miscounted")
                self.assertEqual(200, len(got["clients"]))
                self.assertTrue(got.get("clients_truncated"))
        self.assertTrue(seen, "no shape exercises the client cap any more")

    def test_a_shortened_uri_list_says_so(self):
        """`uri_total` exists so that a pattern reaching too far is visible --
        "fifty URLs hit" and "three thousand URLs hit" are different findings
        about the same rule. The list beside that number is capped, and if
        nothing says so the reader takes the fifty rows as the whole answer
        and the pattern looks precise.
        """
        for shape in hostile_shapes():
            with self.subTest(shape=shape.name):
                # Its own copy of the shape rather than the shared one: this
                # test adds evidence, and a case that the tests of one class
                # hand on to each other in a changed state is a suite whose
                # result depends on the order the runner picked.
                evidence = shape.build()
                try:
                    # More distinct URIs than the list can hold, written into
                    # the shape's own log directory so the case stays
                    # otherwise exactly what the shape describes.
                    (evidence.logs / "many-uris.log").write_text("".join(
                        line(VISITOR, BASE + timedelta(days=3, seconds=i),
                             f"/wp-content/plugins/p{i:03d}/hunted.php",
                             offset="+0000") for i in range(120)),
                        encoding="utf-8")
                    logindex.build(evidence.case_dir, evidence.log_targets)
                    got = logindex.match_pattern(evidence.case_dir,
                                                 "hunted.php")
                    self.assertEqual(120, got["uri_total"],
                                     "the distinct URIs were miscounted")
                    self.assertLess(
                        len(got["uris"]), got["uri_total"],
                        "the cap did not bite, so nothing is proved")
                    self.assertTrue(
                        got.get("truncated") or got.get("uris_truncated"),
                        f"{len(got['uris'])} of {got['uri_total']} URIs came "
                        f"back and the result claims to be complete")
                finally:
                    evidence.cleanup()

    def test_an_empty_result_answers_the_same_questions(self):
        """A result with no hits is still a result, and the caller reading it
        does not know in advance that it is empty. Dropping a field for that
        case turns "nothing matched" into an error at the reader rather than
        an answer.
        """
        for shape in hostile_shapes():
            with self.subTest(shape=shape.name):
                case = self.cases[shape.name].case_dir
                full = logindex.match_pattern(case, self.COMMON)
                empty = logindex.match_pattern(case, "no-such-path-anywhere")
                self.assertEqual(0, empty["clients_total"])
                self.assertEqual(sorted(full), sorted(empty),
                                 "an empty result is shaped differently from "
                                 "a full one")


class ShapesDifferLaw(ShapeCases, unittest.TestCase):
    """The fixtures themselves, because the laws above rest on them.

    Every test in this file is a loop over twelve shapes. If two of those
    shapes build the same evidence, the loop runs the same case twice and the
    green it produces is worth one case, not two -- which is precisely how a
    suite of three hundred tests came to be running on a single shape without
    anybody noticing.

    So: the shapes must differ from each other on disk, and each declared axis
    must reach the analysis rather than stopping at the fixture.
    """

    confirm = False

    def test_no_two_shapes_build_the_same_evidence(self):
        """Content hashes, not sizes: two logs written at different offsets
        hold the same number of bytes, and a fixture axis that only changed
        the digits would pass a size comparison."""
        signatures = {}
        for shape in hostile_shapes():
            evidence = self.cases[shape.name]
            root = evidence.root
            files = sorted(
                (str(p.relative_to(root)).replace("\\", "/"),
                 hashlib.sha256(p.read_bytes()).hexdigest())
                for p in root.rglob("*")
                if p.is_file() and "case" not in p.relative_to(root).parts)
            # The name of the folder the evidence sits in is itself an axis:
            # one shape puts the case under a directory called `uploads` to
            # prove the analyst's own folder names decide nothing.
            signatures[shape.name] = (root.name,) + tuple(files)
        for one, other in itertools.combinations(sorted(signatures), 2):
            with self.subTest(shape=f"{one} vs {other}"):
                self.assertNotEqual(
                    signatures[one], signatures[other],
                    "two shapes build identical evidence, so every loop in "
                    "this file runs that case twice and tests it once")

    def test_every_declared_axis_reaches_the_analysis(self):
        """Each shape names one dial it turns. The dial has to be visible in
        the analysed case, not merely in the fixture: an axis that the engines
        flatten back out is a test that runs on the control shape while
        claiming otherwise."""
        for shape in hostile_shapes():
            with self.subTest(shape=shape.name):
                evidence = self.cases[shape.name]
                options = shape.options
                index = logindex.overview(evidence.case_dir) or {}
                conn = db.connect(evidence.case_dir)
                try:
                    dumps = conn.execute(
                        "SELECT count(*) FROM db_dumps").fetchone()[0]
                finally:
                    conn.close()

                wanted = {offset_seconds(options.get("offset", "+0200"))}
                if options.get("second_offset"):
                    wanted.add(offset_seconds(options["second_offset"]))
                self.assertEqual(
                    sorted(wanted), sorted(int(o) for o in
                                           index.get("tz_offsets") or []),
                    "the offset the log was written in did not survive "
                    "indexing")

                self.assertEqual(2 if options.get("two_dumps") else 1, dumps,
                                 "the second dump was not registered as a "
                                 "second fact")

                if options.get("duplicate_log_name"):
                    other = logindex.match_pattern(evidence.case_dir,
                                                   "/other/")
                    self.assertTrue(
                        other["hits"],
                        "the second vhost's access.log was never read, so "
                        "nothing collides on the basename")

                self.assertEqual(
                    bool(options.get("mixed_case")),
                    any(c.isupper() for c in evidence.shell_rel),
                    "the mixed-case shape is spelled like the control")

                self.assertEqual(
                    bool(options.get("upload_parent")),
                    "uploads" in [p.lower() for p in evidence.case_dir.parts],
                    "the case does not sit under the folder name the shape "
                    "is about")

                self.assertEqual(
                    bool(options.get("truncated_head")),
                    bool(index.get("unparsed")),
                    "a log cut mid-record was read without complaint, or the "
                    "control log has an unreadable line of its own")

                if options.get("many_clients"):
                    self.assertGreater(
                        index.get("clients", 0), options["many_clients"],
                        "the crowd of clients did not reach the index")
                else:
                    self.assertLess(
                        index.get("clients", 0), 200,
                        "the control shapes are above the cap as well, so "
                        "the many-clients shape turns no dial")


if __name__ == "__main__":
    unittest.main()
