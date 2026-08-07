# tests/test_promises.py
"""The promises SHELLHOUND makes about itself, checked everywhere at once.

Every statement below is written down in a docstring or in the README, and
every one of them was, at some point, true in the place somebody thought to
test and false one function further along. A promise that holds in the one
spot with a test is not a promise, it is a coincidence -- so these tests
sweep: over every export the tool offers, over every shape in
`hostile_shapes()`, over both interface languages and both readings of the
clock.

The five promises:

  1. NO ABSOLUTE HOST PATH LEAVES THE MACHINE. Exported paths are
     webroot-relative, because otherwise the directory layout of the
     analyst's forensic VM travels to whoever receives the bundle.
  2. WHAT IS STORED IS ENGLISH. Only rendered prose follows the interface
     language; a case file whose wording depends on which language happened
     to be selected at the time of a click is worthless as evidence.
  3. EVERY CONFIRMED ARTIFACT IS ACCOUNTED FOR in the chronology -- as a
     dated event or under "undated", never nowhere.
  4. A THIRD PARTY'S OPINION NEVER MOVES A SEVERITY. This toolkit reports
     what it measured; a reputation score is somebody else's conclusion
     about somebody else's data.
  5. A SWITCHED-OFF RULE HIDES, IT DOES NOT DELETE. A switch is not a
     retraction.

Nothing here reaches the network: the enrichment lookups are replaced by the
same mechanism `tests/test_enrich.py` uses, and what is asserted is that the
request never gets that far.
"""
import io
import json
import re
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException

from server import db, enrich, i18n, rules as rulelib, ruleswitch, settings
from server.app import create_app
from server.artifacts import counts as artifact_counts
from server.chain import case_chain
from server.config import Config
from server.engines import logindex, sqldump, webshell
from tests.fixtures_hostile import ATTACKER, HostileEvidence, hostile_shapes


# --- reaching the application without a web server --------------------------
#
# The suite has no HTTP client, and the export endpoints are closures inside
# `create_app` -- which is exactly why they were never swept. They are plain
# synchronous functions, so the route table is enough to call them: what is
# under test is the code the running server executes, not a re-implementation
# of it here.

def endpoint(app, path, method="GET"):
    for route in app.routes:
        if getattr(route, "path", None) == path \
                and method in (getattr(route, "methods", None) or ()):
            return route.endpoint
    raise AssertionError(f"the application has no {method} {path}")


def body_model(func):
    """The pydantic model a POST endpoint takes, read off the signature so a
    renamed field breaks here rather than being silently ignored."""
    return func.__annotations__["body"]


def open_case(evidence, slug="case", case_dir=None):
    """Give a hostile case the identity the API needs.

    `workspace.resolve_case` refuses a directory without `case.json`, so the
    fixture's bare case directory cannot be reached through any route until
    it has one."""
    case_dir = Path(case_dir or evidence.case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "case.json").write_text(
        json.dumps({"name": "Hostile", "reference": "R-2026-1", "notes": "",
                    "created": "2026-01-01T00:00:00"}),
        encoding="utf-8")
    return slug


def confirm_everything(app, slug, case_dir):
    """Decide every artifact through the real triage route.

    Setting `triage = 'confirmed'` in SQL, which the fixture offers, skips
    the collection step -- and collection is where the paths that end up in
    an export are made. A test that seeds the IOC box by hand tests its own
    INSERT."""
    conn = db.connect(case_dir)
    try:
        artifacts = [r["artifact"] for r in db.rows(
            conn, "SELECT DISTINCT artifact FROM findings")]
    finally:
        conn.close()
    triage = endpoint(app, "/api/cases/{slug}/triage", "POST")
    return triage(slug, body_model(triage)(artifacts=artifacts,
                                           state="confirmed"))


def spellings(path):
    """The ways one absolute path can appear in a file, by name.

    A naive `assertNotIn(str(root), blob)` passes against a JSON export that
    carries the path in full: `json.dumps` doubles every backslash, so the
    Windows path in the file shares not one character sequence with the one
    the test looked for. The lower-cased form matters because `web_path()`
    lower-cases what it returns, and the forward-slash form because `db._norm`
    rewrites separators."""
    raw = str(path)
    forward = raw.replace("\\", "/")
    return {"as written": raw,
            "with forward slashes": forward,
            "JSON-escaped": json.dumps(raw)[1:-1],
            "lower-cased": forward.lower()}


def host_paths(evidence):
    """Every absolute path of this case that describes THIS machine."""
    out = {"the workspace": evidence.root,
           "the case directory": evidence.case_dir,
           "the webroot": evidence.webroot}
    for i, target in enumerate(evidence.log_targets):
        out[f"log target {i}"] = target
    for i, target in enumerate(evidence.dump_targets):
        out[f"dump target {i}"] = target
    return out


def every_export(app, slug):
    """Every file the application hands out for one case, by name.

    Deliberately NOT the case archive (`/api/cases/{slug}/archive`): that zip
    is the case itself -- case.db and all -- and it carries the registered
    evidence paths because those ARE the case's own record of where the
    evidence was read from. Everything in here is a REPORT: a thing made to
    be given to somebody who is not the analyst.
    """
    out = {}
    export = endpoint(app, "/api/cases/{slug}/iocs/export")
    for fmt in ("json", "stix", "csv"):
        for lang in i18n.LANGUAGES:
            for tz in ("log", "utc"):
                out[f"iocs.{fmt} ({lang}/{tz})"] = export(
                    slug, fmt, lang, tz).body.decode("utf-8")
    accounts = endpoint(app, "/api/cases/{slug}/database/accounts.csv")
    for only in ("", "admins"):
        for lang in i18n.LANGUAGES:
            out[f"accounts.csv ({only or 'all'}/{lang})"] = accounts(
                slug, only, lang).body.decode("utf-8")
    trace = endpoint(app, "/api/cases/{slug}/trace.csv")
    archive = trace(slug, ATTACKER).body
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        for name in zf.namelist():
            out[f"trace.zip/{name}"] = zf.read(name).decode("utf-8")
    patterns = endpoint(app, "/api/patterns/export")
    out["hunt_patterns.json"] = patterns().body.decode("utf-8")
    return out


class ExportedPathsTests(unittest.TestCase):
    """PROMISE 1: no absolute host path leaves the machine.

    The paths in a report have to be webroot-relative. An absolute one is an
    identity for the interface of ONE machine -- it helps nobody who receives
    the bundle, it is wrong on every other machine, and it tells the recipient
    how the analyst's forensic VM is laid out. This was true of the IOC values
    from the day the box existed and false of the chronology from the day it
    was added to the JSON export, which is the shape of the failure this
    sweeps for: a promise kept by the code that was tested and broken by the
    code that travelled alongside it.
    """

    def _case(self, **options):
        evidence = HostileEvidence(**options).build().analyse(confirm=False)
        self.addCleanup(evidence.cleanup)
        slug = open_case(evidence)
        app = create_app(Config(workspace=evidence.root, token="t"))
        confirm_everything(app, slug, evidence.case_dir)
        return evidence, app, slug

    def _assert_clean(self, evidence, exports):
        for name, blob in exports.items():
            for what, path in host_paths(evidence).items():
                for how, needle in spellings(path).items():
                    self.assertNotIn(
                        needle, blob,
                        f"{name} carries {what} {how} -- the recipient of "
                        f"this bundle learns the directory layout of the "
                        f"machine it was made on")

    def test_no_export_of_any_shape_carries_a_host_path(self):
        """The sweep proper: every shape, every export, every spelling."""
        for shape in hostile_shapes():
            with self.subTest(shape=shape.name):
                evidence, app, slug = self._case(**shape.options)
                self._assert_clean(evidence, every_export(app, slug))

    def test_the_sweep_is_looking_at_a_case_that_has_something_to_leak(self):
        """A guard on the guard above.

        Exports of an empty case contain no paths at all and pass every
        assertion in this class. So one shape is checked the other way round:
        the confirmed shell has to BE in the exports, under its
        webroot-relative name, or the sweep is measuring nothing.

        The name is the one the WEB SERVER would use. This assertion used to
        read `"WebRoot/" + shell_rel`, keeping the evidence directory in
        front -- and that spelling is what a real case turned into
        `webroot-copy/images/x.phtml`, a directory nobody but the analyst
        has. So the prefix is now asserted ABSENT as well."""
        evidence, app, slug = self._case(mixed_case=True)
        exports = every_export(app, slug)
        relative = evidence.shell_rel
        for name in ("iocs.json (en/log)", "iocs.csv (en/log)"):
            self.assertIn(relative, exports[name],
                          f"{name} does not name the confirmed shell at all")
            self.assertNotIn(evidence.webroot.name + "/" + relative,
                             exports[name],
                             f"{name} prefixes the indicator with the folder "
                             f"the analyst happened to unpack into")
        self.assertIn(Path(evidence.shell_rel).name, exports["iocs.stix (en/log)"],
                      "the STIX bundle does not name the confirmed shell")

    def test_the_chronology_in_the_json_export_is_relative(self):
        """The back door specifically.

        `iocs.to_json` relativises the indicator values, and the chronology
        was bolted on later carrying `artifact` -- the absolute path the
        interface opens windows with -- straight through. Both the dated
        events and the undated leftovers go out, so both are read here."""
        evidence, app, slug = self._case(mixed_case=True, upload_parent=True)
        export = endpoint(app, "/api/cases/{slug}/iocs/export")
        chain = json.loads(export(slug, "json", "en", "log").body)["chain"]
        self.assertTrue(chain["events"], "no events: nothing was checked")
        self.assertTrue(chain["undated"], "no undated entries: nothing was checked")
        for row in chain["events"] + chain["undated"]:
            self.assertNotIn(
                "artifact_rel", row,
                "the export carries the internal twin of the path as well")
            artifact = row.get("artifact", "")
            self.assertFalse(
                str(artifact).startswith(str(evidence.root)),
                f"the chronology names {artifact} by its absolute path")

    def test_every_path_the_tool_derives_is_relative(self):
        """The rule at the source, not just at the exports.

        `db.case_relative_path` hands the path back UNCHANGED when no
        registered evidence root matches -- "better an absolute path than an
        invented one" -- so the promise rests entirely on the tool never
        deriving a path that misses its roots. A value the analyst types into
        the box by hand is their own statement and is out of scope; every path
        indicator the tool wrote itself is not.

        Swept over the shapes because this is where a matching bug hides: a
        webroot spelled `WebRoot`, or one sitting under a folder called
        `uploads`, is exactly what makes a root comparison miss."""
        for shape in hostile_shapes():
            with self.subTest(shape=shape.name):
                evidence, app, slug = self._case(**shape.options)
                conn = db.connect(evidence.case_dir)
                try:
                    paths = [r["value"] for r in db.rows(
                        conn, "SELECT value, origin FROM iocs WHERE type = 'path'")]
                finally:
                    conn.close()
                self.assertTrue(paths, "no path indicator was collected at all")
                for value in paths:
                    self.assertFalse(
                        Path(value).is_absolute() or ":" in value,
                        f"the collected indicator {value!r} is an absolute "
                        f"path on this machine")
                    # EVERY REGISTERED ROOT, not `evidence.root`. This
                    # assertion named the CASE folder ("cases"), which no
                    # relative path ever began with, so it passed while the
                    # tool was writing `webroot/...` in front of every
                    # indicator -- the exact thing it was written to catch.
                    for folder in registered_folder_names(evidence.case_dir):
                        self.assertFalse(
                            value.lower().startswith(folder.lower() + "/"),
                            f"the collected indicator {value!r} starts in "
                            f"{folder!r}, a directory of the analyst's own "
                            f"making")


def registered_folder_names(case_dir):
    """The folder name of every evidence root registered in the case."""
    conn = db.connect(case_dir)
    try:
        return [Path(str(row["path"])).name
                for row in db.rows(conn, "SELECT path FROM evidence")]
    finally:
        conn.close()


# --- promise 2 --------------------------------------------------------------

_PLACEHOLDER = re.compile(r"\{[a-zA-Z_]+\}")
# Long enough that a fragment is a phrase rather than a word two languages
# happen to share.
_MIN_FRAGMENT = 10
_GERMAN_LETTERS = "äöüÄÖÜß"


def german_fragments():
    """Literal German phrases out of the server's own catalogue.

    Derived rather than listed: a hand-written word list goes stale the day
    somebody adds a translation, and the thing worth detecting is precisely
    "a string from the German catalogue ended up in the case". Fragments that
    also appear in the English rendering of some key are dropped -- those are
    words the two languages share and prove nothing."""
    german, english = set(), set()
    for entry in i18n.CATALOGUE.values():
        for lang, bucket in (("en", english), ("de", german)):
            for chunk in _PLACEHOLDER.split(entry.get(lang, "") or ""):
                text = chunk.strip(" .,:;—-·()")
                if len(text) >= _MIN_FRAGMENT:
                    bucket.add(text)
    return sorted(german - english)


# Columns whose value is a clock reading. Two runs of the same pipeline
# differ in them by construction, and that says nothing about language.
_VOLATILE = {"id", "added", "created", "last_seen", "triaged_at", "ran_at",
             "set_at", "scanned_at", "meta_at", "started", "finished",
             "fetched"}


def stored_rows(case_dir):
    """Every row of every table in the case database, as comparable tuples."""
    conn = db.connect(case_dir)
    try:
        out = {}
        names = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
            if not r[0].startswith("sqlite")]
        for table in sorted(names):
            columns = [d[0] for d in conn.execute(
                f"SELECT * FROM {table} LIMIT 0").description]
            keep = [c for c in columns if c not in _VOLATILE]
            out[table] = sorted(
                tuple((c, row[c]) for c in keep)
                for row in conn.execute(f"SELECT * FROM {table}").fetchall())
        return out
    finally:
        conn.close()


def stored_strings(case_dir):
    """Every text value the case holds, with the table and column it sits
    in, so a failure names the row rather than the database."""
    conn = db.connect(case_dir)
    try:
        out = []
        names = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
            if not r[0].startswith("sqlite")]
        for table in sorted(names):
            columns = [d[0] for d in conn.execute(
                f"SELECT * FROM {table} LIMIT 0").description]
            for row in conn.execute(f"SELECT * FROM {table}").fetchall():
                for column in columns:
                    value = row[column]
                    if isinstance(value, str) and value:
                        out.append((f"{table}.{column}", value))
        return out
    finally:
        conn.close()


class StoredDataStaysEnglishTests(unittest.TestCase):
    """PROMISE 2: the interface language changes nothing that is persisted.

    Findings, IOC origins, triage notes and the record of a hunt travel into
    the case archive and into every export. A German phrase in any of them is
    not a cosmetic slip: it makes two case files of the same incident
    non-comparable, and it puts a sentence into a report in a language the
    recipient did not ask for. The rule is written into `server/i18n.py` at
    length; this checks it against the whole database rather than against the
    handful of strings someone remembered.
    """

    @classmethod
    def setUpClass(cls):
        cls.evidence = HostileEvidence(mixed_case=True, two_dumps=True,
                                       duplicate_log_name=True).build()
        cls.app = create_app(Config(workspace=cls.evidence.root, token="t"))
        cls.cases = {lang: cls._run(lang) for lang in i18n.LANGUAGES}

    @classmethod
    def tearDownClass(cls):
        cls.evidence.cleanup()

    @classmethod
    def _run(cls, lang):
        """The whole pipeline for one language, over the SAME evidence.

        The same directory on disk for both runs, deliberately: two fixtures
        in two temporary directories differ in every stored path, and that
        difference would swamp the one this test is looking for."""
        evidence, app = cls.evidence, cls.app
        slug = f"case-{lang}"
        case_dir = evidence.root / slug
        open_case(evidence, slug, case_dir)
        conn = db.connect(case_dir)
        evidence.register(conn)
        conn.close()
        webshell.scan(case_dir, [str(evidence.webroot)])
        logindex.build(case_dir, evidence.log_targets)
        for target in evidence.dump_targets:
            sqldump.scan(case_dir, [target])
        confirm_everything(app, slug, case_dir)

        flag = endpoint(app, "/api/cases/{slug}/files/flag", "POST")
        flag(slug, body_model(flag)(
            paths=[str(evidence.webroot / evidence.shell_rel)],
            note="picked out by hand"), lang)
        conn = db.connect(case_dir)
        try:
            accounts = [r["id"] for r in db.rows(conn, "SELECT id FROM db_accounts")]
        finally:
            conn.close()
        flag_account = endpoint(
            app, "/api/cases/{slug}/database/accounts/flag", "POST")
        for account_id in accounts:
            flag_account(slug, body_model(flag_account)(account_id=account_id))
        hunt = endpoint(app, "/api/cases/{slug}/hunt/run", "POST")
        hunt(slug, body_model(hunt)(ids=[]))

        # Every read that takes a language. A read has no business writing,
        # which is the other half of what this test is for.
        endpoint(app, "/api/cases/{slug}")(slug, lang)
        endpoint(app, "/api/cases/{slug}/chain")(slug, lang, "log")
        endpoint(app, "/api/cases/{slug}/coverage")(slug, lang, "log")
        endpoint(app, "/api/cases/{slug}/database")(slug, lang)
        endpoint(app, "/api/cases/{slug}/database/accounts.csv")(slug, "", lang)
        endpoint(app, "/api/cases/{slug}/iocs/export")(slug, "json", lang, "log")
        return case_dir

    def test_the_two_languages_store_exactly_the_same_rows(self):
        """The plainest reading of the promise: run the case in German and in
        English and diff the databases."""
        german = stored_rows(self.cases["de"])
        english = stored_rows(self.cases["en"])
        self.assertEqual(sorted(german), sorted(english),
                         "the two runs do not even hold the same tables")
        for table in german:
            with self.subTest(table=table):
                self.assertEqual(
                    english[table], german[table],
                    f"the German run stored something different in {table} "
                    f"-- the language reached the case file")

    def test_the_case_is_full_enough_for_that_comparison_to_mean_something(self):
        """Two empty databases are also identical."""
        rows = stored_rows(self.cases["de"])
        for table in ("findings", "iocs", "ioc_links", "db_accounts",
                      "hunt_runs", "evidence"):
            self.assertTrue(rows[table],
                            f"{table} is empty, so comparing it proves nothing")

    def test_no_stored_string_is_written_in_german(self):
        """The catalogue against the database.

        Even with the two runs identical, both could be German -- the engines
        would then simply be wrong in the same way twice. So the German half
        of the catalogue is held against every text value the case holds."""
        fragments = german_fragments()
        self.assertGreater(len(fragments), 40,
                           "the catalogue yielded almost nothing to look for")
        for where, value in stored_strings(self.cases["de"]):
            for fragment in fragments:
                self.assertNotIn(
                    fragment, value,
                    f"{where} holds the German phrasing {fragment!r} -- it "
                    f"travels into the archive and into every export")

    def test_no_stored_string_carries_a_german_letter(self):
        """The cheap catch the fragment list cannot make.

        A reworded German string is not in the catalogue in that exact form
        any more, but it still spells its umlauts. Nothing in this evidence
        contains one, so any occurrence came from the tool."""
        for where, value in stored_strings(self.cases["de"]):
            found = [c for c in _GERMAN_LETTERS if c in value]
            self.assertEqual(
                [], found,
                f"{where} contains {found} -- German prose was stored: {value!r}")


class ChronologyAccountsForEverythingTests(unittest.TestCase):
    """PROMISE 3: every confirmed artifact appears in the chronology.

    `server/chain.py` states it in capitals: a decision of the analyst that
    quietly disappears from the chronology is the more dangerous half of a
    lie, because the result looks complete. The chain has two places for an
    artifact -- a dated event, or the `undated` list with the reason -- and
    the promise is that there is no third outcome.
    """

    def _confirmed(self, case_dir):
        conn = db.connect(case_dir)
        try:
            return {r["artifact"] for r in db.rows(
                conn, "SELECT DISTINCT artifact FROM findings "
                      "WHERE triage = 'confirmed'")}
        finally:
            conn.close()

    def _accounted(self, chain):
        return ({e["artifact"] for e in chain["events"]}
                | {u["artifact"] for u in chain["undated"]})

    def test_every_shape_accounts_for_every_confirmed_artifact(self):
        for shape in hostile_shapes():
            evidence = shape.build().analyse()
            self.addCleanup(evidence.cleanup)
            confirmed = self._confirmed(evidence.case_dir)
            self.assertTrue(confirmed,
                            f"{shape.name} confirmed nothing, so the "
                            f"chronology has nothing to account for")
            for lang in i18n.LANGUAGES:
                for tz_mode in ("log", "utc"):
                    with self.subTest(shape=shape.name, lang=lang, tz=tz_mode):
                        chain = case_chain(evidence.case_dir, lang, tz_mode)
                        missing = confirmed - self._accounted(chain)
                        self.assertEqual(
                            set(), missing,
                            "these confirmed artifacts appear neither as an "
                            "event nor under undated")

    def test_an_undated_artifact_says_why_it_has_no_time(self):
        """Being listed is not enough. "Somewhere in the chronology, without
        a reason" is the same silence in a longer form: the reader has to be
        able to tell a file the log never mentions from one whose timestamps
        could not be read."""
        evidence = HostileEvidence().build().analyse()
        self.addCleanup(evidence.cleanup)
        chain = case_chain(evidence.case_dir)
        self.assertTrue(chain["undated"], "nothing landed in undated")
        for row in chain["undated"]:
            self.assertTrue(row["why"].strip(),
                            f"{row['artifact']} sits in undated without a reason")
            self.assertTrue(row["artifact_kind"],
                            f"{row['artifact']} sits in undated without a kind")

    def test_truncation_does_not_swallow_a_confirmed_artifact(self):
        """A case with more events than the cap.

        A hundred accounts registered during the log period is what a mass
        registration through a compromised form looks like, and it is enough
        to push every account event ahead of the confirmed shell. The
        chronology then reports the truncation in `gaps` -- and the shell
        itself is in neither list, which is the one outcome the module rules
        out."""
        evidence = HostileEvidence(offset="+0000").build().analyse()
        self.addCleanup(evidence.cleanup)
        first = logindex.overview(evidence.case_dir)["first_epoch"]
        conn = db.connect(evidence.case_dir)
        try:
            conn.execute("INSERT INTO db_dumps (id, path) VALUES (99, 'mass.sql')")
            for i in range(100):
                registered = datetime.fromtimestamp(
                    first + 60 + i, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                conn.execute(
                    "INSERT INTO db_accounts (dump_id, cms, tbl, login, email,"
                    " registered, admin) VALUES (99,'wp','wp_users',?,?,?,1)",
                    (f"bot{i}", f"bot{i}@example.test", registered))
            conn.commit()
        finally:
            conn.close()
        confirmed = self._confirmed(evidence.case_dir)
        chain = case_chain(evidence.case_dir)
        self.assertTrue(chain["truncated"], "the cap was not reached")
        self.assertEqual(
            set(), confirmed - self._accounted(chain),
            "the chronology was cut short and took confirmed artifacts with "
            "it -- they are in neither list")


class ForeignVerdictsMoveNothingTests(unittest.TestCase):
    """PROMISE 4: a reputation score never changes a severity.

    `server/enrich.py` says it outright: what comes back is an opinion, not a
    measurement, and a file is not a webshell because VirusTotal says so, nor
    clean because VirusTotal is silent. The severity of a finding is this
    toolkit's own statement about evidence it read, and a third party must
    not be able to raise or lower it from outside.

    No lookup here reaches the network -- `_LOOKUPS` is replaced the way the
    module allows, and the verdicts injected are the extreme ones, because a
    middling score would not move anything even in code that let it.
    """

    def setUp(self):
        self.evidence = HostileEvidence(two_dumps=True).build().analyse()
        self.addCleanup(self.evidence.cleanup)
        self.workspace = self.evidence.root
        settings.set_key(self.workspace, "virustotal", "vt-key")
        settings.set_key(self.workspace, "abuseipdb", "abuse-key")
        settings.set_ack(self.workspace, True)
        self._real = dict(enrich._LOOKUPS)
        self._intervals = dict(enrich.MIN_INTERVAL)
        for name in enrich.MIN_INTERVAL:
            enrich.MIN_INTERVAL[name] = 0.0
        self.addCleanup(self._restore)

    def _restore(self):
        enrich._LOOKUPS.clear()
        enrich._LOOKUPS.update(self._real)
        enrich.MIN_INTERVAL.clear()
        enrich.MIN_INTERVAL.update(self._intervals)

    def _answer(self, verdict):
        for name in enrich._LOOKUPS:
            enrich._LOOKUPS[name] = lambda key, value, v=verdict: dict(v)

    def _findings(self):
        conn = db.connect(self.evidence.case_dir)
        try:
            return [dict(r) for r in db.rows(
                conn, "SELECT fingerprint, severity, rule, rule_id, triage, "
                      "triage_note, artifact FROM findings ORDER BY fingerprint")]
        finally:
            conn.close()

    def _counts(self):
        conn = db.connect(self.evidence.case_dir)
        try:
            return artifact_counts(conn)
        finally:
            conn.close()

    def _indicators(self):
        """A hash and an address the case actually holds, so the lookup is
        about something this case decided rather than about a stranger."""
        conn = db.connect(self.evidence.case_dir)
        try:
            meta = db.one(conn, "SELECT value FROM meta "
                                "WHERE key = 'webshell_hashes'")
            hashes = json.loads(meta["value"]) if meta else {}
        finally:
            conn.close()
        digest = next((h for h in hashes.values() if len(str(h)) == 64), None)
        self.assertIsNotNone(digest, "the case holds no SHA-256 to ask about")
        return digest, ATTACKER

    def _lookup_both(self, verdict):
        self._answer(verdict)
        digest, ip = self._indicators()
        enrich.lookup(self.workspace, self.evidence.case_dir, "virustotal", digest)
        enrich.lookup(self.workspace, self.evidence.case_dir, "abuseipdb", ip)

    def test_a_damning_verdict_raises_no_severity(self):
        before, counts = self._findings(), self._counts()
        self._lookup_both({"known": True, "score": 70, "of": 70,
                           "label": "trojan.webshell/php",
                           "reports": 900, "distinct_reporters": 300,
                           "tor": True})
        self.assertEqual(before, self._findings(),
                         "storing a reputation verdict rewrote the findings")
        self.assertEqual(counts, self._counts(),
                         "the artifact counts moved after a lookup")

    def test_a_clean_verdict_lowers_no_severity(self):
        """The other direction, which is the dangerous one: a file this tool
        measured as a webshell must not be talked down by an outside service
        that has never seen it."""
        before, counts = self._findings(), self._counts()
        self._lookup_both({"known": False})
        self.assertEqual(before, self._findings(),
                         "an unknown verdict rewrote the findings")
        self.assertEqual(counts, self._counts(),
                         "the artifact counts moved after a lookup")

    def test_the_verdict_is_stored_where_it_belongs(self):
        """The counter-assertion: the two tests above would also pass if the
        lookup had silently done nothing at all. It has to land in
        `enrichment` and nowhere else."""
        self._lookup_both({"known": True, "score": 70, "of": 70})
        conn = db.connect(self.evidence.case_dir)
        try:
            stored = db.rows(conn, "SELECT service, value, kind FROM enrichment")
        finally:
            conn.close()
        self.assertEqual({"virustotal", "abuseipdb"},
                         {r["service"] for r in stored},
                         "the injected verdicts were never stored")

    def test_the_chronology_reports_the_same_severities_afterwards(self):
        """Severity travels: the chain hangs it on every event, and that is
        what a report quotes. Checking the table alone would miss a verdict
        that reached the rendering instead of the row."""
        before = [(e["title"], e["severity"])
                  for e in case_chain(self.evidence.case_dir)["events"]]
        self.assertTrue(before, "the chronology is empty, nothing was checked")
        self._lookup_both({"known": True, "score": 70, "of": 70})
        after = [(e["title"], e["severity"])
                 for e in case_chain(self.evidence.case_dir)["events"]]
        self.assertEqual(before, after,
                         "a foreign verdict changed the severities in the "
                         "chronology")


class MutedRuleHidesTests(unittest.TestCase):
    """PROMISE 5: switching a rule off hides, it never deletes.

    `server/ruleswitch.py` spells out what a switch means: the rule stops
    running, and findings it wrote before stay where they are with their
    triage, because a switch is not a retraction. The work list drops the
    artifacts that are left without a live finding -- and says how many, since
    a list that quietly shrinks is a list nobody can trust.
    """

    def setUp(self):
        self.evidence = HostileEvidence().build().analyse(confirm=False)
        self.addCleanup(self.evidence.cleanup)
        self.slug = open_case(self.evidence)
        self.app = create_app(Config(workspace=self.evidence.root, token="t"))
        self.findings_list = endpoint(self.app, "/api/cases/{slug}/findings")

    def _rows(self):
        conn = db.connect(self.evidence.case_dir)
        try:
            return [dict(r) for r in db.rows(
                conn, "SELECT * FROM findings ORDER BY fingerprint")]
        finally:
            conn.close()

    def _rule_ids(self):
        conn = db.connect(self.evidence.case_dir)
        try:
            return sorted({r["rule_id"] for r in db.rows(
                conn, "SELECT DISTINCT rule_id FROM findings") if r["rule_id"]})
        finally:
            conn.close()

    def test_switching_every_rule_off_deletes_no_row(self):
        before = self._rows()
        self.assertTrue(before, "no findings, nothing to delete")
        for rule_id in self._rule_ids():
            ruleswitch.set_enabled(self.evidence.root, rule_id, False)
        self.assertEqual(before, self._rows(),
                         "muting the rules changed the findings table -- a "
                         "switch is not a retraction")

    def test_the_response_states_how_many_artifacts_went(self):
        """The count, not just the disappearance. Whoever mutes a rule has to
        be able to see the price of it in the same response."""
        full = self.findings_list(self.slug)
        self.assertTrue(full["total"], "the work list was empty to begin with")
        self.assertEqual(0, full["muted_hidden"],
                         "nothing is muted yet, so nothing can be hidden")
        for rule_id in self._rule_ids():
            ruleswitch.set_enabled(self.evidence.root, rule_id, False)
        muted = self.findings_list(self.slug)
        self.assertEqual(0, muted["total"],
                         "every rule is off, so no undecided artifact is left")
        self.assertEqual(full["total"], muted["muted_hidden"],
                         "the response does not account for the artifacts the "
                         "switches took out")
        self.assertEqual(len(self._rule_ids()), muted["muted_rules"])
        self.assertEqual(full["findings_total"], muted["findings_total"],
                         "the findings themselves were counted away as well")

    def test_a_decided_artifact_survives_its_rule_being_muted(self):
        """The distinction the whole promise rests on. A confirmed artifact
        stays in the list even when every rule that pointed at it is off: the
        decision belongs to the analyst, and muting a rule does not take it
        back."""
        conn = db.connect(self.evidence.case_dir)
        try:
            artifact = db.one(conn, "SELECT artifact FROM findings "
                                    "WHERE rule_id = 'webshell.php_in_image'")
            self.assertIsNotNone(artifact, "the fixture stopped producing it")
            artifact = artifact["artifact"]
        finally:
            conn.close()
        triage = endpoint(self.app, "/api/cases/{slug}/triage", "POST")
        triage(self.slug, body_model(triage)(artifacts=[artifact],
                                             state="confirmed"))
        ruleswitch.set_enabled(self.evidence.root, "webshell.php_in_image", False)
        shown = [a["artifact"] for a in self.findings_list(self.slug)["artifacts"]]
        self.assertIn(artifact, shown,
                      "a confirmed artifact vanished because its rule was "
                      "later switched off")

    def test_switching_a_rule_back_on_returns_the_artifacts(self):
        """Hiding is reversible; deleting is not. If the artifacts come back
        unchanged, nothing was thrown away."""
        before = [a["artifact"] for a in self.findings_list(self.slug)["artifacts"]]
        for rule_id in self._rule_ids():
            ruleswitch.set_enabled(self.evidence.root, rule_id, False)
        for rule_id in self._rule_ids():
            ruleswitch.set_enabled(self.evidence.root, rule_id, True)
        after = [a["artifact"] for a in self.findings_list(self.slug)["artifacts"]]
        self.assertEqual(before, after,
                         "the work list did not come back the way it went")

    def test_an_unknown_rule_id_is_not_accepted_by_the_route(self):
        """The off-list names rules by id, and an id that matches nothing
        would be a switch that silently does nothing -- `ruleswitch` treats an
        unknown id as ENABLED for exactly that reason, so the route has to
        refuse it rather than store it."""
        toggle = endpoint(self.app, "/api/rules/{rule_id}/enabled", "POST")
        with self.assertRaises(HTTPException) as caught:
            toggle("webshell.no_such_rule", body_model(toggle)(enabled=False),
                   "en")
        self.assertEqual(404, caught.exception.status_code)
        self.assertNotIn("webshell.no_such_rule",
                         ruleswitch.disabled_ids(self.evidence.root))
        self.assertIn("webshell.php_in_image", rulelib.known_ids())


if __name__ == "__main__":
    unittest.main()
