# tests/test_http.py
"""The HTTP layer: what the routes actually answer, over a real socket.

WHY THIS FILE EXISTS. The worst defect of the last bug hunt lived in a route,
and nothing underneath it could see it. The WHERE fragment that hides the
artifacts of a muted rule was AND-ed onto the chip filters WITHOUT brackets,
so the query read `(chips AND active > 0) OR triage != 'new'` and every
DECIDED artifact walked past every chip: asking to hide the confirmed ones
returned them. The aggregate in server/artifacts.py was right, the engines
were right, and the answer on the wire was wrong. Only a test that asks the
SERVER and reads the ANSWER catches that class of defect, so that is what
everything below does -- no endpoint function is called directly, every
assertion is made about a response.

HOW THE SERVER IS REACHED. `fastapi.testclient.TestClient` needs httpx, which
is not a dependency of this project and is not installed on the machines that
run this suite; importing it fails with ModuleNotFoundError. The application
is therefore started for real: uvicorn (a declared dependency) in a daemon
thread on a socket bound to port 0, driven with `urllib.request` from the
standard library. That is one moving part more than TestClient, and it buys
the guarantee that these answers went through routing, dependency injection,
query-string parsing and JSON serialisation exactly as the browser's do.

THE EVIDENCE IS HOSTILE. The case is built from tests/fixtures_hostile.py with
every dial turned at once: a +0200 log that changes to +0100 halfway, two
vhosts each keeping an access.log, two dumps, mixed-case paths, the evidence
sitting under a folder called "uploads", a truncated head and 250 clients.
Half of the fifty-five bugs the previous suite missed were invisible on the
clean shape, and an endpoint that only ever answered about one lower-case
webroot at offset zero has not been asked anything.

The analysis runs ONCE for the whole module, and the tests that decide
something work on a copy of it -- a suite that re-analyses per test is a suite
nobody runs, and a test that mutates the fixture everybody else reads is a
test that only passes in a particular order.
"""
import hashlib
import io
import json
import shutil
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter
from pathlib import Path

import uvicorn

from server import db, ruleswitch, workspace
from server.app import create_app
from server.config import Config
from server.engines import yarascan
from tests.fixtures_hostile import ATTACKER, VISITOR, HostileEvidence

# The token the tests present. Fixed rather than generated, because a test
# that reads the token out of the Config it just built cannot notice the day
# the server starts comparing against something else.
TOKEN = "shellhound-test-token"

# Artifacts added on top of what the engines find. See _widen_the_matrix.
LOW_CLIENT = "198.51.100.7"
INFO_TABLE = "wp_options"
LOOKALIKE_TABLE = "wpXoptions"
EVIDENCE_TABLE = "wp_links"
EVIDENCE_IP = "198.51.100.5"
YARA_RULE = "http_probe"

# Filled in by setUpModule.
WORKSPACE = None
CASE_DIR = None
CASE = ""
SNAPSHOT = None
EVIDENCE = None
APP = None
SERVER = None
BASE = ""


# --- the server ------------------------------------------------------------

class _LiveServer:
    """uvicorn on a socket this process bound itself.

    The socket is bound to port 0 and handed to uvicorn, rather than picking a
    free port and hoping it is still free a moment later: on a machine running
    several test processes that race is real and shows up as a flaky suite.
    """

    def __init__(self, app):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]
        # Errors stay on: a 500 inside an endpoint is otherwise a bare
        # "Internal Server Error" string in an assertion message, and the
        # traceback is the whole diagnosis. The price is that the tests which
        # expect a 500 print theirs into the run as well.
        self.server = uvicorn.Server(
            uvicorn.Config(app, log_level="error", access_log=False))
        self.thread = threading.Thread(
            target=self.server.run, kwargs={"sockets": [self.socket]},
            daemon=True)

    def start(self):
        self.thread.start()
        deadline = time.monotonic() + 30
        while (not self.server.started and self.thread.is_alive()
               and time.monotonic() < deadline):
            time.sleep(0.02)
        if not self.server.started:
            raise RuntimeError("the test server did not come up")
        return f"http://127.0.0.1:{self.port}"

    def stop(self):
        self.server.should_exit = True
        self.thread.join(timeout=15)


def request(method, path, body=None, token=TOKEN):
    """One request. Returns (status, headers, bytes) for every outcome --
    a 4xx is an ANSWER here and not an exception, because most of what this
    file asserts is which refusal came back."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["X-Token"] = token
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as e:
        # Closed by hand: an HTTPError still holds an open socket, and a suite
        # that leaves one per refusal drowns its own output in ResourceWarning.
        with e:
            return e.code, e.headers, e.read()


def get(path, token=TOKEN):
    return request("GET", path, token=token)


def get_json(path, token=TOKEN):
    status, _headers, body = get(path, token=token)
    try:
        return status, json.loads(body)
    except ValueError:
        return status, body


def post_json(path, body, token=TOKEN):
    status, _headers, raw = request("POST", path, body, token=token)
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, raw


def q(value):
    """A query-string value, encoded. Artifacts are Windows paths full of
    backslashes and colons, and a test that forgets this asserts about a
    request the server never saw."""
    return urllib.parse.quote(str(value), safe="")


# --- the fixture -----------------------------------------------------------

def _widen_the_matrix(case_dir):
    """Give the case every severity, every decision and a name LIKE can trip
    over.

    The hostile shape produces severities 0 and 1 only and leaves everything
    undecided, and a filter exercised on two of four severity classes and one
    of four decisions is a filter half tested -- the bug this file exists for
    was precisely one that only appeared on DECIDED artifacts. The additions
    go in through `db.upsert_finding`, the same writer every engine uses, so
    they are ordinary findings and not a special case the route could tell
    apart.
    """
    conn = db.connect(case_dir)
    try:
        db.upsert_finding(conn, "logs", db.SEV_LOW,
                          "Scanner user agent", "client", LOW_CLIENT,
                          evidence="8 requests carrying a scanner agent")
        db.upsert_finding(conn, "sqldb", db.SEV_INFO,
                          "Value carries a file system path", "table",
                          INFO_TABLE,
                          evidence="upload_path = 'C:\\newsite\\uploads'")
        # A neighbour that differs from INFO_TABLE in exactly the position of
        # its underscore. SQL's LIKE reads `_` as "any character", so this
        # pair is the only way to see whether the search escapes it.
        db.upsert_finding(conn, "sqldb", db.SEV_LOW,
                          "Value carries a file system path", "table",
                          LOOKALIKE_TABLE,
                          evidence="option_value = 'nothing special'")
        # A finding whose EVIDENCE names an address. That is the ordinary case
        # for the artifact view's `related_ips` -- an injected script tag
        # pointing at a host is how the pivot from a database value back into
        # the logs starts -- and it is a shape the clean fixture never has.
        db.upsert_finding(conn, "sqldb", db.SEV_MEDIUM,
                          "Injected <script> in database value", "table",
                          EVIDENCE_TABLE,
                          evidence=f"option_value = '<script "
                                   f"src=\"http://{EVIDENCE_IP}/x.js\">'")
        # One artifact per decision, so that every chip has something to hide
        # and the muted-rule clause has a decided artifact to let past.
        for artifact, state in (("wp_posts", "confirmed"),
                                (LOW_CLIENT, "dismissed"),
                                (INFO_TABLE, "reviewed"),
                                ("203.0.113.9", "reviewed")):
            conn.execute("UPDATE findings SET triage = ?, triaged_at = ? "
                         "WHERE artifact = ?", (state, db.now(), artifact))
        conn.commit()
    finally:
        conn.close()


def _checkpoint(case_dir):
    """Fold the write-ahead log back into every database of the case.

    A copy is only a copy once the -wal is folded in; copying a case while
    SQLite still holds its most recent pages in the sidecar produces a case
    that is missing exactly the findings the test is about.
    """
    for path in sorted(Path(case_dir).glob("*.db")):
        conn = sqlite3.connect(str(path))
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            conn.close()


def case_copy(name):
    """A private copy of the analysed case, inside the workspace.

    Tests that DECIDE something get one of these, so they cannot be seen by
    the tests that only read -- and so nothing depends on the order unittest
    happens to run them in.
    """
    target = WORKSPACE / name
    shutil.copytree(SNAPSHOT, target, ignore=shutil.ignore_patterns("*-shm"))
    return target.name


def setUpModule():
    global WORKSPACE, CASE_DIR, CASE, SNAPSHOT, EVIDENCE, APP, SERVER, BASE
    WORKSPACE = Path(tempfile.mkdtemp(prefix="shellhound-http-ws-"))
    CASE_DIR = workspace.create_case(WORKSPACE, "Hostile HTTP case")
    CASE = CASE_DIR.name
    EVIDENCE = HostileEvidence(offset="+0200", second_offset="+0100",
                               duplicate_log_name=True, two_dumps=True,
                               mixed_case=True, upload_parent=True,
                               truncated_head=True, many_clients=250)
    # The fixture builds its own case directory in a temporary folder, but the
    # HTTP layer can only reach a case that lies IN the workspace: everything
    # else is refused by workspace.resolve_case. Pointing the fixture at the
    # workspace case keeps that guard in the picture instead of working round
    # it; the evidence itself stays where the fixture put it, which is what
    # makes the "evidence under a folder called uploads" axis mean anything.
    EVIDENCE.case_dir = CASE_DIR
    EVIDENCE.build().analyse(confirm=False)
    _widen_the_matrix(CASE_DIR)
    _checkpoint(CASE_DIR)
    SNAPSHOT = Path(tempfile.mkdtemp(prefix="shellhound-http-snap-")) / "case"
    shutil.copytree(CASE_DIR, SNAPSHOT, ignore=shutil.ignore_patterns("*-shm"))

    # One rule of the analyst's own, so that /api/yara/rules/{name} has a name
    # to answer about rather than being skipped as untestable.
    yarascan.write_rule(WORKSPACE, YARA_RULE,
                        'rule %s { strings: $a = "shellhound-http-probe" '
                        'condition: $a }' % YARA_RULE)

    APP = create_app(Config(workspace=WORKSPACE, token=TOKEN))
    SERVER = _LiveServer(APP)
    BASE = SERVER.start()

    # Two indicators, put in through the API. The exports are only worth
    # asserting about once the box has something in it, and going in through
    # the route means the export tests are reading back what the server
    # itself stored.
    for value in (ATTACKER, "malware.example.test"):
        post_json(f"/api/cases/{CASE}/iocs", {"value": value, "note": "seeded"})


def tearDownModule():
    if SERVER is not None:
        SERVER.stop()
    if EVIDENCE is not None:
        EVIDENCE.cleanup()
    for path in (WORKSPACE, SNAPSHOT.parent if SNAPSHOT else None):
        if path:
            shutil.rmtree(path, ignore_errors=True)


# --- the endpoint surface --------------------------------------------------

# Every GET route of the application, with the query string it needs to be
# answerable at all. The test below compares this table against what
# `create_app` actually registered, so a route added tomorrow fails here until
# somebody says how it is reached -- which is the difference between
# enumerating the endpoints and guessing at them.
#
# A value of None means "not an API answer": the two below serve the built
# interface and are asserted separately.
GET_ROUTES = {
    "/api/state": "",
    "/api/archives": "",
    "/api/settings": "",
    "/api/rules": "",
    "/api/yara": "",
    "/api/yara/rules": "",
    "/api/yara/rules/{name}": "",
    "/api/pickpath": "",
    "/api/patterns": "",
    "/api/patterns/export": "",
    "/api/cases/{slug}": "",
    "/api/cases/{slug}/summary": "",
    "/api/cases/{slug}/coverage": "",
    "/api/cases/{slug}/enrichment": "",
    "/api/cases/{slug}/jobs": "",
    "/api/cases/{slug}/dashboard": "",
    "/api/cases/{slug}/chain": "",
    "/api/cases/{slug}/report.html": "",
    "/api/cases/{slug}/search": "q=203.0.113",
    "/api/cases/{slug}/findings": "",
    "/api/cases/{slug}/artifact": "artifact={artifact}",
    "/api/cases/{slug}/file": "path={file}",
    "/api/cases/{slug}/hunt/runs": "",
    "/api/cases/{slug}/browse": "",
    "/api/cases/{slug}/diff": "",
    "/api/cases/{slug}/actors": "",
    "/api/cases/{slug}/trace.csv": f"ips={ATTACKER}",
    "/api/cases/{slug}/iocs": "",
    "/api/cases/{slug}/iocs/cross-case": "",
    "/api/cases/{slug}/iocs/export": "",
    "/api/cases/{slug}/cms": "",
    "/api/cases/{slug}/database": "",
    "/api/cases/{slug}/database/accounts.csv": "",
    "/": None,
    "/favicon.svg": None,
}


def _url(route, slug, artifact=None, file_path=None):
    path = route.replace("{slug}", slug).replace("{name}", YARA_RULE)
    query = (GET_ROUTES[route] or "")
    query = query.replace("{artifact}", q(artifact or "x"))
    query = query.replace("{file}", q(file_path or "x"))
    return path + ("?" + query if query else "")


class EndpointSurfaceTests(unittest.TestCase):
    """Every GET route answers, and every case-scoped one refuses an unknown
    case.

    A route that raises on a case shaped unlike the demo is a 500 the analyst
    meets in the middle of an incident, and half the endpoints here had never
    been asked about two access logs sharing a basename, mixed-case paths or a
    log that changes its UTC offset halfway through.
    """

    def test_the_table_of_routes_is_the_application_s_own(self):
        """A guard on the enumeration itself: an endpoint added to
        `create_app` without a line in GET_ROUTES would otherwise be born
        untested, and nobody would ever notice."""
        registered = {route.path for route in APP.routes
                      if "GET" in (getattr(route, "methods", None) or set())}
        self.assertEqual(registered, set(GET_ROUTES),
                         "GET_ROUTES and the application disagree about which "
                         "endpoints exist")

    def test_every_get_endpoint_answers_on_an_analysed_case(self):
        shell = str(EVIDENCE.webroot / EVIDENCE.shell_rel)
        for route, query in sorted(GET_ROUTES.items()):
            if query is None:
                continue
            with self.subTest(route=route):
                status, _headers, body = get(
                    _url(route, CASE, artifact=shell, file_path=shell))
                self.assertEqual(200, status, f"{route}: {body[:400]!r}")

    def test_every_case_endpoint_refuses_an_unknown_case(self):
        """404, not an empty answer: a case that does not exist and a case
        with nothing in it must not look the same, or a typed slug reads as
        an investigation that found nothing."""
        for route, query in sorted(GET_ROUTES.items()):
            if query is None or "{slug}" not in route:
                continue
            with self.subTest(route=route):
                status, _headers, body = get(
                    _url(route, "no-such-case-at-all", artifact="x",
                         file_path="x"))
                self.assertEqual(404, status, f"{route}: {body[:200]!r}")

    def test_an_unknown_yara_rule_is_refused(self):
        """The rule files are the analyst's own, so a name that is not there
        is an ordinary mistake and has to be answered as one."""
        status, _headers, _body = get("/api/yara/rules/not-a-rule-here")
        self.assertEqual(404, status)

    def test_the_start_page_is_served(self):
        status, _headers, body = get("/")
        self.assertEqual(200, status)
        self.assertIn(b"SHELLHOUND", body)

    def test_the_favicon_is_served_when_the_interface_was_built(self):
        """404 is a legitimate answer here and 500 is not: the server runs
        without a built frontend on purpose, so that a forensic machine
        without a Node toolchain still has the complete API."""
        status, _headers, _body = get("/favicon.svg")
        self.assertIn(status, (200, 404))

    def test_the_api_refuses_a_request_without_the_token(self):
        for route, query in sorted(GET_ROUTES.items()):
            if query is None:
                continue
            with self.subTest(route=route):
                status, _headers, _body = get(
                    _url(route, CASE, artifact="x", file_path="x"), token=None)
                self.assertEqual(401, status)

    def test_the_api_refuses_a_wrong_token(self):
        status, _headers, _body = get("/api/state", token="not-the-token")
        self.assertEqual(401, status)

    def test_the_token_may_travel_in_the_query_string(self):
        """Every export is a plain link the browser follows, and a link cannot
        set a header. If this stops working, all downloads stop working."""
        status, _headers, _body = get(f"/api/state?token={q(TOKEN)}",
                                      token=None)
        self.assertEqual(200, status)


# --- the artifact filters --------------------------------------------------

class ArtifactFilterTests(unittest.TestCase):
    """The work list, as the browser sees it.

    FILTERS HIDE, THEY DO NOT SELECT, and what they hide they must hide for
    every artifact -- decided or not. The defect this class is built around
    let every decided artifact past every chip, and it was invisible to
    everything below the route.
    """

    def findings(self, query=""):
        status, body = get_json(f"/api/cases/{CASE}/findings"
                                + (f"?{query}" if query else ""))
        self.assertEqual(200, status, body)
        return body

    def assert_sound(self, body):
        """Invariants that hold whatever the filter was.

        An artifact that IS shown arrives COMPLETE -- every finding it has,
        because filtering must never hide part of what a decision rests on --
        and the counts describe the WHOLE case rather than the page, which is
        what makes the chips say how much they are hiding.
        """
        shown = [a["artifact"] for a in body["artifacts"]]
        self.assertEqual(len(shown), len(set(shown)),
                         "an artifact was listed twice")
        attached = Counter(f["artifact"] for f in body["findings"])
        for artifact in body["artifacts"]:
            self.assertEqual(
                artifact["findings"], attached[artifact["artifact"]],
                f"{artifact['artifact']} arrived without all its findings")
        self.assertEqual(set(shown), set(attached) if shown else set(),
                         "findings came back for artifacts that were hidden")
        counts = body["counts"]
        for dimension in ("severity", "triage", "source"):
            self.assertEqual(sum(counts[dimension].values()), counts["total"],
                             f"the {dimension} counts do not add up")

    def test_the_unfiltered_list_returns_everything_it_counts(self):
        body = self.findings()
        self.assert_sound(body)
        self.assertEqual(body["total"], len(body["artifacts"]))
        self.assertEqual(body["counts"]["total"],
                         body["total"] + body["muted_hidden"])
        self.assertEqual(body["findings_total"], len(body["findings"]))

    def test_hiding_a_severity_hides_exactly_that_class(self):
        whole = self.findings()
        for severity in ("0", "1", "2", "3"):
            with self.subTest(severity=severity):
                body = self.findings(f"hide_severity={severity}")
                self.assert_sound(body)
                for artifact in body["artifacts"]:
                    self.assertNotEqual(int(severity), artifact["worst"],
                                        artifact["artifact"])
                self.assertEqual(
                    whole["total"] - whole["counts"]["severity"].get(severity, 0),
                    body["total"])

    def test_hiding_several_severities_stacks(self):
        body = self.findings("hide_severity=0,1,2,3")
        self.assert_sound(body)
        self.assertEqual(0, body["total"])
        self.assertEqual([], body["artifacts"])
        self.assertEqual([], body["findings"])

    def test_hiding_a_triage_state_hides_exactly_that_state(self):
        whole = self.findings()
        for state in db.TRIAGE_STATES:
            with self.subTest(state=state):
                body = self.findings(f"hide_triage={state}")
                self.assert_sound(body)
                for artifact in body["artifacts"]:
                    self.assertNotEqual(state, artifact["triage"],
                                        artifact["artifact"])
                self.assertEqual(
                    whole["total"] - whole["counts"]["triage"].get(state, 0),
                    body["total"])

    def test_hiding_a_source_hides_exactly_that_source(self):
        whole = self.findings()
        for source in ("webshell", "sqldb", "logs"):
            with self.subTest(source=source):
                body = self.findings(f"hide_source={source}")
                self.assert_sound(body)
                for artifact in body["artifacts"]:
                    self.assertNotEqual(source, artifact["source"],
                                        artifact["artifact"])
                self.assertEqual(
                    whole["total"] - whole["counts"]["source"].get(source, 0),
                    body["total"])

    def test_a_decided_artifact_obeys_the_severity_chip(self):
        """THE regression. A confirmed artifact is still an artifact of its
        severity, and hiding that severity has to take it with everything
        else -- otherwise the analyst who hides what they have dealt with is
        looking at the one list that still shows it."""
        whole = self.findings()
        decided = [a for a in whole["artifacts"] if a["triage"] != "new"]
        self.assertTrue(decided, "the fixture has no decided artifact")
        for artifact in decided:
            with self.subTest(artifact=artifact["artifact"]):
                body = self.findings(f"hide_severity={artifact['worst']}")
                self.assertNotIn(artifact["artifact"],
                                 [a["artifact"] for a in body["artifacts"]])

    def test_a_decided_artifact_obeys_the_source_chip(self):
        whole = self.findings()
        for artifact in [a for a in whole["artifacts"] if a["triage"] != "new"]:
            with self.subTest(artifact=artifact["artifact"]):
                body = self.findings(f"hide_source={artifact['source']}")
                self.assertNotIn(artifact["artifact"],
                                 [a["artifact"] for a in body["artifacts"]])

    def test_a_decided_artifact_obeys_the_kind_filter(self):
        whole = self.findings()
        for artifact in [a for a in whole["artifacts"] if a["triage"] != "new"]:
            other = ("client" if artifact["artifact_kind"] != "client"
                     else "file")
            with self.subTest(artifact=artifact["artifact"]):
                body = self.findings(f"kind={other}")
                self.assertNotIn(artifact["artifact"],
                                 [a["artifact"] for a in body["artifacts"]])

    def test_a_decided_artifact_obeys_the_search(self):
        """A decision is not a season ticket. The search is a filter like the
        chips, and an artifact somebody has confirmed still has to match the
        term to be in the answer."""
        shell = str(EVIDENCE.webroot / EVIDENCE.shell_rel)
        body = self.findings(f"search={q('kb-media')}")
        self.assert_sound(body)
        self.assertEqual([shell], [a["artifact"] for a in body["artifacts"]])
        decided = [a["artifact"] for a in self.findings()["artifacts"]
                   if a["triage"] != "new"]
        self.assertTrue(decided, "the fixture has no decided artifact")
        for artifact in decided:
            self.assertNotIn(artifact,
                             [a["artifact"] for a in body["artifacts"]])

    def test_the_kind_filter_selects_one_kind(self):
        whole = self.findings()
        for kind in ("file", "client", "table"):
            with self.subTest(kind=kind):
                body = self.findings(f"kind={kind}")
                self.assert_sound(body)
                self.assertTrue(body["artifacts"], f"no {kind} artifact")
                for artifact in body["artifacts"]:
                    self.assertEqual(kind, artifact["artifact_kind"])
                self.assertEqual(
                    sum(1 for a in whole["artifacts"]
                        if a["artifact_kind"] == kind), body["total"])

    def test_an_unknown_kind_returns_nothing_rather_than_everything(self):
        """A filter the server does not understand must not quietly become no
        filter: that is how a list stops being the answer to the question the
        analyst asked."""
        body = self.findings("kind=folder")
        self.assert_sound(body)
        self.assertEqual(0, body["total"])

    def test_a_search_returns_only_artifacts_that_match_it(self):
        for term in ("kb-media", "203.0.113", "iframe", "scanner"):
            with self.subTest(term=term):
                body = self.findings(f"search={q(term)}")
                self.assert_sound(body)
                self.assertTrue(body["artifacts"], f"nothing matched {term}")
                for artifact in body["artifacts"]:
                    rows = [f for f in body["findings"]
                            if f["artifact"] == artifact["artifact"]]
                    self.assertTrue(
                        any(term in (f["rule"] or "").lower()
                            or term in (f["artifact"] or "").lower()
                            or term in (f["evidence"] or "").lower()
                            for f in rows),
                        f"{artifact['artifact']} matches {term} in nothing")

    def test_a_search_returns_the_matching_artifact_complete(self):
        """A hit on one rule is a reason to look at the file, not a reason to
        see only that rule. The shell trips two rules and only one of them
        carries the word searched for."""
        shell = str(EVIDENCE.webroot / EVIDENCE.shell_rel)
        body = self.findings(f"search={q('Unguarded PHP')}")
        self.assert_sound(body)
        rows = [f for f in body["findings"] if f["artifact"] == shell]
        self.assertEqual(2, len(rows),
                         "the search returned the artifact without the "
                         "findings the search did not match")

    def test_a_search_matching_nothing_returns_nothing(self):
        body = self.findings(f"search={q('kein-treffer-hier-xyzzy')}")
        self.assert_sound(body)
        self.assertEqual(0, body["total"])

    def test_a_search_treats_an_underscore_as_a_character(self):
        """An analyst searching for a table called wp_options is searching for
        that table, not for a pattern. Both other list endpoints pass
        ESCAPE '\\' for exactly this reason, so the intent is settled -- and a
        work list that answers with rows the analyst did not ask about is a
        work list that has to be checked by hand."""
        body = self.findings(f"search={q(INFO_TABLE)}")
        self.assertEqual([INFO_TABLE],
                         [a["artifact"] for a in body["artifacts"]])

    def test_filters_combine(self):
        whole = self.findings()
        combinations = (
            ("hide_severity=0&hide_triage=new", {"hide_severity": {0},
                                                 "hide_triage": {"new"}}),
            ("hide_source=webshell&kind=table", {"hide_source": {"webshell"},
                                                 "kind": "table"}),
            (f"hide_triage=new,reviewed&search={q('203.0.113')}",
             {"hide_triage": {"new", "reviewed"}}),
            ("hide_severity=1,2,3&hide_source=logs",
             {"hide_severity": {1, 2, 3}, "hide_source": {"logs"}}),
        )
        for query, expected in combinations:
            with self.subTest(query=query):
                body = self.findings(query)
                self.assert_sound(body)
                for artifact in body["artifacts"]:
                    self.assertNotIn(artifact["worst"],
                                     expected.get("hide_severity", set()))
                    self.assertNotIn(artifact["triage"],
                                     expected.get("hide_triage", set()))
                    self.assertNotIn(artifact["source"],
                                     expected.get("hide_source", set()))
                    if expected.get("kind"):
                        self.assertEqual(expected["kind"],
                                         artifact["artifact_kind"])
                self.assertLessEqual(body["total"], whole["total"])

    def test_the_counts_describe_the_case_and_not_the_page(self):
        """The chips are what the analyst clicks to come back, so their
        numbers have to keep describing what is there -- a count that shrank
        with the list would make a hidden class look like an empty one."""
        whole = self.findings()
        for query in ("hide_severity=0", "kind=client", "limit=2",
                      f"search={q('kb-media')}"):
            with self.subTest(query=query):
                body = self.findings(query)
                self.assertEqual(whole["counts"], body["counts"])
                self.assertEqual(whole["findings_total"],
                                 body["findings_total"])

    def test_a_page_returns_whole_artifacts(self):
        whole = self.findings()
        first = self.findings("limit=2")
        self.assert_sound(first)
        self.assertEqual(2, len(first["artifacts"]))
        self.assertEqual(whole["total"], first["total"])
        second = self.findings("limit=2&offset=2")
        self.assert_sound(second)
        self.assertEqual(
            set(), {a["artifact"] for a in first["artifacts"]}
                   & {a["artifact"] for a in second["artifacts"]},
            "the same artifact appeared on two pages")

    def test_a_muted_rule_hides_undecided_artifacts_and_says_how_many(self):
        """Switching a rule off is what takes an artifact out of the work
        list, and the response has to state the cost: a list that quietly
        shrinks is a list nobody can trust."""
        self.addCleanup(ruleswitch.set_enabled, WORKSPACE, "logs.upload_php",
                        True)
        whole = self.findings()
        ruleswitch.set_enabled(WORKSPACE, "logs.upload_php", False)
        body = self.findings()
        self.assert_sound(body)
        self.assertEqual(1, body["muted_hidden"])
        self.assertEqual(whole["total"] - 1, body["total"])
        self.assertNotIn(ATTACKER, [a["artifact"] for a in body["artifacts"]])
        # The decided one stays: a switch is not a retraction of a decision.
        self.assertIn("203.0.113.9", [a["artifact"] for a in body["artifacts"]])
        self.assertEqual(whole["counts"], body["counts"],
                         "the counts changed although nothing was deleted")

    def test_a_muted_rule_does_not_carry_a_decided_artifact_past_a_chip(self):
        """The exact shape of the defect. The muted-rule clause is AND-ed onto
        the chips, and without its brackets SQL reads
        `(chips AND active > 0) OR triage != 'new'` -- so an artifact that is
        decided AND has no live finding left comes back through every filter
        it was told to obey."""
        self.addCleanup(ruleswitch.set_enabled, WORKSPACE, "logs.upload_php",
                        True)
        ruleswitch.set_enabled(WORKSPACE, "logs.upload_php", False)
        decided = next(a for a in self.findings()["artifacts"]
                       if a["artifact"] == "203.0.113.9")
        self.assertEqual(0, decided["active"],
                         "the fixture no longer has a decided artifact whose "
                         "every rule is muted")
        for query in (f"hide_triage={decided['triage']}",
                      f"hide_severity={decided['worst']}",
                      f"hide_source={decided['source']}",
                      "kind=table"):
            with self.subTest(query=query):
                body = self.findings(query)
                self.assertNotIn("203.0.113.9",
                                 [a["artifact"] for a in body["artifacts"]])


# --- one artifact ----------------------------------------------------------

class ArtifactDetailTests(unittest.TestCase):
    """The view an analyst decides from. Everything about one artifact has to
    arrive in one answer, and it has to arrive at all."""

    def test_an_unknown_artifact_is_refused(self):
        status, body = get_json(
            f"/api/cases/{CASE}/artifact?artifact={q('/nowhere/none.php')}")
        self.assertEqual(404, status, body)

    def test_a_file_artifact_carries_every_finding_and_its_requesters(self):
        """The shell sits at a mixed-case path under a folder called
        `uploads` belonging to the ANALYST, not the site. Both were enough to
        make the pivot from the file into the log index attribute the requests
        to something else."""
        shell = str(EVIDENCE.webroot / EVIDENCE.shell_rel)
        status, body = get_json(
            f"/api/cases/{CASE}/artifact?artifact={q(shell)}")
        self.assertEqual(200, status, body)
        self.assertEqual("file", body["kind"])
        self.assertEqual(2, len(body["findings"]))
        self.assertEqual(0, body["worst"])
        self.assertTrue(body["file"]["exists"])
        self.assertTrue(body["file"]["sha256"])
        self.assertIn(ATTACKER, [h["ip"] for h in body["hunt"]],
                      "the client that loaded the shell is not among its "
                      "requesters")
        self.assertIn(ATTACKER, [r["ip"] for r in body["related_ips"]])

    def test_a_client_artifact_carries_its_own_address(self):
        status, body = get_json(
            f"/api/cases/{CASE}/artifact?artifact={q(ATTACKER)}")
        self.assertEqual(200, status, body)
        self.assertEqual("client", body["kind"])
        self.assertEqual(ATTACKER, body["related_ips"][0]["ip"])
        self.assertTrue(body["actor"])

    def test_an_address_in_the_evidence_becomes_a_related_ip(self):
        """`related_ips` is the pivot back into the logs, and its third source
        is the evidence text itself: an injected script tag names the host it
        loads from, and that host is what the analyst wants to trace. Reaching
        that line takes an address that is not already in the list, which is
        why no case with one lower-case webroot and no injected address ever
        reached it."""
        status, body = get_json(
            f"/api/cases/{CASE}/artifact?artifact={q(EVIDENCE_TABLE)}")
        self.assertEqual(200, status, body)
        self.assertIn(EVIDENCE_IP, [r["ip"] for r in body["related_ips"]])


# --- deciding --------------------------------------------------------------

class TriageEndpointTests(unittest.TestCase):
    """Deciding, through the route. Each test gets its own copy of the
    analysed case, because a decision is a write and tests that share one
    case only pass in the order they were written in."""

    def setUp(self):
        self.slug = case_copy(f"triage-{self._testMethodName[:40]}")

    def artifact(self, name):
        status, body = get_json(
            f"/api/cases/{self.slug}/artifact?artifact={q(name)}")
        self.assertEqual(200, status, body)
        return body

    def decide(self, artifacts, state, note=None, propagate=False,
               fingerprints=None):
        payload = {"artifacts": artifacts, "state": state,
                   "propagate": propagate}
        if note is not None:
            payload["note"] = note
        if fingerprints is not None:
            payload["fingerprints"] = fingerprints
        status, body = post_json(f"/api/cases/{self.slug}/triage", payload)
        self.assertEqual(200, status, body)
        return body

    def test_deciding_something_without_findings_records_nothing_and_says_so(self):
        """A visitor exists in the log index and carries no finding, so there
        is nothing to decide about them. The server answers 200, and the only
        thing that tells the interface nothing was filed is `updated: 0` --
        without it the analyst walks away believing the decision was
        recorded."""
        result = self.decide([VISITOR], "confirmed")
        self.assertEqual(0, result["updated"])
        self.assertEqual(1, result["artifacts"])
        self.assertEqual([], result["collected"])

    def test_deciding_an_artifact_updates_every_one_of_its_findings(self):
        """Eight rules on one dropped shell are eight observations about ONE
        file. Leaving any of them behind is how one artifact ended up in two
        states at once."""
        shell = str(EVIDENCE.webroot / EVIDENCE.shell_rel)
        before = self.artifact(shell)
        self.assertEqual(2, len(before["findings"]))
        result = self.decide([shell], "confirmed", note="the dropped shell")
        self.assertEqual(2, result["updated"])
        self.assertEqual(1, result["artifacts"])
        after = self.artifact(shell)
        self.assertEqual("confirmed", after["triage"])
        self.assertEqual({"confirmed"},
                         {f["triage"] for f in after["findings"]})
        self.assertTrue(all(f["triaged_at"] for f in after["findings"]))

    def test_a_fingerprint_decides_the_whole_artifact(self):
        """An older client sends the fingerprint of the row that was clicked.
        It is read as a pointer to the artifact, because the decision belongs
        to the file and not to whichever of its rules was on screen."""
        shell = str(EVIDENCE.webroot / EVIDENCE.shell_rel)
        one = self.artifact(shell)["findings"][0]["fingerprint"]
        result = self.decide([], "dismissed", fingerprints=[one])
        self.assertEqual(2, result["updated"])
        after = self.artifact(shell)
        self.assertEqual("dismissed", after["triage"])
        self.assertEqual({"dismissed"},
                         {f["triage"] for f in after["findings"]})

    def test_a_state_the_case_cannot_hold_is_refused(self):
        status, body = post_json(f"/api/cases/{self.slug}/triage",
                                 {"artifacts": [ATTACKER], "state": "maybe"})
        self.assertEqual(400, status, body)

    def test_a_note_is_readable_through_the_artifact_endpoint(self):
        """The note is what the report is written from, so it has to come back
        the way it went in -- through a different endpoint than the one that
        stored it."""
        note = "kept: the customer confirmed the upload was not theirs"
        self.decide([ATTACKER], "confirmed", note=note)
        self.assertEqual(note, self.artifact(ATTACKER)["triage_note"])

    def test_a_note_survives_a_decision_that_does_not_carry_one(self):
        """Deciding again is not the same as retracting what was written. The
        interface offers a bare confirm button in five places and a bulk
        decision over a selection, and none of them has a note to send -- so
        the sentence the analyst typed while looking at the file is gone the
        moment somebody confirms the artifact from a list."""
        note = "kept: matches the incident window"
        self.decide([ATTACKER], "reviewed", note=note)
        self.decide([ATTACKER], "confirmed")
        after = self.artifact(ATTACKER)
        self.assertEqual("confirmed", after["triage"])
        self.assertEqual(note, after["triage_note"])

    def test_confirming_a_shell_collects_it_into_the_ioc_box(self):
        """Confirming is the moment provenance is written; the analyst should
        not have to copy the path and the hash into the box by hand."""
        shell = str(EVIDENCE.webroot / EVIDENCE.shell_rel)
        result = self.decide([shell], "confirmed")
        kinds = {item["type"] for item in result["collected"]}
        self.assertIn("path", kinds)
        self.assertIn("hash", kinds)
        status, box = get_json(f"/api/cases/{self.slug}/iocs")
        self.assertEqual(200, status, box)
        self.assertTrue(box)


# --- exports ---------------------------------------------------------------

class ExportTests(unittest.TestCase):
    """What leaves the tool as an exhibit.

    An export travels into a report and a handover, so the content type, the
    file name and the body all have to be right -- a JSON export served as
    text/html is one the recipient's mail gateway rewrites.
    """

    def fetch(self, path):
        status, headers, body = get(f"/api/cases/{CASE}{path}")
        self.assertEqual(200, status, body[:400])
        self.assertTrue(body, f"{path} returned an empty body")
        self.assertIn("attachment", headers.get("content-disposition", ""),
                      f"{path} is not offered as a download")
        return headers, body

    def test_the_ioc_csv_is_a_csv_and_carries_the_box(self):
        headers, body = self.fetch("/iocs/export?format=csv")
        self.assertTrue(headers["content-type"].startswith("text/csv"))
        text = body.decode("utf-8")
        self.assertIn(ATTACKER, text)
        self.assertGreater(len(text.strip().splitlines()), 1,
                           "the export carries a header and nothing else")

    def test_the_ioc_json_export_parses(self):
        headers, body = self.fetch("/iocs/export?format=json")
        self.assertTrue(headers["content-type"].startswith("application/json"))
        data = json.loads(body)
        self.assertIn(ATTACKER, json.dumps(data))

    def test_the_stix_export_is_a_bundle(self):
        headers, body = self.fetch("/iocs/export?format=stix")
        self.assertTrue(headers["content-type"].startswith("application/json"))
        bundle = json.loads(body)
        self.assertEqual("bundle", bundle.get("type"))
        self.assertTrue(bundle.get("objects"))

    def test_the_export_follows_the_filter(self):
        """The buttons export what the analyst is LOOKING at, with the same
        semantics as the view's chips and search. Handing the hoster 'just
        the addresses' must not require editing a CSV by hand -- and an edge
        whose far end was filtered away must go with it, or the file names
        an indicator it does not carry."""
        _h, body = self.fetch(f"/iocs/export?format=csv&search={ATTACKER}")
        text = body.decode("utf-8")
        self.assertIn(ATTACKER, text)
        self.assertNotIn("malware.example.test", text)

        _h, body = self.fetch("/iocs/export?format=csv&hide_types=ip")
        self.assertNotIn(ATTACKER, body.decode("utf-8"))

        _h, body = self.fetch("/iocs/export?format=csv"
                              "&search=matches-nothing-at-all")
        self.assertEqual(1, len(body.decode("utf-8").strip().splitlines()),
                         "an empty filter result is a header and nothing "
                         "else, not the whole box")

    def test_the_box_and_the_exports_carry_the_activity_span(self):
        """An address without a time frame is half an indicator: `added` is
        when it entered the box, first/last_seen is when it ACTED. The log
        index has known the answer all along (actors.first/last); dates in
        the log's own local time, said so in the CSV header and the STIX
        description rather than smuggled into valid_from with the wrong
        frame."""
        status, box = get_json(f"/api/cases/{CASE}/iocs")
        self.assertEqual(200, status, box)
        attacker = next(i for i in box if i["value"] == ATTACKER)
        self.assertRegex(attacker["first_seen"] or "",
                         r"^\d{4}-\d{2}-\d{2}$",
                         "the seeded address appears in the case's logs, so "
                         "the box must say when")
        self.assertRegex(attacker["last_seen"] or "", r"^\d{4}-\d{2}-\d{2}$")
        domain = next(i for i in box if i["value"] == "malware.example.test")
        self.assertIsNone(domain["first_seen"],
                          "a domain has no traffic in the access logs and "
                          "must not invent a span")

        _h, body = self.fetch("/iocs/export?format=csv")
        text = body.decode("utf-8")
        self.assertIn("First seen (log date)", text)
        self.assertIn(attacker["first_seen"], text)

        _h, body = self.fetch("/iocs/export?format=stix")
        descriptions = [o.get("description", "")
                        for o in json.loads(body)["objects"]
                        if o.get("type") == "indicator"]
        self.assertTrue(
            any("Active in the case's logs" in d for d in descriptions),
            "the STIX indicator for the address says when it was active")

    def test_a_pasted_hash_is_stored_lowercase(self):
        """Hex has no case. The collectors write hexdigest() and are already
        lower-case; the analyst pastes from wherever. Unfolded, the same
        digest lives twice and the cross-case comparison -- exact by design
        -- walks past itself."""
        digest = "AB" * 32
        status, _ = post_json(f"/api/cases/{CASE}/iocs", {"value": digest})
        self.assertEqual(200, status)
        post_json(f"/api/cases/{CASE}/iocs", {"value": digest.lower()})
        status, box = get_json(f"/api/cases/{CASE}/iocs")
        values = [i["value"] for i in box]
        self.assertNotIn(digest, values)
        self.assertEqual(1, values.count(digest.lower()),
                         "two spellings of one digest became two entries")

    def test_the_html_report_is_self_contained_and_proves_its_bytes(self):
        headers, body = self.fetch("/report.html?lang=en&tz=utc")
        self.assertTrue(headers["content-type"].startswith("text/html"))
        self.assertEqual(hashlib.sha256(body).hexdigest(),
                         headers["x-content-sha256"])
        text = body.decode("utf-8")
        self.assertIn("<!doctype html>", text)
        self.assertIn("SHELLHOUND", text)
        self.assertNotIn(str(WORKSPACE), text)

    def test_cross_case_iocs_only_return_explicit_box_entries(self):
        other = workspace.create_case(WORKSPACE, "Earlier matching case",
                                      reference="IR-previous")
        try:
            conn = db.connect(other)
            try:
                db.add_ioc(conn, ATTACKER, "ip", ["analyst"],
                           origin="added in the earlier case")
                db.upsert_finding(conn, "logs", db.SEV_HIGH, "raw only",
                                  "client", EVIDENCE_IP)
                conn.commit()
            finally:
                conn.close()
            status, data = get_json(f"/api/cases/{CASE}/iocs/cross-case")
            self.assertEqual(200, status)
            self.assertEqual(1, data["matched_iocs"])
            self.assertEqual("Earlier matching case",
                             data["entries"][0]["matches"][0]["name"])
            self.assertNotIn(EVIDENCE_IP, json.dumps(data))
            self.assertNotIn(str(WORKSPACE), json.dumps(data))
        finally:
            shutil.rmtree(other, ignore_errors=True)

    def test_the_account_list_is_a_csv_and_admins_narrows_it(self):
        """The password reset list after an incident. `only=admins` has to
        actually narrow, and the hashes must not be in either."""
        _headers, everyone = self.fetch("/database/accounts.csv")
        _headers, admins = self.fetch("/database/accounts.csv?only=admins")
        self.assertLessEqual(len(admins.splitlines()),
                             len(everyone.splitlines()))
        self.assertNotIn(b"$P$B", everyone,
                         "a password hash left the tool in an export")

    def test_the_trace_export_is_a_zip_that_vouches_for_its_csv(self):
        """A trace is an exhibit, and an exhibit is only citable with what was
        queried, how much came out and a checksum the recipient can verify.
        The checksum cannot live inside the file it vouches for, which is why
        this endpoint answers with an archive and not a CSV."""
        headers, body = self.fetch(f"/trace.csv?ips={ATTACKER}")
        self.assertEqual("application/zip", headers["content-type"])
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            self.assertEqual({"trace.csv", "MANIFEST.txt"},
                             set(archive.namelist()))
            csv_bytes = archive.read("trace.csv")
            manifest = archive.read("MANIFEST.txt").decode("utf-8")
        digest = hashlib.sha256(csv_bytes).hexdigest()
        self.assertIn(digest, manifest)
        self.assertEqual(digest, headers.get("x-content-sha256"))
        self.assertIn(ATTACKER, manifest)
        self.assertGreater(len(csv_bytes.splitlines()), 1)

    def test_the_pattern_library_exports_as_json(self):
        status, headers, body = get("/api/patterns/export")
        self.assertEqual(200, status)
        self.assertTrue(headers["content-type"].startswith("application/json"))
        self.assertIn("attachment", headers.get("content-disposition", ""))
        json.loads(body)


# --- paths from the client -------------------------------------------------

class PathGuardTests(unittest.TestCase):
    """A case slug and an evidence path both come from the client, and both
    address the file system. The tool runs on the analyst's own machine with
    the analyst's own rights, so a slug that walks out of the workspace reads
    whatever that machine holds."""

    def setUp(self):
        # A case-shaped directory OUTSIDE the workspace: it has a case.json
        # and a case.db, so the only thing standing between it and a client
        # that names it is the guard being tested.
        self.outside = Path(tempfile.mkdtemp(prefix="shellhound-http-out-"))
        self.addCleanup(shutil.rmtree, self.outside, True)
        self.stranger = workspace.create_case(self.outside, "Somebody elses case")

    def test_a_slug_that_walks_out_of_the_workspace_is_refused(self):
        escapes = [
            "..",
            "../..",
            "%2e%2e",
            "..%2Farchive",
            q("../" + self.outside.name + "/" + self.stranger.name),
            q("..\\..\\" + self.stranger.name),
            q(str(self.stranger)),
            q(str(self.stranger.parent)),
        ]
        for slug in escapes:
            for route in ("", "/summary", "/findings", "/dashboard",
                          "/report.html", "/iocs/cross-case", "/iocs/export"):
                with self.subTest(slug=slug, route=route):
                    status, _headers, body = get(f"/api/cases/{slug}{route}")
                    self.assertNotEqual(200, status, body[:200])
                    # 405 belongs in the list: uvicorn hands Starlette the
                    # DECODED path, so an escape written as `..%2Farchive`
                    # arrives as two segments and lands on a route that only
                    # takes POST. Refused is refused -- what matters is that
                    # no answer about a case comes back.
                    self.assertIn(status, (400, 404, 405),
                                  f"{slug}{route} answered {status}")

    def test_a_slug_never_reaches_a_case_of_another_workspace(self):
        """The stranger's case is readable on disk and answers nothing here.
        Two investigations never share state, and that is structural."""
        status, body = get_json(f"/api/cases/{q(str(self.stranger))}")
        self.assertEqual(404, status, body)
        status, body = get_json(f"/api/cases/{self.stranger.name}")
        self.assertEqual(404, status, body)

    def test_an_evidence_path_outside_the_registered_roots_is_refused(self):
        """The file endpoint reads what the client names, so the fence runs on
        the RESOLVED path: a file that exists but belongs to no evidence root
        of this case is not part of the case."""
        outsider = self.stranger / "case.json"
        status, _headers, _body = get(
            f"/api/cases/{CASE}/file?path={q(str(outsider))}")
        self.assertEqual(403, status)

    def test_a_traversal_out_of_an_evidence_root_is_refused(self):
        walked = str(EVIDENCE.webroot / ".." / ".." / ".." / "case.json")
        status, _headers, _body = get(
            f"/api/cases/{CASE}/file?path={q(walked)}")
        self.assertIn(status, (403, 404))

    def test_an_evidence_file_of_the_case_is_readable(self):
        """The guard is only worth having if the honest path still works --
        and this one is mixed-case, under a folder called `uploads` that
        belongs to the analyst rather than to the site."""
        shell = str(EVIDENCE.webroot / EVIDENCE.shell_rel)
        status, body = get_json(f"/api/cases/{CASE}/file?path={q(shell)}")
        self.assertEqual(200, status, body)
        self.assertEqual(1, body["from_line"])
        self.assertTrue(any("system" in line for line in body["lines"]))


if __name__ == "__main__":
    unittest.main()
