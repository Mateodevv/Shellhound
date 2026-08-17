# tests/test_contract.py
"""The contract between the server and the browser: does `api.ts` describe
what actually arrives?

web/src/api.ts declares the shape of every response BY HAND, and TypeScript
believes it. Nothing has ever compared the declaration against the server.
`HuntResult` declared `label` and `note` while the endpoint had always sent
`name` and `cve` -- so the headline of a hunt read the analyst's own name for
a pattern out of a field that was `undefined`, fell back to the raw pattern,
and looked like a design decision. It compiled, it rendered, and it was wrong
for as long as nobody held the two files side by side.

This module holds them side by side. The declarations are parsed out of the
TypeScript as text -- the interfaces are simple, and a Node toolchain has no
business in a Python test run. The answers come from the real endpoints, over
the real ASGI application, against an analysed hostile case.

THE TWO DIRECTIONS ARE NOT SYMMETRIC, and the assertions differ accordingly.

  * A field the CLIENT declares that the server never sends is `undefined` at
    runtime. TypeScript cannot catch it: the declaration is the only thing it
    checks against, so it agrees with itself. It surfaces as an empty cell, a
    `??` fallback or a `NaN` -- never as an error, which is why it can sit in
    a release for months. That is a defect every time, and it is asserted
    strictly.

  * A field the SERVER sends that the client does not declare is usually
    deliberate. `rule_id` is what the rule switch stores, `active` is a number
    the work-list SQL needs and nothing renders, `artifact_rel` is written for
    the export. An undeclared field costs a few bytes and nothing else, and
    forcing every one of them into the browser's type would be busywork that
    invites the opposite mistake. They are therefore held against a DOCUMENTED
    allow-list: a new one has to be named and explained here, not merely
    tolerated -- but it is not by itself a bug.

Optional fields (`name?:`) are allowed to be absent from a single answer,
because that is what the question mark means. They are NOT allowed to be
absent from every answer of every shape: a name no endpoint ever produces is
the `label`/`note` defect again, and the question mark only hides it better.
Where an optional field genuinely cannot occur in this fixture, the entry says
so in `absent_here`, one documented name at a time, instead of the check being
loosened for the whole interface.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

from server import workspace
from server.app import create_app
from server.config import Config
from tests.fixtures_hostile import HostileEvidence, hostile_shapes

REPO = Path(__file__).resolve().parent.parent
API_TS = REPO / "web" / "src" / "api.ts"
# `Coverage` lives next to the component that fetches it rather than in
# api.ts. It is still a declaration of a server response and drifts the same
# way, so it is read from where it stands.
COVERAGE_TSX = REPO / "web" / "src" / "components" / "LogCoverage.tsx"

TOKEN = "contract-token"


# --- reading the TypeScript -------------------------------------------------

def strip_comments(text):
    """The source with comments removed, quotes respected.

    The doc comments in api.ts contain field names in back-ticks (`label`,
    `note`) and would otherwise be parsed as declarations -- the test would
    then assert against the prose about the interface instead of the
    interface."""
    out, i, n = [], 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "'\"`":
            quote, j = ch, i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == quote:
                    j += 1
                    break
                j += 1
            out.append(text[i:j])
            i = j
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            # A block comment can span lines; the newline it swallowed has to
            # come back, because a field declaration ends at one.
            out.append("\n")
        else:
            out.append(ch)
            i += 1
    return "".join(out)


class Declaration:
    """The field names of one declared type, and which of them are optional."""

    def __init__(self, name):
        self.name = name
        self.fields = {}          # field -> is optional
        self.extends = []


def _skip_space(text, pos):
    while pos < len(text) and text[pos] in " \t\r\n":
        pos += 1
    return pos


def _parse_block(text, pos, path, out):
    """Fields of one `{ ... }`, from just after the brace to just after its
    partner. Nested object literals are recorded under `Type.field`, because
    that is where the drift hides: `Coverage.quiet` is an inline object and
    nothing about it is less of a contract for being unnamed."""
    decl = out.setdefault(path, Declaration(path))
    n = len(text)
    while pos < n:
        pos = _skip_space(text, pos)
        if pos >= n or text[pos] == "}":
            return pos + 1
        start = pos
        name = ""
        while pos < n and (text[pos].isalnum() or text[pos] == "_"):
            name += text[pos]
            pos += 1
        optional = pos < n and text[pos] == "?"
        after = _skip_space(text, pos + 1 if optional else pos)
        if not name or after >= n or text[after] != ":":
            # Not a field declaration -- a separator, an index signature or
            # something this parser does not model. Step over one character
            # so the walk cannot stall.
            pos = start + 1
            continue
        decl.fields[name] = optional
        pos = after + 1
        # Walk the type. `<>` and `()` nest without being object literals
        # (`Record<string, unknown>`), so only their depth is tracked; a `{`
        # is a nested declaration and is parsed as one.
        depth = 0
        while pos < n:
            ch = text[pos]
            if ch == "{":
                pos = _parse_block(text, pos + 1, f"{path}.{name}", out)
                continue
            if ch == "}":
                break
            if ch in "<(":
                depth += 1
            elif ch in ">)":
                depth -= 1
            elif depth <= 0 and ch in ";,\n":
                pos += 1
                break
            pos += 1
    return pos


def parse_declarations(*paths):
    """Every interface in the given TypeScript files, by name."""
    out = {}
    for path in paths:
        text = strip_comments(path.read_text(encoding="utf-8"))
        i = 0
        while True:
            i = text.find("interface ", i)
            if i < 0:
                break
            head_end = text.find("{", i)
            if head_end < 0:
                break
            head = text[i + len("interface "):head_end].strip()
            parts = head.split()
            name = parts[0]
            decl_map = {}
            _parse_block(text, head_end + 1, name, decl_map)
            decl = decl_map.pop(name)
            if len(parts) > 2 and parts[1] == "extends":
                decl.extends = [p.strip(",") for p in parts[2:]]
            out[name] = decl
            out.update(decl_map)
            i = head_end + 1
    return out


DECLARED = parse_declarations(API_TS, COVERAGE_TSX)


def fields_of(type_name):
    """The declared fields of a type, its parents folded in."""
    decl = DECLARED[type_name]
    fields = {}
    for parent in decl.extends:
        fields.update(fields_of(parent))
    fields.update(decl.fields)
    return fields


# --- talking to the server --------------------------------------------------

try:
    from fastapi.testclient import TestClient
except Exception:                                # pragma: no cover
    # Starlette's client needs httpx, which is not among this project's
    # dependencies (requirements.txt) and is therefore absent in CI. The
    # fallback below drives the same ASGI application through the same
    # protocol with nothing but the standard library, so the contract is
    # checked everywhere rather than quietly skipped on the machine that
    # matters.
    TestClient = None


class Client:
    """The API as the browser reaches it: through the token fence, with the
    same `X-Lang` and `X-TZ` headers api.ts sends on every call. Prose that
    the server renders times into depends on those two, so a test that omits
    them is not asking the question the frontend asks."""

    HEADERS = {"X-Token": TOKEN, "X-Lang": "en", "X-TZ": "log"}

    def __init__(self, app):
        self.app = app
        self.client = TestClient(app) if TestClient else None

    def get(self, path, **params):
        return self._call("GET", path, params, None)

    def post(self, path, body):
        return self._call("POST", path, {}, body)

    def _call(self, method, path, params, body):
        if self.client is not None:
            res = (self.client.get(path, params=params, headers=self.HEADERS)
                   if method == "GET" else
                   self.client.post(path, json=body, headers=self.HEADERS))
            return res.status_code, self._json(res.content)
        return self._asgi(method, path, params, body)

    @staticmethod
    def _json(raw):
        try:
            return json.loads(raw)
        except ValueError:
            return None

    def _asgi(self, method, path, params, body):
        import asyncio

        payload = b"" if body is None else json.dumps(body).encode()
        headers = [(k.lower().encode(), v.encode())
                   for k, v in self.HEADERS.items()]
        if body is not None:
            headers.append((b"content-type", b"application/json"))

        async def run():
            scope = {"type": "http", "asgi": {"version": "3.0"},
                     "http_version": "1.1", "method": method, "path": path,
                     "raw_path": path.encode(),
                     "query_string": urlencode(params).encode(),
                     "headers": headers, "scheme": "http", "root_path": "",
                     "client": ("127.0.0.1", 51234),
                     "server": ("127.0.0.1", 8710)}
            messages = []

            async def receive():
                return {"type": "http.request", "body": payload,
                        "more_body": False}

            async def send(message):
                messages.append(message)

            await self.app(scope, receive, send)
            status = messages[0]["status"]
            raw = b"".join(m.get("body", b"") for m in messages
                           if m["type"] == "http.response.body")
            return status, raw

        status, raw = asyncio.run(run())
        return status, self._json(raw)


# --- the case the answers come from -----------------------------------------

# Two shapes, not one. The clean one is the control; the one with every dial
# turned is where a field only some evidence produces shows up -- a truncated
# log file, a second offset, a client list past the cap.
SHAPES = ("utc", "everything")

# How many artifacts are asked for their context. The hostile case carries
# 250 clients, and the contract of the answer does not get truer by asking
# all of them; what matters is that every KIND is asked at least once.
CONTEXTS_PER_KIND = 4

_state = {"answers": {}, "evidence": [], "workspaces": []}


def setUpModule():
    shapes = {s.name: s for s in hostile_shapes()}
    for name in SHAPES:
        _state["answers"][name] = _answers_for(shapes[name])


def tearDownModule():
    for evidence in _state["evidence"]:
        evidence.cleanup()
    for path in _state["workspaces"]:
        shutil.rmtree(path, ignore_errors=True)


def _answers_for(shape):
    """One built, analysed case in a workspace the API serves, and every
    response this module makes a statement about."""
    evidence = HostileEvidence(**shape.options)
    evidence.build()
    ws = Path(tempfile.mkdtemp(prefix="shellhound-contract-"))
    # The engines write into the case the API can resolve, not into the
    # fixture's own scratch directory: the endpoints only ever answer for a
    # case that lives in the workspace.
    evidence.case_dir = workspace.create_case(ws, shape.name)
    evidence.analyse()
    _state["evidence"].append(evidence)
    _state["workspaces"].append(ws)

    app = create_app(Config(workspace=ws, token=TOKEN))
    client = Client(app)
    slug = evidence.case_dir.name
    base = f"/api/cases/{slug}"

    out = {"client": client, "slug": slug}
    out["case"] = _ok(client.get(base))
    out["findings"] = _ok(client.get(f"{base}/findings"))
    out["dashboard"] = _ok(client.get(f"{base}/dashboard"))
    out["coverage"] = _ok(client.get(f"{base}/coverage"))
    out["chain"] = _ok(client.get(f"{base}/chain"))
    out["actors"] = _ok(client.get(f"{base}/actors"))

    seen, contexts = {}, []
    for row in out["findings"]["artifacts"]:
        kind = row["artifact_kind"]
        if seen.get(kind, 0) >= CONTEXTS_PER_KIND:
            continue
        seen[kind] = seen.get(kind, 0) + 1
        contexts.append(_ok(client.get(f"{base}/artifact",
                                       artifact=row["artifact"])))
    # The confirmed shell as well, wherever it landed in the list: it is the
    # one artifact that carries a preview, a hash and requests out of the
    # logs, so the optional halves of ArtifactContext are populated at all.
    # A 404 here is not swallowed -- it means no rule flagged the shell, and
    # the sample check below then reports the entries that went empty, which
    # says more than a failure inside the fixture would.
    shell = str(evidence.webroot / Path(evidence.shell_rel))
    status, ctx = client.get(f"{base}/artifact", artifact=shell)
    if status == 200:
        contexts.append(ctx)
    out["contexts"] = contexts

    # Last, because it writes 250 more client findings and would otherwise
    # decide which artifacts the sampling above sees.
    out["hunt"] = _ok(client.post(f"{base}/hunt/run", {"ids": []}))
    return out


def _ok(result):
    status, body = result
    if status != 200:
        raise AssertionError(f"the contract fixture could not be built: "
                             f"HTTP {status} -- {body}")
    return body


def answers(shape):
    return _state["answers"][shape]


# --- what is compared against what ------------------------------------------

class Entry:
    """One declared type, the endpoint that produces it, and the two
    documented allowances."""

    def __init__(self, name, declared, samples, extras=None, absent_here=(),
                 bug=""):
        self.name = name
        self.declared = declared
        self.samples = samples
        # Field the server sends that the client does not declare -> WHY that
        # is deliberate. A name may only be here with a reason next to it.
        self.extras = extras or {}
        # Declared field this fixture cannot produce -> why not. Never a way
        # to wave through a field no endpoint has.
        self.absent_here = dict(absent_here)
        # Set when the mismatch is a confirmed product defect: the entry
        # leaves the sweep and gets a test of its own that states it.
        self.bug = bug


def _sub(container, key):
    return [c[key] for c in container if isinstance(c.get(key), dict)]


CONTRACT = [
    Entry("FindingsResponse -- GET /findings",
          "FindingsResponse", lambda a: [a["findings"]]),
    Entry("FindingsResponse.counts -- GET /findings",
          "FindingsResponse.counts", lambda a: [a["findings"]["counts"]]),
    Entry("ArtifactRow -- GET /findings",
          "ArtifactRow", lambda a: a["findings"]["artifacts"],
          extras={"active": "findings from rules this workspace still runs. "
                            "The work list filters on it in SQL; nothing "
                            "renders it."}),
    Entry("Finding -- GET /findings",
          "Finding", lambda a: a["findings"]["findings"],
          extras={"rule_id": "the stable identity the rule switch stores. "
                             "The interface shows `rule`, the sentence.",
                  "engine": "bookkeeping of the retirement mechanic: which "
                            "engine owns the row. The interface reads the "
                            "derived `retired` flag, never this.",
                  "seen_run": "bookkeeping of the retirement mechanic: the "
                              "run that last reproduced the row. The "
                              "interface reads `retired`, never this."}),

    Entry("ArtifactContext -- GET /artifact",
          "ArtifactContext", lambda a: a["contexts"],
          absent_here={"dump": "no rule in this fixture fires on a dump as a "
                               "whole, so no artifact of kind `dump` exists "
                               "to ask about."}),
    Entry("ArtifactContext.file -- GET /artifact",
          "ArtifactContext.file", lambda a: _sub(a["contexts"], "file")),
    Entry("ArtifactContext.file.preview -- GET /artifact",
          "FilePreview",
          lambda a: _sub(_sub(a["contexts"], "file"), "preview"),
          absent_here={"error": "only sent when the file cannot be read.",
                       "binary": "only sent for a file that is not text."}),
    Entry("ArtifactContext.actor -- GET /artifact",
          "ArtifactContext.actor", lambda a: _sub(a["contexts"], "actor")),
    Entry("ArtifactContext.table -- GET /artifact",
          "ArtifactContext.table", lambda a: _sub(a["contexts"], "table"),
          extras={"id": "the row is selected as `t.*` and its two key "
                        "columns travel with it. The drawer addresses a "
                        "table by name, so neither is declared.",
                  "dump_id": "the dump the table belongs to, as an id. The "
                             "path is sent alongside as `dump_path`, which "
                             "is the form a report can quote."}),
    Entry("RelatedIp -- GET /artifact",
          "RelatedIp",
          lambda a: [ip for c in a["contexts"] for ip in c.get("related_ips", [])]),
    Entry("HuntHit -- GET /artifact",
          "HuntHit",
          lambda a: [h for c in a["contexts"] for h in c.get("hunt", [])],
          extras={"uri": "the request the file was reached by. The drawer "
                         "shows the file name -- which is the same for every "
                         "hit -- and leaves the URI to the trace."}),
    Entry("ActorProfile -- GET /artifact (the measurements below a client)",
          "ActorProfile",
          lambda a: [c["actor"]["actor"] for c in a["contexts"]
                     if isinstance(c.get("actor"), dict)],
          ),

    Entry("CaseChain -- GET /chain", "CaseChain", lambda a: [a["chain"]]),
    Entry("CaseChain.span -- GET /chain",
          "CaseChain.span", lambda a: [a["chain"]["span"]]),
    Entry("CaseChain.offsets -- GET /chain",
          "CaseChain.offsets", lambda a: [a["chain"]["offsets"]]),
    Entry("ChainEvent -- GET /chain", "ChainEvent", lambda a: a["chain"]["events"],
          extras={"artifact_rel": "the artifact as it appears in a URL. The "
                                  "chronology is also written into the JSON "
                                  "export, which has no evidence roots to "
                                  "shorten a path against."}),
    Entry("CaseChain.undated -- GET /chain",
          "CaseChain.undated", lambda a: a["chain"]["undated"],
          extras={"artifact_rel": "as on the events, and for the same "
                                  "export."}),

    Entry("Dashboard -- GET /dashboard", "Dashboard", lambda a: [a["dashboard"]]),
    Entry("Dashboard.logs -- GET /dashboard",
          "Dashboard.logs", lambda a: [a["dashboard"]["logs"]],
          extras={"undated": "lines with a client and a target but no usable "
                             "timestamp. The chronology states them; the "
                             "dashboard does not.",
                  "partial": "the index was cut short.",
                  "tz_offsets": "every offset the logs carry -- the "
                                "chronology names the zone from it."}),
    Entry("Dashboard.timeline -- GET /dashboard",
          "Dashboard.timeline", lambda a: a["dashboard"]["timeline"]),
    Entry("DashboardChronology -- GET /dashboard",
          "DashboardChronology", lambda a: [a["dashboard"]["chronology"]]),
    Entry("DashboardChronology.event_span -- GET /dashboard",
          "DashboardChronology.event_span",
          lambda a: [a["dashboard"]["chronology"]["event_span"]]),
    Entry("DashboardObservation -- GET /dashboard",
          "DashboardObservation",
          lambda a: a["dashboard"]["chronology"]["observations"]),
    Entry("DashboardConfirmedArtifact -- GET /dashboard",
          "DashboardConfirmedArtifact",
          lambda a: a["dashboard"]["confirmed_artifacts"]),
    Entry("EvidenceItem -- GET /dashboard and GET /cases/{slug}",
          "EvidenceItem",
          lambda a: a["dashboard"]["evidence"] + a["case"]["evidence_items"]),
    Entry("LogIndexStatus -- GET /cases/{slug}",
          "LogIndexStatus", lambda a: [a["case"]["log_index"]],
          extras={"undated": "lines that parsed but carry no usable "
                             "timestamp -- counted separately from the ones "
                             "that did not parse at all."}),

    Entry("Coverage -- GET /coverage", "Coverage", lambda a: [a["coverage"]]),
    Entry("Coverage.quiet -- GET /coverage",
          "Coverage.quiet", lambda a: [a["coverage"]["quiet"]]),
    Entry("QuietWindow -- GET /coverage",
          "QuietWindow", lambda a: a["coverage"]["quiet"]["windows"]),
    Entry("FileAnomaly -- GET /coverage",
          "FileAnomaly", lambda a: a["coverage"]["files"]),

    Entry("HuntResult -- POST /hunt/run",
          "HuntResult", lambda a: a["hunt"]["results"],
          extras={"patterns": "the parts the pattern is built from. Declared "
                              "on HuntPattern, which the hunt view already "
                              "holds for the same entry.",
                  "match": "whether those parts are combined with any or "
                           "all. Declared on HuntPattern as well."}),
    Entry("HuntClient -- POST /hunt/run",
          "HuntClient",
          lambda a: [c for r in a["hunt"]["results"] for c in r["clients"]]),
    Entry("HuntResult.uris -- POST /hunt/run",
          "HuntResult.uris",
          lambda a: [u for r in a["hunt"]["results"] for u in r["uris"]]),

    Entry("ActorsResponse -- GET /actors", "ActorsResponse",
          lambda a: [a["actors"]]),
    Entry("ActorsResponse.span -- GET /actors", "ActorsResponse.span",
          lambda a: [a["actors"]["span"]]),
    Entry("Actor -- GET /actors", "Actor", lambda a: a["actors"]["actors"]),
    Entry("ActorAlert -- GET /actors", "ActorAlert",
          lambda a: [al for act in a["actors"]["actors"] for al in act["alerts"]]),
]

CLEAN = [e for e in CONTRACT if not e.bug]


def collect(entry):
    """Every sample of one entry across every shape, so that a field only one
    kind of evidence produces still counts as produced."""
    out = []
    for shape in SHAPES:
        for sample in entry.samples(answers(shape)):
            if isinstance(sample, dict):
                out.append((shape, sample))
    return out


# --- the parser has to be right before anything it says means anything ------

class ParserTests(unittest.TestCase):
    """What the TypeScript parse reads, checked against declarations whose
    content can be read by eye in api.ts.

    A parser that silently returns nothing would make every contract test
    below pass while comparing empty sets, which is exactly the shape of a
    guard that guards nothing."""

    def test_a_flat_interface_is_read_completely(self):
        self.assertEqual({"ip", "name", "hits", "ok_hits"},
                         set(fields_of("HuntHit")))

    def test_the_question_mark_is_carried(self):
        fields = fields_of("Finding")
        self.assertFalse(fields["rule"], "`rule` is not optional")
        self.assertTrue(fields["triaged_at"], "`triaged_at?` is optional")

    def test_an_inline_object_becomes_its_own_declaration(self):
        """`Coverage.quiet` is declared inline. It is no less a contract for
        having no name, and the drift this module exists to find is in it.

        Asserted as PROPERTIES of the parse, not as the field list: pinning
        the list here would mean editing this test every time a field is
        added, which trains whoever does it to edit the test rather than to
        look at what changed."""
        fields = fields_of("Coverage.quiet")
        self.assertTrue(fields, "the inline object was not parsed at all")
        self.assertIn("windows", fields)
        self.assertIn("checked", fields)
        self.assertFalse(fields["windows"], "`windows` is not optional")
        self.assertNotIn("from", fields,
                         "the nested QuietWindow leaked into its parent")

    def test_a_nested_declaration_does_not_leak_into_its_parent(self):
        """`roots: { kind; path; label }[]` sits on one line. A parser that
        splits on `;` reads `path` and `label` as fields of the response
        itself and then demands them from the server."""
        self.assertNotIn("kind", fields_of("FindingsResponse"))
        self.assertEqual({"kind", "path", "label"},
                         set(fields_of("FindingsResponse.roots")))

    def test_extends_is_folded_in(self):
        self.assertIn("slug", fields_of("CaseDetail"),
                      "CaseDetail extends CaseInfo and inherits its fields")

    def test_prose_about_a_field_is_not_read_as_a_field(self):
        """The doc comment on HuntResult names `label` and `note` in
        back-ticks -- the very fields that were wrong. Reading the comment
        would re-introduce them as declarations."""
        self.assertNotIn("label", fields_of("HuntResult"))
        self.assertNotIn("note", fields_of("HuntResult"))

    def test_every_entry_names_a_declaration_that_exists(self):
        for entry in CONTRACT:
            with self.subTest(entry=entry.name):
                self.assertIn(entry.declared, DECLARED)


class FixtureTests(unittest.TestCase):
    """The answers this module reasons about have to be real answers."""

    def test_the_samples_reach_the_endpoints_through_the_token_fence(self):
        """Every sample below came through `require_token`. If the fence let
        an unauthenticated call through, these responses would prove nothing
        about the API the browser talks to."""
        client = answers(SHAPES[0])["client"]
        slug = answers(SHAPES[0])["slug"]
        bare = Client(client.app)
        bare.HEADERS = {"X-Lang": "en", "X-TZ": "log"}
        status, _ = bare.get(f"/api/cases/{slug}/findings")
        self.assertEqual(401, status, "the API answered without a token")

    def test_an_entry_left_out_of_the_sweep_points_at_a_real_test(self):
        """`bug` takes an entry out of the sweep, so the name it gives has to
        lead to the test that states the defect instead. A typo there would
        remove a whole endpoint from the comparison silently, which is the
        failure mode this module exists to prevent."""
        for entry in CONTRACT:
            if not entry.bug:
                continue
            with self.subTest(entry=entry.name):
                self.assertTrue(hasattr(KnownDriftTests, entry.bug),
                                f"no test called {entry.bug}")

    def test_every_entry_actually_got_samples(self):
        """An entry whose extractor returns nothing asserts nothing. That is
        how a contract test goes green while the contract is broken."""
        for entry in CONTRACT:
            with self.subTest(entry=entry.name):
                self.assertTrue(collect(entry),
                                "no sample -- the endpoint, the fixture or "
                                "the extractor changed")


# --- direction one: the client declares what the server does not send -------

class DeclaredButNotSentTests(unittest.TestCase):
    """Fields api.ts promises the browser and the server never delivers.

    This is the direction that hides. TypeScript checks the code against the
    declaration and the declaration against nothing, so a field that is never
    sent is `undefined` at runtime and silent at compile time: an empty cell,
    a fallback, a `NaN` in a total. Nothing throws, nothing logs, and the
    interface goes on looking finished."""

    def test_a_required_field_arrives_in_every_answer(self):
        """Required means required: a field without a question mark that is
        missing from one answer is undefined in that answer, and the code
        reading it was written under the promise that it could not be."""
        for entry in CLEAN:
            required = {f for f, opt in fields_of(entry.declared).items()
                        if not opt} - set(entry.absent_here)
            for shape, sample in collect(entry):
                missing = sorted(required - set(sample))
                with self.subTest(entry=entry.name, shape=shape):
                    self.assertEqual([], missing,
                                     f"{entry.declared} declares {missing} "
                                     f"without a question mark; this answer "
                                     f"has {sorted(sample)}")

    def test_every_declared_field_is_produced_somewhere(self):
        """The question mark says a field MAY be absent, not that the name
        exists. `label` and `note` on a hunt result were required and still
        went unnoticed for months; the same drift behind a question mark is
        invisible for good. A name that no shape and no endpoint ever
        produces is a name the server does not have."""
        for entry in CLEAN:
            declared = set(fields_of(entry.declared)) - set(entry.absent_here)
            produced = set()
            for _, sample in collect(entry):
                produced |= set(sample)
            with self.subTest(entry=entry.name):
                self.assertEqual([], sorted(declared - produced),
                                 f"{entry.declared} declares fields no "
                                 f"answer of this endpoint contains")

    def test_an_undocumented_absence_is_not_allowed_to_be_quiet(self):
        """`absent_here` is an admission that the fixture cannot reach a
        field, not a way to retire one. A name listed there that the server
        does send has stopped being an exception and has to leave the list,
        or the list becomes the place where a real absence hides."""
        for entry in CLEAN:
            produced = set()
            for _, sample in collect(entry):
                produced |= set(sample)
            with self.subTest(entry=entry.name):
                self.assertEqual([], sorted(set(entry.absent_here) & produced),
                                 f"{entry.declared} lists these as "
                                 f"unreachable in this fixture, and they "
                                 f"arrived")


# --- direction two: the server sends what the client does not declare -------

class SentButNotDeclaredTests(unittest.TestCase):
    """Fields the server sends that api.ts does not mention.

    NOT the same defect, and deliberately not the same assertion. An
    undeclared field is invisible to the browser rather than wrong in it: the
    JSON carries it, nothing reads it, and nothing breaks. Several are there
    on purpose -- `rule_id` belongs to the rule switch, `active` to the SQL
    behind the work list, `artifact_rel` to the export.

    So the check is against a documented allow-list rather than a demand for
    symmetry: a new undeclared field has to be looked at once and given a
    reason here. That keeps the interesting case -- a server field the UI
    ought to be showing and cannot -- from being drowned in noise, without
    letting the whole direction go unwatched."""

    def test_undeclared_fields_are_named_and_explained(self):
        for entry in CLEAN:
            declared = set(fields_of(entry.declared))
            for shape, sample in collect(entry):
                unexpected = sorted(set(sample) - declared - set(entry.extras))
                with self.subTest(entry=entry.name, shape=shape):
                    self.assertEqual([], unexpected,
                                     f"the server sends fields api.ts does "
                                     f"not declare. Either declare them or "
                                     f"name them in `extras` with the reason")

    def test_the_allow_list_only_holds_fields_that_are_really_sent(self):
        """An allow-list nobody prunes turns into a list of names that once
        existed, and then it stops meaning anything."""
        for entry in CLEAN:
            produced = set()
            for _, sample in collect(entry):
                produced |= set(sample)
            with self.subTest(entry=entry.name):
                self.assertEqual([], sorted(set(entry.extras) - produced),
                                 f"{entry.declared} allows undeclared fields "
                                 f"the server no longer sends")


# --- the drift this run found ----------------------------------------------

class KnownDriftTests(unittest.TestCase):
    """The mismatches the sweep above found, each stated on its own.

    They are kept out of the sweep and written out here so that the sweep
    stays a working guard for everything else, and so that each defect says
    what it is instead of being one line in a list of subTest failures. When
    one is fixed, its test passes unexpectedly and the suite goes red -- which
    is the reminder to delete the marker."""

    def test_the_two_actor_types_stay_apart(self):
        """The measurements and the row are not the same object.

        `ActorProfile` is what the log index measures about one client.
        `Actor` is that plus what the actors LIST adds for its own rows: the
        alerts, a sparkline to draw, whether the address is in the IOC box,
        and the decision on it. Declaring one type for both paths meant
        `actor.in_box` in the artifact drawer compiled and was `undefined` --
        the badge saying an address is already collected simply never
        appeared, and nothing said why.

        The sweep already checks each of them against its own endpoint. What
        this test defends is the SPLIT: collapsing the two back into one is
        the change that would put the drift back, and it would do so while
        every other test stayed green."""
        profile, actor = set(fields_of("ActorProfile")), set(fields_of("Actor"))
        self.assertTrue(profile, "ActorProfile is gone")
        self.assertTrue(actor - profile,
                        "Actor no longer adds anything to ActorProfile -- the "
                        "two have been collapsed back into one")
        for field in ("sparkline", "in_box", "triage", "alerts"):
            self.assertIn(field, actor, f"the list row lost {field}")
            self.assertNotIn(
                field, profile,
                f"{field} is back on the profile, which the artifact path "
                f"never sends")

    def test_the_coverage_report_declares_the_median_by_the_name_it_sends(self):
        """The typical gap between two requests is what makes a quiet window
        mean anything -- it is the yardstick the threshold is derived from,
        and the number an analyst needs to judge whether four silent hours are
        remarkable for THIS log.

        The interface used to call it `median` while the server has always
        sent `median_gap`, and the declaration was optional, so TypeScript
        never asked and the value was simply never there: the same drift as
        `label`/`note` on a hunt result, with a question mark in front of it.

        ASSERTED AS AGREEMENT, NOT AS A NAME. Writing down which side is
        right would freeze whichever one happened to be written first -- and a
        test that encodes one side of a contract is how the original defect
        survived. Either name is fine; only one of them may be in use."""
        declared = {f.rstrip("?") for f in fields_of("Coverage.quiet")}
        for shape in SHAPES:
            quiet = answers(shape)["coverage"]["quiet"]
            with self.subTest(shape=shape):
                self.assertEqual(
                    set(), declared - set(quiet),
                    f"declared but never sent; the server sends "
                    f"{sorted(quiet)}")

    def test_evidence_stats_is_an_object_on_every_endpoint_that_sends_it(self):
        """`EvidenceItem.stats` is declared `Record<string, unknown>`. The
        case detail decodes the column and sends an object; the dashboard
        hands the stored text straight out, so the same interface arrives as
        `{...}` from one endpoint and as the string `"{...}"` from the other.

        A name check cannot see this and the browser will not either: reading
        `stats.files` off a string is `undefined` rather than an error, and a
        component that works when opened from the case detail shows nothing
        when opened from the dashboard. Whichever way it is settled, the two
        endpoints have to agree."""
        for shape in SHAPES:
            for item in answers(shape)["dashboard"]["evidence"]:
                with self.subTest(shape=shape, path=item["path"]):
                    self.assertIsInstance(
                        item["stats"], dict,
                        "the dashboard sends the stats column undecoded")


if __name__ == "__main__":
    unittest.main()
