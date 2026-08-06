# tests/test_sigma.py
"""SIGMA rules against the access log index.

Two halves. The compiler is checked on what it produces AND on what it
refuses -- the refusals are the more important half, because the failure
mode this backend exists to avoid is a rule that loads happily and matches
nothing. In a forensic tool that is the worst possible object: it looks like
evidence of absence.

The engine half runs real rules against a real index built from real log
lines, because a WHERE fragment that reads correctly and does not execute is
not worth having.
"""
import tempfile
import unittest
from pathlib import Path

from server import db, ruleswitch, sigma
from server.engines import logindex, sigmascan

LOG = """\
203.0.113.7 - - [10/Jun/2026:22:58:11 +0200] "GET /index.php HTTP/1.1" 200 512 "-" "sqlmap/1.7"
203.0.113.7 - - [10/Jun/2026:22:58:12 +0200] "GET /admin HTTP/1.1" 404 120 "-" "sqlmap/1.7"
198.51.100.4 - - [10/Jun/2026:23:01:00 +0200] "GET /shop?id=1 HTTP/1.1" 200 900 "-" "Mozilla/5.0"
198.51.100.4 - - [10/Jun/2026:23:01:05 +0200] "POST /wp-login.php HTTP/1.1" 302 0 "-" "Mozilla/5.0"
"""


def rule(**parts):
    body = ["title: " + parts.get("title", "Test rule"),
            "id: " + parts.get("id", "test.rule"),
            "level: " + parts.get("level", "medium"),
            "detection:"]
    body.append(parts["detection"])
    return "\n".join(body) + "\n"


class CompilerTests(unittest.TestCase):

    def test_a_contains_selection_becomes_a_like(self):
        meta, where, params = sigma.compile_rule(rule(detection=(
            "  sel:\n    c-useragent|contains: sqlmap\n  condition: sel")))
        self.assertIn("LIKE", where)
        self.assertEqual(["%sqlmap%"], params)
        self.assertEqual("test.rule", meta["id"])

    def test_a_list_of_values_is_ored(self):
        _, where, params = sigma.compile_rule(rule(detection=(
            "  sel:\n    c-useragent|contains: [a, b]\n  condition: sel")))
        self.assertIn(" OR ", where)
        self.assertEqual(["%a%", "%b%"], params)

    def test_the_all_modifier_ands_them_instead(self):
        _, where, _ = sigma.compile_rule(rule(detection=(
            "  sel:\n    c-uri|contains|all: [a, b]\n  condition: sel")))
        self.assertIn(" AND ", where)

    def test_two_selections_can_be_combined(self):
        _, where, params = sigma.compile_rule(rule(detection=(
            "  probe:\n    c-uri|contains: union\n"
            "  ok:\n    sc-status: 200\n  condition: probe and ok")))
        self.assertIn(" AND ", where)
        self.assertEqual(["%union%", 200], params)

    def test_a_number_stays_a_number(self):
        """`sc-status: 200` compared as the string '200' matches nothing, and
        matches nothing SILENTLY."""
        _, _, params = sigma.compile_rule(rule(detection=(
            "  sel:\n    sc-status: 404\n  condition: sel")))
        self.assertEqual([404], params)
        self.assertIsInstance(params[0], int)

    def test_wildcards_in_a_value_are_escaped(self):
        """A URL is full of `%` and `_`. Unescaped they become LIKE
        wildcards and the rule quietly widens."""
        _, where, params = sigma.compile_rule(rule(detection=(
            "  sel:\n    c-uri|contains: '%23value'\n  condition: sel")))
        self.assertIn("ESCAPE", where)
        self.assertIn("\\%", params[0])

    def test_one_of_them_and_all_of_them(self):
        detection = ("  sel1:\n    c-uri|contains: a\n"
                     "  sel2:\n    c-uri|contains: b\n  condition: ")
        _, any_where, _ = sigma.compile_rule(
            rule(detection=detection + "1 of them"))
        _, all_where, _ = sigma.compile_rule(
            rule(detection=detection + "all of them"))
        self.assertIn(" OR ", any_where)
        self.assertIn(" AND ", all_where)

    def test_not_is_supported(self):
        _, where, _ = sigma.compile_rule(rule(detection=(
            "  sel:\n    c-uri|contains: a\n"
            "  noise:\n    c-useragent|contains: bot\n"
            "  condition: sel and not noise")))
        self.assertIn("NOT", where)


class RefusalTests(unittest.TestCase):
    """What the backend will not pretend to answer.

    Every one of these could instead be accepted and compiled into something
    that matches nothing. That is the failure this class exists to prevent."""

    def _refused(self, text):
        with self.assertRaises(sigma.SigmaError) as caught:
            sigma.compile_rule(text)
        return str(caught.exception)

    def test_a_field_the_index_does_not_carry(self):
        message = self._refused(rule(detection=(
            "  sel:\n    cs-referrer-x: a\n  condition: sel")))
        self.assertIn("not in the log index", message)

    def test_a_regex_modifier(self):
        message = self._refused(rule(detection=(
            "  sel:\n    c-uri|re: 'foo.*bar'\n  condition: sel")))
        self.assertIn("not supported", message)

    def test_an_aggregation(self):
        message = self._refused(rule(detection=(
            "  sel:\n    c-uri|contains: a\n"
            "  condition: sel | count() by c-ip > 5")))
        self.assertIn("Aggregation", message)

    def test_a_timeframe(self):
        message = self._refused(rule(detection=(
            "  sel:\n    c-uri|contains: a\n  timeframe: 5m\n"
            "  condition: sel")))
        self.assertIn("aggregation", message.lower())

    def test_a_condition_naming_a_selection_that_is_not_there(self):
        message = self._refused(rule(detection=(
            "  sel:\n    c-uri|contains: a\n  condition: other")))
        self.assertIn("not a selection", message)

    def test_a_rule_without_an_id(self):
        message = self._refused(
            "title: X\nlevel: low\ndetection:\n"
            "  sel:\n    c-uri|contains: a\n  condition: sel\n")
        self.assertIn("no `id`", message)

    def test_a_rule_without_a_title(self):
        message = self._refused(
            "id: x.y\nlevel: low\ndetection:\n"
            "  sel:\n    c-uri|contains: a\n  condition: sel\n")
        self.assertIn("no `title`", message)

    def test_broken_yaml(self):
        self.assertIn("YAML", self._refused("title: [unclosed\n"))


class EngineTests(unittest.TestCase):
    """Real rules against a real index."""

    @classmethod
    def setUpClass(cls):
        cls.case = Path(tempfile.mkdtemp(prefix="shellhound-sig-"))
        cls.ws = Path(tempfile.mkdtemp(prefix="shellhound-sigws-"))
        db.connect(cls.case).close()
        logs = Path(tempfile.mkdtemp(prefix="shellhound-siglog-"))
        (logs / "access.log").write_text(LOG, encoding="utf-8")
        logindex.build(cls.case, [str(logs)])

    def _write(self, name, text):
        directory = self.ws / "sigma"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / name).write_text(text, encoding="utf-8")

    def _clear(self):
        directory = self.ws / "sigma"
        if directory.is_dir():
            for path in directory.iterdir():
                path.unlink()
        conn = db.connect(self.case)
        try:
            conn.execute("DELETE FROM findings")
            conn.commit()
        finally:
            conn.close()

    def _findings(self):
        conn = db.connect(self.case)
        try:
            return [dict(r) for r in db.rows(
                conn, "SELECT rule, artifact, severity FROM findings")]
        finally:
            conn.close()

    def setUp(self):
        self._clear()

    def test_a_rule_finds_the_client_it_should(self):
        self._write("scanner.yml", rule(
            title="Scanner user agent", id="own.scanner", level="high",
            detection="  sel:\n    c-useragent|contains: sqlmap\n"
                      "  condition: sel"))
        stats = sigmascan.scan(self.case, workspace=self.ws)
        self.assertEqual(1, stats["rules"])
        found = self._findings()
        self.assertEqual(["203.0.113.7"], [f["artifact"] for f in found])
        self.assertEqual("Scanner user agent", found[0]["rule"])

    def test_it_finds_nobody_when_nothing_matches(self):
        self._write("none.yml", rule(
            id="own.none",
            detection="  sel:\n    c-useragent|contains: nessus\n"
                      "  condition: sel"))
        sigmascan.scan(self.case, workspace=self.ws)
        self.assertEqual([], self._findings())

    def test_a_status_selection_actually_filters(self):
        self._write("posts.yml", rule(
            title="Redirect after login POST", id="own.redirect",
            detection="  sel:\n    cs-method: POST\n"
                      "  redirect:\n    sc-status: 302\n"
                      "  condition: sel and redirect"))
        sigmascan.scan(self.case, workspace=self.ws)
        self.assertEqual(["198.51.100.4"],
                         [f["artifact"] for f in self._findings()])

    def test_a_rule_that_only_hit_refusals_lands_at_low(self):
        """Outcome-gating, which a SIGMA rule cannot express itself: the
        rule's own level applies only when something was answered."""
        self._write("miss.yml", rule(
            title="Only 404s", id="own.notfound", level="high",
            detection="  sel:\n    c-uri|contains: /admin\n"
                      "  condition: sel"))
        sigmascan.scan(self.case, workspace=self.ws)
        found = self._findings()
        self.assertEqual(1, len(found))
        self.assertEqual(db.SEV_LOW, found[0]["severity"])

    def test_an_unusable_rule_is_reported_and_costs_only_itself(self):
        self._write("good.yml", rule(
            title="Good", id="own.good",
            detection="  sel:\n    c-useragent|contains: sqlmap\n"
                      "  condition: sel"))
        self._write("bad.yml", rule(
            id="own.bad",
            detection="  sel:\n    made-up-field: a\n  condition: sel"))
        stats = sigmascan.scan(self.case, workspace=self.ws)
        self.assertEqual(1, stats["rules"])
        self.assertEqual(1, stats["broken_rules"])
        self.assertTrue(self._findings(), "the good rule did not run")

    def test_a_switched_off_rule_does_not_run(self):
        self._write("scanner.yml", rule(
            title="Scanner user agent", id="own.scanner",
            detection="  sel:\n    c-useragent|contains: sqlmap\n"
                      "  condition: sel"))
        ruleswitch.set_enabled(self.ws, "own.scanner", False)
        try:
            stats = sigmascan.scan(self.case, workspace=self.ws)
            self.assertEqual(0, stats["rules"])
            self.assertEqual([], self._findings())
        finally:
            ruleswitch.set_enabled(self.ws, "own.scanner", True)

    def test_no_workspace_means_no_rules_not_an_error(self):
        self.assertEqual(0, sigmascan.scan(self.case)["rules"])

    def test_status_separates_no_rules_from_broken_ones(self):
        empty = sigmascan.status(Path(tempfile.mkdtemp()))
        self.assertEqual("norules", empty["reason"])
        self._write("bad.yml", rule(
            id="own.bad",
            detection="  sel:\n    made-up-field: a\n  condition: sel"))
        st = sigmascan.status(self.ws)
        self.assertEqual("", st["reason"])
        self.assertEqual(1, len(st["broken"]))


if __name__ == "__main__":
    unittest.main()
