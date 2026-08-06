# tests/test_rules.py
"""The rule catalogue and the switch.

The failure this file exists for is DRIFT. A rule id lives next to the rule
that implements it, and the catalogue reads the engines rather than repeating
them -- except for the handful of rules that are not table-driven, which are
listed in `server/rules.py` by hand. Those are the ones that can silently
part ways with the code: somebody renames an id in the engine, the catalogue
keeps the old one, and the off-switch stops matching anything without a
single error anywhere.

The second thing guarded here is what a switch DOES NOT do. Switching a rule
off must not touch findings it already wrote, because triage decisions are
the analyst's and a muted rule is not a retraction.
"""
import os
import re
import tempfile
import unittest
from pathlib import Path

from server import (bundled_rules, db, rules, ruleswitch,
                    settings as settingslib)
from server.engines import errorlog, logindex, sqldump, webshell

ROOT = Path(__file__).resolve().parent.parent
ENGINE_DIR = ROOT / "server" / "engines"
BUNDLED_DIR = ROOT / "server" / "rules_bundled"
# The literal ids the engines pass to `findings.append` / build by hand, and
# the ones the bundled YARA rules declare in their metadata. Both places
# count: an id lives wherever its rule lives.
ID_IN_SOURCE = re.compile(r'"((?:webshell|sqldb|errorlog)\.[a-z_]+)"')


def ids_in_the_code():
    found = set()
    for name in ("webshell.py", "sqldump.py", "errorlog.py"):
        found |= set(ID_IN_SOURCE.findall(
            (ENGINE_DIR / name).read_text(encoding="utf-8")))
    for path in BUNDLED_DIR.glob("*.yar"):
        found |= set(ID_IN_SOURCE.findall(path.read_text(encoding="utf-8")))
    return found


class CatalogueTests(unittest.TestCase):

    def setUp(self):
        self.rows = rules.catalogue()

    def test_it_is_not_empty(self):
        self.assertGreater(len(self.rows), 25)

    def test_every_id_is_unique(self):
        ids = [r["id"] for r in self.rows]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_id_is_prefixed_with_a_known_engine(self):
        for row in self.rows:
            self.assertIn(row["engine"], rules.ENGINES, row["id"])

    def test_every_rule_has_a_name_and_a_severity(self):
        for row in self.rows:
            self.assertTrue(row["name"].strip(), row["id"])
            self.assertIn(row["severity"],
                          (db.SEV_HIGH, db.SEV_MEDIUM, db.SEV_LOW, db.SEV_INFO))

    def test_the_table_driven_rules_all_arrived(self):
        ids = {r["id"] for r in self.rows}
        for entry in sqldump.RULES:
            self.assertIn(entry[0], ids)
        for kind in logindex._ALERT_FINDING:
            self.assertIn(f"logs.{kind}", ids)

    def test_the_bundled_yara_rules_all_arrived(self):
        ids = {r["id"] for r in self.rows}
        for entry in bundled_rules.catalogue():
            self.assertIn(entry["id"], ids)

    def test_every_rule_says_what_form_it_is_in(self):
        """The analyst decides whether they want a rule by reading it. A
        YARA rule shows its source, a table rule its pattern, and the rest
        say plainly that there is no single expression to show rather than
        inventing a readable-looking one."""
        for row in self.rows:
            self.assertIn(row["format"], ("yara", "regex", "builtin"))
            if row["format"] in ("yara", "regex"):
                self.assertTrue(row["source"].strip(), row["id"])

    def test_no_id_in_an_engine_is_missing_from_the_catalogue(self):
        """The drift check. Any id an engine names must be listed, or it is a
        rule nobody can switch off."""
        missing = ids_in_the_code() - {r["id"] for r in self.rows}
        self.assertEqual(set(), missing, "engines emit ids nobody catalogued")

    def test_no_catalogued_id_is_absent_from_the_engines(self):
        """The other direction: a catalogue entry for a rule that no longer
        exists is a switch that does nothing."""
        stale = {r["id"] for r in self.rows
                 if not r["id"].startswith("logs.")} - ids_in_the_code()
        self.assertEqual(set(), stale, "catalogued rules the engines dropped")


class SwitchTests(unittest.TestCase):

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="shellhound-rs-"))
        self.rid = "webshell.eval_input"

    def test_everything_starts_switched_on(self):
        for row in rules.public(self.ws)["rules"]:
            self.assertTrue(row["enabled"], row["id"])

    def test_a_rule_can_be_switched_off_and_back_on(self):
        ruleswitch.set_enabled(self.ws, self.rid, False)
        self.assertFalse(ruleswitch.enabled(self.ws, self.rid))
        ruleswitch.set_enabled(self.ws, self.rid, True)
        self.assertTrue(ruleswitch.enabled(self.ws, self.rid))

    def test_an_unknown_id_counts_as_enabled(self):
        """A rule an upgrade adds must arrive RUNNING. The alternative is a
        rule that silently does not fire because a stale off-list names it."""
        self.assertTrue(ruleswitch.enabled(self.ws, "webshell.invented_later"))

    def test_the_off_list_survives_an_unrelated_settings_write(self):
        ruleswitch.set_enabled(self.ws, self.rid, False)
        settingslib.set_ack(self.ws, True)
        self.assertEqual({self.rid}, ruleswitch.disabled_ids(self.ws))

    def test_yara_and_rule_switches_do_not_overwrite_each_other(self):
        ruleswitch.set_enabled(self.ws, self.rid, False)
        settingslib.set_yara_disabled(self.ws, {"vendor.yar"})
        self.assertEqual({self.rid}, ruleswitch.disabled_ids(self.ws))
        self.assertEqual({"vendor.yar"}, settingslib.yara_disabled(self.ws))

    def test_filter_rules_drops_the_switched_off_ones(self):
        ruleswitch.set_enabled(self.ws, "sqldb.php_tag", False)
        kept = ruleswitch.filter_rules(self.ws, sqldump.RULES)
        self.assertNotIn("sqldb.php_tag", [r[0] for r in kept])
        self.assertEqual(len(sqldump.RULES) - 1, len(kept))


class EffectTests(unittest.TestCase):
    """What the switch does to an actual scan."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="shellhound-re-"))
        self.case = Path(tempfile.mkdtemp(prefix="shellhound-rc-"))
        self.root = Path(tempfile.mkdtemp(prefix="shellhound-rr-"))
        db.connect(self.case).close()
        (self.root / "shell.php").write_text(
            "<?php eval(base64_decode($_POST['x'])); ?>", encoding="utf-8")

    def _rules_found(self):
        conn = db.connect(self.case)
        try:
            return {r["rule"] for r in db.rows(conn, "SELECT rule FROM findings")}
        finally:
            conn.close()

    def test_the_rule_fires_while_it_is_on(self):
        webshell.scan(self.case, [str(self.root)], workspace=self.ws)
        self.assertTrue(any("eval" in r for r in self._rules_found()))

    def test_it_writes_nothing_once_switched_off(self):
        ruleswitch.set_enabled(self.ws, "webshell.eval_input", False)
        webshell.scan(self.case, [str(self.root)], workspace=self.ws)
        self.assertFalse(any("eval/assert" in r for r in self._rules_found()))

    def test_switching_off_does_not_delete_what_it_already_wrote(self):
        """A switch is not a retraction. An artifact somebody confirmed does
        not stop being confirmed because the rule was later muted."""
        webshell.scan(self.case, [str(self.root)], workspace=self.ws)
        before = self._rules_found()
        self.assertTrue(before)
        ruleswitch.set_enabled(self.ws, "webshell.eval_input", False)
        webshell.scan(self.case, [str(self.root)], workspace=self.ws)
        self.assertTrue(self._rules_found() >= before)

    def test_without_a_workspace_every_rule_runs(self):
        """The engines are callable on their own -- the tests do it. No
        workspace means no off-list, not an empty rule set."""
        webshell.scan(self.case, [str(self.root)])
        self.assertTrue(self._rules_found())

    def test_the_other_rules_keep_running(self):
        ruleswitch.set_enabled(self.ws, "webshell.eval_input", False)
        (self.root / "drop.php").write_text(
            "<?php file_put_contents('x.php', $_POST['c']); ?>",
            encoding="utf-8")
        webshell.scan(self.case, [str(self.root)], workspace=self.ws)
        self.assertTrue(any("dropper" in r.lower() or "File dropper" in r
                            for r in self._rules_found()))


if __name__ == "__main__":
    unittest.main()
