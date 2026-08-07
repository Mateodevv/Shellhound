# tests/test_yara_rules.py
"""Managing YARA rule files from the interface.

Two things are being guarded here. The first is the file name: it arrives
from the browser and becomes a PATH, and a local single-seat tool is not a
reason to hand out a write-anywhere endpoint. The second is the off-switch:
a rule set can come from a CERT or a vendor feed, so parking one must not
edit somebody else's text.

The compile checks skip without yara-python, exactly as the engine does.
Everything about names, storage and the off-switch runs either way, because
that is where the damage would be.
"""
import os
import tempfile
import unittest
from pathlib import Path

from server import settings as settingslib
from server.engines import yarascan

GOOD = 'rule Demo { strings: $a = "evil" condition: $a }'


class NameTests(unittest.TestCase):
    """The name is hostile input until proven otherwise."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="shellhound-yn-"))

    def test_a_bare_name_gets_the_suffix(self):
        name, _ = yarascan._safe_path(self.ws, "my-rules")
        self.assertEqual("my-rules.yar", name)

    def test_an_existing_suffix_is_kept(self):
        for given in ("a.yar", "a.yara", "A.YAR"):
            name, _ = yarascan._safe_path(self.ws, given)
            self.assertEqual(given, name)

    def test_the_path_stays_in_the_rules_directory(self):
        _, full = yarascan._safe_path(self.ws, "ok.yar")
        self.assertEqual(os.path.abspath(yarascan.rules_dir(self.ws)),
                         os.path.dirname(full))

    def test_traversal_and_separators_are_refused(self):
        for evil in ("../evil", "..\\evil", "a/b", "a\\b", "..", "../../x.yar",
                     "/etc/passwd", "C:\\Windows\\x.yar", ".hidden", "",
                     "   ", "x" * 80, "a;b", "a b", "a|b", "\u0000x"):
            with self.assertRaises(yarascan.RuleError,
                                   msg=f"accepted {evil!r}"):
                yarascan._safe_path(self.ws, evil)

    def test_writing_cannot_escape_either(self):
        """The guard is checked on the way in, not only in the helper."""
        with self.assertRaises(yarascan.RuleError):
            yarascan.write_rule(self.ws, "../escaped.yar", GOOD)
        self.assertFalse((self.ws.parent / "escaped.yar").exists())


class RuleParsingTests(unittest.TestCase):

    def test_declarations_are_found_including_modifiers(self):
        self.assertEqual(
            ["Foo", "Bar", "Baz"],
            yarascan.rule_names_in(
                "rule Foo {}\nprivate rule Bar {}\nglobal private rule Baz {}"))

    def test_the_word_rule_elsewhere_is_not_counted(self):
        """A bare count of "rule " picks it out of comments and strings, and
        then the interface reports a file as holding rules it does not."""
        text = ('// this rule is about a rule\n'
                'rule Real { strings: $a = "a rule of thumb" condition: $a }')
        self.assertEqual(["Real"], yarascan.rule_names_in(text))


class StorageTests(unittest.TestCase):

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="shellhound-ys-"))

    def test_a_rule_file_is_written_and_read_back(self):
        out = yarascan.write_rule(self.ws, "demo", GOOD)
        self.assertEqual("demo.yar", out["name"])
        self.assertEqual(["Demo"], out["rules"])
        self.assertIn("rule Demo", yarascan.read_rule(self.ws, "demo.yar"))

    def test_the_directory_is_created_on_first_write(self):
        self.assertFalse(os.path.isdir(yarascan.rules_dir(self.ws)))
        yarascan.write_rule(self.ws, "demo", GOOD)
        self.assertTrue(os.path.isdir(yarascan.rules_dir(self.ws)))

    def test_a_second_write_replaces_rather_than_appends(self):
        yarascan.write_rule(self.ws, "demo", GOOD)
        yarascan.write_rule(self.ws, "demo", 'rule Other { condition: false }')
        text = yarascan.read_rule(self.ws, "demo.yar")
        self.assertNotIn("Demo", text)
        self.assertEqual(["Other"], yarascan.rule_names_in(text))

    def test_no_temporary_file_is_left_behind(self):
        yarascan.write_rule(self.ws, "demo", GOOD)
        leftovers = [n for n in os.listdir(yarascan.rules_dir(self.ws))
                     if n.endswith(".tmp")]
        self.assertEqual([], leftovers)

    def test_reading_something_that_is_not_there(self):
        with self.assertRaises(yarascan.RuleError) as caught:
            yarascan.read_rule(self.ws, "nope.yar")
        self.assertEqual("err.yaraUnknown", caught.exception.key)

    def test_deleting_removes_the_file(self):
        yarascan.write_rule(self.ws, "demo", GOOD)
        yarascan.delete_rule(self.ws, "demo.yar")
        self.assertEqual([], yarascan.rule_file_names(self.ws))


class OffSwitchTests(unittest.TestCase):

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="shellhound-yo-"))
        yarascan.write_rule(self.ws, "demo", GOOD)

    def test_a_switched_off_file_is_not_compiled(self):
        self.assertEqual(1, len(yarascan.rule_files(self.ws)))
        yarascan.set_rule_enabled(self.ws, "demo.yar", False)
        self.assertEqual([], yarascan.rule_files(self.ws))

    def test_it_is_still_listed_so_it_can_come_back(self):
        yarascan.set_rule_enabled(self.ws, "demo.yar", False)
        rows = yarascan.list_rules(self.ws)
        self.assertEqual(1, len(rows))
        self.assertFalse(rows[0]["enabled"])
        self.assertEqual(["demo.yar"], yarascan.rule_file_names(self.ws))

    def test_switching_off_does_not_touch_the_file(self):
        """It may be somebody else's text -- a vendor feed, a CERT ruleset."""
        before = yarascan.read_rule(self.ws, "demo.yar")
        yarascan.set_rule_enabled(self.ws, "demo.yar", False)
        self.assertEqual(before, yarascan.read_rule(self.ws, "demo.yar"))

    def test_it_can_be_switched_back_on(self):
        yarascan.set_rule_enabled(self.ws, "demo.yar", False)
        yarascan.set_rule_enabled(self.ws, "demo.yar", True)
        self.assertEqual(1, len(yarascan.rule_files(self.ws)))

    def test_switching_something_that_is_not_there(self):
        with self.assertRaises(yarascan.RuleError):
            yarascan.set_rule_enabled(self.ws, "nope.yar", False)

    def test_deleting_clears_the_off_entry(self):
        """Otherwise a later file of the same name arrives switched off, for
        a reason nothing on screen explains."""
        yarascan.set_rule_enabled(self.ws, "demo.yar", False)
        yarascan.delete_rule(self.ws, "demo.yar")
        yarascan.write_rule(self.ws, "demo", GOOD)
        self.assertTrue(yarascan.list_rules(self.ws)[0]["enabled"])

    def test_the_off_list_survives_an_unrelated_settings_write(self):
        """settings.load() drops what it does not know, so every key the file
        may carry has to be part of the model."""
        yarascan.set_rule_enabled(self.ws, "demo.yar", False)
        settingslib.set_ack(self.ws, True)
        self.assertEqual({"demo.yar"}, settingslib.yara_disabled(self.ws))

    def test_status_separates_no_rules_from_all_switched_off(self):
        """Two silences that look identical in the job output and are not."""
        if yarascan.yara is None:
            self.skipTest("yara-python not installed")
        self.assertEqual("", yarascan.status(self.ws)["reason"])
        yarascan.set_rule_enabled(self.ws, "demo.yar", False)
        self.assertEqual("alloff", yarascan.status(self.ws)["reason"])
        yarascan.delete_rule(self.ws, "demo.yar")
        self.assertEqual("norules", yarascan.status(self.ws)["reason"])


@unittest.skipIf(yarascan.yara is None, "yara-python not installed")
class CompileTests(unittest.TestCase):

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="shellhound-yc-"))

    def test_a_broken_rule_is_refused_at_save_time(self):
        """Cheaper than finding out mid-case, when the scan reports it as
        skipped."""
        with self.assertRaises(yarascan.RuleError) as caught:
            yarascan.write_rule(self.ws, "bad", "rule Broken { this is not yara")
        self.assertEqual("err.yaraCompile", caught.exception.key)

    def test_the_broken_file_is_not_written(self):
        try:
            yarascan.write_rule(self.ws, "bad", "rule Broken {")
        except yarascan.RuleError:
            pass
        self.assertEqual([], yarascan.rule_file_names(self.ws))

    def test_a_file_broken_outside_the_editor_is_reported_not_hidden(self):
        """Rules can be dropped into the folder by hand."""
        os.makedirs(yarascan.rules_dir(self.ws), exist_ok=True)
        Path(yarascan.rules_dir(self.ws), "hand.yar").write_text(
            "rule Nope {", encoding="utf-8")
        row = yarascan.list_rules(self.ws)[0]
        self.assertTrue(row["error"])


class ExplanationCoverageTests(unittest.TestCase):
    """Every shipped rule has to be explainable in the interface.

    `explain.ts` maps a SUBSTRING of the rule name to a translation key, and
    the fallback for an unmatched name is silence -- a finding on screen with
    nothing behind the "what does this mean" panel. Nothing failed when two
    new rules arrived without an entry, because the mapping lives in
    TypeScript and the rule names in a .yar file, and no test looked at both.
    """

    ROOT = Path(__file__).resolve().parent.parent

    def _rule_keys(self):
        import re
        text = (self.ROOT / "web" / "src" / "explain.ts").read_text(
            encoding="utf-8")
        # Not `split("]")`: the type annotation `[string, string][]` puts two
        # of them before the array even opens.
        block = text.split("RULE_KEYS", 1)[1].split("\n];", 1)[0]
        return re.findall(r"\[\s*'((?:[^'\\]|\\.)*)'\s*,\s*'([^']+)'\s*\]",
                          block)

    def test_every_bundled_rule_name_reaches_an_explanation(self):
        from server import rules
        keys = self._rule_keys()
        self.assertGreater(len(keys), 20, "the mapping did not parse")
        missing = [r["name"] for r in rules.catalogue()
                   if not any(k.lower() in r["name"].lower() for k, _ in keys)]
        self.assertEqual([], missing)

    def test_every_key_the_mapping_names_exists_in_both_languages(self):
        for lang in ("en", "de"):
            text = (self.ROOT / "web" / "src" / "i18n" / f"{lang}.ts").read_text(
                encoding="utf-8")
            for _, key in self._rule_keys():
                for part in (".what", ".why"):
                    self.assertIn(f"'{key}{part}'", text, f"{lang}: {key}{part}")


if __name__ == "__main__":
    unittest.main()
