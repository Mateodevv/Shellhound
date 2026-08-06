# tests/test_patterns.py
"""The two halves of the hunt library.

The assertions that matter are about the seam between them. A bundled pattern
lives in the package and an own pattern lives in the workspace, and almost
every way of getting that wrong is silent: a delete that undoes itself on the
next start, a duplicate that reports every hit twice, an upgrade that discards
the analyst's decisions, an export that lands as a pile of skips.
"""

import json
import tempfile
import unittest
from pathlib import Path

from server import patterns


class BundledSetTests(unittest.TestCase):
    """The shipped file itself. It goes into a wheel, so a mistake here is
    shipped to everyone."""

    def setUp(self):
        self.rows = patterns.bundled()

    def test_the_file_is_there_and_not_empty(self):
        self.assertTrue(self.rows, "no bundled patterns were read")

    def test_every_entry_has_a_stable_id(self):
        """The per-workspace off-switch stores ids. A generated id would
        forget every decision on the next start."""
        for row in self.rows:
            self.assertTrue(row["id"], f"{row['pattern']} has no id")
            self.assertNotRegex(row["id"], r"^[0-9a-f]{12}$",
                                "looks like a generated id")

    def test_ids_are_unique(self):
        ids = [r["id"] for r in self.rows]
        self.assertEqual(len(ids), len(set(ids)))

    def test_patterns_are_unique(self):
        """Two entries matching the same path would report every hit twice."""
        seen = [r["pattern"].lower() for r in self.rows]
        self.assertEqual(len(seen), len(set(seen)))

    def test_every_entry_survives_its_own_validation(self):
        """A shipped pattern that `add` would reject is a pattern nobody can
        re-create after switching it off."""
        for row in self.rows:
            patterns._validate(row["pattern"])

    def test_every_entry_says_what_a_hit_means(self):
        for row in self.rows:
            self.assertTrue(row["label"], f"{row['id']} has no label")
            self.assertTrue(row["about"], f"{row['id']} explains nothing")

    def test_they_are_marked_as_bundled(self):
        for row in self.rows:
            self.assertEqual("bundled", row["source"])


class LibraryTests(unittest.TestCase):

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="shellhound-pat-"))
        self.first = patterns.bundled()[0]["id"]

    def test_a_fresh_workspace_already_has_the_shipped_patterns(self):
        """The point of the feature: a new installation can hunt before the
        analyst has written anything."""
        lib = patterns.library(self.ws)
        self.assertTrue(lib)
        self.assertTrue(all(p["source"] == "bundled" for p in lib))
        self.assertEqual([], patterns.load(self.ws))

    def test_own_patterns_come_after_the_bundled_ones(self):
        patterns.add(self.ws, "/my/own/path.php", "mine")
        lib = patterns.library(self.ws)
        self.assertEqual("own", lib[-1]["source"])
        self.assertEqual("bundled", lib[0]["source"])

    def test_switching_one_off_removes_it_from_the_run(self):
        patterns.set_enabled(self.ws, self.first, False)
        ids = [p["id"] for p in patterns.library(self.ws)]
        self.assertNotIn(self.first, ids)

    def test_a_switched_off_pattern_is_still_offered_back(self):
        """Otherwise it is a delete with extra steps and no way back."""
        patterns.set_enabled(self.ws, self.first, False)
        shown = {p["id"]: p for p in
                 patterns.library(self.ws, include_disabled=True)}
        self.assertIn(self.first, shown)
        self.assertFalse(shown[self.first]["enabled"])

    def test_switching_it_back_on_works(self):
        patterns.set_enabled(self.ws, self.first, False)
        patterns.set_enabled(self.ws, self.first, True)
        self.assertIn(self.first, [p["id"] for p in patterns.library(self.ws)])

    def test_deleting_a_bundled_pattern_switches_it_off_instead(self):
        """A delete would last until the next start and then undo itself."""
        out = patterns.remove(self.ws, self.first)
        self.assertEqual({"removed": 0, "disabled": 1}, out)
        self.assertNotIn(self.first, [p["id"] for p in patterns.library(self.ws)])

    def test_a_bundled_pattern_cannot_be_edited(self):
        with self.assertRaises(patterns.PatternError) as caught:
            patterns.update(self.ws, self.first, pattern="/something/else")
        self.assertEqual("err.patternBundled", caught.exception.key)

    def test_the_shipped_file_is_never_written_to(self):
        before = patterns.BUNDLED_FILE.read_bytes()
        patterns.set_enabled(self.ws, self.first, False)
        patterns.add(self.ws, "/another/path.php")
        patterns.remove(self.ws, self.first)
        self.assertEqual(before, patterns.BUNDLED_FILE.read_bytes())

    def test_decisions_survive_an_upgrade_that_adds_patterns(self):
        """The off-switch stores ids, so a bundled set that grows must not
        disturb what was already switched off."""
        patterns.set_enabled(self.ws, self.first, False)
        patterns.add(self.ws, "/mine.php", "mine")
        self.assertEqual({self.first}, patterns.disabled_ids(self.ws))
        self.assertEqual(["mine"], [p["label"] for p in patterns.load(self.ws)])


class DuplicateTests(unittest.TestCase):

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="shellhound-dup-"))
        self.entry = patterns.bundled()[0]

    def test_a_copy_of_a_bundled_pattern_is_refused(self):
        with self.assertRaises(patterns.PatternError) as caught:
            patterns.add(self.ws, self.entry["pattern"], "my copy")
        self.assertEqual("err.patternKnown", caught.exception.key)

    def test_it_is_refused_even_while_switched_off(self):
        """Otherwise switching the bundled one back on later would silently
        duplicate every hit it produces."""
        patterns.set_enabled(self.ws, self.entry["id"], False)
        with self.assertRaises(patterns.PatternError):
            patterns.add(self.ws, self.entry["pattern"], "my copy")


class ExchangeTests(unittest.TestCase):

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="shellhound-exc-"))

    def test_the_export_carries_own_patterns_only(self):
        """The bundled ones travel with the tool; exporting them would land
        on the other side as duplicates and report a pile of skips."""
        patterns.add(self.ws, "/mine/one.php", "one")
        out = json.loads(patterns.export_text(self.ws))
        self.assertEqual(["one"], [p["label"] for p in out["patterns"]])

    def test_an_exported_file_imports_cleanly_elsewhere(self):
        patterns.add(self.ws, "/mine/one.php", "one")
        patterns.add(self.ws, "/mine/two.php", "two")
        other = Path(tempfile.mkdtemp(prefix="shellhound-exc2-"))
        got = patterns.import_text(other, patterns.export_text(self.ws))
        self.assertEqual({"added": 2, "skipped": 0, "invalid": 0}, got)

    def test_an_import_that_repeats_a_bundled_pattern_skips_it(self):
        text = patterns.bundled()[0]["pattern"] + " | copy"
        self.assertEqual({"added": 0, "skipped": 1, "invalid": 0},
                         patterns.import_text(self.ws, text))


class WorkspaceFileTests(unittest.TestCase):

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="shellhound-file-"))

    def test_an_older_library_without_the_disabled_key_still_loads(self):
        """Workspaces written before this feature existed."""
        patterns.library_path(self.ws).write_text(
            json.dumps({"patterns": [{"id": "x1", "pattern": "/old.php",
                                      "label": "old"}]}), encoding="utf-8")
        self.assertEqual(["old"], [p["label"] for p in patterns.load(self.ws)])
        self.assertEqual(set(), patterns.disabled_ids(self.ws))

    def test_a_bare_list_still_loads(self):
        """The oldest form of the file."""
        patterns.library_path(self.ws).write_text(
            json.dumps([{"id": "x1", "pattern": "/old.php", "label": "old"}]),
            encoding="utf-8")
        self.assertEqual(["old"], [p["label"] for p in patterns.load(self.ws)])

    def test_a_broken_file_costs_the_own_patterns_and_nothing_else(self):
        """It must never be the reason the interface no longer opens -- and
        the shipped patterns have nothing to do with that file."""
        patterns.library_path(self.ws).write_text("{ not json",
                                                  encoding="utf-8")
        self.assertEqual([], patterns.load(self.ws))
        self.assertTrue(patterns.library(self.ws))

    def test_saving_does_not_write_derived_fields(self):
        """`source` and `enabled` say which half an entry came from and
        whether it is switched on. Both are computed; stored, they would go
        stale.

        TWO patterns, not one: a freshly built entry carries neither field, so
        it is only the SECOND save -- which round-trips the first through
        `load`, where the fields are attached -- that can leak them."""
        patterns.add(self.ws, "/mine.php", "mine")
        patterns.add(self.ws, "/mine-too.php", "also mine")
        raw = json.loads(
            patterns.library_path(self.ws).read_text(encoding="utf-8"))
        for row in raw["patterns"]:
            self.assertNotIn("source", row)
            self.assertNotIn("enabled", row)


if __name__ == "__main__":
    unittest.main()
