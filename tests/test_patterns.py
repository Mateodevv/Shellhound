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
from server.engines import logindex


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
            self.assertTrue(row["id"], f"{row['patterns']} has no id")
            self.assertNotRegex(row["id"], r"^[0-9a-f]{12}$",
                                "looks like a generated id")

    def test_ids_are_unique(self):
        ids = [r["id"] for r in self.rows]
        self.assertEqual(len(ids), len(set(ids)))

    def test_patterns_are_unique(self):
        """Two entries matching the same path would report every hit twice."""
        seen = [tuple(sorted(q.lower() for q in r["patterns"])) for r in self.rows]
        self.assertEqual(len(seen), len(set(seen)))

    def test_every_entry_survives_its_own_validation(self):
        """A shipped pattern that `add` would reject is a pattern nobody can
        re-create after switching it off."""
        for row in self.rows:
            patterns._validate(row["patterns"])

    def test_every_entry_says_what_a_hit_means(self):
        for row in self.rows:
            self.assertTrue(row["name"], f"{row['id']} has no label")
            self.assertTrue(row["description"], f"{row['id']} explains nothing")

    def test_they_are_marked_as_bundled(self):
        for row in self.rows:
            self.assertEqual("bundled", row["source"])


class Wp2ShellPatternTests(unittest.TestCase):
    """The shipped wp2shell IOCs stay narrow on real IIS W3C fields."""

    @staticmethod
    def entry():
        return next(row for row in patterns.bundled()
                    if row["id"] == "wordpress-wp2shell-poc-webshell")

    @staticmethod
    def batch_entry():
        return next(row for row in patterns.bundled()
                    if row["id"] == "wordpress-wp2shell-batch-tooling")

    def test_the_entry_names_both_vulnerabilities_and_its_limit(self):
        entry = self.entry()
        self.assertEqual("CVE-2026-63030 + CVE-2026-60137", entry["cve"])
        self.assertIn("WHAT A HIT DOES NOT PROVE:", entry["description"])
        self.assertIn("batch", entry["description"].lower())

    def test_the_known_poc_shell_path_matches_without_selecting_static_assets(
            self):
        header = (
            "#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query "
            "sc-status sc-bytes cs(User-Agent) cs(Referer)\n"
        )
        attacker = "198.51.100.40"
        with tempfile.TemporaryDirectory(prefix="shellhound-wp2shell-") as root:
            case = Path(root, "case")
            logs = Path(root, "logs")
            case.mkdir()
            logs.mkdir()
            Path(logs, "u_ex.log").write_text(
                header
                + "2026-08-26 12:00:00 198.51.100.40 GET "
                  "/wp-content/plugins/wp2shell_79b06a80/"
                  "wp2shell_79b06a80.php t=token%26c=id 200 12 wp2shell -\n"
                + "2026-08-26 12:00:01 203.0.113.8 GET "
                  "/wp-content/plugins/wp2shell-helper/assets/app.js "
                  "- 200 1200 Mozilla/5.0 -\n",
                encoding="utf-8",
            )
            logindex.build(case, [str(logs)])

            entry = self.entry()
            match = logindex.match_patterns(
                case, entry["patterns"], entry["match"])

        self.assertEqual(1, match["hits"])
        self.assertEqual([attacker], [row["ip"] for row in match["clients"]])
        self.assertIn("wp2shell_79b06a80.php", match["uris"][0]["uri"])

    def test_batch_rule_requires_endpoint_post_and_exploit_tool_agent(self):
        """The batch endpoint alone is legitimate WordPress traffic.

        All three dimensions must survive into the SQL matcher; otherwise a
        browser request to the endpoint, a GET, or an explicit tool marker on
        some unrelated URL becomes a false wp2shell hit.
        """
        header = (
            "#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query "
            "sc-status sc-bytes cs(User-Agent) cs(Referer)\n"
        )
        with tempfile.TemporaryDirectory(prefix="shellhound-wp2shell-") as root:
            case = Path(root, "case")
            logs = Path(root, "logs")
            case.mkdir()
            logs.mkdir()
            Path(logs, "u_ex.log").write_text(
                header
                # The three public-tool forms seen in the production corpus.
                + "2026-08-26 12:00:00 198.51.100.40 POST "
                  "/wp-json/batch/v1 - 207 12 wp2shell -\n"
                + "2026-08-26 12:00:01 198.51.100.41 POST / "
                  "rest_route=%2Fbatch%2Fv1 200 12 cve-2026-63030/1.0 -\n"
                + "2026-08-26 12:00:02 198.51.100.42 POST / "
                  "rest_route=/batch/v1 401 12 rezwp2shell -\n"
                # Each near miss lacks one required dimension.
                + "2026-08-26 12:00:03 203.0.113.8 POST / "
                  "rest_route=/batch/v1 207 12 Mozilla/5.0 -\n"
                + "2026-08-26 12:00:04 203.0.113.9 GET "
                  "/wp-json/batch/v1 - 200 12 wp2shell -\n"
                + "2026-08-26 12:00:05 203.0.113.10 POST "
                  "/unrelated - 200 12 wp2shell -\n",
                encoding="utf-8",
            )
            logindex.build(case, [str(logs)])

            entry = self.batch_entry()
            match = logindex.match_patterns(
                case, entry["patterns"], entry["match"],
                request=entry["request"])

        self.assertEqual(["POST"], entry["request"]["methods"])
        self.assertEqual(3, match["hits"])
        self.assertEqual(2, match["ok_hits"])
        self.assertEqual(
            {"198.51.100.40", "198.51.100.41", "198.51.100.42"},
            {row["ip"] for row in match["clients"]})
        self.assertEqual(match["hits"], sum(
            day["requests"] for day in match["timeline"]))


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
        patterns.add(self.ws, ["/my/own/path.php"], "mine")
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
            patterns.update(self.ws, self.first, patterns_in=["/something/else"])
        self.assertEqual("err.patternBundled", caught.exception.key)

    def test_the_shipped_file_is_never_written_to(self):
        before = patterns.BUNDLED_FILE.read_bytes()
        patterns.set_enabled(self.ws, self.first, False)
        patterns.add(self.ws, ["/another/path.php"])
        patterns.remove(self.ws, self.first)
        self.assertEqual(before, patterns.BUNDLED_FILE.read_bytes())

    def test_decisions_survive_an_upgrade_that_adds_patterns(self):
        """The off-switch stores ids, so a bundled set that grows must not
        disturb what was already switched off."""
        patterns.set_enabled(self.ws, self.first, False)
        patterns.add(self.ws, ["/mine.php"], "mine")
        self.assertEqual({self.first}, patterns.disabled_ids(self.ws))
        self.assertEqual(["mine"], [p["name"] for p in patterns.load(self.ws)])


class DuplicateTests(unittest.TestCase):

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="shellhound-dup-"))
        self.entry = patterns.bundled()[0]

    def test_a_copy_of_a_bundled_pattern_is_refused(self):
        with self.assertRaises(patterns.PatternError) as caught:
            # A COPY, match mode included. The signature covers how the
            # paths combine, because "either of these" and "both of these"
            # are different rules -- so a faithful copy has to carry it.
            patterns.add(self.ws, self.entry["patterns"], "my copy",
                         match=self.entry["match"])
        self.assertEqual("err.patternKnown", caught.exception.key)

    def test_it_is_refused_even_while_switched_off(self):
        """Otherwise switching the bundled one back on later would silently
        duplicate every hit it produces."""
        patterns.set_enabled(self.ws, self.entry["id"], False)
        with self.assertRaises(patterns.PatternError):
            patterns.add(self.ws, self.entry["patterns"], "my copy",
                         match=self.entry["match"])


class ExchangeTests(unittest.TestCase):

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="shellhound-exc-"))

    def test_the_export_carries_own_patterns_only(self):
        """The bundled ones travel with the tool; exporting them would land
        on the other side as duplicates and report a pile of skips."""
        patterns.add(self.ws, ["/mine/one.php"], "one")
        out = json.loads(patterns.export_text(self.ws))
        self.assertEqual(["one"], [p["name"] for p in out["patterns"]])

    def test_an_exported_file_imports_cleanly_elsewhere(self):
        patterns.add(self.ws, ["/mine/one.php"], "one")
        patterns.add(self.ws, ["/mine/two.php"], "two")
        other = Path(tempfile.mkdtemp(prefix="shellhound-exc2-"))
        got = patterns.import_text(other, patterns.export_text(self.ws))
        self.assertEqual({"added": 2, "skipped": 0, "invalid": 0}, got)

    def test_request_conditions_survive_json_exchange(self):
        patterns.add(
            self.ws, ["/batch/v1"], "filtered", request={
                "methods": ["post"], "user_agents": ["tool-name*"]})
        other = Path(tempfile.mkdtemp(prefix="shellhound-exc-filter-"))
        patterns.import_text(other, patterns.export_text(self.ws))
        got = patterns.load(other)[0]
        self.assertEqual(["POST"], got["request"]["methods"])
        self.assertEqual(["tool-name*"], got["request"]["user_agents"])

    def test_an_import_that_repeats_a_bundled_pattern_skips_it(self):
        # The WHOLE entry, paths and combination mode: the signature covers
        # both, so importing one path of a two-path rule is importing a
        # different rule and belongs in the library.
        entry = patterns.bundled()[0]
        text = json.dumps({"patterns": [{"patterns": entry["patterns"],
                                         "match": entry["match"],
                                         "name": "copy"}]})
        self.assertEqual({"added": 0, "skipped": 1, "invalid": 0},
                         patterns.import_text(self.ws, text))

    def test_importing_part_of_a_bundled_rule_is_a_new_rule(self):
        """One path out of a two-path AND-rule is a different statement --
        "requested this" rather than "requested both" -- and the library has
        no reason to refuse it."""
        one = patterns.bundled()[0]["patterns"][0]
        self.assertEqual({"added": 1, "skipped": 0, "invalid": 0},
                         patterns.import_text(self.ws, one + " | part"))


class DescriptionTests(unittest.TestCase):
    """`note` is a tag beside the name and has to stay short. The description
    is the long form -- what a hit here proves, and what it does not."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="shellhound-about-"))
        self.text = ("Only requested by someone running the exploit. A 2xx "
                     "means the upload handler answered, not that a file "
                     "landed.")

    def test_a_pattern_can_be_created_with_one(self):
        entry = patterns.add(self.ws, ["/exploit/path.php"], "Name", "CVE-2026-1",
                             self.text)
        self.assertEqual(self.text, entry["description"])
        self.assertEqual(self.text, patterns.load(self.ws)[0]["description"])

    def test_it_can_be_added_afterwards(self):
        entry = patterns.add(self.ws, ["/exploit/path.php"])
        self.assertEqual("", entry["description"])
        patterns.update(self.ws, entry["id"], description=self.text)
        self.assertEqual(self.text, patterns.load(self.ws)[0]["description"])

    def test_editing_the_name_leaves_it_alone(self):
        """`update` takes None for "do not touch"; an omitted description
        must not blank the one that is there."""
        entry = patterns.add(self.ws, ["/exploit/path.php"], description=self.text)
        patterns.update(self.ws, entry["id"], name="Renamed")
        got = patterns.load(self.ws)[0]
        self.assertEqual("Renamed", got["name"])
        self.assertEqual(self.text, got["description"])

    def test_it_can_be_cleared(self):
        entry = patterns.add(self.ws, ["/exploit/path.php"], description=self.text)
        patterns.update(self.ws, entry["id"], description="")
        self.assertEqual("", patterns.load(self.ws)[0]["description"])

    def test_it_survives_export_and_import(self):
        """The export is the exchange format. A description that does not
        travel is a description the receiving analyst has to guess."""
        patterns.add(self.ws, ["/exploit/path.php"], "Name", "CVE-2026-1",
                     self.text)
        other = Path(tempfile.mkdtemp(prefix="shellhound-about2-"))
        patterns.import_text(other, patterns.export_text(self.ws))
        self.assertEqual(self.text, patterns.load(other)[0]["description"])

    def test_a_pattern_without_one_is_still_fine(self):
        entry = patterns.add(self.ws, ["/exploit/path.php"])
        self.assertIn("description", entry)
        self.assertEqual("", entry["description"])

    def test_the_line_import_form_leaves_it_empty(self):
        """Three fields separated by `|`. Prose would run into the separator,
        so the line form does not carry a description at all."""
        patterns.import_text(self.ws, "/a/path.php | Name | CVE-2026-1")
        got = patterns.load(self.ws)[0]
        self.assertEqual("CVE-2026-1", got["cve"])
        self.assertEqual("", got["description"])


class WorkspaceFileTests(unittest.TestCase):

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="shellhound-file-"))

    def test_an_older_library_without_the_disabled_key_still_loads(self):
        """Workspaces written before this feature existed."""
        patterns.library_path(self.ws).write_text(
            json.dumps({"patterns": [{"id": "x1", "pattern": "/old.php",
                                      "label": "old"}]}), encoding="utf-8")
        self.assertEqual(["old"], [p["name"] for p in patterns.load(self.ws)])
        self.assertEqual(set(), patterns.disabled_ids(self.ws))

    def test_a_bare_list_still_loads(self):
        """The oldest form of the file."""
        patterns.library_path(self.ws).write_text(
            json.dumps([{"id": "x1", "pattern": "/old.php", "label": "old"}]),
            encoding="utf-8")
        self.assertEqual(["old"], [p["name"] for p in patterns.load(self.ws)])

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
        patterns.add(self.ws, ["/mine.php"], "mine")
        patterns.add(self.ws, ["/mine-too.php"], "also mine")
        raw = json.loads(
            patterns.library_path(self.ws).read_text(encoding="utf-8"))
        for row in raw["patterns"]:
            self.assertNotIn("source", row)
            self.assertNotIn("enabled", row)


class ShapeTests(unittest.TestCase):
    """A pattern entry is FOUR fields and one condition: the paths, the name,
    the advisory, and what a hit proves."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="shellhound-shape-"))

    def test_the_four_fields_round_trip(self):
        patterns.add(self.ws, ["/a/path.php"], "Name", "CVE-2026-1", "Why")
        got = patterns.load(self.ws)[0]
        self.assertEqual(["/a/path.php"], got["patterns"])
        self.assertEqual("Name", got["name"])
        self.assertEqual("CVE-2026-1", got["cve"])
        self.assertEqual("Why", got["description"])

    def test_a_file_written_before_the_rename_still_loads(self):
        """label/note/about were the old names, and a workspace file outlives
        a rename."""
        patterns.library_path(self.ws).write_text(json.dumps({"patterns": [{
            "id": "x1", "pattern": "/old.php", "label": "Old",
            "note": "CVE-2019-1", "about": "text"}]}), encoding="utf-8")
        got = patterns.load(self.ws)[0]
        self.assertEqual(["/old.php"], got["patterns"])
        self.assertEqual("Old", got["name"])
        self.assertEqual("CVE-2019-1", got["cve"])
        self.assertEqual("text", got["description"])
        self.assertEqual(patterns.MATCH_ANY, got["match"])

    def test_the_bundled_set_uses_the_same_shape(self):
        for row in patterns.bundled():
            for key in ("patterns", "match", "name", "cve", "description"):
                self.assertIn(key, row, row["id"])
            self.assertIsInstance(row["patterns"], list)


class CombinationTests(unittest.TestCase):
    """Several paths in one entry, combined OVER CLIENTS."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="shellhound-comb-"))

    def test_several_paths_are_stored(self):
        entry = patterns.add(self.ws, ["/exploit*", "/shell.php"],
                             match=patterns.MATCH_ALL)
        self.assertEqual(["/exploit*", "/shell.php"], entry["patterns"])
        self.assertEqual("all", entry["match"])

    def test_the_default_is_any(self):
        self.assertEqual("any", patterns.add(self.ws, ["/a.php"])["match"])

    def test_an_unknown_combination_is_refused(self):
        with self.assertRaises(patterns.PatternError) as caught:
            patterns.add(self.ws, ["/a.php"], match="maybe")
        self.assertEqual("err.patternMatchMode", caught.exception.key)

    def test_duplicate_paths_inside_one_entry_collapse(self):
        entry = patterns.add(self.ws, ["/a.php", "/A.PHP", "/b.php"])
        self.assertEqual(["/a.php", "/b.php"], entry["patterns"])

    def test_order_does_not_make_a_second_rule(self):
        """"/a AND /b" and "/b AND /a" are the same rule, and storing both
        would report every hit twice."""
        patterns.add(self.ws, ["/a.php", "/b.php"], match="all")
        with self.assertRaises(patterns.PatternError) as caught:
            patterns.add(self.ws, ["/b.php", "/a.php"], match="all")
        self.assertEqual("err.patternKnown", caught.exception.key)

    def test_the_same_paths_with_a_different_combination_are_a_different_rule(self):
        """"either of these" and "both of these" are different claims."""
        patterns.add(self.ws, ["/a.php", "/b.php"], match="any")
        patterns.add(self.ws, ["/a.php", "/b.php"], match="all")
        self.assertEqual(2, len(patterns.load(self.ws)))

    def test_an_entry_needs_at_least_one_path(self):
        with self.assertRaises(patterns.PatternError) as caught:
            patterns.add(self.ws, [])
        self.assertEqual("err.patternEmpty", caught.exception.key)

    def test_there_is_a_ceiling(self):
        """Beyond a handful it stops being a rule and becomes a query."""
        with self.assertRaises(patterns.PatternError) as caught:
            patterns.add(self.ws, [f"/p{i}.php" for i in range(20)])
        self.assertEqual("err.patternTooMany", caught.exception.key)

    def test_every_path_has_to_be_substantial(self):
        with self.assertRaises(patterns.PatternError) as caught:
            patterns.add(self.ws, ["/good/path.php", "*"])
        self.assertEqual("err.patternTooShort", caught.exception.key)

    def test_the_combination_survives_export_and_import(self):
        patterns.add(self.ws, ["/a.php", "/b.php"], "N", "C", "D", "all")
        other = Path(tempfile.mkdtemp(prefix="shellhound-comb2-"))
        patterns.import_text(other, patterns.export_text(self.ws))
        got = patterns.load(other)[0]
        self.assertEqual(["/a.php", "/b.php"], got["patterns"])
        self.assertEqual("all", got["match"])


if __name__ == "__main__":
    unittest.main()
