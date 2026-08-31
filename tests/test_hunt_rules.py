"""Pattern Hunt v2 has one safe meaning in the editor, API and index."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from server import huntrules, patterns


def rule(value="/wp-content/*.php"):
    return {"client_match": "any", "requests": [{"clauses": [
        {"field": "uri", "operator": "wildcard", "values": [value]},
        {"field": "status", "operator": "in", "values": ["2xx", "403"]},
    ]}]}


class RuleLanguageTests(unittest.TestCase):
    def test_dsl_round_trips_without_changing_the_hash(self):
        canonical = huntrules.normalise_rule(rule())
        text = huntrules.to_dsl(canonical)
        self.assertEqual(canonical, huntrules.parse_dsl(text))
        self.assertEqual(huntrules.rule_hash(canonical),
                         huntrules.rule_hash(huntrules.parse_dsl(text)))

    def test_request_and_clause_order_do_not_change_the_hash(self):
        first = {"client_match": "all", "requests": [
            {"clauses": [
                {"field": "method", "operator": "in", "values": ["POST", "GET"]},
                {"field": "path", "operator": "contains", "values": ["/admin/"]},
            ]},
            {"clauses": [{"field": "query", "operator": "contains",
                          "values": ["option=com_jce"]}]},
        ]}
        second = {"client_match": "all", "requests": [
            first["requests"][1],
            {"clauses": list(reversed(first["requests"][0]["clauses"]))},
        ]}
        self.assertEqual(huntrules.rule_hash(first), huntrules.rule_hash(second))

    def test_only_the_allow_list_is_accepted(self):
        attacks = [
            "client any\nrequest\n sql equals [\"x\"]\nend",
            "client any\nrequest\n uri regex [\".*\"]\nend",
            "client any\nrequest\n uri wildcard []\nend",
            "client any\nrequest\n status in [\"9xx\"]\nend",
            "client any\nrequest\n method contains [\"GET\"]\nend",
        ]
        for text in attacks:
            with self.subTest(text=text), self.assertRaises(huntrules.RuleError):
                huntrules.parse_dsl(text)

    def test_sql_text_is_data_not_language(self):
        value = "x%' OR 1=1; DROP TABLE requests; --"
        parsed = huntrules.parse_dsl(
            "client any\nrequest\n  uri equals " + json.dumps([value]) + "\nend")
        self.assertEqual([value], parsed["requests"][0]["clauses"][0]["values"])

    def test_legacy_shape_lifts_without_changing_its_meaning(self):
        lifted = huntrules.legacy_rule(
            ["/one/*.php", "/two/final.php"], "all",
            {"methods": ["post"], "user_agents": ["tool-name*"]})
        self.assertEqual("all", lifted["client_match"])
        self.assertEqual(2, len(lifted["requests"]))
        for step in lifted["requests"]:
            self.assertEqual({"uri", "method", "user_agent"},
                             {clause["field"] for clause in step["clauses"]})


class PatternVersionTests(unittest.TestCase):
    def setUp(self):
        self.workspace = Path(tempfile.mkdtemp(prefix="shellhound-hunt-v2-"))

    def tearDown(self):
        shutil.rmtree(self.workspace, ignore_errors=True)

    def test_old_file_is_migrated_to_a_v2_rule(self):
        patterns.library_path(self.workspace).write_text(json.dumps({
            "patterns": [{"id": "legacy", "pattern": "/legacy/path.php",
                          "label": "Legacy"}]}), encoding="utf-8")
        entry = patterns.load(self.workspace)[0]
        self.assertEqual(1, entry["version"])
        self.assertEqual("/legacy/path.php",
                         entry["rule"]["requests"][0]["clauses"][0]["values"][0])
        self.assertEqual(entry["rule_hash"], huntrules.rule_hash(entry["rule"]))

    def test_save_conflict_history_restore_and_archive_are_append_only(self):
        original = patterns.add(self.workspace, [], "Original", rule=rule())
        changed = patterns.update(self.workspace, original["id"], name="Changed",
                                  expected_version=1)
        self.assertEqual(2, changed["version"])
        with self.assertRaises(patterns.PatternError) as caught:
            patterns.update(self.workspace, original["id"], name="Lost update",
                            expected_version=1)
        self.assertEqual("err.patternVersionConflict", caught.exception.key)
        restored = patterns.restore(self.workspace, original["id"], 1,
                                    expected_version=2)
        self.assertEqual(3, restored["version"])
        self.assertEqual("Original", restored["name"])
        self.assertEqual([1, 2, 3], [row["version"] for row in
                                     patterns.versions(self.workspace, original["id"])])
        patterns.remove(self.workspace, original["id"])
        archived = patterns.find(self.workspace, original["id"])
        self.assertTrue(archived["archived"])
        self.assertFalse(archived["enabled"])
        self.assertNotIn(original["id"], [row["id"] for row in
                                          patterns.library(self.workspace)])

    def test_clone_records_its_exact_parent(self):
        source = patterns.bundled()[0]
        clone = patterns.clone(self.workspace, source["id"], name="Local variant")
        self.assertEqual("own", clone["source"])
        self.assertEqual({"id": source["id"], "version": source["version"],
                          "source": "bundled"}, clone["derived_from"])
        self.assertEqual("Local variant", clone["name"])

    def test_archived_rule_still_prevents_an_accidental_duplicate(self):
        original = patterns.add(self.workspace, [], "Original", rule=rule())
        patterns.remove(self.workspace, original["id"])
        with self.assertRaises(patterns.PatternError) as caught:
            patterns.add(self.workspace, [], "Duplicate", rule=rule())
        self.assertEqual("err.patternKnown", caught.exception.key)

    def test_custom_clone_does_not_duplicate_an_existing_variant(self):
        source = patterns.bundled()[0]
        changed = rule("/unique/variant.php")
        patterns.clone(self.workspace, source["id"], rule=changed,
                       name="First variant")
        with self.assertRaises(patterns.PatternError) as caught:
            patterns.clone(self.workspace, source["id"], rule=changed,
                           name="Second variant")
        self.assertEqual("err.patternKnown", caught.exception.key)


if __name__ == "__main__":
    unittest.main()
