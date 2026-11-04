"""Saved analyst choices survive unavailable or malformed JSON snapshots."""
import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from server import db, patterns, workspace


class PatternStorageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="shellhound-storage-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = patterns.library_path(self.root)
        self.first = patterns.add(self.root, ["/storage-marker-one"], name="First")
        self.original = self.path.read_bytes()

    def test_read_error_blocks_every_mutation_and_retry_preserves_data(self):
        bundled_id = patterns.bundled()[0]["id"]
        operations = [
            lambda: patterns.add(self.root, ["/storage-marker-two"]),
            lambda: patterns.update(self.root, self.first["id"], name="Changed"),
            lambda: patterns.set_enabled(self.root, bundled_id, False),
            lambda: patterns.remove(self.root, self.first["id"]),
            lambda: patterns.restore(self.root, self.first["id"], 1),
            lambda: patterns.clone(self.root, self.first["id"]),
            lambda: patterns.import_text(self.root, "/storage-marker-import"),
            lambda: patterns.save(self.root, []),
        ]
        read_text = Path.read_text

        def unavailable(path, *args, **kwargs):
            if path == self.path:
                raise PermissionError("harmless private marker")
            return read_text(path, *args, **kwargs)

        for operation in operations:
            with self.subTest(operation=operation), patch.object(Path, "read_text", unavailable):
                with self.assertRaises(patterns.PatternStorageError) as error:
                    operation()
                self.assertNotIn("private marker", str(error.exception))
            self.assertEqual(self.original, self.path.read_bytes())
        patterns.add(self.root, ["/storage-marker-two"])
        self.assertEqual(2, len(patterns.load(self.root)))

    def test_malformed_snapshots_never_discard_existing_rows(self):
        first = json.loads(self.original)["patterns"][0]
        invalid = [None, 1, "marker", {"patterns": {}}, {"patterns": [first, None]},
                   {"patterns": [first, {"id": "bad", "patterns": ["x"]}]},
                   {"patterns": [{**first, "archived": "false"}]},
                   {"patterns": [{**first, "own_enabled": 1}]},
                   {"patterns": [{**first, "history": [None]}]},
                   {"patterns": [{**first, "version": []}]},
                   {"patterns": [{**first, "patterns": [23]}]},
                   {"patterns": [first], "disabled": "one"},
                   {"patterns": [first], "disabled": [None]}]
        for body in invalid:
            with self.subTest(body=body):
                self.path.write_text(json.dumps(body), encoding="utf-8")
                before = self.path.read_bytes()
                with self.assertRaises(patterns.PatternStorageError):
                    patterns.load(self.root)
                with self.assertRaises(patterns.PatternStorageError):
                    patterns.add(self.root, ["/storage-marker-new"])
                self.assertEqual(before, self.path.read_bytes())
        self.path.write_bytes(self.original)
        self.assertEqual("First", patterns.load(self.root)[0]["name"])

    def test_invalid_json_and_encoding_are_unavailable(self):
        for body in (b"{ marker", b"\xff"):
            self.path.write_bytes(body)
            with self.assertRaises(patterns.PatternStorageError):
                patterns.export_text(self.root)
            self.assertEqual(body, self.path.read_bytes())

    def test_failed_replace_preserves_target_and_cleans_unique_temporary(self):
        old_tmp = self.root / "hunt_patterns.json.tmp"
        old_tmp.write_text("unrelated marker", encoding="utf-8")
        with patch.object(patterns.os, "replace", side_effect=PermissionError("marker")):
            with self.assertRaises(patterns.PatternStorageError):
                patterns.update(self.root, self.first["id"], name="Changed")
        self.assertEqual(self.original, self.path.read_bytes())
        self.assertEqual([], list(self.root.glob(".hunt-patterns-*.tmp")))
        self.assertEqual("unrelated marker", old_tmp.read_text())
        patterns.update(self.root, self.first["id"], name="Changed")
        self.assertEqual("Changed", patterns.load(self.root)[0]["name"])

    def test_legacy_choices_unknown_fields_and_history_survive(self):
        legacy = {"id": "legacy", "pattern": "/storage-marker-legacy",
                  "label": "Legacy", "archived": True, "own_enabled": False,
                  "private_extra": "harmless secret marker"}
        for body in ([legacy], {"patterns": [legacy], "root_extra": {"marker": 1}}):
            self.path.write_text(json.dumps(body), encoding="utf-8")
            entry = patterns.load(self.root)[0]
            self.assertNotIn("private_extra", entry)
            self.assertTrue(entry["archived"])
            patterns.add(self.root, ["/storage-marker-added"])
            stored = json.loads(self.path.read_text())
            self.assertEqual("harmless secret marker", stored["patterns"][0]["private_extra"])
            self.assertFalse(stored["patterns"][0]["own_enabled"])
            if isinstance(body, dict):
                self.assertEqual(body["root_extra"], stored["root_extra"])
            stored["patterns"][0]["history"][0]["private_extra"] = "history marker"
            self.path.write_text(json.dumps(stored), encoding="utf-8")
            patterns.update(self.root, "legacy", name="Renamed")
            self.assertNotIn("private_extra", patterns.versions(self.root, "legacy")[0])
            self.assertEqual("history marker", json.loads(self.path.read_text())["patterns"][0]["history"][0]["private_extra"])
            patterns.restore(self.root, "legacy", 1)
            self.assertEqual("Legacy", patterns.load(self.root)[0]["name"])

    def test_nested_raw_metadata_survives_unrelated_add_and_toggles(self):
        body = json.loads(self.original)
        row = body["patterns"][0]
        row["rule"]["private_extra"] = "rule marker"
        row["rule"]["requests"][0]["clauses"][0]["private_extra"] = "clause marker"
        row["derived_from"] = {"id": "parent", "version": 1, "source": "own",
                               "private_extra": "provenance marker"}
        row["history"][0]["rule"]["private_extra"] = "history rule marker"
        row["history"][0]["derived_from"] = dict(row["derived_from"])
        self.path.write_text(json.dumps(body), encoding="utf-8")
        for operation in (
                lambda: patterns.add(self.root, ["/storage-marker-unrelated"]),
                lambda: patterns.set_enabled(self.root, patterns.bundled()[0]["id"], False),
                lambda: patterns.set_enabled(self.root, self.first["id"], False)):
            operation()
            stored = json.loads(self.path.read_text())["patterns"][0]
            for key in ("rule", "derived_from", "history"):
                self.assertEqual(row[key], stored[key])
        public = patterns.load(self.root)[0]
        self.assertNotIn("private_extra", json.dumps(public))

        changed = patterns.update(self.root, self.first["id"],
                                  patterns_in=["/storage-marker-edited"])
        self.assertEqual(["/storage-marker-edited"], changed["patterns"])
        stored = json.loads(self.path.read_text())["patterns"][0]
        self.assertNotIn("private_extra", stored["rule"])
        self.assertEqual(row["history"][0], stored["history"][0])
        restored = patterns.restore(self.root, self.first["id"], 1)
        self.assertEqual(self.first["rule"], restored["rule"])
        self.assertEqual(row["history"][0], json.loads(self.path.read_text())["patterns"][0]["history"][0])

    def test_parallel_mutations_keep_both_additions_and_toggles(self):
        barrier = threading.Barrier(8)
        bundled_ids = [entry["id"] for entry in patterns.bundled()[:4]]

        def mutate(index):
            barrier.wait(timeout=10)
            if index < 4:
                patterns.add(self.root, [f"/storage-marker-parallel-{index}"])
            else:
                patterns.set_enabled(self.root, bundled_ids[index - 4], False)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(mutate, range(8)))
        self.assertEqual(5, len(patterns.load(self.root)))
        self.assertEqual(set(bundled_ids), patterns.disabled_ids(self.root))


class CaseMetadataStorageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="shellhound-case-storage-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.case = workspace.create_case(self.root, "Synthetic case", "STORAGE-1")
        self.path = self.case / workspace.CASE_FILE
        self.original = self.path.read_bytes()
        self.info = workspace.case_info(self.case)

    def test_read_failure_never_creates_revision_or_replaces_metadata(self):
        read_text = Path.read_text

        def unavailable(path, *args, **kwargs):
            if path == self.path:
                raise PermissionError("private metadata marker")
            return read_text(path, *args, **kwargs)

        with patch.object(Path, "read_text", unavailable):
            with self.assertRaises(workspace.CaseMetadataError) as error:
                workspace.case_info(self.case)
            self.assertNotIn("private metadata marker", str(error.exception))
            with self.assertRaises(workspace.CaseMetadataError):
                workspace.update_case(self.case, profile={"summary": "Changed"},
                                      expected_profile_revision=self.info["profile_revision"])
        self.assertEqual(self.original, self.path.read_bytes())
        self.assertEqual(self.info["profile_revision"], workspace.case_info(self.case)["profile_revision"])
        updated = workspace.update_case(self.case, notes="Retry succeeded",
                                        expected_profile_revision=self.info["profile_revision"])
        self.assertEqual("Retry succeeded", updated["notes"])

    def test_invalid_metadata_and_missing_file_cannot_be_saved(self):
        for body in (b"{ marker", b"[]", b"null", b'{"name": 7}',
                     b'{"profile": []}', b'{"profile": {"sectors": "marker"}}', b"\xff"):
            with self.subTest(body=body):
                self.path.write_bytes(body)
                with self.assertRaises(workspace.CaseMetadataError):
                    workspace.case_info(self.case)
                with self.assertRaises(workspace.CaseMetadataError):
                    workspace.update_case(self.case, name="Replacement")
                self.assertEqual(body, self.path.read_bytes())
        self.path.unlink()
        with self.assertRaises(workspace.CaseMetadataError):
            workspace.case_info(self.case)
        with self.assertRaises(workspace.CaseMetadataError):
            workspace.update_case(self.case, notes="No replacement")
        self.assertFalse(self.path.exists())
        self.assertEqual(self.case.resolve(), workspace.resolve_case(self.root, self.case.name))

    def test_list_isolates_bad_case_and_does_not_offer_a_synthetic_revision(self):
        other = workspace.create_case(self.root, "Other case", "STORAGE-2")
        for missing in (False, True):
            with self.subTest(missing=missing):
                if missing:
                    self.path.unlink()
                else:
                    self.path.write_text("{ marker", encoding="utf-8")
                rows = {row["slug"]: row for row in workspace.list_cases(self.root)}
                failed = rows[self.case.name]
                self.assertFalse(failed["metadata_available"])
                self.assertEqual(self.case.name, failed["name"])
                self.assertNotIn("profile_revision", failed)
                self.assertIn("metadata_error", failed)
                self.assertTrue(rows[other.name]["metadata_available"])
                self.assertEqual("Other case", workspace.case_info(other)["name"])

    def test_failed_replace_keeps_file_database_and_retry_intact(self):
        with patch.object(workspace.os, "replace", side_effect=PermissionError("marker")):
            with self.assertRaises(workspace.CaseMetadataError):
                workspace.update_case(self.case, name="Changed")
        self.assertEqual(self.original, self.path.read_bytes())
        self.assertEqual([], list(self.case.glob(".case-*.tmp")))
        conn = db.connect(self.case)
        try:
            self.assertEqual("Synthetic case", conn.execute("SELECT value FROM meta WHERE key='name'").fetchone()[0])
        finally:
            conn.close()
        self.assertEqual("Changed", workspace.update_case(self.case, name="Changed")["name"])

    def test_legacy_metadata_unknown_fields_and_conflict_check_are_preserved(self):
        identity = {"name": "Legacy", "reference": "STORAGE-1", "unknown": {"marker": 1}}
        self.path.write_text(json.dumps(identity), encoding="utf-8")
        info = workspace.case_info(self.case)
        saved = workspace.update_case(self.case, notes="Kept", expected_profile_revision=info["profile_revision"])
        self.assertEqual(identity["unknown"], json.loads(self.path.read_text())["unknown"])
        self.assertEqual(info["profile"], saved["profile"])
        workspace.update_case(self.case, name="New name")
        before = self.path.read_bytes()
        with self.assertRaises(workspace.CaseProfileConflict):
            workspace.update_case(self.case, name="Stale name", expected_profile_revision=info["profile_revision"])
        self.assertEqual(before, self.path.read_bytes())


if __name__ == "__main__":
    unittest.main()
