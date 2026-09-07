"""Case identity, privacy and archive compatibility for OpenCTI integration."""
import json
import tempfile
import unittest
import uuid
import zipfile
from pathlib import Path
from unittest.mock import patch

from server import case_profile, db, workspace


class CaseProfileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="shellhound-profile-")
        self.root = Path(self.temporary.name)
        self.ws = self.root / "cases"

    def tearDown(self):
        self.temporary.cleanup()

    def _meta(self, case, key):
        conn = db.connect(case)
        try:
            row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            return row[0] if row else None
        finally:
            conn.close()

    def test_new_case_persists_generated_pseudonym_and_defaults(self):
        case = workspace.create_case(self.ws, "Synthetic", reference=" PIM-5165 ")
        info = workspace.case_info(case)
        self.assertEqual("PIM-5165", info["reference"])
        self.assertEqual("TLP:AMBER+STRICT", info["profile"]["marking"])
        self.assertRegex(info["profile"]["pseudonym"], r"^Organization-[a-f0-9]{12}$")
        self.assertEqual(str(uuid.UUID(info["profile"]["organization_id"])),
                         info["profile"]["organization_id"])
        self.assertEqual(info["profile"], json.loads(self._meta(case, "profile")))
        registry = json.loads((self.ws / case_profile.REGISTRY_FILE).read_text())
        self.assertEqual([{"id": info["profile"]["organization_id"],
                           "name": info["profile"]["pseudonym"]}], registry)

    def test_same_organization_can_be_used_by_multiple_cases(self):
        first = workspace.create_case(self.ws, "First", "PIM-1")
        profile = workspace.case_info(first)["profile"]
        second = workspace.create_case(self.ws, "Second", "PIM-2",
                                       profile={"organization_id": profile["organization_id"]})
        self.assertEqual(profile, workspace.case_info(second)["profile"])
        self.assertEqual(1, len(case_profile.list_organizations(self.ws)))

    def test_partial_profile_save_preserves_pseudonym_and_other_fields(self):
        case = workspace.create_case(self.ws, "Synthetic", profile={
            "summary": "Investigation", "sectors": ["Retail", "Retail"],
            "countries": ["DE"], "software": [{"name": "Example CMS", "version": "1.0"}],
            "vulnerabilities": [{"name": "cve-2026-12345", "status": "confirmed"},
                                {"name": "Unverified upload issue", "status": "suspected",
                                 "description": "Investigation pending"}],
            "first_seen": "2026-09-01", "last_seen": "2026-09-07T20:00:00+02:00"})
        original = workspace.case_info(case)["profile"]
        updated = workspace.update_case(case, profile={"marking": "TLP:RED"})["profile"]
        self.assertEqual({**original, "marking": "TLP:RED"}, updated)
        self.assertEqual(["Retail"], updated["sectors"])
        self.assertEqual("CVE-2026-12345", updated["vulnerabilities"][0]["name"])
        self.assertEqual("suspected", updated["vulnerabilities"][1]["status"])
        self.assertEqual(updated, json.loads(self._meta(case, "profile")))

    def test_invalid_profile_does_not_create_registry_or_case(self):
        invalid = [None, [], {"customer_name": "Private Company"},
                   {"sectors": "Retail"}, {"countries": [123]}, {"countries": ["Germany"]},
                   {"software": [{"name": ""}]},
                   {"software": [{"name": "CMS", "secret": "hidden"}]},
                   {"vulnerabilities": [{"name": "CVE-2026-12345", "status": "maybe"}]},
                   {"first_seen": "2026-09-08", "last_seen": "2026-09-07"},
                   {"first_seen": "not-a-date"}, {"marking": "TLP:PUBLIC"},
                   {"organization_id": str(uuid.uuid4())},
                   {"pseudonym": "Actual Customer Name"}]
        for profile in invalid:
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                case_profile.normalize(profile, self.ws)
            self.assertFalse(self.ws.exists())

    def test_org_name_cannot_be_written_through_any_supported_interface(self):
        with self.assertRaisesRegex(ValueError, "generated"):
            case_profile.create_organization(self.ws, name="Actual Customer Name")
        case = workspace.create_case(self.ws, "Synthetic")
        expected = workspace.case_info(case)["profile"]["pseudonym"]
        updated = workspace.update_case(case, profile={"pseudonym": "Actual Customer Name"})
        self.assertEqual(expected, updated["profile"]["pseudonym"])
        self.assertNotIn("Actual Customer Name", (case / workspace.CASE_FILE).read_text())
        self.assertNotIn("Actual Customer Name", (self.ws / case_profile.REGISTRY_FILE).read_text())

    def test_changing_organization_uses_registry_display_name(self):
        case = workspace.create_case(self.ws, "Synthetic")
        old_profile = workspace.case_info(case)["profile"]
        new = case_profile.create_organization(self.ws)
        result = workspace.update_case(case, profile={**old_profile, "organization_id": new["id"]})
        self.assertEqual(new["name"], result["profile"]["pseudonym"])

    def test_reads_of_legacy_cases_never_assign_pseudonyms(self):
        self.ws.mkdir()
        case = self.ws / "legacy"
        case.mkdir()
        path = case / workspace.CASE_FILE
        identity = {"name": "Legacy", "reference": "PIM-legacy", "notes": "Old notes"}
        path.write_text(json.dumps(identity), encoding="utf-8")
        original = path.read_bytes()
        with patch.object(case_profile, "_write_organizations", side_effect=AssertionError("read wrote")):
            self.assertEqual([], case_profile.list_organizations(self.ws))
            for _ in range(2):
                info = workspace.case_info(case)
                self.assertEqual("", info["profile"]["organization_id"])
                self.assertEqual("TLP:AMBER+STRICT", info["profile"]["marking"])
                self.assertEqual(1, len(workspace.list_cases(self.ws)))
        self.assertEqual(original, path.read_bytes())
        self.assertFalse((self.ws / case_profile.REGISTRY_FILE).exists())
        self.assertFalse(db.case_db_path(case).exists())
        workspace.update_case(case, notes="Edited notes")
        self.assertFalse((self.ws / case_profile.REGISTRY_FILE).exists())
        self.assertTrue(workspace.update_case(case, profile={})["profile"]["organization_id"])

    def test_duplicate_case_ids_rejected_without_partial_writes(self):
        first = workspace.create_case(self.ws, "First", "PIM-1")
        with self.assertRaisesRegex(ValueError, "already used"):
            workspace.create_case(self.ws, "Second", " pim-1 ")
        self.assertEqual(1, len(workspace.list_cases(self.ws)))
        self.assertEqual(1, len(case_profile.list_organizations(self.ws)))
        second = workspace.create_case(self.ws, "Second", "PIM-2")
        before = (second / workspace.CASE_FILE).read_bytes()
        with self.assertRaisesRegex(ValueError, "already used"):
            workspace.update_case(second, name="Should not save", reference="PIM-1")
        self.assertEqual(before, (second / workspace.CASE_FILE).read_bytes())
        self.assertEqual("PIM-1", workspace.update_case(first, reference="PIM-1")["reference"])
        workspace.create_case(self.ws, "Unidentified one")
        workspace.create_case(self.ws, "Unidentified two")

    def test_case_id_freezes_only_after_export(self):
        case = workspace.create_case(self.ws, "Synthetic", "PIM-1")
        self.assertFalse(workspace.case_info(case)["reference_locked"])
        workspace.update_case(case, reference="PIM-2")
        conn = db.connect(case)
        try:
            conn.execute("INSERT INTO meta(key,value) VALUES('opencti_case_reference','PIM-2')")
            conn.commit()
        finally:
            conn.close()
        self.assertTrue(workspace.case_info(case)["reference_locked"])
        for reference in ("PIM-3", "", "pim-2"):
            with self.subTest(reference=reference), self.assertRaisesRegex(ValueError, "cannot change"):
                workspace.update_case(case, reference=reference)
        self.assertEqual("New case name", workspace.update_case(
            case, name="New case name", reference="PIM-2")["name"])

    def test_archive_restores_profile_pseudonym_and_export_lock_in_new_workspace(self):
        case = workspace.create_case(self.ws, "Synthetic", "PIM-1", profile={"summary": "Context"})
        profile = workspace.case_info(case)["profile"]
        conn = db.connect(case)
        try:
            conn.execute("INSERT INTO meta(key,value) VALUES('opencti_case_reference','PIM-1')")
            conn.commit()
        finally:
            conn.close()
        archive, summary = workspace.archive_case(self.ws, case)
        self.assertEqual(profile, summary["profile"])
        other_ws = self.root / "restored"
        result = workspace.import_archive(other_ws, archive)
        restored = workspace.case_info(result["dir"])
        self.assertEqual(profile, restored["profile"])
        self.assertTrue(restored["reference_locked"])
        self.assertEqual([{"id": profile["organization_id"], "name": profile["pseudonym"]}],
                         case_profile.list_organizations(other_ws))
        another = workspace.create_case(other_ws, "Related", "PIM-2",
                                        profile={"organization_id": profile["organization_id"]})
        self.assertEqual(profile["pseudonym"], workspace.case_info(another)["profile"]["pseudonym"])

    def test_archive_with_duplicate_id_is_rejected_before_extraction(self):
        case = workspace.create_case(self.ws, "Synthetic", "PIM-1")
        archive, _ = workspace.archive_case(self.ws, case)
        workspace.import_archive(self.ws, archive)
        with self.assertRaisesRegex(workspace.ImportError_, "already used"):
            workspace.import_archive(self.ws, archive)
        self.assertEqual(1, len(workspace.list_cases(self.ws)))

    def test_archived_id_is_reserved_but_restored_case_can_keep_it(self):
        case = workspace.create_case(self.ws, "Synthetic", "PIM-1")
        archive, _ = workspace.archive_case(self.ws, case)
        with self.assertRaisesRegex(ValueError, "archived case"):
            workspace.create_case(self.ws, "Different case", "pim-1")
        other = workspace.create_case(self.ws, "Other", "PIM-2")
        with self.assertRaisesRegex(ValueError, "archived case"):
            workspace.update_case(other, reference="PIM-1")
        restored = workspace.import_archive(self.ws, archive)
        self.assertEqual("PIM-1", workspace.update_case(
            restored["dir"], reference="PIM-1", name="Updated name")["reference"])

    def test_legacy_archive_retains_rename_and_no_profile_migration(self):
        archive = self.root / "legacy.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr(workspace.CASE_FILE, json.dumps({"name": "Old", "notes": "Legacy"}))
        one = workspace.import_archive(self.ws, archive)
        two = workspace.import_archive(self.ws, archive)
        self.assertFalse(one["renamed"])
        self.assertTrue(two["renamed"])
        self.assertNotEqual(one["slug"], two["slug"])
        self.assertEqual("", workspace.case_info(one["dir"])["profile"]["organization_id"])
        self.assertFalse((self.ws / case_profile.REGISTRY_FILE).exists())

    def test_import_refuses_customer_mapping_and_registry_conflicts(self):
        profile = case_profile.normalize({}, self.ws)
        for payload in ({**profile, "real_name": "Private company"},
                        {**profile, "pseudonym": "Private company"},
                        {**profile, "pseudonym": "Organization-000000000000"}):
            with self.subTest(payload=payload):
                archive = self.root / "invalid.zip"
                with zipfile.ZipFile(archive, "w") as zf:
                    zf.writestr(workspace.CASE_FILE, json.dumps({"name": "Invalid", "profile": payload}))
                with self.assertRaises(workspace.ImportError_):
                    workspace.import_archive(self.ws, archive)
                self.assertEqual([], workspace.list_cases(self.ws))

    def test_corrupt_registry_is_not_silently_replaced(self):
        self.ws.mkdir()
        path = self.ws / case_profile.REGISTRY_FILE
        path.write_text("broken", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "cannot be read"):
            case_profile.create_organization(self.ws)
        self.assertEqual("broken", path.read_text())


if __name__ == "__main__":
    unittest.main()
