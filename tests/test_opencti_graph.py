"""Privacy, identity and provenance guarantees of the OpenCTI preview."""
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from server import db, opencti_graph as graph, workspace
from server.paths import display_path, io_path


class OpenCTIGraphTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=io_path(tempfile.gettempdir()))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(display_path(Path(self.temp.name).resolve()))
        self.case = workspace.create_case(self.root / "cases", "Never export customer name", "PIM-5165")
        self.evidence = self.root / "Evidence sensitive customer"
        self.evidence.mkdir()
        self.file = self.evidence / "uploads" / "example.php"
        self.file.parent.mkdir()
        self.content = b"synthetic file for provenance testing\n"
        self.file.write_bytes(self.content)
        self.sha = hashlib.sha256(self.content).hexdigest()
        self.conn = db.connect(self.case)
        self.addCleanup(self.conn.close)
        self.conn.execute("INSERT INTO evidence (kind,path,added) VALUES ('webroot',?,?)",
                          (str(self.evidence), db.now()))
        self.path_id = db.add_ioc(self.conn, "uploads/example.php", "path", ["webshell", "confirmed"])
        self.hash_id = db.add_ioc(self.conn, self.sha, "hash", ["confirmed"])
        self.ip_id = db.add_ioc(self.conn, "198.51.100.42", "ip")
        self.url_id = db.add_ioc(self.conn, "https://example.test/resource", "url")
        self.domain_id = db.add_ioc(self.conn, "example.test", "domain")
        self.email_id = db.add_ioc(self.conn, "admin@example.test", "email")
        self.user_id = db.add_ioc(self.conn, "admin", "user")
        self.other_id = db.add_ioc(self.conn, "content_table", "other")
        db.link_iocs(self.conn, self.hash_id, self.path_id, "hash-of")
        db.link_iocs(self.conn, self.ip_id, self.path_id, "requested", "1 request, 0 successful responses")
        db.link_iocs(self.conn, self.domain_id, self.other_id, "host-in")
        db.link_iocs(self.conn, self.email_id, self.user_id, "account-of")
        for ioc_id, role in ((self.path_id, "direct"), (self.hash_id, "hash")):
            self.conn.execute("INSERT INTO ioc_sources(ioc_id,artifact,role,active,added) VALUES(?,?,?,1,?)",
                              (ioc_id, str(self.file), role, db.now()))
        db.upsert_finding(self.conn, "webshell", 0, "Synthetic confirmed classification", "file", str(self.file))
        self.conn.execute("UPDATE findings SET triage='confirmed'")
        self.conn.commit()

    def preview(self, **options):
        return graph.build_preview(self.case, options)

    def test_complete_graph_defaults_do_not_create_indicators_or_upload_payloads(self):
        preview = self.preview()
        self.assertFalse(preview["errors"])
        self.assertEqual(8, len(preview["iocs"]))
        self.assertTrue(all(r["selected"] for r in preview["iocs"]))
        self.assertEqual({"hash-of", "requested", "host-in", "account-of"},
                         {e["kind"] for e in preview["relationships"]})
        types = [o["type"] for o in preview["objects"]]
        self.assertEqual(1, types.count("incident"))
        self.assertEqual(1, types.count("report"))
        self.assertEqual(1, types.count("file"))
        self.assertEqual(1, types.count("malware"))
        self.assertEqual(1, types.count("url"))
        self.assertEqual("https://example.test/resource",
                         next(o["value"] for o in preview["objects"] if o["type"] == "url"))
        self.assertNotIn("indicator", types)
        self.assertNotIn("artifact", types)
        self.assertFalse(any(s["selected"] for s in preview["samples"]))
        self.assertNotIn("payload_bin", json.dumps(preview))
        hashes = next(o["hashes"] for o in preview["objects"] if o["type"] == "file")
        self.assertEqual(self.sha, hashes["SHA-256"])
        self.assertEqual(hashlib.md5(self.content).hexdigest(), hashes["MD5"])
        self.assertNotIn("communicates-with", json.dumps(preview))

    def test_all_references_are_in_bundle_or_existing_markings(self):
        preview = self.preview(indicator_ids=[self.hash_id])
        ids = {o["id"] for o in preview["objects"]} | set(graph.MARKINGS.values())
        for obj in preview["objects"]:
            for key, value in obj.items():
                if key.endswith("_ref"):
                    self.assertIn(value, ids, (key, value))
                if key.endswith("_refs"):
                    self.assertTrue(set(value) <= ids, (key, value))

    def test_http_urls_survive_while_local_paths_and_url_credentials_are_redacted(self):
        sanitizer = graph._Sanitizer(self.case, [{"path": str(self.evidence)}])
        value = "https://example.test/a and http://example.test/b alongside C:/Users/test/private.txt"
        clean = sanitizer.text(value)
        self.assertIn("https://example.test/a", clean)
        self.assertIn("http://example.test/b", clean)
        self.assertNotIn("C:/Users/test", clean)
        clean = sanitizer.text("https://alice:secret@example.test/a")
        self.assertNotIn("secret", clean)

    def test_case_name_and_local_paths_never_leave_preview_even_in_profile_or_evidence(self):
        private = str(self.evidence) + "/uploads/example.php"
        self.conn.execute("UPDATE iocs SET origin=?,note=? WHERE id=?",
                          (private, r"See C:\Users\Private\case.bin and \\server\share\secret.txt password=secret", self.path_id))
        self.conn.execute("UPDATE findings SET evidence=?", (private,))
        self.conn.commit()
        info = workspace.case_info(self.case)
        info["profile"] = {"summary": private, "software": [{"name": private, "version": "1"}],
                           "vulnerabilities": [{"name": "Other", "status": "suspected", "description": private}]}
        with patch("server.workspace.case_info", return_value=info):
            preview = self.preview(include_notes=True, include_evidence=True)
        text = json.dumps(preview)
        for forbidden in ("Never export customer name", "Evidence sensitive customer", "Private", "secret.txt", "password=secret"):
            self.assertNotIn(forbidden, text)
        self.assertNotIn(str(self.root).replace("\\", "\\\\"), text)
        self.assertIn("uploads/example.php", text)

    def test_partial_selection_does_not_export_excluded_iocs_or_dangling_edges(self):
        preview = self.preview(ioc_ids=[self.ip_id])
        self.assertEqual([self.ip_id], [r["id"] for r in preview["iocs"] if r["selected"]])
        exported = json.dumps(preview["objects"])
        self.assertIn("198.51.100.42", exported)
        self.assertNotIn("example.test", exported)
        self.assertFalse(any(e["selected"] for e in preview["relationships"]))
        self.assertNotIn("file", [o["type"] for o in preview["objects"]])

    def test_repeat_and_case_rename_keep_ids_and_fingerprints(self):
        first = self.preview()
        workspace.update_case(self.case, name="Another local customer name")
        second = self.preview()
        self.assertEqual(first["fingerprint"], second["fingerprint"])
        self.assertEqual({o["id"] for o in first["objects"]}, {o["id"] for o in second["objects"]})
        self.conn.execute("UPDATE iocs SET note='A new analyst observation' WHERE id=?", (self.ip_id,))
        self.conn.commit()
        third = self.preview(include_notes=True)
        self.assertNotEqual(second["fingerprint"], third["fingerprint"])

    def test_persistent_source_identity_survives_value_correction_but_not_delete_and_reuse(self):
        first = self.preview(indicator_ids=[self.ip_id])
        row = next(r for r in first["iocs"] if r["id"] == self.ip_id)
        original_owned = {x for x in row["object_ids"] if x.startswith(("note--", "indicator--"))}
        self.conn.execute("UPDATE iocs SET value='198.51.100.43' WHERE id=?", (self.ip_id,))
        self.conn.commit()
        second = self.preview(indicator_ids=[self.ip_id])
        updated = next(r for r in second["iocs"] if r["id"] == self.ip_id)
        self.assertEqual(original_owned, {x for x in updated["object_ids"] if x.startswith(("note--", "indicator--"))})
        self.conn.execute("DELETE FROM iocs WHERE id=?", (self.ip_id,))
        self.conn.execute("INSERT INTO iocs(id,value,type,added) VALUES(?,?,?,?)",
                          (self.ip_id, "198.51.100.99", "ip", db.now()))
        self.conn.commit()
        replacement = next(r for r in self.preview(indicator_ids=[self.ip_id])["iocs"] if r["id"] == self.ip_id)
        self.assertNotEqual(row["source_uid"], replacement["source_uid"])
        self.assertTrue(original_owned.isdisjoint(replacement["object_ids"]))

    def test_withdrawal_revokes_only_disappeared_own_assertions(self):
        previous = self.preview(indicator_ids=[self.hash_id])["objects"]
        self.conn.execute("UPDATE findings SET triage='dismissed'")
        self.conn.execute("UPDATE ioc_sources SET active=0")
        self.conn.commit()
        current = self.preview(indicator_ids=[self.hash_id])["objects"]
        foreign = {"id": "malware--external", "type": "malware", "created_by_ref": "identity--other",
                   "x_shellhound_case_reference": "PIM-5165"}
        withdrawn = graph.withdrawal_objects(previous + [foreign], current, "PIM-5165")
        revoked = [o for o in withdrawn if o.get("revoked")]
        self.assertTrue(any(o["type"] == "malware" for o in revoked))
        self.assertTrue(all(o["type"] in {"note", "indicator", "relationship", "malware"} for o in revoked))
        self.assertNotIn("malware--external", {o["id"] for o in withdrawn})
        self.assertTrue(any(o["type"] == "note" and not o.get("revoked") for o in withdrawn))
        self.assertEqual([], graph.withdrawal_objects(previous, previous, "PIM-5165"))

    def test_reconfirmation_creates_stable_new_generation_without_unrevoking_history(self):
        original = self.preview()["objects"]
        self.conn.execute("UPDATE findings SET triage='dismissed'")
        self.conn.execute("UPDATE ioc_sources SET active=0")
        self.conn.commit()
        reduced = self.preview()["objects"]
        withdrawn = graph.withdrawal_objects(original, reduced, "PIM-5165")
        history = {o["id"]: o for o in original}
        history.update({o["id"]: o for o in withdrawn})
        self.conn.execute("UPDATE findings SET triage='confirmed'")
        self.conn.execute("UPDATE ioc_sources SET active=1")
        self.conn.commit()
        fresh = self.preview()["objects"]
        reactivated = graph.reactivate_objects(list(history.values()), fresh)
        old_malware = next(o for o in original if o["type"] == "malware")
        new_malware = next(o for o in reactivated if o["type"] == "malware")
        self.assertNotEqual(old_malware["id"], new_malware["id"])
        self.assertTrue(history[old_malware["id"]]["revoked"])
        self.assertNotIn("revoked", new_malware)
        report = next(o for o in reactivated if o["type"] == "report")
        self.assertIn(new_malware["id"], report["object_refs"])
        self.assertNotIn(old_malware["id"], report["object_refs"])
        history.update({o["id"]: o for o in reactivated})
        repeated = graph.reactivate_objects(list(history.values()), fresh)
        self.assertEqual({o["id"] for o in reactivated}, {o["id"] for o in repeated})

    def test_retracted_and_retired_confirmations_never_classify_malware(self):
        self.conn.execute("UPDATE ioc_sources SET active=0")
        self.conn.execute("UPDATE findings SET triage='dismissed'")
        self.conn.commit()
        preview = self.preview()
        self.assertNotIn("malware", [o["type"] for o in preview["objects"]])
        self.assertFalse(any(r["indicator_suggested"] for r in preview["iocs"]))
        self.assertIn("withdrawn", json.dumps(preview))
        self.conn.execute("UPDATE ioc_sources SET active=1")
        self.conn.execute("UPDATE findings SET triage='confirmed',engine='webshell',seen_run=1")
        self.conn.execute("INSERT INTO meta VALUES('engine_done:webshell','2')")
        self.conn.commit()
        self.assertNotIn("malware", [o["type"] for o in self.preview()["objects"]])

    def test_changed_file_does_not_mix_old_sha256_with_current_md5_or_classify_new_content(self):
        self.file.write_bytes(b"different benign content")
        preview = self.preview()
        row = next(r for r in preview["iocs"] if r["id"] == self.hash_id)
        self.assertIn("does not match", " ".join(row["warnings"]))
        old = [o for o in preview["objects"] if o["type"] == "file" and o["hashes"].get("SHA-256") == self.sha]
        self.assertEqual({"SHA-256": self.sha}, old[0]["hashes"])
        self.assertNotIn("malware", [o["type"] for o in preview["objects"]])
        self.assertFalse(row["indicator_suggested"])
        file_ids = {o["id"] for o in preview["objects"] if o["type"] == "file"}
        relationships = [o for o in preview["objects"] if o["type"] == "relationship"]
        self.assertFalse(any(o["source_ref"] in file_ids and o["target_ref"] in file_ids for o in relationships))
        requested = next(o for o in relationships if " requested " in o.get("description", ""))
        self.assertTrue(requested["target_ref"].startswith("note--"))

    def test_generic_manual_file_confirmation_does_not_invent_webshell_type(self):
        self.conn.execute("UPDATE findings SET source='analyst',rule_id='analyst.file_review',rule='Manual file review'")
        self.conn.commit()
        preview = self.preview()
        self.assertNotIn("malware", [o["type"] for o in preview["objects"]])
        hashed = next(r for r in preview["iocs"] if r["id"] == self.hash_id)
        self.assertTrue(hashed["indicator_suggested"])
        self.assertIn("Associated file confirmed", json.dumps(preview["objects"]))

    def test_explicit_manual_file_classifications_export_verified_file_and_malware(self):
        for statement, malware_type, name in (
            ("Analyst classified the file as a webshell.", "webshell", "Confirmed web shell "),
            ("Analyst classified the file as a malware sample.", "unknown", "Confirmed malware "),
        ):
            with self.subTest(malware_type=malware_type):
                self.conn.execute("UPDATE findings SET source='analyst',rule_id='analyst.file_review',"
                                  "rule='Manual file review',evidence=?", (statement,))
                self.conn.commit()
                preview = self.preview()
                malware = [o for o in preview["objects"] if o["type"] == "malware"]
                self.assertEqual(1, len(malware))
                self.assertEqual([malware_type], malware[0]["malware_types"])
                self.assertEqual(name + self.sha[:12], malware[0]["name"])
                self.assertFalse(malware[0]["is_family"])
                file = next(o for o in preview["objects"] if o["type"] == "file")
                self.assertEqual(self.sha, file["hashes"]["SHA-256"])
                self.assertEqual([file["id"]], malware[0]["sample_refs"])
                report = next(o for o in preview["objects"] if o["type"] == "report")
                self.assertIn(malware[0]["id"], report["object_refs"])
                self.assertNotIn("artifact", [o["type"] for o in preview["objects"]])
                self.assertFalse(any(s["selected"] for s in preview["samples"]))

    def test_manual_classification_change_replaces_old_assertion_and_updates_ioc_status(self):
        self.conn.execute("UPDATE findings SET source='analyst',rule_id='analyst.file_review',"
                          "evidence='Analyst classified the file as a webshell.'")
        self.conn.commit()
        webshell = self.preview()
        self.conn.execute("UPDATE findings SET evidence='Analyst classified the file as a malware sample.'")
        self.conn.commit()
        malware = self.preview()
        old = next(o for o in webshell["objects"] if o["type"] == "malware")
        new = next(o for o in malware["objects"] if o["type"] == "malware")
        self.assertNotEqual(old["id"], new["id"])
        self.assertEqual(["unknown"], new["malware_types"])
        revoked = graph.withdrawal_objects(webshell["objects"], malware["objects"], "PIM-5165")
        self.assertTrue(any(o["id"] == old["id"] and o.get("revoked") for o in revoked))
        old_row = next(r for r in webshell["iocs"] if r["id"] == self.hash_id)
        new_row = next(r for r in malware["iocs"] if r["id"] == self.hash_id)
        self.assertNotEqual(old_row["fingerprint"], new_row["fingerprint"])
        self.conn.execute("UPDATE findings SET triage='reviewed',"
                          "evidence='Analyst reviewed the file; the decision remains open.'")
        self.conn.commit()
        self.assertNotIn("malware", [o["type"] for o in self.preview()["objects"]])

    def test_yara_or_ordinary_finding_text_does_not_become_manual_malware_classification(self):
        for source, rule_id in (("yara", "analyst.file_review"), ("analyst", "other.rule")):
            with self.subTest(source=source, rule_id=rule_id):
                self.conn.execute("UPDATE findings SET source=?,rule_id=?,"
                                  "evidence='Analyst classified the file as a malware sample.'",
                                  (source, rule_id))
                self.conn.commit()
                preview = self.preview()
                self.assertNotIn("malware", [o["type"] for o in preview["objects"]])
                self.assertIn("file", [o["type"] for o in preview["objects"]])
                self.assertIn("Associated file confirmed", json.dumps(preview["objects"]))

    def test_explicit_manual_malware_classification_supersedes_older_webshell_scan(self):
        db.upsert_finding(self.conn, "analyst", 0, "Manual file review", "file", str(self.file),
                          evidence="Analyst classified the file as a malware sample.",
                          rule_id="analyst.file_review")
        self.conn.execute("UPDATE findings SET triage='confirmed'")
        self.conn.commit()
        malware = [o for o in self.preview()["objects"] if o["type"] == "malware"]
        self.assertEqual(1, len(malware))
        self.assertEqual(["unknown"], malware[0]["malware_types"])

    def test_webshell_takes_precedence_across_separate_classified_occurrences_of_same_bytes(self):
        alternate = self.evidence / "alternate.php"
        alternate.write_bytes(self.content)
        alternate_id = db.add_ioc(self.conn, "alternate.php", "path")
        for ioc_id, role in ((alternate_id, "direct"), (self.hash_id, "hash")):
            self.conn.execute("INSERT INTO ioc_sources(ioc_id,artifact,role,active,added) VALUES(?,?,?,1,?)",
                              (ioc_id, str(alternate), role, db.now()))
        db.upsert_finding(self.conn, "analyst", 0, "Manual file review", "file", str(alternate),
                          evidence="Analyst classified the file as a malware sample.",
                          rule_id="analyst.file_review")
        self.conn.execute("UPDATE findings SET triage='confirmed'")
        self.conn.commit()
        malware = [o for o in self.preview()["objects"] if o["type"] == "malware"]
        self.assertEqual(1, len(malware))
        self.assertEqual(["webshell"], malware[0]["malware_types"])

    def test_case_notes_can_be_excluded_while_including_ioc_notes(self):
        workspace.update_case(self.case, notes="Private case narrative")
        self.conn.execute("UPDATE iocs SET note='Allowed IOC narrative' WHERE id=?", (self.ip_id,))
        self.conn.commit()
        preview = self.preview(include_notes=True, exclude_profile_fields=["case_notes"])
        exported = json.dumps(preview["objects"])
        self.assertNotIn("Private case narrative", exported)
        self.assertIn("Allowed IOC narrative", exported)

    def test_root_collision_is_ambiguous_without_structured_hash_provenance(self):
        second = self.root / "second-evidence"
        (second / "uploads").mkdir(parents=True)
        (second / "uploads" / "example.php").write_bytes(b"different file in second root")
        self.conn.execute("INSERT INTO evidence(kind,path,added) VALUES('webroot',?,?)", (str(second), db.now()))
        self.conn.execute("DELETE FROM ioc_sources")
        self.conn.commit()
        preview = self.preview()
        path = next(r for r in preview["iocs"] if r["id"] == self.path_id)
        self.assertIn("ambiguous", " ".join(path["warnings"]))
        unavailable = [s for s in preview["samples"] if not s["available"]]
        self.assertEqual(1, len(unavailable))
        # A matching content hash safely selects the correct root even though
        # the relative path alone cannot do so.
        hashed = next(r for r in preview["iocs"] if r["id"] == self.hash_id)
        file_id = next(x for x in hashed["object_ids"] if x.startswith("file--"))
        self.assertTrue(any(s["available"] and s["file_id"] == file_id for s in preview["samples"]))

    def test_sample_resolution_returns_only_exact_reviewed_bytes_and_safe_filename(self):
        sample = next(s for s in self.preview()["samples"] if s["available"])
        resolved = graph.resolve_sample(self.case, sample["id"], sample["sha256"])
        self.assertEqual(self.content, resolved["content"])
        self.assertEqual("example.php", resolved["filename"])
        self.assertNotIn("path", resolved)
        self.file.write_bytes(b"changed after preview")
        with self.assertRaises(ValueError):
            graph.resolve_sample(self.case, sample["id"], sample["sha256"])
        with self.assertRaises(ValueError):
            graph.resolve_sample(self.case, "invalid-id", self.sha)

    def test_sample_size_bound_and_symlink_escape(self):
        with patch.object(graph, "MAX_SAMPLE_BYTES", 4):
            preview = self.preview()
        self.assertTrue(any("limit" in w for r in preview["iocs"] for w in r["warnings"]))
        self.assertFalse(any(s["available"] for s in preview["samples"]))
        self.assertIsNone(graph._safe_existing(self.case / "case.json", [{"path": str(self.evidence)}]))

    def test_an_unavailable_registered_root_does_not_hide_other_readable_evidence(self):
        result = graph._safe_existing(self.file, [{"path": str(self.root / "offline-share")},
                                                 {"path": str(self.evidence)}])
        self.assertIsNotNone(result)

    def test_hash_can_resolve_two_different_paths_to_the_same_content(self):
        alternate = self.evidence / "alternate.php"
        alternate.write_bytes(self.content)
        alternate_id = db.add_ioc(self.conn, "alternate.php", "path")
        db.link_iocs(self.conn, self.hash_id, alternate_id, "hash-of")
        self.conn.execute("DELETE FROM ioc_sources")
        self.conn.commit()
        preview = self.preview()
        self.assertEqual(1, sum(o["type"] == "file" for o in preview["objects"]))
        self.assertEqual(1, sum(s["available"] for s in preview["samples"]))

    def test_profile_status_and_per_item_exclusions(self):
        info = workspace.case_info(self.case)
        info["profile"] = {"organization_id": "stable-org", "pseudonym": "Organization-012345",
                           "sectors": ["Technology"], "countries": ["DE"], "summary": "Hidden summary",
                           "software": [{"name": "Example CMS", "version": "1.2"}],
                           "vulnerabilities": [{"name": "CVE-2026-12345", "status": "confirmed"},
                                               {"name": "CVE-2026-12346", "status": "suspected"},
                                               {"name": "Misconfiguration", "status": "suspected"}]}
        self.conn.execute("UPDATE iocs SET note='private note' WHERE id=?", (self.path_id,))
        self.conn.execute("UPDATE findings SET evidence='private excerpt'")
        self.conn.commit()
        with patch("server.workspace.case_info", return_value=info):
            preview = self.preview(include_notes=True, include_evidence=True,
                                   exclude_note_ioc_ids=[self.path_id],
                                   exclude_evidence_ioc_ids=[self.path_id, self.hash_id],
                                   exclude_profile_fields=["summary", "software"])
        objects = preview["objects"]
        vulnerability_links = [o for o in objects if o["type"] == "relationship"
                               and o["source_ref"].startswith("incident--")
                               and o["target_ref"].startswith("vulnerability--")]
        self.assertEqual(2, len(vulnerability_links))
        self.assertTrue(all(o["relationship_type"] == "related-to" for o in vulnerability_links))
        self.assertEqual({"Exploitation confirmed: CVE-2026-12345",
                          "Exploitation suspected: CVE-2026-12346"},
                         {o["description"] for o in vulnerability_links})
        vulnerability_notes = [o["content"] for o in objects if o["type"] == "note"]
        for link in vulnerability_links:
            self.assertIn(link["description"], vulnerability_notes)
        self.assertEqual(2, sum(o["type"] == "vulnerability" for o in objects))
        exported = json.dumps(objects)
        for forbidden in ("private note", "private excerpt", "Hidden summary", "Example CMS"):
            self.assertNotIn(forbidden, exported)
        self.assertIn("Misconfiguration", exported)

    def test_url_credentials_are_never_an_observable_or_unredacted_context(self):
        self.conn.execute("UPDATE iocs SET value='https://alice:supersecret@example.test/a' WHERE id=?", (self.url_id,))
        self.conn.commit()
        preview = self.preview()
        self.assertNotIn("supersecret", json.dumps(preview))
        url = next(r for r in preview["iocs"] if r["id"] == self.url_id)
        self.assertFalse(url["indicator_supported"])

    @unittest.skipUnless(os.name == "nt", "Windows extended paths")
    def test_long_unicode_path_reads_and_redacts_correctly(self):
        deep = Path(io_path(self.evidence))
        while len(display_path(deep)) < 295:
            deep /= "long-directory-ä"
        deep.mkdir(parents=True)
        target = deep / "sample.php"
        target.write_bytes(self.content)
        self.conn.execute("UPDATE ioc_sources SET artifact=?", (display_path(target),))
        self.conn.execute("UPDATE findings SET artifact=?", (display_path(target),))
        self.conn.commit()
        sample = next(s for s in self.preview()["samples"] if s["available"])
        self.assertNotIn("Evidence sensitive customer", sample["display_path"])
        self.assertNotIn("\\\\?\\", sample["display_path"])
        self.assertEqual(self.content, graph.resolve_sample(self.case, sample["id"], sample["sha256"])["content"])


if __name__ == "__main__":
    unittest.main()
