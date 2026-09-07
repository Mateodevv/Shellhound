"""Structured IOC identity, migration, evidence and export regressions."""
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from server import db, ioc_model as model, opencti_graph as graph, workspace


class StructuredIocTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = workspace.create_case(self.root / "cases", "Synthetic objects", "PIM-OBJECT-QA")
        self.conn = db.connect(self.case)
        self.addCleanup(self.conn.close)

    def collect(self, root="root-a", content=b"inert sample", relative="uploads/sample.txt", classification=""):
        folder = self.root / root
        path = folder / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        self.conn.execute("INSERT OR IGNORE INTO evidence(kind,path,added) VALUES('webroot',?,?)", (str(folder), db.now()))
        digest = hashlib.sha256(content).hexdigest()
        path_id = db.add_ioc(self.conn, relative, "path", context=str(path), path_context="system")
        hash_id = db.add_ioc(self.conn, digest, "hash")
        db.link_iocs(self.conn, hash_id, path_id, "hash-of")
        file_id = model.collect_file(self.conn, str(path), digest, hash_id, path_id, classification)
        return path, path_id, hash_id, file_id

    def test_identity_is_typed_and_scoped(self):
        domain = db.add_ioc(self.conn, "EXAMPLE.test.", "domain")
        self.assertEqual(domain, db.add_ioc(self.conn, "example.test", "domain"))
        self.assertNotEqual(domain, db.add_ioc(self.conn, "EXAMPLE.test.", "path"))
        self.assertNotEqual(db.add_ioc(self.conn, "admin", "user", context="system-a"),
                            db.add_ioc(self.conn, "admin", "user", context="system-b"))
        self.assertEqual(db.add_ioc(self.conn, "2001:db8::1", "ip"), db.add_ioc(self.conn, "2001:0db8:0:0:0:0:0:1", "ip"))
        self.assertNotEqual(db.add_ioc(self.conn, "/sample", "path", context="server", path_context="system"),
                            db.add_ioc(self.conn, "/sample", "path", context="server", path_context="http-request"))

    def test_hunt_cves_export_as_context_with_audit_support_and_no_verdict(self):
        entry = {"id": "qa-rule", "version": 2, "name": "Synthetic pattern",
                 "cve": "cve-2026-12345, CVE-2026-12346, CVE-2026-12345"}
        client = {"ip": "198.51.100.9", "hits": 3, "ok_hits": 3, "first_epoch": 1700000000,
                  "last_epoch": 1700000010, "source_path": "C:\\PrivateCustomer\\access.log",
                  "line_no": 17, "uri": "/synthetic"}
        with patch("urllib.request.urlopen", side_effect=AssertionError("Unexpected network")):
            model.collect_hunt_cves(self.conn, entry, 5, client, "rule-sha", "index-sha")
            model.collect_hunt_cves(self.conn, entry, 5, client, "rule-sha", "index-sha")
        self.assertEqual(3, self.conn.execute("SELECT count(*) FROM iocs").fetchone()[0])
        ip = db.one(self.conn, "SELECT * FROM iocs WHERE type='ip'")
        self.assertEqual("unassessed", ip["assessment"])
        detail = model.detail(self.conn, ip["id"])
        self.assertEqual(1, len(detail["observations"]))
        self.assertEqual(3, detail["observations"][0]["count"])
        self.assertEqual(2, len(detail["relationships"]))
        self.assertEqual({"cve-context"}, {l["kind"] for l in detail["relationships"]})
        self.conn.commit()
        preview = graph.build_preview(self.case, {"include_evidence": True})
        self.assertNotIn("PrivateCustomer", json.dumps(preview))
        self.assertIn("Pattern Hunt test #5", json.dumps(preview))
        self.assertEqual(2, sum(o["type"] == "relationship" and o["source_ref"].startswith("ipv4-addr--")
                               and o["target_ref"].startswith("vulnerability--") for o in preview["objects"]))
        for link in detail["relationships"]:
            model.withdraw(self.conn, link["id"], "Reviewed false positive")
        model.collect_hunt_cves(self.conn, entry, 6, client, "rule-sha", "index-sha")
        self.assertEqual([], db.ioc_links(self.conn))

    def test_hunt_without_explicit_cve_or_without_hits_creates_no_iocs(self):
        client = {"ip": "198.51.100.9", "hits": 1}
        model.collect_hunt_cves(self.conn, {"name": "CVE-2026-12345"}, 1, client, "r", "i")
        model.collect_hunt_cves(self.conn, {"cve": "CVE-2026-12345"}, 1, {**client, "hits": 0}, "r", "i")
        self.assertEqual(0, self.conn.execute("SELECT count(*) FROM iocs").fetchone()[0])

    def test_automatic_cve_link_loses_support_when_finding_is_dismissed(self):
        ip = db.add_ioc(self.conn, "198.51.100.9", "ip")
        db.upsert_finding(self.conn, "logs", 1, "Request references CVE-2026-12345", "client", "198.51.100.9")
        finding = db.one(self.conn, "SELECT * FROM findings")
        model.collect_cves(self.conn, ip, [finding])
        self.assertEqual("cve-context", db.ioc_links(self.conn)[0]["kind"])
        self.conn.execute("UPDATE findings SET triage='dismissed'")
        self.assertEqual([], db.ioc_links(self.conn))
        detail = model.detail(self.conn, ip)
        self.assertFalse(detail["relationships"][0]["active"])
        self.assertIn("no longer active", detail["relationships"][0]["withdrawal_reason"])

    def test_scoped_accounts_export_separately_and_context_is_not_disclosed(self):
        first = db.add_ioc(self.conn, "admin", "user", context="private-system-one")
        second = db.add_ioc(self.conn, "admin", "user", context="private-system-two")
        db.add_ioc(self.conn, "unscoped-admin", "user")
        self.conn.commit()
        preview = graph.build_preview(self.case)
        accounts = [o for o in preview["objects"] if o["type"] == "user-account"]
        self.assertEqual(2, len(accounts))
        self.assertNotEqual(accounts[0]["id"], accounts[1]["id"])
        self.assertNotIn("private-system", json.dumps(preview))
        self.assertNotEqual(first, second)

    def test_one_file_multiple_locations_and_separate_versions(self):
        _, path_a, hash_a, file_a = self.collect()
        _, path_b, hash_b, file_b = self.collect("root-b")
        self.assertEqual(file_a, file_b)
        self.assertEqual(hash_a, hash_b)
        self.assertNotEqual(path_a, path_b)
        self.assertEqual(2, len(model.detail(self.conn, file_a)["observations"]))
        _, same_path, _, changed = self.collect(content=b"different content")
        self.assertEqual(path_a, same_path)
        self.assertNotEqual(file_a, changed)
        self.assertEqual({"MD5", "SHA-1", "SHA-256"}, set(model.detail(self.conn, file_a)["object"]["file"]["hashes"]))

    def test_changed_content_does_not_mix_hashes_or_size(self):
        path, path_id, _, _ = self.collect()
        historic = "a" * 64
        hash_id = db.add_ioc(self.conn, historic, "hash")
        historic_file = model.collect_file(self.conn, str(path), historic, hash_id, path_id, "webshell")
        meta = model.detail(self.conn, historic_file)["object"]["file"]
        self.assertEqual({"SHA-256": historic}, meta["hashes"])
        self.assertIsNone(meta["size"])
        self.assertEqual("", meta["classification"])

    def test_explicit_metadata_verification_requires_matching_registered_content(self):
        path, _, hash_id, file_id = self.collect()
        self.conn.execute("UPDATE ioc_files SET hashes=?,size=NULL,verified_at='' WHERE ioc_id=?",
                          (json.dumps({"SHA-256": hashlib.sha256(b'inert sample').hexdigest()}), file_id))
        with patch("urllib.request.urlopen", side_effect=AssertionError("Unexpected network")):
            self.assertEqual(1, model.verify_file(self.conn, file_id)["verified_locations"])
        self.assertEqual(3, len(model.detail(self.conn, file_id)["object"]["file"]["hashes"]))
        path.write_bytes(b"changed bytes")
        with self.assertRaises(ValueError):
            model.verify_file(self.conn, file_id)
        self.assertEqual(hashlib.sha256(b'inert sample').hexdigest(), model.detail(self.conn, file_id)["object"]["file"]["hashes"]["SHA-256"])
        self.assertIsNotNone(hash_id)

    def test_assessments_require_reason_and_do_not_change_findings(self):
        ioc = db.add_ioc(self.conn, "198.51.100.9", "ip", ["confirmed"])
        self.assertEqual("unassessed", model.detail(self.conn, ioc)["object"]["assessment"])
        with self.assertRaises(ValueError):
            model.assess(self.conn, ioc, "malicious", "  ")
        model.assess(self.conn, ioc, "malicious", "Specific hostile request")
        model.assess(self.conn, ioc, "benign", "Authorized assessment exercise")
        detail = model.detail(self.conn, ioc)
        self.assertEqual(["benign", "malicious"], [r["state"] for r in detail["assessments"]])
        self.assertEqual(["confirmed"], detail["object"]["tags"])

    def test_relationship_requires_evidence_and_valid_endpoints(self):
        ip = db.add_ioc(self.conn, "198.51.100.9", "ip")
        cve = db.add_ioc(self.conn, "CVE-2026-12345", "vulnerability")
        with self.assertRaises(ValueError):
            model.relationship(self.conn, ip, cve, "exploitation-confirmed", "")
        with self.assertRaises(ValueError):
            model.relationship(self.conn, cve, ip, "exploitation-confirmed", "Finding 1")
        link = model.relationship(self.conn, ip, cve, "exploit-attempt", "Access log line 5")
        self.assertEqual(link, model.relationship(self.conn, ip, cve, "exploit-attempt", "Access log line 6"))
        self.assertEqual(2, len(model.detail(self.conn, ip)["relationships"][0]["evidence"]))
        model.withdraw(self.conn, link, "Log source was wrongly attributed")
        self.assertEqual([], db.ioc_links(self.conn))
        # A repeated automatic collection must not silently undo withdrawal.
        db.link_iocs(self.conn, ip, cve, "exploit-attempt", "Repeated collection")
        self.assertEqual([], db.ioc_links(self.conn))
        self.assertEqual("withdrawn", model.detail(self.conn, ip)["relationships"][0]["events"][-1]["action"])

    def test_observations_are_idempotent_snapshots_with_multiple_sources(self):
        ip = db.add_ioc(self.conn, "198.51.100.9", "ip")
        one = model.observe(self.conn, ip, "http-request", source_ref="access-log-1", path="/sample", count=5)
        self.assertEqual(one, model.observe(self.conn, ip, "http-request", source_ref="access-log-1", path="/sample", count=7))
        model.observe(self.conn, ip, "http-request", source_ref="access-log-2", path="/sample", count=2)
        self.assertEqual([2, 7], sorted(o["count"] for o in model.detail(self.conn, ip)["observations"]))

    def test_export_file_without_original_retains_identity_metadata(self):
        path, _, _, file_id = self.collect()
        self.conn.commit()
        before = graph.build_preview(self.case, {"ioc_ids": [file_id]})
        path.unlink()
        after = graph.build_preview(self.case, {"ioc_ids": [file_id]})
        old = next(o for o in before["objects"] if o["type"] == "file")
        new = next(o for o in after["objects"] if o["type"] == "file")
        self.assertEqual(old["id"], new["id"])
        self.assertEqual(old["hashes"], new["hashes"])
        self.assertEqual(old["size"], new["size"])
        self.assertFalse(any(s["available"] for s in after["samples"]))

    def test_structured_export_cve_relationships_privacy_and_withdrawal(self):
        ip = db.add_ioc(self.conn, "198.51.100.9", "ip")
        cve = db.add_ioc(self.conn, "CVE-2026-12345", "vulnerability")
        local = db.add_ioc(self.conn, "/opt/private-copy/raw.log", "path", path_context="local-evidence")
        model.assess(self.conn, ip, "suspicious", "private assessment explanation")
        model.observe(self.conn, ip, "http-request", source_ref="log1", local_path="C:\\PrivateCustomer\\raw.log",
                      detail="private evidence excerpt", path="/login", count=4)
        link = model.relationship(self.conn, ip, cve, "exploit-attempt", "private source reference", "private supporting detail")
        self.conn.commit()
        with patch("urllib.request.urlopen", side_effect=AssertionError("Unexpected network")):
            before = graph.build_preview(self.case)
        wire = json.dumps(before)
        for hidden in ("PrivateCustomer", "/opt/private-copy", "private source", "private supporting", "private assessment", "private evidence"):
            self.assertNotIn(hidden, wire)
        objects = before["objects"]
        self.assertTrue(any(o["type"] == "relationship" and o["target_ref"].startswith("vulnerability--")
                            and o["source_ref"].startswith("ipv4-addr--") for o in objects))
        disclosed = graph.build_preview(self.case, {"include_evidence": True, "include_notes": True})
        self.assertIn("private supporting detail", json.dumps(disclosed))
        self.assertNotIn("PrivateCustomer", json.dumps(disclosed))
        model.withdraw(self.conn, link, "Retracted test assertion")
        self.conn.commit()
        after = graph.build_preview(self.case)
        self.assertFalse(any(o["type"] == "relationship" and o["target_ref"].startswith("vulnerability--")
                             and o["source_ref"].startswith("ipv4-addr--") for o in after["objects"]))
        self.assertTrue(any(o["type"] == "relationship" for o in graph.withdrawal_objects(before["objects"], after["objects"], "PIM-OBJECT-QA")))
        self.assertIsNotNone(local)

    def test_excluded_endpoint_removes_relationship_and_evidence(self):
        ip = db.add_ioc(self.conn, "198.51.100.9", "ip")
        cve = db.add_ioc(self.conn, "CVE-2026-12345", "vulnerability")
        model.relationship(self.conn, ip, cve, "cve-context", "private reference")
        self.conn.commit()
        preview = graph.build_preview(self.case, {"ioc_ids": [ip], "include_evidence": True})
        self.assertNotIn("CVE-2026-12345", json.dumps(preview["objects"]))
        self.assertNotIn("private reference", json.dumps(preview["objects"]))

    def test_delete_removes_structured_children_before_row_id_reuse(self):
        ip = db.add_ioc(self.conn, "198.51.100.9", "ip")
        cve = db.add_ioc(self.conn, "CVE-2026-12345", "vulnerability")
        model.relationship(self.conn, ip, cve, "cve-context", "Finding 1")
        model.assess(self.conn, ip, "suspicious", "Finding 1")
        model.observe(self.conn, ip, "finding", finding_id=1)
        self.conn.execute("DELETE FROM iocs WHERE id=?", (ip,))
        for table in ("ioc_assessments", "ioc_observations", "ioc_relationship_evidence", "ioc_relationship_events"):
            self.assertEqual(0, self.conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0])

    def test_legacy_migration_preserves_ids_source_uids_and_unassessed_state(self):
        old = self.root / "legacy"
        old.mkdir()
        conn = sqlite3.connect(old / "case.db")
        conn.executescript(db.SCHEMA)
        conn.execute("ALTER TABLE iocs ADD COLUMN source_uid TEXT NOT NULL DEFAULT ''")
        conn.execute("INSERT INTO iocs(id,value,type,note,added,source_uid) VALUES(7,?,'hash','old note',?,'stable-source')", ("a" * 64, db.now()))
        conn.execute("INSERT INTO ioc_sources(ioc_id,artifact,role,active,added) VALUES(7,?,'hash',0,?)", (str(self.root / "root-a" / "file.txt"), db.now()))
        conn.commit()
        conn.close()
        migrated = db.connect(old)
        try:
            row = db.one(migrated, "SELECT * FROM iocs WHERE id=7")
            self.assertEqual("stable-source", row["source_uid"])
            self.assertEqual("old note", row["note"])
            self.assertEqual("unassessed", row["assessment"])
            file_row = db.one(migrated, "SELECT * FROM iocs WHERE type='file'")
            self.assertTrue(file_row["legacy_warning"])
            self.assertEqual(0, db.one(migrated, "SELECT active FROM ioc_sources WHERE ioc_id=?", (file_row["id"],))["active"])
            count = migrated.execute("SELECT count(*) FROM iocs").fetchone()[0]
        finally:
            migrated.close()
        again = db.connect(old)
        self.assertEqual(count, again.execute("SELECT count(*) FROM iocs").fetchone()[0])
        again.close()

    def test_v13_relationship_repair_requires_exact_provenance_and_is_idempotent(self):
        path, path_id, hash_id, file_id = self.collect()
        other_path, other_id, other_hash, other_file = self.collect("root-b", content=b"other bytes")
        ip = db.add_ioc(self.conn, "198.51.100.9", "ip")
        for ioc_id, artifact, role in ((path_id, path, "direct"), (hash_id, path, "hash"),
                                      (other_id, other_path, "direct"), (other_hash, other_path, "hash"),
                                      (ip, path, "requester")):
            self.conn.execute("INSERT OR IGNORE INTO ioc_sources(ioc_id,artifact,role,added) VALUES(?,?,?,?)",
                              (ioc_id, str(artifact), role, db.now()))
        db.link_iocs(self.conn, ip, path_id, "requested")
        db.link_iocs(self.conn, ip, other_id, "requested")  # No matching requester provenance.
        self.conn.execute("DELETE FROM ioc_links WHERE kind='located-at'")
        before = db.one(self.conn, "SELECT * FROM ioc_files WHERE ioc_id=?", (file_id,))
        model.migrate(self.conn)
        links = db.ioc_links(self.conn)
        self.assertEqual(2, sum(l["kind"] == "located-at" for l in links))
        requests = [l for l in links if l["kind"] == "request-context"]
        self.assertEqual([file_id], [l["dst_id"] for l in requests])
        self.assertIn("not established", requests[0]["note"])
        self.assertEqual(before, db.one(self.conn, "SELECT * FROM ioc_files WHERE ioc_id=?", (file_id,)))
        self.assertEqual("", db.one(self.conn, "SELECT legacy_warning FROM iocs WHERE id=?", (file_id,))["legacy_warning"])
        model.withdraw(self.conn, requests[0]["id"], "Incorrect historic attribution")
        counts = [self.conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
                  for t in ("iocs", "ioc_links", "ioc_observations", "ioc_relationship_evidence")]
        model.migrate(self.conn)
        self.assertFalse(any(l["kind"] == "request-context" for l in db.ioc_links(self.conn)))
        self.assertEqual(counts, [self.conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
                                 for t in ("iocs", "ioc_links", "ioc_observations", "ioc_relationship_evidence")])
        self.assertNotEqual(file_id, other_file)

    def test_ambiguous_legacy_file_versions_do_not_gain_ip_file_links(self):
        path, path_id, hash_id, _ = self.collect()
        _, _, newer_hash, _ = self.collect(content=b"new version")
        ip = db.add_ioc(self.conn, "198.51.100.9", "ip")
        for ioc_id, role in ((path_id, "direct"), (hash_id, "hash"), (newer_hash, "hash"), (ip, "requester")):
            self.conn.execute("INSERT OR IGNORE INTO ioc_sources(ioc_id,artifact,role,added) VALUES(?,?,?,?)",
                              (ioc_id, str(path), role, db.now()))
        db.link_iocs(self.conn, ip, path_id, "requested")
        model.migrate(self.conn)
        self.assertFalse(any(l["kind"] == "request-context" for l in db.ioc_links(self.conn)))
