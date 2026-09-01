"""OpenCTI contract tests use an in-process transport, never the network."""
import json
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path

import httpx

from server import db, opencti, opencti_case, settings


def configuration():
    return {
        "url": "https://opencti.example.test",
        "token": "secret-opencti-token-abcd",
        "taxii_collection_url": "https://opencti.example.test/taxii/collections/one/objects",
        "verified_at": "2026-09-01T10:00:00Z",
    }


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.workspace = Path(tempfile.mkdtemp(prefix="shellhound-opencti-settings-"))

    def test_token_is_masked_and_connection_change_requires_retest(self):
        settings.set_opencti(self.workspace, configuration())
        settings.verify_opencti(self.workspace, {
            "verified_at": "2026-09-01T10:00:00Z", "version": "7.260817.0",
            "capabilities": ["KNOWLEDGE_KNUPDATE", "KNOWLEDGE_KNUPLOAD"],
            "markings": [], "authors": [],
        })
        public = settings.public(self.workspace)["opencti"]
        self.assertNotIn(configuration()["token"], json.dumps(public))
        self.assertEqual("…abcd", public["token_hint"])
        self.assertTrue(public["verified"])
        settings.set_opencti(self.workspace, {"url": "https://new.example.test"})
        self.assertFalse(settings.public(self.workspace)["opencti"]["verified"])
        self.assertEqual(configuration()["token"], settings.opencti(self.workspace)["token"])

    def test_only_https_without_embedded_credentials_is_accepted(self):
        for value in ("http://opencti.test", "https://u:p@opencti.test", "file:///tmp/x"):
            with self.subTest(value=value), self.assertRaises(opencti.OpenCtiError):
                opencti.validate_https_url(value)


class StixTests(unittest.TestCase):
    def test_observable_ids_are_deterministic_and_actor_is_only_an_ip(self):
        first = opencti.observable_object({"type": "ip", "value": "2001:0db8::1"})
        second = opencti.observable_object({"type": "ip", "value": "2001:db8:0:0::1"})
        self.assertEqual(first["id"], second["id"])
        self.assertEqual("ipv6-addr", first["type"])
        self.assertNotIn("threat", json.dumps(first).lower())

    def test_report_contains_observable_note_file_artifact_and_opt_in_indicator(self):
        publication = str(uuid.uuid4())
        items = [
            {"kind": "observable", "local_ref": "ioc:1", "type": "domain",
             "value": "Bad.Example.", "indicator": True},
            {"kind": "file", "local_ref": "file:x", "path": "C:/not-opened/x.php",
             "relative_path": "uploads/x.php", "name": "x.php", "size": 12,
             "hashes": {"SHA-256": "a" * 64}, "mime_type": "text/x-php",
             "indicator": False},
            {"kind": "finding", "local_ref": "finding:3", "id": 3,
             "rule": "Manual file review", "content": "Confirmed by analyst"},
        ]
        built = opencti.build_bundle(
            {"slug": "case", "name": "Case", "reference": "IR-1"}, publication,
            "Short forensic assessment", "marking-definition--" + str(uuid.uuid4()),
            "identity--" + str(uuid.uuid4()), items, "2026-09-01T10:00:00Z")
        types = [row["type"] for row in built["bundle"]["objects"]]
        self.assertIn("report", types)
        self.assertIn("note", types)
        self.assertIn("file", types)
        self.assertIn("artifact", types)
        self.assertEqual(1, types.count("indicator"))
        self.assertEqual(1, len(built["uploads"]))
        self.assertNotIn("C:/not-opened", json.dumps(built["bundle"]))

    def test_indicator_is_never_inferred_from_labels(self):
        built = opencti.build_bundle(
            {"slug": "c", "name": "C"}, str(uuid.uuid4()), "summary", "", "",
            [{"kind": "observable", "type": "ip", "value": "192.0.2.1",
              "tags": ["confirmed", "successful"], "indicator": False}])
        self.assertNotIn("indicator", [row["type"] for row in built["bundle"]["objects"]])

    def test_selected_file_enriches_the_same_hash_observable(self):
        sha256 = "b" * 64
        built = opencti.build_bundle(
            {"slug": "c", "name": "C"}, str(uuid.uuid4()), "summary", "", "",
            [{"kind": "observable", "type": "hash", "value": sha256},
             {"kind": "file", "path": "never-opened", "relative_path": "x.txt",
              "name": "x.txt", "size": 99, "hashes": {"SHA-256": sha256},
              "mime_type": "text/plain"}])
        files = [row for row in built["bundle"]["objects"] if row["type"] == "file"]
        self.assertEqual(1, len(files))
        self.assertEqual("x.txt", files[0]["name"])
        self.assertEqual(99, files[0]["size"])


class CaseStateTests(unittest.TestCase):
    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix="shellhound-opencti-case-"))
        self.evidence = self.case / "evidence"
        self.evidence.mkdir()
        self.file = self.evidence / "harmless.txt"
        self.file.write_text("synthetic marker only", encoding="utf-8")
        self.conn = db.connect(self.case)
        self.conn.execute("INSERT INTO evidence(kind,path,added) VALUES('webroot',?,?)",
                          (str(self.evidence), db.now()))
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_draft_roundtrip_and_file_is_resolved_inside_evidence(self):
        saved = opencti_case.save_draft(self.conn, {
            "items": [{"kind": "file", "path": str(self.file), "indicator": True}],
            "summary": "share", "marking_id": "m1"})
        self.assertEqual(saved, opencti_case.get_draft(self.conn))
        snap = opencti_case.file_snapshot(self.conn, str(self.file), "file:1")
        self.assertEqual("harmless.txt", snap["relative_path"])
        self.assertEqual(64, len(snap["hashes"]["SHA-256"]))

    def test_outside_file_is_rejected(self):
        outside = self.case / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        with self.assertRaises(opencti_case.CaseOpenCtiError):
            opencti_case.safe_file(self.conn, str(outside))

    def test_symlink_escape_is_rejected(self):
        outside = self.case / "outside-link-target.txt"
        outside.write_text("outside", encoding="utf-8")
        link = self.evidence / "escaped.txt"
        try:
            link.symlink_to(outside)
        except OSError as exc:
            self.skipTest(f"symlinks are unavailable on this host: {exc}")
        with self.assertRaises(opencti_case.CaseOpenCtiError):
            opencti_case.safe_file(self.conn, str(link))

    def test_current_schema_contains_opencti_audit_tables(self):
        tables = {row[0] for row in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        for name in ("opencti_lookup_snapshots", "opencti_draft",
                     "opencti_publications", "opencti_publication_files",
                     "ioc_external_sources"):
            self.assertIn(name, tables)

    def test_registered_evidence_roots_are_redacted_from_release_text(self):
        message = f"file found below {self.evidence}\\uploads"
        clean = opencti_case.redact_evidence_roots(message, [str(self.evidence)])
        self.assertNotIn(str(self.evidence), clean)
        self.assertIn("<evidence-root>", clean)

    def test_version_11_file_receipts_gain_identity_columns(self):
        legacy = Path(tempfile.mkdtemp(prefix="shellhound-opencti-v11-"))
        raw = sqlite3.connect(legacy / db.CASE_DB)
        raw.executescript("""
          CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
          INSERT INTO meta VALUES ('schema_version','11');
          CREATE TABLE opencti_publication_files (
            id INTEGER PRIMARY KEY, publication_id TEXT NOT NULL,
            relative_path TEXT NOT NULL, sha256 TEXT NOT NULL DEFAULT '',
            size INTEGER NOT NULL DEFAULT 0, artifact_stix_id TEXT NOT NULL,
            remote_id TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending',
            error_code TEXT NOT NULL DEFAULT '', error_message TEXT NOT NULL DEFAULT '',
            UNIQUE(publication_id,artifact_stix_id));
        """)
        raw.commit()
        raw.close()
        upgraded = db.connect(legacy)
        try:
            columns = {row[1] for row in upgraded.execute(
                "PRAGMA table_info(opencti_publication_files)")}
            self.assertTrue({"device", "inode", "mtime_ns"}.issubset(columns))
            self.assertEqual(str(db.CASE_SCHEMA_VERSION), upgraded.execute(
                "SELECT value FROM meta WHERE key='schema_version'").fetchone()[0])
        finally:
            upgraded.close()


class ClientTests(unittest.TestCase):
    def _handler(self, request):
        if request.method == "GET":
            return httpx.Response(200, json={"objects": []})
        if request.url.path.endswith("/graphql"):
            body = json.loads(request.content)
            if "ShellhoundConnection" in body["query"]:
                return httpx.Response(200, json={"data": {
                    "about": {"version": "7.260817.0"},
                    "me": {"id": "user-1", "name": "Shellhound",
                           "capabilities": [
                               {"name": "KNOWLEDGE_KNUPDATE"},
                               {"name": "KNOWLEDGE_KNUPLOAD"},
                           ]},
                    "markingDefinitions": {"edges": [{"node": {
                        "id": "m1", "standard_id": "marking-definition--1",
                        "definition_type": "TLP", "definition": "TLP:AMBER"}}]},
                    "identities": {"edges": [{"node": {
                        "id": "o1", "standard_id": "identity--1",
                        "name": "Shellhound", "entity_type": "Organization"}}]},
                }})
            if "ShellhoundObservableLookup" in body["query"]:
                value = body["variables"]["search"]
                return httpx.Response(200, json={"data": {
                    "stixCyberObservables": {"edges": [{"node": {
                        "id": "remote-1", "standard_id": "ipv4-addr--1",
                        "entity_type": "IPv4-Addr", "observable_value": value,
                        "x_opencti_score": 80, "objectLabel": {"edges": []},
                        "objectMarking": {"edges": []}, "indicators": {"edges": []},
                        "stixCoreRelationships": {"edges": []},
                    }}]}}})
        if request.method == "POST" and "/taxii/" in request.url.path:
            return httpx.Response(202, json={"status": "pending", "id": "status-1"})
        return httpx.Response(500)

    def test_connection_lookup_and_taxii_use_the_fake_transport(self):
        with opencti.OpenCtiClient(
                configuration(), httpx.MockTransport(self._handler)) as client:
            result = client.test_connection()
            self.assertEqual("7.260817.0", result["version"])
            self.assertEqual("TLP:AMBER", result["markings"][0]["name"])
            lookup = client.lookup("ip", "192.0.2.8")
            self.assertTrue(lookup["matched"])
            pushed = client.taxii_push({"objects": [{"type": "ipv4-addr"}]})
            self.assertEqual("pending", pushed["status"])

    def test_redirect_and_remote_body_are_not_exposed(self):
        def handler(_request):
            return httpx.Response(302, headers={"location": "https://evil.test/secret"})
        with opencti.OpenCtiClient(
                configuration(), httpx.MockTransport(handler)) as client:
            with self.assertRaises(opencti.OpenCtiError) as caught:
                client.graphql("query { about { version } }")
        self.assertEqual("redirect", caught.exception.code)
        self.assertNotIn("evil.test", str(caught.exception))

    def test_missing_upload_permission_blocks_verification(self):
        def handler(request):
            if request.method == "GET":
                return httpx.Response(200, json={"objects": []})
            return httpx.Response(200, json={"data": {
                "about": {"version": "7.260817.0"},
                "me": {"id": "u1", "name": "limited", "capabilities": [
                    {"name": "KNOWLEDGE_KNUPDATE"}]},
                "markingDefinitions": {"edges": []}, "identities": {"edges": []},
            }})
        with opencti.OpenCtiClient(
                configuration(), httpx.MockTransport(handler)) as client:
            with self.assertRaises(opencti.OpenCtiError) as caught:
                client.test_connection()
        self.assertEqual("missing_capabilities", caught.exception.code)

    def test_failed_taxii_status_is_sanitized(self):
        def handler(_request):
            return httpx.Response(202, json={
                "status": "failed", "failures": [{"message": "secret body"}]})
        with opencti.OpenCtiClient(
                configuration(), httpx.MockTransport(handler)) as client:
            with self.assertRaises(opencti.OpenCtiError) as caught:
                client.taxii_push({"objects": []})
        self.assertEqual("taxii_failed", caught.exception.code)
        self.assertNotIn("secret body", str(caught.exception))

    def test_timeout_has_a_sanitized_error(self):
        def handler(_request):
            raise httpx.ReadTimeout("secret upstream detail")
        with opencti.OpenCtiClient(
                configuration(), httpx.MockTransport(handler)) as client:
            with self.assertRaises(opencti.OpenCtiError) as caught:
                client.graphql("query { about { version } }")
        self.assertEqual("timeout", caught.exception.code)
        self.assertNotIn("secret upstream detail", str(caught.exception))

    def test_http_413_is_reported_without_remote_content(self):
        def handler(_request):
            return httpx.Response(413, text="sensitive proxy response")
        with opencti.OpenCtiClient(
                configuration(), httpx.MockTransport(handler)) as client:
            with self.assertRaises(opencti.OpenCtiError) as caught:
                client.graphql("query { about { version } }")
        self.assertEqual("too_large", caught.exception.code)
        self.assertNotIn("sensitive proxy response", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
