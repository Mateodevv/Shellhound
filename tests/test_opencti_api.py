"""Real HTTP regression coverage for the OpenCTI boundary and IOC identity."""
import hashlib
import json
import os
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from server import db, workspace
from server.app import create_app
from server.config import Config
from tests.test_http import _LiveServer


class OpenCTIHTTPTests(unittest.TestCase):
    def test_structured_ioc_api_validation_and_offline_details(self):
        base = f"/api/cases/{self.slug}"
        for value, kind in (("198.51.100.9", "ip"), ("CVE-2026-12345", "vulnerability")):
            self.assertEqual(200, self.request("POST", base + "/iocs", {"value": value, "type": kind})[0])
        rows = self.request("GET", base + "/iocs")[1]
        ip = next(r["id"] for r in rows if r["type"] == "ip")
        cve = next(r["id"] for r in rows if r["type"] == "vulnerability")
        self.assertEqual(401, self.request("POST", base + f"/iocs/{ip}/assessments", {"state": "malicious", "reason": "Finding 1"}, token="bad")[0])
        self.assertEqual(400, self.request("POST", base + f"/iocs/{ip}/assessments", {"state": "malicious", "reason": " "})[0])
        self.assertEqual(200, self.request("POST", base + f"/iocs/{ip}/assessments", {"state": "suspicious", "reason": "Finding 1"})[0])
        code, link = self.request("POST", base + "/ioc-relationships", {"src": ip, "dst": cve, "kind": "exploit-attempt", "reference": "Access log line 5"})
        self.assertEqual(200, code)
        with patch("server.opencti_service.OpenCTIClient", side_effect=AssertionError("Unexpected network")):
            code, detail = self.request("GET", base + f"/iocs/{ip}/detail")
        self.assertEqual(200, code)
        self.assertEqual("suspicious", detail["object"]["assessment"])
        self.assertEqual("manual", detail["relationships"][0]["origin"])
        self.assertEqual(200, self.request("POST", base + f"/ioc-relationships/{link['id']}/withdraw", {"reason": "Wrong attribution"})[0])
        self.assertEqual(404, self.request("GET", base + "/iocs/999999/detail")[0])

    def test_ioc_tags_are_authenticated_local_deltas(self):
        base = f"/api/cases/{self.slug}/iocs"
        _, created = self.request("POST", base, {"value": "198.51.100.9", "type": "ip"})
        url = base + f"/{created['id']}/tags"
        self.assertEqual(401, self.request("POST", url, {"add": ["test"]}, token="bad")[0])
        with patch("server.opencti_service.OpenCTIClient", side_effect=AssertionError("Unexpected network")):
            status, payload = self.request("POST", url, {"add": [" IOC ", "ioc", "true positive"]})
            self.assertEqual(200, status)
            self.assertEqual(1, sum(t.casefold() == "ioc" for t in payload["tags"]))
            self.assertIn("analyst", payload["tags"])
            self.request("POST", url, {"add": ["scanner"]})
            _, payload = self.request("POST", url, {"remove": ["IOC"], "add": ["OpenCTI label"]})
            self.assertIn("scanner", payload["tags"])
            self.assertIn("OpenCTI label", payload["tags"])
            self.assertNotIn("IOC", payload["tags"])
            _, detail = self.request("GET", base + f"/{created['id']}/detail")
            self.assertEqual("malicious", detail["object"]["assessment"])
            self.assertEqual([], detail["assessments"])
        for invalid in (" ", "x" * 129, "two\nlines"):
            self.assertEqual(400, self.request("POST", url, {"add": [invalid]})[0])
        self.assertEqual(422, self.request("POST", url, {"add": ["tag"] * 101})[0])
        self.assertEqual(404, self.request("POST", base + "/999999/tags", {"add": ["tag"]})[0])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = workspace.create_case(self.root, "Integration test", "PIM-LOCAL-1")
        self.slug = self.case.name
        self.server = _LiveServer(create_app(Config(workspace=self.root, token="local-test")))
        self.base = self.server.start()
        self.addCleanup(self.server.stop)

    def request(self, method, path, body=None, token="local-test"):
        req = urllib.request.Request(self.base + path,
            data=json.dumps(body).encode() if body is not None else None,
            method=method, headers={"Content-Type": "application/json", "X-Token": token})
        try:
            response = urllib.request.urlopen(req, timeout=10)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            return response.status, json.loads(response.read())

    def test_offline_reads_auth_and_retired_external_routes(self):
        with patch("server.opencti_service.OpenCTIClient", side_effect=AssertionError("network")):
            for path in ["/api/opencti/settings", "/api/organizations", f"/api/cases/{self.slug}/opencti"]:
                self.assertEqual(401, self.request("GET", path, token="bad")[0])
                self.assertEqual(200, self.request("GET", path)[0])
            self.assertEqual(410, self.request("POST", "/api/settings/key",
                {"service": "virustotal", "key": "not-a-key"})[0])
            self.assertEqual(410, self.request("POST", f"/api/cases/{self.slug}/enrich",
                {"service": "abuseipdb", "value": "198.51.100.7"})[0])

    def test_case_profile_and_preview_are_reviewable_without_token(self):
        code, organization = self.request("POST", "/api/organizations", {})
        self.assertEqual(200, code)
        code, case = self.request("PATCH", f"/api/cases/{self.slug}", {"profile": {
            "organization_id": organization["id"], "summary": "Synthetic test only",
            "vulnerabilities": [{"name": "CVE-2026-1234", "status": "suspected"}]}})
        self.assertEqual(200, code, case)
        self.assertEqual(organization["name"], case["profile"]["pseudonym"])
        code, preview = self.request("POST", f"/api/cases/{self.slug}/opencti/preview", {})
        self.assertEqual(200, code, preview)
        self.assertTrue(preview["preview_id"])
        self.assertIn("incident", {o["type"] for o in preview["objects"]})
        self.assertIn("report", {o["type"] for o in preview["objects"]})
        self.assertEqual(400, self.request("POST", f"/api/cases/{self.slug}/opencti/export",
                                         {"preview_id": preview["preview_id"]})[0])

    def test_wizard_creates_complete_profile_before_any_transfer(self):
        _, organization = self.request("POST", "/api/organizations", {})
        profile = {
            "organization_id": organization["id"], "pseudonym": organization["name"],
            "summary": "Synthetic incident for wizard acceptance",
            "sectors": ["Technology", "Manufacturing"], "countries": ["de", "AT"],
            "first_seen": "2026-09-01", "last_seen": "2026-09-08",
            "software": [{"name": "Example CMS", "version": "5.2"}],
            "vulnerabilities": [
                {"name": "CVE-2026-12345", "status": "confirmed", "description": "Verified locally"},
                {"name": "Custom plugin flaw", "status": "suspected", "description": "Upload validation under investigation"},
            ], "marking": "TLP:AMBER+STRICT",
        }
        with patch("server.opencti_service.OpenCTIClient", side_effect=AssertionError("Unexpected network")):
            status, created = self.request("POST", "/api/cases", {
                "name": "Wizard acceptance", "reference": "PIM-WIZARD-1", "profile": profile,
            })
            self.assertEqual(200, status, created)
            _, saved = self.request("GET", f"/api/cases/{created['slug']}")
        expected = {**profile, "countries": ["DE", "AT"]}
        self.assertEqual(expected, saved["profile"])
        self.assertEqual("PIM-WIZARD-1", saved["reference"])
        _, state = self.request("GET", f"/api/cases/{created['slug']}/opencti")
        self.assertEqual([], state["exports"])
        self.assertEqual([], state["jobs"])
        status, preview = self.request("POST", f"/api/cases/{created['slug']}/opencti/preview", {})
        self.assertEqual(200, status, preview)
        types = {obj["type"] for obj in preview["objects"]}
        self.assertTrue({"incident", "report", "identity", "location", "vulnerability"} <= types)

    def test_keys_are_masked_and_case_id_collision_is_validation_error(self):
        code, response = self.request("PATCH", "/api/opencti/settings", {
            "url": "https://cti.example", "token": "private-test-secret",
            "ingester_id": "dba5717c-b7d1-474f-8aad-bf9c2d61312c"})
        self.assertEqual(200, code, response)
        self.assertNotIn("private-test-secret", json.dumps(response))
        self.assertEqual(400, self.request("POST", "/api/cases",
            {"name": "Duplicate", "reference": "pim-local-1"})[0])

    def test_ioc_delete_removes_provenance_and_reused_id_gets_new_identity(self):
        conn = db.connect(self.case)
        try:
            ioc_id = db.add_ioc(conn, "198.51.100.7", "ip")
            other = db.add_ioc(conn, "example.invalid", "domain")
            db.link_iocs(conn, other, ioc_id, "related-to")
            conn.execute("INSERT INTO ioc_sources(ioc_id,artifact,role,active,added) VALUES(?,?,?,?,?)",
                         (ioc_id, "synthetic.txt", "direct", 1, db.now()))
            source = conn.execute("SELECT source_uid FROM iocs WHERE id=?", (ioc_id,)).fetchone()[0]
            conn.commit()
        finally:
            conn.close()
        self.assertEqual(200, self.request("DELETE", f"/api/cases/{self.slug}/iocs/{ioc_id}")[0])
        conn = db.connect(self.case)
        try:
            self.assertEqual(0, conn.execute("SELECT count(*) FROM ioc_sources WHERE ioc_id=?", (ioc_id,)).fetchone()[0])
            self.assertEqual(0, conn.execute("SELECT count(*) FROM ioc_links").fetchone()[0])
            conn.execute("INSERT INTO iocs(id,value,type,added) VALUES(?,?,?,?)",
                         (ioc_id, "203.0.113.8", "ip", db.now()))
            replacement = conn.execute("SELECT source_uid FROM iocs WHERE id=?", (ioc_id,)).fetchone()[0]
            self.assertTrue(replacement)
            self.assertNotEqual(source, replacement)
        finally:
            conn.close()

    def _inert_evidence(self):
        evidence = self.root / "evidence"
        evidence.mkdir()
        sample = evidence / "example.txt"
        sample.write_bytes(b"Synthetic inert sample, no executable code.\n")
        conn = db.connect(self.case)
        try:
            conn.execute("INSERT INTO evidence(kind,path,added) VALUES(?,?,?)",
                         ("webroot", str(evidence), db.now()))
            conn.commit()
        finally:
            conn.close()
        return sample

    def test_file_hashes_survive_windows_path_and_handle_ctime_difference(self):
        sample = self._inert_evidence()
        original = os.fstat
        def handle_stat(fd):
            value = original(fd)
            return SimpleNamespace(st_dev=value.st_dev, st_ino=value.st_ino,
                st_size=value.st_size, st_mtime_ns=value.st_mtime_ns,
                st_ctime_ns=value.st_ctime_ns + 1_000_000_000)
        with patch("server.app.os.fstat", side_effect=handle_stat):
            code, detail = self.request("GET", f"/api/cases/{self.slug}/file?path=" +
                                        urllib.parse.quote(str(sample), safe=""))
        self.assertEqual(200, code, detail)
        self.assertEqual(hashlib.sha256(sample.read_bytes()).hexdigest(), detail["hashes"]["sha256"])

    def test_explicit_file_classifications_reach_preview_and_can_be_corrected(self):
        sample = self._inert_evidence()
        route = f"/api/cases/{self.slug}/files/review"
        self.assertEqual(400, self.request("POST", route, {"path": str(sample),
            "state": "confirmed", "classification": "malware"})[0])
        self.assertEqual(400, self.request("POST", route, {"path": str(sample),
            "state": "confirmed", "classification": "c2", "note": "Invalid classification"})[0])
        for classification, malware_type in (("webshell", "webshell"), ("malware", "unknown")):
            with self.subTest(classification=classification):
                code, decision = self.request("POST", route, {"path": str(sample),
                    "state": "confirmed", "classification": classification,
                    "note": "Synthetic analyst confirmation for integration testing."})
                self.assertEqual(200, code, decision)
                self.assertEqual(classification, decision["review"]["classification"])
                code, preview = self.request("POST", f"/api/cases/{self.slug}/opencti/preview", {})
                self.assertEqual(200, code, preview)
                self.assertEqual([], preview["errors"])
                malware = [o for o in preview["objects"] if o["type"] == "malware"]
                self.assertEqual(1, len(malware), malware)
                self.assertEqual([malware_type], malware[0]["malware_types"])
                self.assertFalse(malware[0]["is_family"])
        conn = db.connect(self.case)
        try:
            event = db.one(conn, "SELECT note FROM triage_events ORDER BY id DESC LIMIT 1")
            self.assertIn("Classification changed to malware:", event["note"])
        finally:
            conn.close()
        self.assertEqual(200, self.request("POST", route, {"path": str(sample),
            "state": "dismissed", "note": "Synthetic correction."})[0])
        code, preview = self.request("POST", f"/api/cases/{self.slug}/opencti/preview", {})
        self.assertEqual(200, code, preview)
        self.assertFalse(any(o["type"] == "malware" for o in preview["objects"]))

    def test_manual_review_of_changed_bytes_retires_old_hash_provenance(self):
        sample = self._inert_evidence()
        route = f"/api/cases/{self.slug}/files/review"
        old_hash = hashlib.sha256(sample.read_bytes()).hexdigest()
        self.assertEqual(200, self.request("POST", route, {"path": str(sample),
            "state": "confirmed", "note": "First synthetic file review."})[0])
        conn = db.connect(self.case)
        try:
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('webshell_hashes',?)",
                         (json.dumps({str(sample): old_hash}),))
            conn.commit()
        finally:
            conn.close()
        sample.write_bytes(b"Different inert bytes at the same relative path.\n")
        new_hash = hashlib.sha256(sample.read_bytes()).hexdigest()
        code, result = self.request("POST", route, {"path": str(sample), "state": "confirmed",
            "classification": "malware", "note": "Reviewed the changed synthetic bytes."})
        self.assertEqual(200, code, result)
        self.assertIn(new_hash, [i["value"] for i in result["collected"]])
        self.assertNotIn(old_hash, [i["value"] for i in result["collected"]])
        conn = db.connect(self.case)
        try:
            active = {r["value"]: r["active"] for r in db.rows(conn,
                "SELECT i.value,s.active FROM iocs i JOIN ioc_sources s ON s.ioc_id=i.id WHERE i.type='hash'")}
            self.assertEqual({old_hash: 0, new_hash: 1}, active)
        finally:
            conn.close()
        code, preview = self.request("POST", f"/api/cases/{self.slug}/opencti/preview", {})
        self.assertEqual(200, code, preview)
        malware = [o for o in preview["objects"] if o["type"] == "malware"]
        self.assertEqual(1, len(malware), malware)
        referenced_file = next(o for o in preview["objects"] if o["id"] == malware[0]["sample_refs"][0])
        self.assertEqual(new_hash, referenced_file["hashes"]["SHA-256"])


if __name__ == "__main__":
    unittest.main()
