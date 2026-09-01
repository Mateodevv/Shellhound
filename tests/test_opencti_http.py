"""HTTP contract for the manual OpenCTI workflow, with no real network."""
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from server import db, opencti, opencti_case, workspace
import server.app as app_module
from server.config import Config


TOKEN = "opencti-http-test"
MARKING_INTERNAL = "marking-internal"
MARKING_STANDARD = "marking-definition--" + str(uuid.uuid4())
AUTHOR_INTERNAL = "author-internal"
AUTHOR_STANDARD = "identity--" + str(uuid.uuid4())


class FakeOpenCtiClient:
    """The endpoint contract, never an OpenCTI installation."""

    taxii_calls = 0
    last_taxii_bundle = None
    upload_calls = 0
    upload_failures_remaining = 0

    def __init__(self, config):
        self.config = config

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def test_connection(self):
        return {
            "verified_at": "2026-09-01T10:00:00Z",
            "version": "7.260817.0",
            "user": {"id": "service-user", "name": "Shellhound"},
            "capabilities": ["KNOWLEDGE_KNUPDATE", "KNOWLEDGE_KNUPLOAD"],
            "markings": [{"id": MARKING_INTERNAL,
                          "standard_id": MARKING_STANDARD,
                          "name": "TLP:AMBER", "type": "TLP"}],
            "authors": [{"id": AUTHOR_INTERNAL,
                         "standard_id": AUTHOR_STANDARD,
                         "name": "Incident Response", "type": "Organization"}],
        }

    def lookup(self, kind, value):
        return {
            "matched": True,
            "matches": [{"id": "observable-main", "value": value,
                          "entity_type": kind, "score": 75}],
            "related": [{"id": "domain-related", "value": "related.example",
                         "type": "Domain-Name", "ioc_type": "domain",
                         "relationship": "resolves-to", "promotable": True}],
        }

    def taxii_push(self, bundle):
        type(self).taxii_calls += 1
        type(self).last_taxii_bundle = bundle
        return {"status": "complete", "id": "taxii-status"}

    def find_observable_id(self, standard_id):
        return "remote-" + standard_id

    def upload_file(self, _remote_id, _path, _marking_id=""):
        type(self).upload_calls += 1
        if type(self).upload_failures_remaining:
            type(self).upload_failures_remaining -= 1
            raise opencti.OpenCtiError(
                "upload_failed", "Synthetic upload failed", 502)
        return {"id": "uploaded-file"}


class OpenCtiHttpTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="shellhound-opencti-http-"))
        self.case_dir = workspace.create_case(
            self.root, "Synthetic OpenCTI case", "IR-SYNTHETIC")
        self.slug = self.case_dir.name
        self.evidence = self.case_dir / "synthetic-evidence"
        self.evidence.mkdir()
        self.file = self.evidence / "harmless.txt"
        self.file.write_text("synthetic marker only", encoding="utf-8")
        conn = db.connect(self.case_dir)
        try:
            conn.execute(
                "INSERT INTO evidence(kind,path,added) VALUES('webroot',?,?)",
                (str(self.evidence), db.now()))
            self.ioc_id = db.add_ioc(
                conn, "192.0.2.8", "ip", ["analyst"], origin="synthetic test")
            db.upsert_finding(conn, "test", db.SEV_LOW, "Synthetic finding",
                              "client", "192.0.2.8", evidence="harmless marker")
            conn.execute(
                "UPDATE findings SET triage='confirmed' WHERE rule='Synthetic finding'")
            conn.commit()
        finally:
            conn.close()
        self.patch = patch.object(
            app_module.openctilib, "OpenCtiClient", FakeOpenCtiClient)
        self.patch.start()
        self.client = TestClient(app_module.create_app(
            Config(workspace=self.root, token=TOKEN)))
        self.headers = {"X-Token": TOKEN}
        FakeOpenCtiClient.taxii_calls = 0
        FakeOpenCtiClient.last_taxii_bundle = None
        FakeOpenCtiClient.upload_calls = 0
        FakeOpenCtiClient.upload_failures_remaining = 0

    def tearDown(self):
        self.client.close()
        self.patch.stop()

    def request(self, method, path, body=None):
        return self.client.request(method, path, headers=self.headers, json=body)

    def configure(self):
        stored = self.request("PUT", "/api/settings/opencti", {
            "url": "https://opencti.example.test",
            "token": "never-return-this-token",
            "taxii_collection_url": (
                "https://opencti.example.test/taxii/collections/shellhound/objects"),
        })
        self.assertEqual(200, stored.status_code)
        self.assertNotIn("never-return-this-token", stored.text)
        tested = self.request("POST", "/api/settings/opencti/test")
        self.assertEqual(200, tested.status_code, tested.text)
        selected = self.request("PUT", "/api/settings/opencti", {
            "author_id": AUTHOR_INTERNAL,
            "author_name": "Incident Response",
            "default_marking_id": MARKING_INTERNAL,
            "default_marking_name": "TLP:AMBER",
        })
        self.assertEqual(200, selected.status_code)
        self.assertTrue(selected.json()["verified"])

    def test_configuration_lookup_and_confirmed_promotion(self):
        self.configure()
        looked_up = self.request(
            "POST", f"/api/cases/{self.slug}/opencti/lookups",
            {"targets": [{"kind": "ip", "value": "192.0.2.8"}]})
        self.assertEqual(200, looked_up.status_code, looked_up.text)
        snapshot = self.request(
            "GET", f"/api/cases/{self.slug}/opencti/context?kind=ip&key=192.0.2.8")
        row = snapshot.json()["entries"][0]
        promoted = self.request(
            "POST", f"/api/cases/{self.slug}/opencti/context/promote", {
                "snapshot_id": row["id"], "external_id": "domain-related",
                "value": "related.example", "type": "domain",
            })
        self.assertEqual(200, promoted.status_code, promoted.text)
        conn = db.connect(self.case_dir)
        try:
            self.assertEqual("confirmed", conn.execute(
                "SELECT triage FROM findings WHERE rule='Synthetic finding'").fetchone()[0])
            ioc = conn.execute(
                "SELECT id,origin FROM iocs WHERE value='related.example'").fetchone()
            self.assertEqual("selected from OpenCTI context", ioc["origin"])
            self.assertEqual(1, conn.execute(
                "SELECT count(*) FROM ioc_external_sources WHERE ioc_id=?",
                (ioc["id"],)).fetchone()[0])
        finally:
            conn.close()

    def test_preview_publish_and_duplicate_confirmation(self):
        self.configure()
        base = f"/api/cases/{self.slug}/opencti"
        draft = {"items": [{"kind": "ioc", "id": self.ioc_id,
                            "indicator": False}],
                 "summary": "Synthetic forensic context",
                 "marking_id": MARKING_INTERNAL}
        self.assertEqual(200, self.request("PUT", base + "/draft", draft).status_code)
        preview = self.request("POST", base + "/preview", {})
        self.assertEqual(200, preview.status_code, preview.text)
        previewed = preview.json()
        conn = db.connect(self.case_dir)
        try:
            snapshot = conn.execute(
                "SELECT snapshot FROM opencti_publications WHERE id=?",
                (previewed["publication_id"],)).fetchone()["snapshot"]
            expected_bundle = opencti_case.json_load(snapshot, {})["bundle"]
        finally:
            conn.close()
        rows = self.request("GET", base + "/publications").json()["entries"]
        self.assertEqual("previewed", rows[0]["status"])
        published = self.request("POST", base + "/publish", {
            "publication_id": previewed["publication_id"],
            "expected_fingerprint": previewed["fingerprint"],
            "confirm_duplicate": False,
        })
        self.assertEqual(200, published.status_code, published.text)
        self.assertEqual("published", published.json()["status"])
        self.assertEqual(expected_bundle, FakeOpenCtiClient.last_taxii_bundle)
        self.assertEqual([], self.request("GET", base + "/draft").json()["items"])

        self.request("PUT", base + "/draft", draft)
        duplicate_preview = self.request("POST", base + "/preview", {}).json()
        refused = self.request("POST", base + "/publish", {
            "publication_id": duplicate_preview["publication_id"],
            "expected_fingerprint": duplicate_preview["fingerprint"],
            "confirm_duplicate": False,
        })
        self.assertEqual(409, refused.status_code)
        self.assertEqual("duplicate", refused.json()["detail"]["code"])
        confirmed = self.request("POST", base + "/publish", {
            "publication_id": duplicate_preview["publication_id"],
            "expected_fingerprint": duplicate_preview["fingerprint"],
            "confirm_duplicate": True,
        })
        self.assertEqual(200, confirmed.status_code, confirmed.text)

    def test_partial_file_upload_is_retried_without_republishing_taxii(self):
        self.configure()
        base = f"/api/cases/{self.slug}/opencti"
        draft = {
            "items": [{"kind": "file", "path": str(self.file),
                       "indicator": False}],
            "summary": "Synthetic file context",
            "marking_id": MARKING_INTERNAL,
        }
        self.assertEqual(200, self.request("PUT", base + "/draft", draft).status_code)
        preview = self.request("POST", base + "/preview", {}).json()
        FakeOpenCtiClient.upload_failures_remaining = 1
        partial = self.request("POST", base + "/publish", {
            "publication_id": preview["publication_id"],
            "expected_fingerprint": preview["fingerprint"],
        })
        self.assertEqual(200, partial.status_code, partial.text)
        self.assertEqual("partial", partial.json()["status"])
        self.assertEqual(1, FakeOpenCtiClient.taxii_calls)
        self.assertEqual("failed", partial.json()["files"][0]["status"])

        retried = self.request(
            "POST", base + "/publications/" + preview["publication_id"] + "/retry")
        self.assertEqual(200, retried.status_code, retried.text)
        self.assertEqual("published", retried.json()["status"])
        self.assertEqual("uploaded", retried.json()["files"][0]["status"])
        self.assertEqual(1, FakeOpenCtiClient.taxii_calls)
        self.assertEqual(2, FakeOpenCtiClient.upload_calls)


if __name__ == "__main__":
    unittest.main()
