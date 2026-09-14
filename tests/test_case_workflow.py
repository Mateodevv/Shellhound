"""A complete API workflow with real jobs/storage and a simulated OpenCTI boundary."""
import hashlib
import json
import threading
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.parse import urlencode

from server import db, diagnostics, opencti_graph, opencti_service, patterns, workspace
from server.app import create_app
from server.config import Config
from server.jobs import JobManager
from server.opencti_client import OpenCTIClient, OpenCTIError
from tests.fixtures_workflow import CVE, IP, create
from tests.test_scan_retry_api import LocalClient


class CaseWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="workflow-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = create(self.root)
        self.config = Config(workspace=self.fixture["workspace"], token="workflow-test")
        self.remote_config = {"url": "https://cti.example.test", "token": "synthetic-token",
                              "ingester_id": "qa", "sample_uploads": False, "timeout": 2}
        self.remote = MagicMock(spec=OpenCTIClient)
        self.remote.find_existing_shared.return_value = None
        self.remote.connectors.return_value = []
        self.remote.lookup.return_value = []
        self.remote.push.return_value = {"id": "qa-taxii-work"}
        self.remote.taxii_status.return_value = {"status": "complete", "failure_count": 0, "pending_count": 0}
        self.remote.resolve.side_effect = lambda identifier: {"id": "remote-" + identifier, "standard_id": identifier}
        self.manager = JobManager()
        self.addCleanup(self.manager.pool.shutdown, wait=True)
        self.addCleanup(self.manager.cancel_all_and_wait)
        for target, value in (("server.app.manager", self.manager),
                              ("server.opencti_service.manager", self.manager),
                              ("server.opencti_service.settings.opencti_config", lambda _: dict(self.remote_config)),
                              ("server.opencti_service.POLL_LIMIT", 1),
                              ("server.opencti_service.POLL_SECONDS", 0)):
            patcher = patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch("server.opencti_service.OpenCTIClient", return_value=self.remote)
        self.client_factory = patcher.start()
        self.addCleanup(patcher.stop)
        self.client = None
        self.start_server()
        self.addCleanup(lambda: self.client.close())
        info = self.post("/api/cases", {"name": "Workflow acceptance", "reference": "QA-WORKFLOW",
            "profile": {"organization_name": "Synthetic organization", "sectors": ["Technology"],
                        "subsectors": [{"name": "Software", "sector": "Technology"}],
                        "countries": ["DE"], "state": "DE-BE", "city": "Berlin",
                        "summary": "Harmless workflow acceptance only.", "first_seen": "2026-09-12"}})
        self.slug = info["slug"]
        self.case = self.config.workspace / self.slug
        self.route = f"/api/cases/{self.slug}"

    def start_server(self):
        self.client = LocalClient(create_app(self.config), {"x-token": self.config.token})

    def post(self, path, body):
        response = self.client.post(path, json=body)
        self.assertEqual(200, response.status_code, response.text)
        return response.json()

    def get(self, path):
        response = self.client.get(path)
        self.assertEqual(200, response.status_code, response.text)
        return response.json()

    def wait(self, *jobs):
        self.assertEqual([], self.manager.wait_for(self.case, jobs, timeout=25))
        states = {j["id"]: j for j in self.get(self.route + "/jobs")}
        for job in jobs:
            self.assertEqual("done", states[job]["state"], states[job].get("error"))

    def analyze_and_review(self):
        for kind, path in (("webroot", self.fixture["site"]), ("access_logs", self.fixture["logs"]),
                           ("sql_dump", self.fixture["dump"])):
            self.post(self.route + "/evidence", {"kind": kind, "path": str(path)})
        run = self.post(self.route + "/analyze", {"mode": "all"})
        self.wait(*(j["job"] for j in run["started"]))
        conn = db.connect(self.case)
        try:
            findings = db.rows(conn, "SELECT artifact FROM findings WHERE source='yara'")
            self.assertEqual(2, sum(f["artifact"] == str(self.fixture["files"]["review.txt"]) for f in findings))
            self.assertFalse(any(f["artifact"] == str(self.fixture["files"]["ordinary.txt"]) for f in findings))
            # A synthetic database finding tests row-kind triage without attack SQL.
            db.upsert_finding(conn, "sqldb", 2, "Synthetic database review", "table", "cms_users",
                              evidence="Inert account fixture", line=1, rule_id="qa.database")
            conn.commit()
        finally:
            conn.close()
        for name, classes in (("review.txt", ["webshell", "seo-spam"]), ("dropper.txt", ["dropper"])):
            self.post(self.route + "/triage", {"artifacts": [str(self.fixture["files"][name])],
                "state": "confirmed", "classifications": classes, "propagate": False})
        self.post(self.route + "/triage", {"artifacts": ["cms_users"], "state": "dismissed", "propagate": False})
        entry = patterns.add(self.config.workspace, [], name="Synthetic CVE marker", cve=CVE,
            rule={"client_match": "any", "requests": [{"clauses": [
                {"field": "uri", "operator": "contains", "values": ["/review.txt"]}]}]})
        hunt = self.post(self.route + "/hunt/batch-tests", {"ids": [entry["id"]]})
        self.wait(hunt["job_id"])
        rows = self.get(self.route + "/iocs")
        self.ip_id = next(r["id"] for r in rows if r["type"] == "ip" and r["value"] == IP)
        self.assertTrue(any(r["type"] == "vulnerability" and r["value"].upper() == CVE for r in rows))
        for name, expected_tags in (("review.txt", {"Webshell", "SEO-Spam"}), ("dropper.txt", {"Dropper"})):
            digest = hashlib.sha256(self.fixture["files"][name].read_bytes()).hexdigest()
            file_ioc = next(row for row in rows if row["type"] == "file" and row["value"] == digest)
            self.assertTrue(expected_tags <= set(file_ioc["tags"]))
        self.assertIn(CVE, next(row for row in rows if row["id"] == self.ip_id)["tags"])
        hashes = {hashlib.sha256(p.read_bytes()).hexdigest() for n, p in self.fixture["files"].items() if n != "ordinary.txt"}
        self.assertEqual(hashes, {r["value"] for r in rows if r["type"] == "file"})
        # Repeated decisions must not create duplicate IoCs or audit transitions.
        before = self.snapshot()
        self.post(self.route + "/triage", {"artifacts": [str(self.fixture["files"]["dropper.txt"])],
                  "state": "confirmed", "classifications": ["dropper"], "propagate": False})
        after = self.snapshot()
        for table in ("iocs", "triage_events"):
            self.assertEqual(before[table], after[table])

    def snapshot(self):
        conn = db.connect(self.case)
        try:
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            return {table: sorted([tuple(row) for row in conn.execute(f'SELECT * FROM "{table}"')], key=repr)
                    for table in tables}
        finally:
            conn.close()

    def roundtrip(self):
        profile = self.get(self.route)["profile"]
        before = self.snapshot()
        closed = self.post(self.route + "/archive?require_idle=true", {})
        self.assertFalse(self.case.exists())
        restored = self.post("/api/import", {"file": closed["file"]})
        self.assertEqual(self.slug, restored["slug"])
        self.assertEqual(before, self.snapshot(), "Every persisted table must survive, not just summary counts")
        self.assertEqual(profile, self.get(self.route)["profile"])
        self.assertFalse((self.case / db.LOG_DB).exists())
        # Originals remain external to the archive; absence is explicit.
        self.fixture["logs"].unlink()
        detail = self.get(self.route)
        self.assertFalse(next(e for e in detail["evidence_items"] if e["kind"] == "access_logs")["exists"])

    def test_local_case_analysis_review_restart_archive_restore(self):
        self.remote_config = {"url": "", "token": "", "ingester_id": ""}
        self.client_factory.side_effect = AssertionError("Local workflow must not contact OpenCTI")
        self.analyze_and_review()
        saved = self.snapshot()
        self.client.close()
        self.start_server()
        self.assertEqual(saved, self.snapshot())
        self.assertEqual("QA-WORKFLOW", self.get(self.route)["reference"])
        preview = opencti_graph.build_preview(self.case)
        self.assertEqual([], preview["errors"])
        self.assertTrue(any(r["kind"] == "cve-context" for r in preview["relationships"]))
        self.roundtrip()
        self.client_factory.assert_not_called()

    def test_enrichment_transfer_resume_and_restore_preserve_remote_identities(self):
        self.analyze_and_review()
        self.remote.connectors.return_value = [{"id": "qa-enrich", "name": "Synthetic provider", "active": True,
            "auto": False, "connector_type": "INTERNAL_ENRICHMENT", "scope": ["IPv4-Addr"]}]
        self.remote.lookup.side_effect = lambda kind, value: [{"id": "qa-ip", "entity_type": "IPv4-Addr",
            "observable_value": IP, "labels": [{"value": "Provider QA"}], "score": 58}] if kind == "ip" else []
        self.remote.enrich.return_value = {"id": "qa-enrichment-work"}
        self.remote.work.return_value = {"status": "complete", "errors": []}
        enriched = self.post(self.route + "/opencti/enrich", {"ioc_ids": [self.ip_id], "connector_ids": ["qa-enrich"]})
        self.wait(enriched["job_id"])
        state = self.get(self.route + "/opencti")
        self.assertEqual("complete", state["enrichments"][0]["state"])
        self.assertEqual(58, next(r for r in state["lookups"] if r["ioc_id"] == self.ip_id)["entities"][0]["score"])
        self.assertIn("Provider QA", next(r for r in self.get(self.route + "/iocs") if r["id"] == self.ip_id)["tags"])
        self.remote.taxii_status.side_effect = OpenCTIError("Synthetic connection interruption")
        preview = self.post(self.route + "/opencti/preview", {})
        self.assertEqual([], preview["errors"])
        transfer = self.post(self.route + "/opencti/export", {"preview_id": preview["preview_id"]})
        self.assertEqual([], self.manager.wait_for(self.case, [transfer["job_id"]], timeout=25))
        self.assertEqual(1, self.remote.push.call_count)
        duplicate = self.client.post(self.route + "/opencti/export", json={"preview_id": preview["preview_id"]})
        self.assertNotEqual(200, duplicate.status_code)
        self.client.close()
        self.start_server()
        self.remote.taxii_status.side_effect = None
        retried = self.post(self.route + "/opencti/retry", {"export_id": transfer["export_id"]})
        self.wait(retried["job_id"])
        self.assertEqual(1, self.remote.push.call_count, "An accepted batch must be checked, not resubmitted")
        self.assertEqual("complete", self.get(self.route + "/opencti")["exports"][0]["state"])
        self.remote.upload_sample.assert_not_called()
        self.roundtrip()
        self.assertEqual("complete", self.get(self.route + "/opencti")["exports"][0]["state"])
        self.assertEqual(1, self.remote.enrich.call_count)

    def test_interrupted_job_is_recovered_without_changing_decisions(self):
        self.analyze_and_review()
        before = self.snapshot()
        conn = db.connect(self.case)
        try:
            job = conn.execute("INSERT INTO jobs(kind,state,created) VALUES('webshell','running',?)", (db.now(),)).lastrowid
            conn.commit()
        finally:
            conn.close()
        self.client.close()
        self.start_server()
        interrupted = next(j for j in self.get(self.route + "/jobs") if j["id"] == job)
        self.assertEqual("failed", interrupted["state"])
        self.assertIn("Interrupted", interrupted["error"])
        for table in ("findings", "iocs", "triage_events"):
            self.assertEqual(before[table], self.snapshot()[table])
        run = self.post(self.route + "/analyze", {"mode": "all"})
        self.wait(*(j["job"] for j in run["started"]))
        self.assertEqual(before["triage_events"], self.snapshot()["triage_events"])


    def test_unreadable_file_has_a_correlated_log_and_keeps_decisions(self):
        self.analyze_and_review()
        before = self.snapshot()
        target = self.fixture["files"]["review.txt"]
        url = self.route + "/file?" + urlencode({"path": str(target)})
        with patch("server.app.open", side_effect=PermissionError("Synthetic denied file"), create=True):
            result = self.client.get(url)
        self.assertEqual(400, result.status_code)
        self.assertIn("file not readable", result.json()["detail"])
        records = diagnostics.read(self.config.workspace)
        self.assertTrue(any(r.get("component") == "files" and r.get("target") == diagnostics.fingerprint(str(target)) for r in records))
        self.assertTrue(any(r.get("status") == 400 and r.get("request_id") for r in records))
        self.assertEqual(before["findings"], self.snapshot()["findings"])
        self.assertEqual(200, self.client.get(url).status_code)
        target.unlink()
        missing = self.client.get(url)
        self.assertEqual(404, missing.status_code)
        self.assertTrue(missing.json()["detail"])

    def test_job_arriving_after_idle_check_blocks_closure(self):
        # The first wait check has already returned. Inject a real job exactly
        # when the second, scheduling-locked check starts.
        gate = threading.Event()
        self.addCleanup(gate.set)
        original = self.manager.case_operation
        def race(case):
            self.manager.submit(case, "synthetic", lambda ctx: gate.wait(10))
            return original(case)
        with patch.object(self.manager, "case_operation", side_effect=race):
            result = self.client.post(self.route + "/archive?require_idle=true", json={})
        self.assertEqual(409, result.status_code)
        self.assertTrue(self.case.exists())
        self.assertEqual([], workspace.list_archives(self.config.workspace))
        gate.set()

if __name__ == "__main__":
    unittest.main()
