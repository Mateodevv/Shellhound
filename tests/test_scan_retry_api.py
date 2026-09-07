"""HTTP-level warning receipts and exact-file retries over synthetic evidence."""
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from server import case_report, db, workspace
from server.app import create_app
from server.config import Config
from server.jobs import JobManager
from tests.test_http import _LiveServer


class LocalClient:
    """Use the project's existing socket harness, with no test-only dependency."""
    def __init__(self, app, headers):
        self.server = _LiveServer(app)
        self.base = self.server.start()
        self.headers = headers

    def request(self, method, path, json=None, headers=None):
        import json as codec
        request = urllib.request.Request(
            self.base + path, data=codec.dumps(json).encode() if json is not None else None,
            method=method, headers={"Content-Type": "application/json", **self.headers, **(headers or {})})
        try:
            response = urllib.request.urlopen(request, timeout=20)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            text = response.read().decode()
            return SimpleNamespace(status_code=response.status, text=text, json=lambda: codec.loads(text))

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path, **kwargs):
        return self.request("POST", path, **kwargs)

    def close(self):
        self.server.stop()
        self.server.socket.close()


class ScanRetryApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="scan retry ")
        self.root = Path(self.temp.name)
        self.config = Config(workspace=self.root / "workspace", token="synthetic-test")
        self.case = workspace.create_case(self.config.workspace, "Synthetic retries")
        self.evidence = self.root / "Evidence with spaces ä"
        self.evidence.mkdir()
        self.files = [self.evidence / "large-one.php", self.evidence / "large-two.php"]
        for target in self.files:
            with target.open("wb") as handle:
                handle.truncate(6 * 1024 * 1024)
        self.small = self.evidence / "ordinary.txt"
        self.small.write_text("synthetic ordinary file", encoding="utf-8")
        conn = db.connect(self.case)
        conn.execute("INSERT INTO evidence(kind,path,added) VALUES ('webroot',?,?)",
                     (str(self.evidence), db.now()))
        conn.commit()
        conn.close()
        self.manager = JobManager()
        self.manager_patch = patch("server.app.manager", self.manager)
        self.manager_patch.start()
        self.client = LocalClient(create_app(self.config), headers={"x-token": self.config.token})
        self.url = f"/api/cases/{self.case.name}"

    def tearDown(self):
        self.manager.cancel_all_and_wait()
        self.manager.pool.shutdown(wait=True)
        self.client.close()
        self.manager_patch.stop()
        self.temp.cleanup()

    def scan(self, yara=False):
        if yara:
            directory = self.config.workspace / "yara"
            directory.mkdir(exist_ok=True)
            (directory / "synthetic.yar").write_text("rule Synthetic { condition: false }", encoding="utf-8")
        response = self.client.post(self.url + "/analyze", json={"mode": "all"})
        self.assertEqual(200, response.status_code, response.text)
        ids = [item["job"] for item in response.json()["started"]]
        self.assertEqual([], self.manager.wait_for(self.case, ids, timeout=15))
        return {job["kind"]: job for job in self.client.get(self.url + "/jobs").json()}

    def details(self, job):
        response = self.client.get(self.url + f"/jobs/{job}/skipped")
        self.assertEqual(200, response.status_code, response.text)
        return response.json()

    def retry(self, job, body):
        response = self.client.post(self.url + f"/jobs/{job}/retry-skipped", json=body)
        self.assertEqual(200, response.status_code, response.text)
        ids = response.json()["jobs"]
        self.assertEqual([], self.manager.wait_for(self.case, ids, timeout=15))
        return ids[0]

    def test_skips_complete_both_scanners_and_reports_keep_coverage_warning(self):
        jobs = self.scan(yara=True)
        for engine in ("webshell", "yara"):
            self.assertEqual("complete_with_warnings", jobs[engine]["analysis_status"])
            self.assertEqual(2, jobs[engine]["warning_count"])
            self.assertEqual(2, self.details(jobs[engine]["id"])["retryable"])
        dashboard = self.client.get(self.url + "/dashboard").json()
        self.assertTrue(dashboard["analysis_complete"])
        self.assertEqual(2, dashboard["analysis_warnings"], "same file skipped by two scanners counts once")
        evidence = self.client.get(self.url).json()["evidence_items"][0]
        self.assertTrue(evidence["scanned_at"])
        self.assertEqual("complete_with_warnings", evidence["stats"]["last_attempt"]["status"])
        notes = " ".join(case_report.collect(self.case)["coverage"]["notes"])
        self.assertIn("2 evidence files", notes)
        self.assertNotIn(str(self.evidence), notes)
        self.assertEqual(400, self.client.post(self.url + "/analyze", json={"mode": "new"}).status_code)

    def test_selected_retry_only_reads_selected_file_then_all_resolves_remainder(self):
        original = self.scan()["webshell"]
        details = self.details(original["id"])
        first = next(e for e in details["items"] if e["path"] == str(self.files[0]))
        self.files[0].write_text("<?php echo 'synthetic'; ?>", encoding="utf-8")
        from server.engines import webshell
        real_scan = webshell.scan_file
        with patch.object(webshell, "scan_file", wraps=real_scan) as scanned:
            retry_id = self.retry(original["id"], {"mode": "selected", "ids": [first["id"]]})
        self.assertEqual([str(self.files[0])], [call.args[0] for call in scanned.call_args_list])
        details = self.details(original["id"])
        self.assertEqual(1, details["unresolved"])
        self.assertEqual("resolved", next(e for e in details["items"] if e["id"] == first["id"])["status"])
        self.assertEqual(2, details["total"], "original audit entries are immutable")
        self.files[1].write_text("<?php echo 'synthetic'; ?>", encoding="utf-8")
        self.retry(original["id"], {"mode": "all"})
        self.assertEqual(0, self.details(original["id"])["unresolved"])
        dashboard = self.client.get(self.url + "/dashboard").json()
        self.assertTrue(dashboard["analysis_complete"])
        self.assertEqual(0, dashboard["analysis_warnings"])
        jobs = self.client.get(self.url + "/jobs").json()
        self.assertEqual(1, sum(j["kind"] == "cms" for j in jobs), "retry must not rerun other engines")
        self.assertEqual(original["id"], next(j for j in jobs if j["id"] == retry_id)["scan_context"]["parent_job_id"])
        self.assertEqual("complete", self.client.get(self.url).json()["evidence_items"][0]["stats"]["last_attempt"]["status"])

    def test_retry_all_preserves_and_resolves_each_logical_alias(self):
        uploads = self.evidence / "uploads"
        uploads.mkdir()
        sample = uploads / "sample.php"
        with sample.open("wb") as handle:
            handle.truncate(6 * 1024 * 1024)
        alias = self.evidence / "z-cache"
        if os.name == "nt":
            import _winapi
            _winapi.CreateJunction(str(uploads), str(alias))
        else:
            alias.symlink_to(uploads, target_is_directory=True)
        try:
            jobs = self.scan(yara=True)
            for file in [*self.files, sample]:
                file.write_text("ordinary marker", encoding="utf-8")
            for kind in ("webshell", "yara"):
                with self.subTest(kind=kind):
                    job_id = jobs[kind]["id"]
                    self.assertEqual(4, self.details(job_id)["unresolved"])
                    retry_id = self.retry(job_id, {"mode": "all"})
                    retry = next(job for job in self.client.get(self.url + "/jobs").json()
                                 if job["id"] == retry_id)
                    self.assertEqual("done", retry["state"])
                    self.assertEqual(4, retry["stats"]["scanned"])
                    details = self.details(job_id)
                    self.assertEqual(0, details["unresolved"])
                    self.assertTrue(all(entry["status"] == "resolved" for entry in details["items"]))
        finally:
            if os.name == "nt":
                alias.rmdir()
            else:
                alias.unlink()

    def test_retry_still_skipped_is_retryable_and_survives_manager_restart(self):
        original = self.scan()["webshell"]["id"]
        retry_id = self.retry(original, {"mode": "all"})
        self.assertEqual(2, self.details(original)["unresolved"])
        self.manager.pool.shutdown(wait=True)
        self.manager = JobManager()
        self.manager_patch.stop()
        self.manager_patch = patch("server.app.manager", self.manager)
        self.manager_patch.start()
        details = self.details(original)
        self.assertEqual(2, details["retryable"])
        self.assertEqual(retry_id, details["items"][0]["retry_job_id"])

    def test_invalid_selection_changed_rules_and_superseded_jobs_refuse_retry(self):
        original = self.scan()["webshell"]["id"]
        url = self.url + f"/jobs/{original}/retry-skipped"
        for body, code in (({"mode": "selected", "ids": []}, 400),
                           ({"mode": "selected", "ids": [9999]}, 400),
                           ({"mode": "selected", "ids": [True]}, 422),
                           ({"mode": "selected", "ids": ["0"]}, 422)):
            self.assertEqual(code, self.client.post(url, json=body).status_code)
        from server import ruleswitch
        ruleswitch.set_enabled(self.config.workspace, "webshell.upload_php", False)
        response = self.client.post(url, json={"mode": "all"})
        self.assertEqual(409, response.status_code)
        self.assertIn("changed", response.text)
        ruleswitch.set_enabled(self.config.workspace, "webshell.upload_php", True)
        self.scan()
        self.assertEqual(409, self.client.post(url, json={"mode": "all"}).status_code)
        jobs = self.client.get(self.url + "/jobs").json()
        self.assertFalse(next(j for j in jobs if j["id"] == original)["warnings_current"])

    def test_foreign_job_and_root_escape_cannot_be_retried(self):
        original = self.scan()["webshell"]["id"]
        other = workspace.create_case(self.config.workspace, "Other synthetic")
        self.assertEqual(404, self.client.post(f"/api/cases/{other.name}/jobs/{original}/retry-skipped",
                                              json={"mode": "all"}).status_code)
        conn = db.connect(self.case)
        conn.execute("UPDATE job_skips SET path=? WHERE job_id=? AND ordinal=0",
                     (str(self.root / "outside.php"), original))
        conn.commit()
        conn.close()
        self.assertEqual(409, self.client.post(self.url + f"/jobs/{original}/retry-skipped",
                                              json={"mode": "selected", "ids": [0]}).status_code)
        self.assertEqual(401, self.client.post(self.url + f"/jobs/{original}/retry-skipped",
                                              json={"mode": "all"}, headers={"x-token": "wrong"}).status_code)

    def test_busy_retry_progress_and_cancellation_leave_parent_complete(self):
        original = self.scan()["webshell"]["id"]
        started, release = threading.Event(), threading.Event()
        from server.engines import webshell
        def slow_scan(*args, **kwargs):
            ctx = args[2]
            ctx.phase_progress(0, "Finding files… 7 found", "discovering", 7, None)
            started.set()
            release.wait(5)
            return {"skipped": 0, "file_skips": 0}
        with patch.object(webshell, "scan", side_effect=slow_scan):
            response = self.client.post(self.url + f"/jobs/{original}/retry-skipped", json={"mode": "all"})
            self.assertEqual(200, response.status_code)
            retry_id = response.json()["jobs"][0]
            try:
                self.assertTrue(started.wait(5))
                jobs = self.client.get(self.url + "/jobs").json()
                progress = next(j for j in jobs if j["id"] == retry_id)["progress_details"]
                self.assertEqual({"phase": "discovering", "completed": 7, "total": None}, progress)
                self.assertTrue(self.client.get(self.url + "/dashboard").json()["analysis_complete"])
                self.assertEqual(409, self.client.post(self.url + "/analyze", json={"mode": "all"}).status_code)
                self.assertEqual(409, self.client.post(self.url + f"/jobs/{original}/retry-skipped", json={"mode": "all"}).status_code)
                self.assertTrue(self.client.post(self.url + f"/jobs/{retry_id}/cancel").json()["cancelled"])
            finally:
                release.set()
            self.assertEqual([], self.manager.wait_for(self.case, [retry_id], timeout=10))
        self.assertEqual(2, self.details(original)["unresolved"])
        self.assertTrue(self.client.get(self.url + "/dashboard").json()["analysis_complete"])

    def test_legacy_warning_only_receipt_reconciles_on_upgrade_without_guessing_paths(self):
        job_id = self.scan()["webshell"]["id"]
        conn = db.connect(self.case)
        stats = json.loads(db.one(conn, "SELECT stats FROM jobs WHERE id=?", (job_id,))["stats"])
        stats.pop("file_skips")
        conn.execute("UPDATE jobs SET stats=?, scan_context='{}' WHERE id=?", (json.dumps(stats), job_id))
        conn.execute("UPDATE job_skips SET category='other',root='' WHERE job_id=?", (job_id,))
        evidence = db.one(conn, "SELECT stats FROM evidence")
        receipt = json.loads(evidence["stats"])
        receipt["last_attempt"]["status"] = "partial"
        receipt["last_attempt"]["engines"]["webshell"] = {"state": "partial", "stats": stats}
        conn.execute("UPDATE evidence SET scanned_at='',stats=?", (json.dumps(receipt),))
        conn.execute("UPDATE meta SET value='11' WHERE key='schema_version'")
        conn.commit()
        conn.close()
        detail = self.client.get(self.url).json()["evidence_items"][0]
        self.assertTrue(detail["scanned_at"])
        self.assertEqual("complete_with_warnings", detail["stats"]["last_attempt"]["status"])
        self.assertTrue(self.client.get(self.url + "/dashboard").json()["analysis_complete"])
        self.assertEqual(0, self.details(job_id)["retryable"])

    def test_entirely_broken_yara_rules_are_scheduled_and_remain_incomplete(self):
        directory = self.config.workspace / "yara"
        directory.mkdir()
        (directory / "broken.yar").write_text("rule Broken { invalid }", encoding="utf-8")
        jobs = self.scan()
        self.assertIn("yara", jobs)
        self.assertEqual("partial", jobs["yara"]["analysis_status"])
        self.assertFalse(self.client.get(self.url + "/dashboard").json()["analysis_complete"])
        self.assertEqual("partial", self.client.get(self.url).json()["evidence_items"][0]["stats"]["last_attempt"]["status"])

    def test_retry_all_runs_eligible_files_and_keeps_ineligible_warnings(self):
        original = self.scan()["webshell"]["id"]
        self.files[0].unlink()
        self.files[0].mkdir()
        self.files[1].write_text("<?php echo 'synthetic'; ?>", encoding="utf-8")
        self.assertEqual(1, self.details(original)["retryable"])
        self.retry(original, {"mode": "all"})
        details = self.details(original)
        self.assertEqual(1, details["unresolved"])
        remaining = next(e for e in details["items"] if e["status"] == "unresolved")
        self.assertFalse(remaining["retryable"])
        self.assertIn("folder", remaining["latest_reason"])

    def test_retry_failure_preserves_committed_resolution_and_refreshes_findings(self):
        original = self.scan()["webshell"]["id"]
        for file in self.files:
            file.write_text("<?php echo 'synthetic'; ?>", encoding="utf-8")
        from server.engines import webshell
        from server.events import hub
        real_scan = webshell.scan_file
        attempted = []
        def fail_second(path, root):
            # Directory enumeration order differs across filesystems. Interrupt
            # the second actual attempt, regardless of which filename it has.
            attempted.append(path)
            if len(attempted) == 2:
                raise RuntimeError("synthetic interruption after one committed file")
            return real_scan(path, root)
        with patch.object(webshell, "scan_file", side_effect=fail_second), patch.object(hub, "publish") as publish:
            retry = self.retry(original, {"mode": "all"})
        jobs = self.client.get(self.url + "/jobs").json()
        self.assertEqual("failed", next(j for j in jobs if j["id"] == retry)["state"])
        details = self.details(original)
        self.assertEqual(1, details["unresolved"])
        self.assertEqual(2, len(attempted))
        self.assertEqual([attempted[0]], [entry["path"] for entry in details["items"]
                                         if entry["status"] == "resolved"])
        self.assertEqual([attempted[1]], [entry["path"] for entry in details["items"]
                                         if entry["status"] == "unresolved"])
        self.assertTrue(self.client.get(self.url + "/dashboard").json()["analysis_complete"])
        self.assertTrue(any(call.args[0] == {"type": "invalidate", "scope": "webshell"}
                            for call in publish.call_args_list))

    def test_incremental_replacement_does_not_keep_superseded_root_warnings(self):
        other = self.root / "Other evidence"
        other.mkdir()
        pending = other / "large.php"
        with pending.open("wb") as handle:
            handle.truncate(6 * 1024 * 1024)
        conn = db.connect(self.case)
        conn.execute("INSERT INTO evidence(kind,path,added) VALUES ('webroot',?,?)", (str(other), db.now()))
        conn.commit()
        conn.close()
        original = self.scan()["webshell"]["id"]
        for file in self.files:
            file.write_text("<?php echo 'synthetic'; ?>", encoding="utf-8")
        conn = db.connect(self.case)
        conn.execute("DELETE FROM evidence WHERE path=?", (str(self.evidence),))
        conn.execute("INSERT INTO evidence(kind,path,added) VALUES ('webroot',?,?)", (str(self.evidence), db.now()))
        conn.commit()
        conn.close()
        response = self.client.post(self.url + "/analyze", json={"mode": "new"})
        self.assertEqual(200, response.status_code, response.text)
        self.assertEqual([], self.manager.wait_for(self.case, [j["job"] for j in response.json()["started"]], timeout=10))
        jobs = self.client.get(self.url + "/jobs").json()
        historical = next(j for j in jobs if j["id"] == original)
        self.assertEqual(3, historical["warning_count"])
        self.assertEqual(1, historical["current_warning_count"])
        self.assertEqual(1, self.client.get(self.url + "/dashboard").json()["analysis_warnings"])
        pending.write_text("<?php echo 'synthetic'; ?>", encoding="utf-8")
        self.retry(original, {"mode": "all"})
        self.assertEqual(0, self.client.get(self.url + "/dashboard").json()["analysis_warnings"])

    def test_registered_single_file_retains_its_original_scan_root(self):
        conn = db.connect(self.case)
        conn.execute("UPDATE evidence SET path=?", (str(self.files[0]),))
        conn.commit()
        conn.close()
        original = self.scan()["webshell"]["id"]
        self.assertEqual(1, self.details(original)["retryable"])
        self.files[0].write_text("<?php echo 'synthetic'; ?>", encoding="utf-8")
        self.retry(original, {"mode": "all"})
        self.assertEqual(0, self.details(original)["unresolved"])


if __name__ == "__main__":
    unittest.main()
