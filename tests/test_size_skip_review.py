"""Analyst size-skip decisions and bounded overrides through the real HTTP API."""
import json
import unittest
from unittest.mock import patch

from server import case_report, db
from server.engines import webshell
from server.engines.scan_limits import MAX_OVERRIDE_SCAN_BYTES
from server.skip_reasons import classify_skip
from tests import test_scan_retry_api as fixtures


class SizeSkipReviewTests(unittest.TestCase):
    setUp = fixtures.ScanRetryApiTests.setUp
    tearDown = fixtures.ScanRetryApiTests.tearDown
    scan = fixtures.ScanRetryApiTests.scan
    details = fixtures.ScanRetryApiTests.details
    retry = fixtures.ScanRetryApiTests.retry

    def accept(self, job, ids=None):
        response = self.client.post(self.url + f"/jobs/{job}/accept-skipped", json={
            "mode": "all" if ids is None else "selected", "ids": ids or [], "group": "size_limit"})
        self.assertEqual(200, response.status_code, response.text)
        return response.json()

    def filtered(self, job, group="size_limit", status="pending", offset=0):
        response = self.client.get(self.url + f"/jobs/{job}/skipped?group={group}&status={status}&offset={offset}")
        self.assertEqual(200, response.status_code, response.text)
        return response.json()

    def test_selected_acceptance_persists_without_changing_findings_or_clearing_coverage(self):
        job = self.scan()["webshell"]["id"]
        before = self.details(job)
        self.assertEqual({"size_limit": 2, "other": 0, "accepted": 0}, before["counts"])
        self.assertEqual(6 * 1024 * 1024, before["items"][0]["size_bytes"])
        conn = db.connect(self.case)
        original_skips = db.rows(conn, "SELECT * FROM job_skips WHERE job_id=?", (job,))
        original_findings = db.rows(conn, "SELECT * FROM findings")
        conn.close()
        self.accept(job, [before["items"][0]["id"]])
        self.assertEqual(1, self.filtered(job)["total"])
        accepted = self.filtered(job, status="accepted")
        self.assertEqual(1, accepted["total"])
        self.assertTrue(accepted["items"][0]["accepted_at"])
        self.assertTrue(accepted["items"][0]["forceable"])
        self.assertFalse(accepted["items"][0]["acceptable"])
        self.accept(job)
        conn = db.connect(self.case)
        self.assertEqual(original_skips, db.rows(conn, "SELECT * FROM job_skips WHERE job_id=?", (job,)))
        self.assertEqual(original_findings, db.rows(conn, "SELECT * FROM findings"))
        self.assertEqual(0, db.one(conn, "SELECT count(*) n FROM file_scan_results")["n"])
        self.assertEqual(2, db.one(conn, "SELECT count(*) n FROM skip_reviews")["n"])
        conn.close()
        dashboard = self.client.get(self.url + "/dashboard").json()
        self.assertEqual(0, dashboard["analysis_warnings"])
        self.assertEqual(2, dashboard["analysis_accepted"])
        self.assertTrue(dashboard["analysis_complete"])
        notes = " ".join(case_report.collect(self.case)["coverage"]["notes"])
        self.assertIn("2 evidence files have analyst-accepted size skips", notes)
        self.assertIn("remain unexamined", notes)
        self.assertNotIn(str(self.evidence), notes)
        # Reopen the database through an independent application instance.
        reopened = fixtures.LocalClient(fixtures.create_app(self.config), {"x-token": self.config.token})
        try:
            self.assertEqual(2, reopened.get(self.url + f"/jobs/{job}/skipped?status=accepted").json()["total"])
        finally:
            reopened.close()

    def test_forced_selected_scan_and_later_accepted_scan_leave_default_limit_unchanged(self):
        jobs = self.scan(yara=True)
        for kind in ("webshell", "yara"):
            job = jobs[kind]["id"]
            first = self.details(job)["items"][0]["id"]
            retry_id = self.retry(job, {"mode": "selected", "ids": [first],
                                       "group": "size_limit", "allow_large_files": True})
            details = self.details(job)
            self.assertEqual(1, details["unresolved"])
            self.assertEqual("resolved", next(e for e in details["items"] if e["id"] == first)["status"])
            retry_job = next(j for j in self.client.get(self.url + "/jobs").json() if j["id"] == retry_id)
            self.assertTrue(retry_job["scan_context"]["allow_large_files"])
            self.assertEqual(1, len(retry_job["scan_context"]["entries"]))
            self.assertEqual(6 * 1024 * 1024, retry_job["scan_context"]["entries"][0]["max_bytes"])
            self.accept(job)
            self.retry(job, {"mode": "all", "group": "size_limit", "status": "accepted",
                             "allow_large_files": True})
            self.assertEqual(0, self.details(job)["accepted"])
            self.assertEqual(0, self.details(job)["unresolved"])
        self.assertEqual(0, self.client.get(self.url + "/dashboard").json()["analysis_accepted"])
        # A later full run still applies the default limit to both files.
        self.scan(yara=True)
        history = self.client.get(self.url + "/jobs").json()
        for kind in ("webshell", "yara"):
            latest = max((j for j in history if j["kind"] == kind
                          and j["scan_context"].get("mode") != "retry"), key=lambda j: j["id"])
            self.assertEqual(2, latest["warning_count"])

    def test_failed_force_reopens_warning_as_other_failure_and_keeps_acceptance_audit(self):
        job = self.scan()["webshell"]["id"]
        first = self.details(job)["items"][0]["id"]
        self.accept(job, [first])
        with patch.object(webshell, "scan_file", return_value=([], "read error: synthetic access denied", None)):
            self.retry(job, {"mode": "selected", "ids": [first], "group": "size_limit",
                             "status": "accepted", "allow_large_files": True})
        item = self.filtered(job, group="other")["items"][0]
        self.assertEqual(first, item["id"])
        self.assertEqual("unresolved", item["status"])
        self.assertFalse(item["acceptable"])
        self.assertFalse(item["forceable"])
        url = self.url + f"/jobs/{job}/accept-skipped"
        self.assertEqual(409, self.client.post(url, json={"mode": "selected", "ids": [first]}).status_code)
        self.assertEqual(0, self.details(job)["accepted"])
        conn = db.connect(self.case)
        self.assertEqual(1, db.one(conn, "SELECT count(*) n FROM skip_reviews")["n"])
        conn.close()

    def test_select_all_ids_cover_pagination_and_can_exclude_one(self):
        job = self.scan()["webshell"]["id"]
        conn = db.connect(self.case)
        for ordinal in range(2, 205):
            conn.execute("INSERT INTO job_skips(job_id,ordinal,path,root,reason,category) VALUES (?,?,?,?,?,'file')",
                         (job, ordinal, str(self.evidence / f"size-{ordinal}.php"), str(self.evidence),
                          "too large for content scan (6291456 bytes)"))
        stats = json.loads(db.one(conn, "SELECT stats FROM jobs WHERE id=?", (job,))["stats"])
        stats.update(skipped=205, file_skips=205, skip_details=205)
        conn.execute("UPDATE jobs SET stats=? WHERE id=?", (json.dumps(stats), job))
        conn.commit()
        conn.close()
        details = self.filtered(job)
        self.assertEqual(100, len(details["items"]))
        self.assertEqual(205, len(details["selection_ids"]["acceptable"]))
        selected = details["selection_ids"]["acceptable"]
        selected.remove(137)
        self.accept(job, selected)
        self.assertEqual([137], [item["id"] for item in self.filtered(job)["items"]])
        self.assertEqual(100, self.filtered(job, status="accepted", offset=100)["items"][0]["id"])
        self.assertEqual(204, self.filtered(job, status="accepted")["total"])

    def test_refuses_other_errors_unknown_ids_invalid_filters_and_unbounded_override(self):
        job = self.scan()["webshell"]["id"]
        conn = db.connect(self.case)
        conn.execute("UPDATE job_skips SET reason='read error: synthetic size limit permission denied' "
                     "WHERE job_id=? AND ordinal=1", (job,))
        conn.commit()
        conn.close()
        url = self.url + f"/jobs/{job}/accept-skipped"
        for body, code in (({"mode": "selected", "ids": [0, 1]}, 409),
                           ({"mode": "selected", "ids": [999]}, 400),
                           ({"mode": "selected", "ids": [True]}, 422),
                           ({"group": "other"}, 400), ({"status": "nonsense"}, 400)):
            self.assertEqual(code, self.client.post(url, json=body).status_code)
        self.assertEqual(0, self.details(job)["accepted"], "invalid batches must not partially accept")
        self.assertEqual(400, self.client.get(self.url + f"/jobs/{job}/skipped?group=nonsense").status_code)
        self.assertEqual(401, self.client.post(url, json={}, headers={"x-token": "wrong"}).status_code)
        retry_url = self.url + f"/jobs/{job}/retry-skipped"
        self.assertEqual(400, self.client.post(retry_url, json={"allow_large_files": True}).status_code)
        self.assertEqual(422, self.client.post(retry_url, json={"group": "size_limit", "allow_large_files": "true"}).status_code)
        target = next(e for e in self.details(job)["items"] if e["id"] == 0)
        with open(target["path"], "wb") as handle:
            handle.truncate(MAX_OVERRIDE_SCAN_BYTES + 1)
        limited = self.filtered(job)["items"][0]
        self.assertFalse(limited["forceable"])
        self.assertTrue(limited["acceptable"])
        self.assertIn("256 MiB", limited["action_reason"])
        self.assertEqual(409, self.client.post(retry_url, json={"mode": "selected", "ids": [0],
                            "group": "size_limit", "allow_large_files": True}).status_code)

    def test_acceptance_requires_current_evidence_but_not_unchanged_rules(self):
        job = self.scan()["webshell"]["id"]
        from server import ruleswitch
        ruleswitch.set_enabled(self.config.workspace, "webshell.upload_php", False)
        self.assertTrue(self.filtered(job)["items"][0]["acceptable"])
        self.assertFalse(self.filtered(job)["items"][0]["forceable"])
        self.accept(job, [0])
        self.scan()
        self.assertEqual(409, self.client.post(self.url + f"/jobs/{job}/accept-skipped",
                                              json={"mode": "selected", "ids": [1]}).status_code)

    def test_schema_12_upgrade_keeps_original_skips_and_starts_without_decisions(self):
        job = self.scan()["webshell"]["id"]
        conn = db.connect(self.case)
        conn.execute("DROP TABLE skip_reviews")
        conn.execute("UPDATE meta SET value='12' WHERE key='schema_version'")
        conn.commit()
        conn.close()
        conn = db.connect(self.case)
        self.assertEqual("13", db.one(conn, "SELECT value FROM meta WHERE key='schema_version'")["value"])
        self.assertEqual(0, db.one(conn, "SELECT count(*) n FROM skip_reviews")["n"])
        self.assertEqual(2, db.one(conn, "SELECT count(*) n FROM job_skips WHERE job_id=?", (job,))["n"])
        conn.close()
        self.accept(job)


class SkipReasonTests(unittest.TestCase):
    def test_historical_size_messages_are_exactly_classified(self):
        for reason in ("too large for content scan (6291456 bytes)",
                       "scan error: too large for a YARA scan",
                       "file grew beyond the content scan size limit",
                       "scan error: file grew beyond the YARA scan size limit"):
            self.assertEqual("size_limit", classify_skip(reason)["group"])
        self.assertEqual("other", classify_skip("read error: too large for a YARA scan")["group"])
        self.assertEqual("other", classify_skip("too large for a YARA scan", "rule")["group"])


if __name__ == "__main__":
    unittest.main()
