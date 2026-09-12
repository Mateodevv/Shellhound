"""Durable hunt runs and exact drilldowns using harmless synthetic requests."""
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from server import db, hunt_batches, patterns, workspace
from server.app import create_app
from server.config import Config
from server.engines import logindex
from server.jobs import CaseBusy, JobManager
from tests.test_scan_retry_api import LocalClient


def marker_rule(value="/marker"):
    return {"client_match": "any", "requests": [{"clauses": [
        {"field": "uri", "operator": "contains", "values": [value]}]}]}


def line(ip, path="/marker", minute="01", status=200):
    return f'{ip} - - [07/Sep/2026:12:{minute}:00 +0000] "GET {path} HTTP/1.1" {status} 10 "-" "Synthetic client"\n'


class HuntBatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hunt batches ")
        self.root = Path(self.temp.name)
        self.config = Config(workspace=self.root / "workspace", token="synthetic-test")
        self.case = workspace.create_case(self.config.workspace, "Harmless hunt")
        self.log = self.root / "example access.log"
        # One client's rows deliberately arrive out of chronological order.
        self.log.write_text(line("192.0.2.1", minute="03") +
                            line("192.0.2.1", minute="01") +
                            line("192.0.2.1", "/ordinary", minute="02") +
                            "".join(line(f"198.51.100.{i}") for i in range(1, 206)), encoding="utf-8")
        logindex.build(self.case, [str(self.log)])
        conn = db.connect(self.case)
        conn.execute("INSERT INTO evidence(kind,path,added) VALUES ('access_logs',?,?)",
                     (str(self.log), db.now()))
        conn.commit()
        conn.close()
        for entry in patterns.library(self.config.workspace):
            patterns.set_enabled(self.config.workspace, entry["id"], False)
        self.entry = patterns.add(self.config.workspace, [], name="Marker requests", rule=marker_rule())
        self.manager = JobManager()
        self.manager_patch = patch("server.app.manager", self.manager)
        self.manager_patch.start()
        self.client = LocalClient(create_app(self.config), {"x-token": self.config.token})
        self.url = f"/api/cases/{self.case.name}"

    def tearDown(self):
        self.manager.cancel_all_and_wait()
        self.manager.pool.shutdown(wait=True)
        self.client.close()
        self.manager_patch.stop()
        self.temp.cleanup()

    def start(self, ids=None):
        response = self.client.post(self.url + "/hunt/batch-tests", json={"ids": ids or []})
        self.assertEqual(200, response.status_code, response.text)
        return response.json()

    def finish(self, started):
        self.assertEqual([], self.manager.wait_for(self.case, [started["job_id"]]))
        response = self.client.get(self.url + "/hunt/batch-tests/" + started["batch_id"])
        self.assertEqual(200, response.status_code, response.text)
        return response.json()

    def test_batch_history_keeps_snapshot_and_zero_hits_without_applying_findings(self):
        empty = patterns.add(self.config.workspace, [], name="No matches", rule=marker_rule("/absent"))
        run = self.finish(self.start())
        self.assertEqual({"total": 2, "checked": 2, "matched": 1, "failed": 0, "remaining": 0}, run["counts"])
        self.assertEqual(208, run["index_summary"]["requests"])
        self.assertTrue(run["fresh"])
        self.assertNotIn("hits", run["counts"])
        patterns.update(self.config.workspace, self.entry["id"], name="Renamed library rule")
        restored = self.client.get(self.url + "/hunt/batch-tests").json()["runs"][0]
        self.assertEqual("Marker requests", restored["patterns"][0]["name"])
        self.assertIn("rule", restored["patterns"][0]["test"])
        single = self.finish(self.start([empty["id"]]))
        self.assertEqual(1, single["counts"]["checked"])
        self.assertEqual(0, single["counts"]["matched"])
        conn = db.connect(self.case)
        try:
            self.assertEqual(0, conn.execute("SELECT count(*) FROM findings").fetchone()[0])
        finally:
            conn.close()

    def test_saved_checks_keep_all_ip_cve_links_and_reuse_them_on_repeat(self):
        patterns.update(self.config.workspace, self.entry["id"], cve="CVE-2026-12345 CVE-2026-54321")
        for iteration in (1, 2):
            run = self.finish(self.start([self.entry["id"]]))
            self.assertEqual("done", run["state"])
            self.assertEqual(206, run["patterns"][0]["test"]["clients"])
            conn = db.connect(self.case)
            try:
                links = [r for r in db.ioc_links(conn) if r["kind"] == "cve-context"]
                self.assertEqual(412, len(links), "Every matched IP keeps both CVEs beyond UI page limits")
                self.assertEqual(206, conn.execute("SELECT count(*) FROM iocs WHERE type='ip'").fetchone()[0])
                self.assertEqual(0, conn.execute("SELECT count(*) FROM findings").fetchone()[0])
                self.assertEqual(412 * iteration, conn.execute("SELECT count(*) FROM ioc_relationship_evidence WHERE observation_id IS NOT NULL").fetchone()[0])
            finally:
                conn.close()

        from server import opencti_graph
        workspace.update_case(self.case, reference="PIM-SYNTHETIC-CVE")
        preview = opencti_graph.build_preview(self.case)
        self.assertFalse(preview["errors"])
        exported = [o for o in preview["objects"] if o["type"] == "relationship"
                    and o["source_ref"].startswith("ipv4-addr--")
                    and o["target_ref"].startswith("vulnerability--")]
        self.assertEqual(412, len(exported))
        self.assertTrue(all(o["relationship_type"] == "related-to" for o in exported))

    def test_cve_collection_rejects_a_different_index_generation(self):
        with self.assertRaises(logindex.StaleHuntIndex):
            list(logindex.iter_rule_clients(self.case, marker_rule(), expected_fingerprint="old-generation"))

    def test_dashboard_links_latest_check_without_creating_or_combining_findings(self):
        patterns.add(self.config.workspace, [], name="Overlapping marker", rule=marker_rule("/mar"))
        run = self.finish(self.start())
        patterns.update(self.config.workspace, self.entry["id"], name="New library name")
        dashboard = self.client.get(self.url + "/dashboard").json()
        summary = dashboard["hunt_summary"]
        self.assertEqual(run["batch_id"], summary["batch_id"])
        self.assertEqual((2, 2, 2), (summary["matched"], summary["checked"], summary["total"]))
        self.assertTrue(summary["fresh"])
        self.assertTrue(summary["complete"])
        self.assertIn("Marker requests", summary["pattern_names"])
        self.assertNotIn("New library name", summary["pattern_names"])
        self.assertNotIn("hits", summary)
        self.assertNotIn("clients", summary)
        self.assertEqual(0, dashboard["findings_total"])
        self.assertEqual([], dashboard["top_findings"]["groups"])
        other = workspace.create_case(self.config.workspace, "Unrelated synthetic case")
        self.assertIsNone(self.client.get(f"/api/cases/{other.name}/dashboard").json()["hunt_summary"])
        empty = patterns.add(self.config.workspace, [], name="No match check", rule=marker_rule("/absent"))
        self.finish(self.start([empty["id"]]))
        self.assertIsNone(self.client.get(self.url + "/dashboard").json()["hunt_summary"])
        self.assertEqual(2, self.client.get(self.url + "/hunt/batch-tests/" + run["batch_id"]).json()["counts"]["matched"])

    def test_dashboard_marks_changed_registrations_as_historical(self):
        run = self.finish(self.start())
        conn = db.connect(self.case)
        conn.execute("UPDATE evidence SET path=?", (str(self.root / "different log.log"),))
        conn.commit()
        conn.close()
        summary = self.client.get(self.url + "/dashboard").json()["hunt_summary"]
        self.assertEqual(run["batch_id"], summary["batch_id"])
        self.assertEqual(1, summary["matched"])
        self.assertFalse(summary["fresh"])

    def test_exact_ip_pages_and_chronological_cluster_anchor(self):
        run = self.finish(self.start())
        test = run["patterns"][0]["test"]
        endpoint = self.url + f"/hunt/tests/{test['id']}"
        first = self.client.post(endpoint + "/clients", json={"limit": 200}).json()
        self.assertEqual(206, first["total"])
        self.assertEqual(200, len(first["clients"]))
        second = self.client.post(endpoint + "/clients", json={"cursor": first["next_cursor"]}).json()
        self.assertEqual(6, len(second["clients"]))
        self.assertFalse({r["client"] for r in first["clients"]} & {r["client"] for r in second["clients"]})
        anchor = next(row for row in first["clients"] if row["client"] == "192.0.2.1")
        self.assertEqual(2, anchor["request_id"])
        groups = self.client.post(endpoint + "/clusters", json={"client": "192.0.2.1"}).json()
        self.assertEqual(1, groups["total"])
        self.assertEqual(2, groups["clusters"][0]["request_id"])
        trace = self.client.post(self.url + "/trace", json={"ips": ["192.0.2.1"],
            "after_request_id": anchor["request_id"], "index_fingerprint": test["index_fingerprint"]}).json()
        self.assertEqual(["/ordinary", "/marker"], [row["uri"] for row in trace["rows"]])
        self.assertEqual([3, 1], [row["request_id"] for row in trace["rows"]])
        # A visible group reached through a later IP page is selectable
        # directly, without scanning a bounded sample of earlier groups.
        later_ip = second["clients"][-1]["client"]
        later = self.client.post(endpoint + "/clusters", json={"client": later_ip}).json()["clusters"][0]
        selected = logindex.rule_clusters(self.case, test["rule"], cluster_keys=[later["cluster_key"]],
                                          expected_fingerprint=test["index_fingerprint"])
        self.assertEqual(1, selected["total"])
        self.assertEqual(later_ip, selected["clusters"][0]["client"])

    def test_one_pattern_failure_keeps_results_and_checks_remaining_patterns(self):
        broken = patterns.add(self.config.workspace, [], name="Unavailable query", rule=marker_rule("/failure"))
        patterns.add(self.config.workspace, [], name="Later query", rule=marker_rule("/ordinary"))
        original = logindex.match_rule
        def evaluate(case, rule, **kwargs):
            if rule["requests"][0]["clauses"][0]["values"] == ["/failure"]:
                raise sqlite3.OperationalError("synthetic failure")
            return original(case, rule, **kwargs)
        with patch("server.app.logindex.match_rule", side_effect=evaluate):
            run = self.finish(self.start())
        self.assertEqual("done", run["state"])
        self.assertEqual({"total": 3, "checked": 2, "matched": 2, "failed": 1, "remaining": 0}, run["counts"])
        failed = next(row for row in run["patterns"] if row["id"] == broken["id"])
        self.assertEqual("failed", failed["status"])
        self.assertIsNone(failed["test"])
        summary = self.client.get(self.url + "/dashboard").json()["hunt_summary"]
        self.assertEqual(2, summary["matched"])
        self.assertFalse(summary["complete"])
        self.assertEqual(1, self.finish(self.start([broken["id"]]))["counts"]["checked"])

    def test_cancellation_interrupts_query_and_blocks_overlapping_reindex(self):
        patterns.add(self.config.workspace, [], name="Later query", rule=marker_rule("/ordinary"))
        entered, release = threading.Event(), threading.Event()
        original = logindex.match_rule
        def pause(case, rule, **kwargs):
            entered.set()
            release.wait(5)
            return original(case, rule, **kwargs)
        with patch("server.app.logindex.match_rule", side_effect=pause):
            started = self.start()
            self.assertTrue(entered.wait(5))
            self.assertEqual(409, self.client.post(self.url + "/hunt/batch-tests", json={}).status_code)
            with self.assertRaises(CaseBusy):
                with self.manager.case_operation(self.case):
                    self.fail("overlapping index submission was allowed")
            self.manager.cancel(self.case, started["job_id"])
            release.set()
            run = self.finish(started)
        self.assertEqual("cancelled", run["state"])
        self.assertEqual(0, run["counts"]["checked"])
        self.assertEqual(2, run["counts"]["remaining"])
        self.assertTrue(all(item["status"] == "not_run" for item in run["patterns"]))

    def test_stale_history_is_retained_and_all_drilldowns_and_apply_refuse(self):
        run = self.finish(self.start())
        test = run["patterns"][0]["test"]
        endpoint = self.url + f"/hunt/tests/{test['id']}"
        group = self.client.post(endpoint + "/clusters", json={"client": "192.0.2.1"}).json()["clusters"][0]
        body = {"cluster_keys": [group["cluster_key"]], "pattern_id": self.entry["id"], "expected_version": 1}
        applied = self.client.post(endpoint + "/apply", json=body)
        self.assertEqual(200, applied.status_code, applied.text)
        conn = db.connect(self.case)
        try:
            conn.execute("UPDATE findings SET triage='confirmed'")
            conn.commit()
        finally:
            conn.close()
        self.assertTrue(self.client.post(endpoint + "/apply", json=body).json()["already_applied"])
        conn = db.connect(self.case)
        try:
            self.assertEqual("confirmed", conn.execute("SELECT triage FROM findings").fetchone()[0])
        finally:
            conn.close()
        self.log.write_text(self.log.read_text(encoding="utf-8") + line("192.0.2.2"), encoding="utf-8")
        logindex.build(self.case, [str(self.log)])
        self.assertFalse(self.client.get(self.url + "/hunt/batch-tests/" + run["batch_id"]).json()["fresh"])
        for suffix, payload in (("/clients", {}), ("/clusters", {}), ("/apply", body)):
            self.assertEqual(409, self.client.post(endpoint + suffix, json=payload).status_code)
        self.assertEqual(409, self.client.post(self.url + "/trace", json={"ips": ["192.0.2.1"],
            "index_fingerprint": test["index_fingerprint"]}).status_code)
        self.assertEqual(409, self.client.get(self.url + "/access/request/2?index_fingerprint=" + test["index_fingerprint"]).status_code)

    def test_interrupted_and_legacy_runs_never_invent_complete_rosters(self):
        conn = db.connect(self.case)
        try:
            context = hunt_batches.context([self.entry], logindex.index_snapshot(self.case))
            context["patterns"][0]["status"] = "running"
            conn.execute("INSERT INTO jobs(kind,state,created,run_id,scan_context) VALUES ('hunt','running',?,?,?)",
                         (db.now(), "interrupted", json.dumps(context)))
            conn.execute("INSERT INTO jobs(kind,state,created,run_id) VALUES ('hunt','done',?,?)", (db.now(), "legacy"))
            conn.commit()
        finally:
            conn.close()
        interrupted = self.client.get(self.url + "/hunt/batch-tests/interrupted").json()
        self.assertEqual("failed", interrupted["state"])
        self.assertEqual("not_run", interrupted["patterns"][0]["status"])
        legacy = self.client.get(self.url + "/hunt/batch-tests/legacy").json()
        self.assertFalse(legacy["roster_known"])
        self.assertIsNone(legacy["counts"]["total"])
        self.assertIsNone(legacy["counts"]["remaining"])

    def test_apply_rechecks_registrations_after_cluster_evaluation(self):
        run = self.finish(self.start())
        test = run["patterns"][0]["test"]
        endpoint = self.url + f"/hunt/tests/{test['id']}"
        group = self.client.post(endpoint + "/clusters", json={"client": "192.0.2.1"}).json()["clusters"][0]
        original = logindex.rule_clusters

        def remove_registration(*args, **kwargs):
            result = original(*args, **kwargs)
            conn = db.connect(self.case)
            try:
                conn.execute("DELETE FROM evidence WHERE kind='access_logs'")
                conn.commit()
            finally:
                conn.close()
            return result

        with patch("server.app.logindex.rule_clusters", side_effect=remove_registration):
            response = self.client.post(endpoint + "/apply", json={
                "cluster_keys": [group["cluster_key"]], "pattern_id": self.entry["id"],
                "expected_version": 1})
        self.assertEqual(409, response.status_code)
        conn = db.connect(self.case)
        try:
            self.assertEqual(0, conn.execute("SELECT count(*) FROM findings").fetchone()[0])
            self.assertEqual(0, conn.execute("SELECT count(*) FROM hunt_applications").fetchone()[0])
        finally:
            conn.close()

    def test_apply_holds_case_write_lock_during_final_freshness_check(self):
        run = self.finish(self.start())
        test = run["patterns"][0]["test"]
        endpoint = self.url + f"/hunt/tests/{test['id']}"
        group = self.client.post(endpoint + "/clusters", json={"client": "192.0.2.1"}).json()["clusters"][0]
        other = workspace.create_case(self.config.workspace, "Independent synthetic case")
        original = logindex.index_fingerprint
        checks = []

        def check_registration_lock(case_dir):
            fingerprint = original(case_dir)
            checks.append(case_dir)
            if len(checks) == 2:
                # This is the final validation after the expensive query.
                # Another registration writer must wait for this case only.
                conn = sqlite3.connect(db.case_db_path(self.case), timeout=0)
                try:
                    with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                        conn.execute("DELETE FROM evidence WHERE kind='access_logs'")
                finally:
                    conn.close()
                conn = db.connect(other)
                try:
                    conn.execute("INSERT INTO evidence(kind,path,added) VALUES ('access_logs',?,?)",
                                 (str(self.log), db.now()))
                    conn.commit()
                finally:
                    conn.close()
            return fingerprint

        with patch("server.app.logindex.index_fingerprint", side_effect=check_registration_lock):
            response = self.client.post(endpoint + "/apply", json={
                "cluster_keys": [group["cluster_key"]], "pattern_id": self.entry["id"],
                "expected_version": 1})
        self.assertEqual(200, response.status_code, response.text)
        self.assertEqual(2, len(checks))
        conn = db.connect(self.case)
        try:
            self.assertEqual(1, conn.execute("SELECT count(*) FROM evidence").fetchone()[0])
            # The reservation ends with application; normal removal still works.
            conn.execute("DELETE FROM evidence WHERE kind='access_logs'")
            conn.commit()
        finally:
            conn.close()

    def test_missing_partial_index_and_disabled_patterns_have_clear_refusals(self):
        patterns.set_enabled(self.config.workspace, self.entry["id"], False)
        self.assertEqual(400, self.client.post(self.url + "/hunt/batch-tests", json={"ids": [self.entry["id"]]}).status_code)
        patterns.set_enabled(self.config.workspace, self.entry["id"], True)
        conn = sqlite3.connect(db.log_db_path(self.case))
        conn.execute("UPDATE meta SET value='1' WHERE key='partial'")
        conn.commit()
        conn.close()
        self.assertEqual(409, self.client.post(self.url + "/hunt/batch-tests", json={}).status_code)
        db.log_db_path(self.case).unlink()
        self.assertEqual(409, self.client.post(self.url + "/hunt/batch-tests", json={}).status_code)

    def test_rebuilding_unchanged_logs_invalidates_saved_request_ids(self):
        run = self.finish(self.start())
        fingerprint = run["index_fingerprint"]
        logindex.build(self.case, [str(self.log)])
        self.assertNotEqual(fingerprint, logindex.index_fingerprint(self.case))
        self.assertFalse(self.client.get(self.url + "/hunt/batch-tests/" + run["batch_id"]).json()["fresh"])

    def test_source_changes_before_reindex_block_new_checks_and_saved_evidence_actions(self):
        run = self.finish(self.start())
        test = run["patterns"][0]["test"]
        endpoint = self.url + f"/hunt/tests/{test['id']}"
        group = self.client.post(endpoint + "/clusters", json={"client": "192.0.2.1"}).json()["clusters"][0]
        apply_body = {"cluster_keys": [group["cluster_key"]], "pattern_id": self.entry["id"], "expected_version": 1}
        original = self.log.read_text(encoding="utf-8")
        original_stat = self.log.stat()
        extra = self.root / "additional.log"
        extra.write_text(line("203.0.113.2"), encoding="utf-8")
        for change in ("content", "registered_addition", "file_deletion", "registration_removal"):
            with self.subTest(change=change):
                if change == "content":
                    self.log.write_text(original + line("203.0.113.3"), encoding="utf-8")
                elif change == "file_deletion":
                    self.log.unlink()
                else:
                    conn = db.connect(self.case)
                    if change == "registered_addition":
                        conn.execute("INSERT INTO evidence(kind,path,added) VALUES ('access_logs',?,?)", (str(extra), db.now()))
                    else:
                        conn.execute("DELETE FROM evidence WHERE kind='access_logs'")
                    conn.commit()
                    conn.close()
                # The old SQLite file and generation have not changed.
                self.assertEqual(test["index_fingerprint"], logindex.index_fingerprint(self.case))
                history = self.client.get(self.url + "/hunt/batch-tests/" + run["batch_id"]).json()
                self.assertFalse(history["fresh"])
                self.assertEqual(test["hits"], history["patterns"][0]["test"]["hits"])
                self.assertFalse(self.client.get(self.url + "/hunt/batch-tests").json()["runs"][0]["fresh"])
                self.assertEqual(409, self.client.post(self.url + "/hunt/batch-tests", json={}).status_code)
                self.assertEqual(409, self.client.post(self.url + "/hunt/tests", json={"rule": marker_rule()}).status_code)
                for suffix, payload in (("/clients", {}), ("/clusters", {}), ("/apply", apply_body)):
                    self.assertEqual(409, self.client.post(endpoint + suffix, json=payload).status_code)
                self.assertEqual(409, self.client.post(self.url + "/trace", json={"ips": ["192.0.2.1"],
                    "index_fingerprint": test["index_fingerprint"], "after_request_id": 2}).status_code)
                self.assertEqual(409, self.client.get(self.url + "/access/request/2?index_fingerprint=" + test["index_fingerprint"]).status_code)
                # Restore exactly the evidence snapshot for the next scenario.
                self.log.write_text(original, encoding="utf-8")
                os.utime(self.log, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
                conn = db.connect(self.case)
                conn.execute("DELETE FROM evidence WHERE kind='access_logs'")
                conn.execute("INSERT INTO evidence(kind,path,added) VALUES ('access_logs',?,?)", (str(self.log), db.now()))
                conn.commit()
                conn.close()
                self.assertTrue(self.client.get(self.url + "/hunt/batch-tests/" + run["batch_id"]).json()["fresh"])


if __name__ == "__main__":
    unittest.main()
