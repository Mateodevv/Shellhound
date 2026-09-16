"""Dashboard evidence counts and drill-downs, using harmless stored findings."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from server import db, first_sign, workspace
from server.app import create_app
from server.casework import timeline_preview
from server.chain import case_chain
from server.config import Config
from server.engines import logindex
from tests.test_scan_retry_api import LocalClient


def access(path, hour):
    return f'192.0.2.8 - - [16/Sep/2026:{hour:02}:00:00 +0200] "GET /{path} HTTP/1.1" 200 24 "-" "Synthetic client"\n'


class TimelinePreviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="timeline preview ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = workspace.create_case(self.root / "cases", "Timeline")
        self.other = workspace.create_case(self.root / "cases", "Separate case")
        self.webroot = self.root / "website copy"
        self.webroot.mkdir()
        self.confirmed = self.webroot / "confirmed.txt"
        self.pending = self.webroot / "pending.txt"
        for file in (self.confirmed, self.pending):
            file.write_text("Harmless example evidence", encoding="utf-8")
        self.log = self.root / "access.log"
        self.log.write_text(access("confirmed.txt", 8) + access("confirmed.txt", 9)
                            + access("pending.txt", 10) + access("pending.txt", 11), encoding="utf-8")
        conn = db.connect(self.case)
        for kind, path in (("webroot", self.webroot), ("access_logs", self.log)):
            conn.execute("INSERT INTO evidence(kind,path,added) VALUES (?,?,?)", (kind, str(path), db.now()))
        for file, decision in ((self.confirmed, "confirmed"), (self.pending, "new")):
            db.upsert_finding(conn, "webshell", db.SEV_HIGH, "Harmless review marker", "file", str(file),
                              rule_id="test." + file.stem)
            conn.execute("UPDATE findings SET triage=? WHERE artifact=?", (decision, str(file)))
        conn.commit()
        conn.close()
        logindex.build(self.case, [str(self.log)])
        self.times = patch("server.chain.filesystem_times", return_value={"created": 1789534800, "modified": 1789538400})
        self.times.start()
        self.addCleanup(self.times.stop)
        self.config = Config(workspace=self.root / "cases", token="synthetic-token")
        self.client = LocalClient(create_app(self.config), {"x-token": self.config.token})
        self.addCleanup(self.client.close)
        self.url = "/api/cases/" + self.case.name

    def query(self, suffix):
        response = self.client.get(self.url + suffix)
        self.assertEqual(200, response.status_code)
        return response.json()

    def execute(self, query, args=()):
        conn = db.connect(self.case)
        try:
            conn.execute(query, args)
            conn.commit()
        finally:
            conn.close()

    def test_four_series_equal_exact_filtered_event_counts(self):
        result = self.query("/timeline-preview")
        self.assertEqual({"filesystem_confirmed": 2, "filesystem_pending": 2,
                          "log_confirmed": 2, "log_pending": 2}, result["totals"])
        for bucket in result["buckets"]:
            for source in ("filesystem", "log"):
                for state in ("confirmed", "pending"):
                    found = self.query(f"/chain?scope={state}&event_source={source}"
                                       f"&from_epoch={bucket['start']}&to_epoch={bucket['end']}")
                    self.assertEqual(bucket[source + "_" + state], found["total_events"])
                    self.assertTrue(all(e["source"] == source and e["review_state"] == state for e in found["events"]))
        self.assertLessEqual(len(self.query("/timeline-preview?bins=12")["buckets"]), 12)

    def test_duplicate_findings_and_decision_changes_keep_stable_events(self):
        before = self.query("/chain?scope=all")
        conn = db.connect(self.case)
        db.upsert_finding(conn, "yara", db.SEV_MEDIUM, "Second harmless review marker", "file", str(self.pending))
        conn.commit()
        conn.close()
        self.assertEqual(8, self.query("/chain?scope=all")["total_events"])
        pending = [e for e in before["events"] if e["review_state"] == "pending"]
        self.assertTrue(pending)
        self.assertTrue(all(not e["first_sign_eligible"] and not e["first_sign_selectable"] for e in pending))
        denied = self.client.post(self.url + "/first-sign", json={"event_id": pending[0]["id"]})
        self.assertEqual(409, denied.status_code)
        self.execute("UPDATE findings SET triage='confirmed' WHERE artifact=?", (str(self.pending),))
        confirmed = self.query("/chain?scope=all")
        self.assertEqual({e["id"] for e in before["events"]}, {e["id"] for e in confirmed["events"]})
        self.assertTrue(all(e["review_state"] == "confirmed" for e in confirmed["events"]))
        self.execute("UPDATE findings SET triage='dismissed' WHERE artifact=?", (str(self.pending),))
        self.assertEqual(4, self.query("/chain?scope=all")["total_events"])

    def test_unknown_and_stale_are_not_reported_as_current_zero_results(self):
        self.log.write_text(self.log.read_text() + access("ordinary.txt", 12), encoding="utf-8")
        stale = self.query("/timeline-preview")
        self.assertEqual(4, stale["unavailable"])
        self.assertEqual(0, stale["totals"]["log_confirmed"] + stale["totals"]["log_pending"])
        self.assertEqual(4, stale["totals"]["filesystem_confirmed"] + stale["totals"]["filesystem_pending"])
        logindex.build(self.case, [str(self.log)])
        self.assertEqual(0, self.query("/timeline-preview")["unavailable"])
        self.execute("INSERT INTO findings(fingerprint,source,severity,rule,artifact_kind,artifact,created,last_seen) "
                     "VALUES ('undated','sqldb',1,'Harmless database review','table','example_table',?,?)", (db.now(), db.now()))
        self.assertEqual(1, self.query("/timeline-preview")["undated"])

    def test_clock_correction_once_and_muted_pending_evidence(self):
        before = self.query("/chain?scope=all")
        self.execute("INSERT INTO meta(key,value) VALUES ('clock_offsets',?)", (json.dumps({"logs": 3600}),))
        after = self.query("/chain?scope=all")
        by_id = {e["id"]: e for e in before["events"]}
        for event in after["events"]:
            self.assertEqual(by_id[event["id"]]["epoch"] + (3600 if event["source"] == "log" else 0), event["epoch"])
        result = timeline_preview.summarize(self.case, muted={"test.pending"})
        self.assertEqual(0, result["totals"]["filesystem_pending"] + result["totals"]["log_pending"])
        self.assertEqual(str(self.confirmed), first_sign.summarize(self.case, case_chain(self.case, event_cap=None))["event"]["artifact"])

    def test_scope_validation_case_isolation_and_unfiltered_default(self):
        self.assertEqual(4, self.query("/chain")["total_events"])
        for suffix in ("/chain?scope=wrong", "/chain?event_source=wrong", "/chain?from_epoch=2&to_epoch=1", "/timeline-preview?bins=25"):
            self.assertEqual(422, self.client.get(self.url + suffix).status_code)
        other = self.client.get("/api/cases/" + self.other.name + "/timeline-preview").json()
        self.assertEqual(0, sum(other["totals"].values()))

    def test_database_account_context_remains_neutral_in_default_chronology(self):
        self.execute("INSERT INTO db_accounts(dump_id,login,registered,tbl) VALUES (1,'synthetic','2026-09-16 08:30:00','example_users')")
        accounts = [e for e in self.query("/chain")["events"] if e["kind"] == "konto"]
        self.assertEqual(1, len(accounts))
        self.assertEqual("context", accounts[0]["review_state"])
        self.assertFalse(accounts[0]["first_sign_selectable"])
        self.assertFalse(any(e["kind"] == "konto" for e in self.query("/chain?scope=pending")["events"]))

    def test_filtering_before_pagination_and_focusing_beyond_first_page(self):
        result = case_chain(self.case, event_cap=None, scope="all")
        base = next(e for e in result["events"] if e["source"] == "log" and e["review_state"] == "pending")
        many = [dict(base, id="event-" + str(i), epoch=1000+i, at=1000+i) for i in range(205)]
        with patch("server.app.case_chain", return_value={**result, "events": list(reversed(many))}):
            found = self.query("/chain?scope=pending&event_source=log&from_epoch=1000&to_epoch=1205&focus=event-173")
            self.assertEqual(205, found["total_events"])
            self.assertEqual(160, found["offset"])
            self.assertTrue(found["focus_found"])
            self.assertIn("event-173", [e["id"] for e in found["events"]])
            missing = self.query("/chain?scope=pending&from_epoch=1000&to_epoch=1100&focus=event-173")
            self.assertFalse(missing["focus_found"])


class TimelineAggregationTests(unittest.TestCase):
    def test_long_ranges_empty_intervals_and_single_event(self):
        def event(id, epoch):
            return dict(id=id, epoch=epoch, source="log", review_state="pending", fresh=True)
        for bins in (1, 12, 24):
            result = timeline_preview.aggregate({"events": [event("a", 1), event("b", 2000000000)], "undated": []}, bins)
            self.assertLessEqual(len(result["buckets"]), bins)
            self.assertEqual(2, result["totals"]["log_pending"])
            if bins > 1:
                self.assertTrue(any(b["log_pending"] == 0 for b in result["buckets"]))
        single = timeline_preview.aggregate({"events": [event("a", 1000), event("a", 1000)], "undated": []})
        self.assertEqual(1, len(single["buckets"]))
        self.assertEqual(1, single["totals"]["log_pending"])
        across_epoch = timeline_preview.aggregate({"events": [event("a", -1), event("b", 1)]}, 1)
        self.assertEqual(1, len(across_epoch["buckets"]))
        bucket = across_epoch["buckets"][0]
        self.assertEqual(2, len(timeline_preview.filter_events([event("a", -1), event("b", 1)],
                              scope="pending", from_epoch=bucket["start"], to_epoch=bucket["end"])))
