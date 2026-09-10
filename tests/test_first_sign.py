"""Harmless incident anchors: chronology, provenance and analyst choice."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from server import db, first_sign, workspace
from server.chain import case_chain
from server.engines import logindex


def access_line(uri, hour=12, status=200, ip="192.0.2.7", zone="+0200"):
    return (f'{ip} - - [07/Sep/2026:{hour:02d}:01:00 {zone}] '
            f'"GET {uri} HTTP/1.1" {status} 10 "-" "Synthetic client"\n')


class FirstSignTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="first sign ")
        self.root = Path(self.temp.name)
        self.case = workspace.create_case(self.root / "workspace", "First sign")
        self.webroot = self.root / "evidence copy"
        self.webroot.mkdir()
        self.file = self.webroot / "marker.php"
        self.file.write_text("Harmless marker text", encoding="utf-8")
        os.utime(self.file, (1000000000, 1000000000))
        self.log = self.root / "access.log"
        self.log.write_text(access_line("/ordinary", hour=9) +
                            access_line("/marker.php", hour=12) +
                            access_line("/marker.php", hour=11, status=404), encoding="utf-8")
        conn = db.connect(self.case)
        for kind, path in (("webroot", self.webroot), ("access_logs", self.log)):
            conn.execute("INSERT INTO evidence(kind,path,added) VALUES (?,?,?)",
                         (kind, str(path), db.now()))
        db.upsert_finding(conn, "webshell", db.SEV_HIGH, "Harmless marker review",
                          "file", str(self.file), rule_id="test.marker")
        conn.execute("UPDATE findings SET triage='confirmed'")
        conn.commit()
        conn.close()
        logindex.build(self.case, [str(self.log)])

    def tearDown(self):
        self.temp.cleanup()

    def chain(self, **kwargs):
        return case_chain(self.case, event_cap=None, **kwargs)

    def summary(self, **kwargs):
        return first_sign.summarize(self.case, self.chain(**kwargs))

    def execute(self, sql, params=()):
        conn = db.connect(self.case)
        try:
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()

    def choose(self, event, note=""):
        conn = db.connect(self.case)
        try:
            conn.execute("BEGIN IMMEDIATE")
            first_sign.set_override(conn, self.chain(), event["id"] if event else None, note)
            conn.commit()
        finally:
            conn.close()

    def test_recorded_webshell_request_beats_older_copy_metadata(self):
        result = self.summary()
        event = result["event"]
        self.assertEqual("suggested", result["state"])
        self.assertEqual("request", event["first_sign_basis"])
        self.assertEqual("erfolg", event["kind"])
        self.assertGreater(event["epoch"], 1000000000)
        self.assertEqual(7200, event["at"] - event["epoch"])

    def test_metadata_is_review_labelled_fallback_not_ctime(self):
        self.execute("DELETE FROM evidence WHERE kind='access_logs'")
        result = self.summary()
        self.assertEqual("metadata_only", result["state"])
        self.assertEqual(1000000000, result["event"]["epoch"])
        self.assertEqual("datei-geaendert", result["event"]["kind"])
        changed = [e for e in self.chain()["events"] if e["kind"] == "metadaten-geaendert"]
        self.assertTrue(all(not e["first_sign_eligible"] for e in changed))

    def test_no_confirmed_and_undated_are_distinct(self):
        self.execute("UPDATE findings SET triage='new'")
        self.assertEqual("no_confirmed", self.summary()["state"])
        self.execute("UPDATE findings SET triage='confirmed'")
        self.execute("DELETE FROM evidence")
        self.assertEqual("undated", self.summary()["state"])

    def test_registration_changes_stale_index_and_queued_index_disable_log_candidates(self):
        for mode in ("unregistered", "changed", "busy"):
            with self.subTest(mode=mode):
                if mode == "unregistered":
                    self.execute("DELETE FROM evidence WHERE kind='access_logs'")
                elif mode == "changed":
                    self.log.write_text(self.log.read_text() + access_line("/new"), encoding="utf-8")
                else:
                    logindex.build(self.case, [str(self.log)])
                    self.execute("INSERT INTO jobs(kind,state,created) VALUES ('index_logs','queued',?)", (db.now(),))
                self.assertEqual("metadata_only", self.summary()["state"])
                if mode == "unregistered":
                    self.execute("INSERT INTO evidence(kind,path,added) VALUES ('access_logs',?,?)",
                                 (str(self.log), db.now()))

    def test_ids_ignore_display_and_analyst_clock_offsets(self):
        local = self.chain()
        utc = self.chain(tz_mode="utc")
        self.assertEqual({e["id"] for e in local["events"]}, {e["id"] for e in utc["events"]})
        self.assertEqual(self.summary()["event"]["epoch"], self.summary(tz_mode="utc")["event"]["epoch"])
        self.execute("INSERT INTO meta(key,value) VALUES ('clock_offsets',?)", (json.dumps({"logs": -3600}),))
        shifted = self.chain()
        self.assertEqual({e["id"] for e in local["events"]}, {e["id"] for e in shifted["events"]})
        old = next(e for e in local["events"] if e["kind"] == "erfolg")
        new = next(e for e in shifted["events"] if e["kind"] == "erfolg")
        self.assertEqual(old["epoch"] - 3600, new["epoch"])

    def test_manual_choice_stays_put_and_reports_earlier_candidate(self):
        events = self.chain()["events"]
        # Explicitly choose the evidence-copy creation (later than the logs).
        with patch("server.chain.filesystem_times", return_value={"created": 2000000000, "modified": 1000000000}):
            chosen = next(e for e in self.chain()["events"] if e["kind"] == "datei-erstellt")
            self.choose(chosen, "Reviewed independently")
            result = self.summary()
            self.assertEqual("manual", result["mode"])
            self.assertEqual(chosen["id"], result["event"]["id"])
            self.assertTrue(result["earlier_candidate"])
            self.assertEqual("Reviewed independently", result["note"])
            self.choose(None)
            self.assertEqual("automatic", self.summary()["mode"])

    def test_manual_choice_is_preserved_as_stale_after_revocation(self):
        chosen = self.summary()["event"]
        self.choose(chosen, "A retained analyst note")
        self.execute("UPDATE findings SET triage='dismissed'")
        result = self.summary()
        self.assertEqual("stale_override", result["state"])
        self.assertEqual(chosen["id"], result["event"]["id"])
        self.assertEqual("A retained analyst note", result["note"])
        self.assertIsNone(result["automatic_event"])
        self.assertFalse(result["event"]["first_sign_selectable"])
        self.assertFalse(result["event"]["first_sign_eligible"])

    def test_manual_source_removal_never_silently_switches_to_metadata(self):
        self.choose(self.summary()["event"])
        self.execute("DELETE FROM evidence WHERE kind='access_logs'")
        result = self.summary()
        self.assertEqual("stale_override", result["state"])
        self.assertEqual("filesystem", result["automatic_event"]["first_sign_basis"])

    def test_removed_webroot_cannot_retarget_file_to_an_unrelated_basename(self):
        nested = self.webroot / "nested"
        nested.mkdir()
        path = nested / self.file.name
        self.file.rename(path)
        self.execute("UPDATE findings SET artifact=? WHERE artifact=?",
                     (str(path), str(self.file)))
        self.log.write_text(access_line("/marker.php", hour=8) +
                            access_line("/nested/marker.php", hour=12), encoding="utf-8")
        logindex.build(self.case, [str(self.log)])
        chosen = self.summary()["event"]
        self.assertEqual(str(path), chosen["artifact"])
        self.assertEqual("nested/marker.php", chosen["artifact_rel"])
        self.choose(chosen, "Confirmed nested path")
        self.execute("DELETE FROM evidence WHERE kind='webroot'")
        result = self.summary()
        self.assertEqual("stale_override", result["state"])
        self.assertEqual(chosen["id"], result["event"]["id"])
        self.assertIsNone(result["automatic_event"])
        file_events = [event for event in self.chain()["events"]
                       if event["artifact"] == str(path) and event["source"] == "log"]
        self.assertTrue(file_events, "Historical observations may remain visible")
        self.assertTrue(all(not event["first_sign_eligible"] and
                            not event["first_sign_selectable"] for event in file_events))
        self.choose(None)
        self.assertEqual("undated", self.summary()["state"])

    def test_override_rejects_unknown_context_event_and_oversized_notes(self):
        conn = db.connect(self.case)
        try:
            with self.assertRaises(ValueError):
                first_sign.set_override(conn, self.chain(), "unknown")
            event = self.summary()["event"]
            with self.assertRaises(ValueError):
                first_sign.set_override(conn, self.chain(), event["id"], "x" * 2001)
            changed = next((e for e in self.chain()["events"] if e["kind"] == "metadaten-geaendert"), None)
            if changed:
                with self.assertRaises(ValueError):
                    first_sign.set_override(conn, self.chain(), changed["id"])
        finally:
            conn.close()

    def test_ordinary_ip_browsing_is_manual_only(self):
        conn = db.connect(self.case)
        try:
            conn.execute("UPDATE findings SET triage='dismissed'")
            db.upsert_finding(conn, "logs", db.SEV_HIGH, "Reviewed synthetic client",
                              "client", "192.0.2.7", rule_id="test.client")
            conn.execute("UPDATE findings SET triage='confirmed' WHERE artifact_kind='client'")
            conn.commit()
        finally:
            conn.close()
        result = self.summary()
        self.assertEqual("undated", result["state"])
        first = next(e for e in self.chain()["events"] if e["kind"] == "erstkontakt")
        self.assertTrue(first["first_sign_selectable"])
        self.assertFalse(first["first_sign_eligible"])
        self.choose(first)
        self.assertEqual("manual", self.summary()["mode"])

    def test_verified_alert_uses_matching_activity_not_earlier_ordinary_browsing(self):
        conn = db.connect(self.case)
        try:
            conn.execute("UPDATE findings SET triage='dismissed'")
            db.upsert_finding(conn, "logs", db.SEV_HIGH, "Reviewed synthetic client",
                              "client", "192.0.2.7", rule_id="logs.marker")
            conn.execute("UPDATE findings SET triage='confirmed' WHERE artifact_kind='client'")
            conn.commit()
        finally:
            conn.close()
        actor = {"first_epoch": 1000000000, "last_epoch": 1000000400,
                 "tz": 7200, "requests": 4, "alerts": [
                     {"kind": "marker", "detail": "Reviewed marker activity",
                      "example": "/marker.php", "severity": db.SEV_HIGH,
                      "epoch": 1000000000, "first_sign_epoch": 1000000300,
                      "first_sign_tz": 3600, "first_sign_example": "/matched-marker"}]}
        with patch("server.chain.logindex.chain_facts", return_value={
                "files": {}, "clients": {"192.0.2.7": actor}}):
            result = self.summary()
        self.assertEqual(1000000300, result["event"]["epoch"])
        self.assertEqual("alarm", result["event"]["kind"])
        self.assertEqual(3600, result["event"]["at"] - result["event"]["epoch"])
        self.assertIn("/matched-marker", result["event"]["detail"])
        self.assertNotIn("/marker.php", result["event"]["detail"])

        conn = db.connect(self.case)
        try:
            db.upsert_finding(conn, "logs", db.SEV_HIGH, "Other confirmed observation",
                              "client", "192.0.2.7", rule_id="test.other")
            conn.execute("UPDATE findings SET triage='confirmed' WHERE rule_id='test.other'")
            conn.commit()
        finally:
            conn.close()
        for triage in ("new", "dismissed"):
            self.execute("UPDATE findings SET triage=? WHERE rule_id='logs.marker'", (triage,))
            with patch("server.chain.logindex.chain_facts", return_value={
                    "files": {}, "clients": {"192.0.2.7": actor}}):
                self.assertEqual("undated", self.summary()["state"])
                alarm = next(e for e in self.chain()["events"] if e["kind"] == "alarm")
                self.assertTrue(alarm["first_sign_selectable"])
                self.assertFalse(alarm["first_sign_eligible"])

    def test_hunt_match_requires_exact_confirmed_finding_and_current_generation(self):
        conn = db.connect(self.case)
        epoch = 1788771600
        try:
            conn.execute("UPDATE findings SET triage='dismissed'")
            db.upsert_finding(conn, "logs", db.SEV_HIGH, "Selected marker request",
                              "client", "192.0.2.7", rule_id="hunt.marker.v1")
            conn.execute("UPDATE findings SET triage='confirmed' WHERE artifact_kind='client'")
            test_id = conn.execute("INSERT INTO hunt_tests(pattern_id,pattern_version,rule_hash,rule_json,tested_at,index_fingerprint) "
                                   "VALUES ('marker',1,'safe-hash','{}',?,?)",
                                   (db.now(), logindex.index_fingerprint(self.case))).lastrowid
            app_id = conn.execute("INSERT INTO hunt_applications(test_id,pattern_id,pattern_version,rule_hash,applied_at,idempotency_key) "
                                  "VALUES (?,'marker',1,'safe-hash',?,'safe-key')", (test_id, db.now())).lastrowid
            conn.execute("INSERT INTO hunt_application_clusters(application_id,cluster_key,client,method,uri_pattern,status_class,first_epoch) "
                         "VALUES (?,'safe-cluster','192.0.2.7','GET','/marker.php','2xx',?)", (app_id, epoch))
            conn.commit()
        finally:
            conn.close()
        self.assertEqual("hunt_match", self.summary()["event"]["first_sign_basis"])
        self.assertEqual(epoch, self.summary()["event"]["epoch"])
        logindex.build(self.case, [str(self.log)])
        self.assertEqual("undated", self.summary()["state"])
        conn = db.connect(self.case)
        try:
            new_test = conn.execute("INSERT INTO hunt_tests(pattern_id,pattern_version,rule_hash,rule_json,tested_at,index_fingerprint) "
                                    "VALUES ('marker',1,'safe-hash','{}',?,?)",
                                    (db.now(), logindex.index_fingerprint(self.case))).lastrowid
            new_app = conn.execute("INSERT INTO hunt_applications(test_id,pattern_id,pattern_version,rule_hash,applied_at,idempotency_key) "
                                   "VALUES (?,'marker',1,'safe-hash',?,'safe-retry')", (new_test, db.now())).lastrowid
            conn.execute("INSERT INTO hunt_application_clusters(application_id,cluster_key,client,method,uri_pattern,status_class,first_epoch) "
                         "VALUES (?,'safe-cluster','192.0.2.7','GET','/marker.php','2xx',?)", (new_app, epoch))
            conn.commit()
        finally:
            conn.close()
        self.assertEqual("hunt_match", self.summary()["event"]["first_sign_basis"])
        self.assertEqual(1, len([e for e in self.chain()["events"] if e["kind"] == "hunt-match"]))

    def test_index_generation_replacement_during_read_disables_candidates(self):
        current = logindex.index_fingerprint(self.case)
        with patch("server.chain.logindex.index_fingerprint", side_effect=[current, "replacement"]):
            chain = self.chain()
        self.assertTrue(all(not e["first_sign_eligible"] for e in chain["events"] if e["source"] == "log"))


if __name__ == "__main__":
    unittest.main()
