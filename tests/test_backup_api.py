"""Backup HTTP boundaries and case-local content decisions, using harmless text."""
import hashlib
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from server import backups, db, workspace
from server.app import create_app
from server.config import Config
from server.jobs import JobManager
from tests.test_http import _LiveServer


class BackupApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="backup API with spaces ")
        self.root = Path(self.temp.name)
        self.config = Config(workspace=self.root / "cases", token="backup-api-test")
        self.case = workspace.create_case(self.config.workspace, "Backup API")
        self.other = workspace.create_case(self.config.workspace, "Other case")
        self.manager = JobManager()
        self.patches = [patch("server.app.manager", self.manager),
                        patch("server.jobs.manager", self.manager)]
        for item in self.patches:
            item.start()
        self.server = _LiveServer(create_app(self.config))
        self.base = self.server.start()
        self.prefix = f"/api/cases/{self.case.name}"
        self.serial = 0

    def tearDown(self):
        self.server.stop()
        self.manager.cancel_all_and_wait()
        self.manager.pool.shutdown(wait=True)
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def request(self, method, path, body=None, *, token=True):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-Token"] = self.config.token
        payload = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=payload,
                                     headers=headers, method=method)
        try:
            response = urllib.request.urlopen(req, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            try:
                return response.status, json.loads(raw)
            except ValueError:
                return response.status, raw.decode(errors="replace")

    def ok(self, method, suffix, body=None):
        status, result = self.request(method, self.prefix + suffix, body)
        self.assertEqual(200, status, result)
        return result

    def root_source(self, name="backup", *, case=None, files=None):
        self.serial += 1
        root = self.root / f"{name} {self.serial}"
        root.mkdir()
        for name, content in (files or {"example.txt": "Harmless text\n"}).items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        with closing(db.connect(case or self.case)) as conn:
            evidence_id = conn.execute(
                "INSERT INTO evidence(kind,path,added) VALUES ('webroot',?,?)",
                (str(root), db.now())).lastrowid
            conn.commit()
        return evidence_id, root

    def site(self, zone="UTC"):
        return self.ok("POST", "/backups/sites", {"label": "Example website", "timezone": zone})["id"]

    def snapshot(self, site, evidence, root, **options):
        body = {"site_id": site, "evidence_id": evidence, "root": str(root),
                "label": root.name, **options}
        return self.ok("POST", "/backups/snapshots", body)["id"]

    def jobs(self, case=None):
        with closing(db.connect(case or self.case)) as conn:
            return db.rows(conn, "SELECT * FROM jobs ORDER BY id")

    def wait(self, job, case=None):
        self.assertEqual([], self.manager.wait_for(case or self.case, [job], timeout=10))
        row = next(row for row in self.jobs(case) if row["id"] == job)
        self.assertEqual("done", row["state"], row["error"])
        return json.loads(row["stats"])

    def finding(self, path, *, state="new", note="", case=None, inventory=False):
        with closing(db.connect(case or self.case)) as conn:
            db.upsert_finding(conn, "analyst", db.SEV_LOW, "Harmless review observation",
                              "file", str(path), rule_id="analyst.api_fixture")
            conn.execute("UPDATE findings SET triage=?,triage_note=? WHERE artifact=?",
                         (state, note, str(path)))
            if inventory:
                backups.remember(conn, str(path), backups.hash_file(path))
            conn.commit()

    def state(self, path, case=None):
        with closing(db.connect(case or self.case)) as conn:
            return db.one(conn, "SELECT triage,triage_note FROM findings WHERE artifact=?",
                          (str(path),))

    def test_every_backup_operation_requires_authentication(self):
        routes = [
            ("GET", "/backups", None),
            ("GET", "/backups/compare?site_id=1", None),
            ("GET", "/backups/history?site_id=1&path=example.txt", None),
            ("GET", "/backups/artifact?artifact=example.txt", None),
            ("GET", "/backups/diff?left=1&right=2&path=example.txt", None),
            ("POST", "/backups/sites", {"label": "Example"}),
            ("PATCH", "/backups/sites/1", {"label": "Example"}),
            ("POST", "/backups/snapshots", {"site_id": 1, "evidence_id": 1, "label": "Copy"}),
            ("PATCH", "/backups/snapshots/1", {"site_id": 1, "evidence_id": 1, "label": "Copy"}),
            ("POST", "/backups/prepare", {}),
            ("POST", "/backups/preview-root", {"evidence_id": 1, "root": str(self.root)}),
            ("POST", "/backups/findings", {"snapshot_id": 1, "path": "example.txt"}),
            ("POST", "/log-sources/preview", {"path": str(self.root), "timezone": "UTC"}),
        ]
        for method, suffix, body in routes:
            with self.subTest(method=method, route=suffix):
                status, result = self.request(method, self.prefix + suffix, body, token=False)
                self.assertEqual(401, status, result)
        self.assertEqual(401, self.request("GET", "/api/timezones", token=False)[0])
        self.assertEqual([], self.jobs())

    def test_unknown_case_does_not_return_an_empty_comparison_or_schedule_work(self):
        routes = [
            ("GET", "/backups", None),
            ("GET", "/backups/history?site_id=1&path=example.txt", None),
            ("GET", "/backups/compare?site_id=1", None),
            ("GET", "/backups/diff?left=1&right=2&path=example.txt", None),
            ("GET", "/backups/artifact?artifact=example.txt", None),
            ("POST", "/backups/sites", {"label": "Example"}),
            ("POST", "/backups/prepare", {}),
            ("POST", "/backups/preview-root", {"evidence_id": 1, "root": str(self.root)}),
            ("POST", "/backups/findings", {"snapshot_id": 1, "path": "example.txt"}),
        ]
        for method, suffix, body in routes:
            with self.subTest(route=suffix):
                self.assertEqual(404, self.request(method, "/api/cases/no-such-case" + suffix, body)[0])
        self.assertEqual([], self.jobs())

    def test_named_zone_catalogue_preview_and_webroot_choice_round_trip(self):
        status, catalogue = self.request("GET", "/api/timezones")
        self.assertEqual(200, status)
        self.assertIn("Europe/Berlin", catalogue["zones"])
        log = self.root / "diagnostic.log"
        log.write_text("2026/07/10 12:00:00 [error] 123#123: Ordinary diagnostic\n", encoding="utf-8")
        result = self.ok("POST", "/log-sources/preview", {"path": str(log), "timezone": "Europe/Berlin"})
        self.assertEqual("2026-07-10T10:00:00+00:00", result["sources"][0]["time_examples"][0]["utc"])
        unknown = self.ok("POST", "/log-sources/preview", {"path": str(log), "timezone": "unknown"})
        self.assertIsNone(unknown["sources"][0]["time_examples"][0]["epoch"])
        status, _ = self.request("POST", self.prefix + "/log-sources/preview", {"path": str(log), "timezone": "Invalid/Example"})
        self.assertEqual(400, status)
        root = self.root / "new imported webroot"
        root.mkdir()
        (root / "example.txt").write_text("Harmless text\n", encoding="utf-8")
        before = (root / "example.txt").stat().st_mtime_ns
        self.ok("POST", "/evidence", {"kind": "webroot", "path": str(root), "source_timezone": "Europe/Berlin"})
        with closing(db.connect(self.case)) as conn:
            zones = [row[0] for row in conn.execute("SELECT source_timezone FROM evidence WHERE path=?", (str(root),))]
        self.assertIn("Europe/Berlin", zones)
        self.assertEqual(before, (root / "example.txt").stat().st_mtime_ns)

    def test_snapshot_dates_keep_explicit_offsets_and_ambiguous_dates_unknown(self):
        site = self.site("Europe/Berlin")
        cases = [
            ("2026-07-10T12:00:00", "auto", datetime(2026, 7, 10, 10, tzinfo=timezone.utc).timestamp()),
            ("2026-07-10T12:00:00+03:00", "Europe/Berlin", datetime(2026, 7, 10, 9, tzinfo=timezone.utc).timestamp()),
            ("2026-10-25T02:30:00", "Europe/Berlin", None),
            ("2026-07-10T12:00:00", "unknown", None),
        ]
        expected = {}
        for date, zone, epoch in cases:
            evidence, root = self.root_source()
            sid = self.snapshot(site, evidence, root, captured_at=date, timezone=zone)
            expected[sid] = (date, epoch)
        for item in self.ok("GET", "/backups")["snapshots"]:
            self.assertEqual(expected[item["id"]], (item["captured_at"], item["captured_epoch"]))
        evidence, root = self.root_source()
        status, _ = self.request("POST", self.prefix + "/backups/snapshots", {
            "site_id": site, "evidence_id": evidence, "root": str(root),
            "label": "Malformed date", "captured_at": "not a recorded date"})
        self.assertEqual(400, status)

    def test_roots_are_fenced_and_preview_contains_bounded_relative_paths(self):
        site = self.site()
        evidence, root = self.root_source(files={f"nested/file-{n}.txt": "Example\n" for n in range(8)})
        preview = self.ok("POST", "/backups/preview-root", {"evidence_id": evidence, "root": str(root)})
        self.assertEqual(5, len(preview["paths"]))
        self.assertTrue(preview["more"])
        self.assertTrue(all(path.startswith("nested/") for path in preview["paths"]))
        self.snapshot(site, evidence, root)
        for bad_root in (self.root, root / "nested", root / "missing"):
            status, _ = self.request("POST", self.prefix + "/backups/snapshots", {
                "site_id": site, "evidence_id": evidence, "root": str(bad_root), "label": "Invalid root"})
            self.assertEqual(400, status, str(bad_root))
        status, _ = self.request("POST", self.prefix + "/backups/preview-root", {"evidence_id": evidence, "root": str(self.root)})
        self.assertEqual(400, status)
        self.assertEqual(1, len(self.ok("GET", "/backups")["snapshots"]))

    def test_prepare_rejects_ids_outside_this_case_without_creating_jobs(self):
        for ids in ([99999], [-1], [0]):
            status, result = self.request("POST", self.prefix + "/backups/prepare", {"snapshot_ids": ids})
            self.assertEqual(400, status, result)
        self.assertEqual([], self.jobs())
        other_prefix = f"/api/cases/{self.other.name}"
        site = self.site()
        evidence, root = self.root_source()
        snapshot = self.snapshot(site, evidence, root)
        self.assertEqual(400, self.request("POST", other_prefix + "/backups/prepare", {"snapshot_ids": [snapshot]})[0])
        self.assertEqual([], self.jobs(self.other))

    def test_busy_case_refuses_backup_mutations_but_other_case_remains_independent(self):
        release = threading.Event()
        started = threading.Event()
        def block(ctx):
            started.set()
            release.wait(10)
            return {}
        job = self.manager.submit(self.case, "test-blocker", block)
        try:
            self.assertTrue(started.wait(3))
            for suffix, body in (("/backups/sites", {"label": "Website"}), ("/backups/prepare", {})):
                self.assertEqual(409, self.request("POST", self.prefix + suffix, body)[0])
            self.assertEqual(200, self.request("POST", f"/api/cases/{self.other.name}/backups/sites", {"label": "Other website"})[0])
        finally:
            release.set()
        self.wait(job)

    def test_prepare_diff_and_manual_selection_recheck_evidence_and_preserve_triage(self):
        site = self.site()
        evidence, first = self.root_source(files={"nested/item.txt": "Earlier ordinary text\n"})
        left = self.snapshot(site, evidence, first)
        evidence, second = self.root_source(files={"nested/item.txt": "Later ordinary text\n"})
        right = self.snapshot(site, evidence, second)
        job = self.ok("POST", "/backups/prepare", {"snapshot_ids": [left, right]})["job"]
        self.assertEqual(0, self.wait(job)["failed_sources"])
        history = self.ok("GET", f"/backups/history?site_id={site}&path=nested%2Fitem.txt")
        self.assertEqual(2, len(history["entries"]))
        diff = self.ok("GET", f"/backups/diff?left={left}&right={right}&path=nested%2Fitem.txt")
        self.assertIn("-Earlier ordinary text", diff["lines"])
        body = {"snapshot_id": right, "path": "nested/item.txt", "note": "Check this recorded change"}
        self.ok("POST", "/backups/findings", body)
        self.finding(second / "nested/item.txt", state="dismissed", note="Independent decision")
        self.ok("POST", "/backups/findings", body)
        self.assertEqual("dismissed", self.state(second / "nested/item.txt")["triage"])
        with closing(db.connect(self.case)) as conn:
            self.assertEqual(1, conn.execute("SELECT COUNT(*) FROM findings WHERE rule_id='analyst.backup_observation'").fetchone()[0])
        (second / "nested/item.txt").write_text("Changed after indexing\n", encoding="utf-8")
        self.assertEqual(400, self.request("POST", self.prefix + "/backups/findings", body)[0])
        self.assertEqual(400, self.request("GET", self.prefix + f"/backups/diff?left={left}&right={right}&path=nested%2Fitem.txt")[0])

    def test_shared_confirmation_discovers_renamed_copies_only_inside_this_case(self):
        _, first = self.root_source(files={"original.txt": "Shared harmless content\n"})
        _, second = self.root_source(files={"renamed.txt": "Shared harmless content\n", "different.txt": "Different\n"})
        _, foreign = self.root_source(case=self.other, files={"foreign.txt": "Shared harmless content\n"})
        source, copy, outside = first / "original.txt", second / "renamed.txt", foreign / "foreign.txt"
        self.finding(source)
        self.finding(outside, case=self.other)
        response = self.ok("POST", "/triage", {"artifacts": [str(source)], "state": "confirmed",
                                                "note": "Explicit shared content decision", "classifications": ["malware"],
                                                "share_content": True, "propagate": False})
        completed = self.wait(response["content_assessment"]["job"])
        self.assertIn(str(copy), completed["content_assessment"]["applied"])
        self.assertEqual("confirmed", self.state(copy)["triage"])
        self.assertIsNone(self.state(second / "different.txt"))
        self.assertEqual("new", self.state(outside, self.other)["triage"])
        with closing(db.connect(self.case)) as conn:
            inherited = db.one(conn, "SELECT * FROM content_inheritance WHERE artifact=?", (str(copy),))
            self.assertEqual(str(source), inherited["origin"])
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM findings WHERE artifact_kind='client'").fetchone()[0])
        with closing(db.connect(self.other)) as conn:
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM content_assessments").fetchone()[0])

    def test_shared_benign_decision_preserves_conflicting_independent_review(self):
        paths = []
        for state, note in (("new", "Source note"), ("reviewed", "Preserve copy note"), ("confirmed", "Independent confirmation")):
            _, root = self.root_source()
            path = root / "example.txt"
            paths.append(path)
            self.finding(path, state=state, note=note, inventory=True)
        response = self.ok("POST", "/triage", {"artifacts": [str(paths[0])], "state": "dismissed",
                                                "note": "Content is benign", "share_content": True})
        completed = self.wait(response["content_assessment"]["job"])
        self.assertIn(str(paths[1]), completed["content_assessment"]["applied"])
        self.assertIn(str(paths[2]), completed["content_assessment"]["conflicts"])
        self.assertEqual({"triage": "dismissed", "triage_note": "Preserve copy note"}, self.state(paths[1]))
        self.assertEqual("confirmed", self.state(paths[2])["triage"])
        with closing(db.connect(self.case)) as conn:
            inherited = db.one(conn, "SELECT origin FROM content_inheritance WHERE artifact=?", (str(paths[1]),))
            self.assertEqual(str(paths[0]), inherited["origin"])
            self.assertIsNone(db.one(conn, "SELECT origin FROM content_inheritance WHERE artifact=?", (str(paths[2]),)))

    def test_occurrence_only_decision_does_not_become_a_shared_assessment(self):
        _, first = self.root_source()
        _, second = self.root_source()
        source, copy = first / "example.txt", second / "example.txt"
        self.finding(source, inventory=True)
        self.finding(copy, inventory=True)
        response = self.ok("POST", "/triage", {"artifacts": [str(source)], "state": "dismissed",
                                                "share_content": False})
        self.assertEqual("new", self.state(copy)["triage"])
        self.assertNotIn("job", response["content_assessment"])
        with closing(db.connect(self.case)) as conn:
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM content_assessments").fetchone()[0])

    def test_manual_file_review_shares_verified_content_without_confirming_requests(self):
        _, first = self.root_source()
        _, second = self.root_source()
        source, copy = first / "example.txt", second / "example.txt"
        response = self.ok("POST", "/files/review", {
            "path": str(source), "state": "confirmed", "classification": "malware",
            "note": "Harmless synthetic content assessment", "share_content": True,
        })
        self.wait(response["content_assessment"]["job"])
        self.assertEqual("confirmed", self.state(source)["triage"])
        self.assertEqual("confirmed", self.state(copy)["triage"])
        with closing(db.connect(self.case)) as conn:
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM findings WHERE artifact_kind='client'").fetchone()[0])

    def test_changed_file_review_rolls_back_observation_and_content_assessment(self):
        _, root = self.root_source()
        source = root / "example.txt"
        self.finding(source, note="Keep the earlier observation")
        with closing(db.connect(self.case)) as conn:
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES ('webshell_hashes',?)",
                         (json.dumps({str(source): hashlib.sha256(source.read_bytes()).hexdigest()}),))
            conn.commit()
            before = db.rows(conn, "SELECT * FROM findings ORDER BY id")
        source.write_text("Different harmless content\n", encoding="utf-8")
        status, body = self.request("POST", self.prefix + "/files/review", {
            "path": str(source), "state": "confirmed", "classification": "malware",
            "share_content": True,
        })
        self.assertEqual(409, status, body)
        with closing(db.connect(self.case)) as conn:
            self.assertEqual(before, db.rows(conn, "SELECT * FROM findings ORDER BY id"))
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM content_assessments").fetchone()[0])
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM triage_events").fetchone()[0])
        self.assertEqual([], self.jobs())

    def test_explicit_benign_ioc_assessment_reaches_existing_identical_file(self):
        _, root = self.root_source()
        path = root / "example.txt"
        self.finding(path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        with closing(db.connect(self.case)) as conn:
            ioc_id = db.add_ioc(conn, digest, "hash", origin="Harmless test hash")
            conn.commit()
        self.ok("POST", f"/iocs/{ioc_id}/assessments", {"state": "benign", "reason": "Analyst verified this content"})
        jobs = self.jobs()
        self.assertEqual(1, len(jobs))
        self.wait(jobs[0]["id"])
        self.assertEqual("dismissed", self.state(path)["triage"])

    def test_ioc_assessment_waits_for_running_work_and_inventories_its_completed_output(self):
        _, root = self.root_source()
        path = root / "example.txt"
        self.finding(path)
        copy = root / "created by the running job.txt"
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        with closing(db.connect(self.case)) as conn:
            ioc_id = db.add_ioc(conn, digest, "hash", origin="Harmless test hash")
            conn.commit()
        release, started = threading.Event(), threading.Event()
        def preparing(ctx):
            started.set()
            release.wait(10)
            copy.write_bytes(path.read_bytes())
            return {}
        blocker = self.manager.submit(self.case, "test-source-preparation", preparing)
        try:
            self.assertTrue(started.wait(3))
            self.ok("POST", f"/iocs/{ioc_id}/assessments", {"state": "malicious", "reason": "Explicit content assessment"})
            jobs = self.jobs()
            deferred = [job for job in jobs if job["kind"] == "backup_comparison"]
            self.assertEqual(1, len(deferred))
            self.assertIn(deferred[0]["state"], ("queued", "running"))
            self.assertEqual("new", self.state(path)["triage"])
            self.assertFalse(copy.exists())
        finally:
            release.set()
        self.wait(blocker)
        result = self.wait(deferred[0]["id"])
        self.assertEqual("confirmed", self.state(path)["triage"])
        self.assertEqual("confirmed", self.state(copy)["triage"])
        self.assertIn(str(copy), result["content_assessment"]["applied"])


if __name__ == "__main__":
    unittest.main()
