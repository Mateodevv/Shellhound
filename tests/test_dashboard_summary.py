"""Dashboard software and artifact previews from harmless stored observations."""
import json
import tempfile
import unittest
from pathlib import Path

from server import db, ruleswitch, workspace
from server.app import create_app
from server.config import Config
from tests.test_scan_retry_api import LocalClient


class DashboardSummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dashboard summary ")
        self.config = Config(workspace=Path(self.temp.name) / "cases", token="synthetic-test")
        self.case = workspace.create_case(self.config.workspace, "Synthetic overview")
        self.client = LocalClient(create_app(self.config), {"x-token": self.config.token})
        self.url = f"/api/cases/{self.case.name}"

    def tearDown(self):
        self.client.close()
        self.temp.cleanup()

    def get(self, suffix):
        response = self.client.get(self.url + suffix)
        self.assertEqual(200, response.status_code, response.text)
        return response.json()

    def seed_findings(self, observations):
        conn = db.connect(self.case)
        try:
            for item in observations:
                values = {"source": "webshell", "rule": "Harmless marker",
                          "artifact_kind": "file", "severity": 0, "triage": "new",
                          "engine": "synthetic", "seen_run": 0, "rule_id": "",
                          "created": db.now(), "last_seen": db.now(), **item}
                values.setdefault("fingerprint", values["artifact"] + values["rule"])
                columns = ",".join(values)
                marks = ",".join("?" for _ in values)
                conn.execute(f"INSERT INTO findings({columns}) VALUES ({marks})",
                             list(values.values()))
            conn.commit()
        finally:
            conn.close()

    def test_missing_inventory_does_not_invent_a_system(self):
        result = self.get("/dashboard")
        self.assertEqual({"installations": [], "databases": []}, result["system_summary"])
        self.assertEqual([], result["notable_artifacts"])
        self.assertEqual({}, result["triage"])
        self.assertEqual({"groups": [], "total_groups": 0, "informational": 0,
                          "hidden": 0}, result["top_findings"])

    def test_top_groups_count_the_whole_case_and_open_before_pagination(self):
        self.seed_findings([
            {"artifact": f"site alpha/item-{i:04}.txt"} for i in range(2005)
        ] + [
            {"artifact": "site alpha/item-0000.txt", "source": "yara",
             "rule": "Supporting harmless marker", "severity": 2},
            {"artifact": "example_table", "artifact_kind": "table", "source": "sqldb",
             "severity": 2, "triage": "confirmed"},
            {"artifact": "example_content", "artifact_kind": "table", "source": "sqldb",
             "rule": "document.write marker", "severity": 1, "triage": "confirmed"},
            {"artifact": "custom-note.txt", "source": "yara"},
            {"artifact": "dismissed-note.txt", "triage": "dismissed"},
        ])
        overview = self.get("/dashboard")["top_findings"]
        self.assertEqual(4, overview["total_groups"])
        self.assertEqual(["db_markup", "db_injected", "webshell"],
                         [group["category"] for group in overview["groups"]])
        webshell = overview["groups"][2]
        self.assertEqual((0, 2005, {"file": 2005}),
                         (webshell["confirmed"], webshell["awaiting_review"], webshell["kinds"]))
        self.assertEqual("site alpha/item-0000.txt", webshell["example"]["artifact"])
        page = self.get("/findings?category=webshell&hide_triage=dismissed&limit=2&offset=2003")
        self.assertEqual(2005, page["total"])
        self.assertEqual(["site alpha/item-2003.txt", "site alpha/item-2004.txt"],
                         [row["artifact"] for row in page["artifacts"]])
        self.assertTrue(all(row["category"] == "webshell" for row in page["artifacts"]))
        first = self.get("/findings?category=webshell&hide_triage=dismissed&limit=1")
        self.assertEqual(2, len(first["findings"]))  # Supporting evidence still travels.
        self.assertEqual(0, self.get("/findings?category=not-a-category")["total"])
        other = workspace.create_case(self.config.workspace, "Separate synthetic case")
        separate = self.client.get(f"/api/cases/{other.name}/dashboard").json()
        self.assertEqual([], separate["top_findings"]["groups"])

    def test_top_groups_mix_decisions_without_counting_detections_twice(self):
        self.seed_findings([
            {"artifact": "confirmed.txt", "triage": "confirmed", "severity": 2},
            {"artifact": "confirmed.txt", "rule": "Supporting note", "severity": 0},
            {"artifact": "reviewed.txt", "triage": "reviewed"},
            {"artifact": "new.txt"},
            {"artifact": "database_table", "artifact_kind": "table", "source": "sqldb"},
            {"artifact": "custom.txt", "source": "yara"},
            {"artifact": "obfuscated.txt", "rule": "Obfuscation decode chain marker"},
        ])
        groups = self.get("/dashboard")["top_findings"]["groups"]
        self.assertEqual(["webshell", "obfuscation", "yara"], [g["category"] for g in groups])
        self.assertEqual((1, 2, {"file": 3}),
                         (groups[0]["confirmed"], groups[0]["awaiting_review"], groups[0]["kinds"]))
        self.assertEqual("confirmed.txt", groups[0]["example"]["artifact"])
        conn = db.connect(self.case)
        try:
            conn.execute("UPDATE findings SET triage='dismissed' WHERE artifact='confirmed.txt'")
            conn.commit()
        finally:
            conn.close()
        changed = self.get("/dashboard")["top_findings"]["groups"][0]
        self.assertEqual((0, 2), (changed["confirmed"], changed["awaiting_review"]))

    def test_hidden_informational_and_historical_decisions_stay_distinct(self):
        self.seed_findings([
            {"artifact": "historic.txt", "triage": "confirmed", "engine": "old-synthetic"},
            {"artifact": "historic-reviewed.txt", "triage": "reviewed", "engine": "old-synthetic"},
            {"artifact": "historic-undecided.txt", "engine": "old-synthetic"},
            {"artifact": "muted.txt", "rule_id": "synthetic.muted"},
            {"artifact": "muted-confirmed.txt", "triage": "confirmed", "rule_id": "synthetic.muted"},
            {"artifact": "info-client", "artifact_kind": "client", "source": "logs",
             "rule": "Scanner tool User-Agent marker", "severity": 3},
            {"artifact": "confirmed-info.txt", "source": "yara", "severity": 3,
             "triage": "confirmed"},
            {"artifact": "dismissed.txt", "triage": "dismissed"},
        ])
        conn = db.connect(self.case)
        try:
            conn.execute("INSERT INTO meta(key,value) VALUES ('engine_done:old-synthetic','1')")
            conn.commit()
        finally:
            conn.close()
        ruleswitch.set_enabled(self.config.workspace, "synthetic.muted", False)
        top = self.get("/dashboard")["top_findings"]
        self.assertEqual((1, 2), (top["informational"], top["hidden"]))
        self.assertEqual(["webshell", "yara"], [g["category"] for g in top["groups"]])
        group = top["groups"][0]
        self.assertEqual((2, 1, 2), (group["confirmed"], group["awaiting_review"], group["historical"]))
        shown = self.get("/findings?category=webshell&hide_triage=dismissed")
        self.assertEqual({"historic.txt", "historic-reviewed.txt", "muted-confirmed.txt"},
                         {row["artifact"] for row in shown["artifacts"]})

    def test_primary_category_uses_current_observations_before_old_severity(self):
        self.seed_findings([
            {"artifact": "changed.txt", "source": "yara", "rule": "Old marker",
             "severity": 0, "engine": "old-synthetic"},
            {"artifact": "changed.txt", "rule": "Obfuscation decode chain marker", "severity": 1},
            {"artifact": "line-order.txt", "source": "yara", "line": 20},
            {"artifact": "line-order.txt", "rule": "Other note", "line": 10},
        ])
        conn = db.connect(self.case)
        try:
            conn.execute("INSERT INTO meta(key,value) VALUES ('engine_done:old-synthetic','1')")
            conn.commit()
        finally:
            conn.close()
        rows = self.get("/findings")["artifacts"]
        self.assertEqual({"changed.txt": "obfuscation", "line-order.txt": "webshell"},
                         {row["artifact"]: row["category"] for row in rows})
        top = self.get("/dashboard")["top_findings"]["groups"]
        self.assertEqual(["webshell", "obfuscation"], [g["category"] for g in top])
        self.assertTrue(all(g["historical"] == 0 for g in top))

    def test_software_keeps_separate_sources_and_effective_versions(self):
        conn = db.connect(self.case)
        try:
            conn.executemany(
                "INSERT INTO cms_installs(id,root,cms,version,version_source) VALUES (?,?,?,?,?)", [
                    (1, "site alpha", "wordpress", "6.0", "site alpha/version.txt"),
                    (2, "site beta", "joomla", "", ""),
                ])
            conn.executemany(
                "INSERT INTO cms_items(id,install_id,type,name,slug,version) VALUES (?,?,?,?,?,?)", [
                    (1, 1, "plugin", "Gallery", "gallery", "1.0"),
                    (2, 1, "plugin", "Forms", "forms", ""),
                    (3, 1, "theme", "Simple", "simple", "2.0"),
                    (4, 2, "component", "Calendar", "calendar", ""),
                ])
            conn.executemany(
                "INSERT INTO cms_version_overrides(scope,key,version,note,set_at) VALUES (?,?,?,?,?)", [
                    ("install", "site alpha", "6.1", "Analyst verified", db.now()),
                    ("item", "site alpha|plugin|gallery", "1.1", "Analyst verified", db.now()),
                ])
            conn.executemany("INSERT INTO db_dumps(id,path,meta,kind) VALUES (?,?,?,?)", [
                (1, "alpha export.sql", json.dumps({"server": "8.0.30", "database": "example"}), "export"),
                (2, "beta export.sql", "{}", "export"),
                (3, "install schema.sql", json.dumps({"server": "not an export"}), "schema"),
            ])
            conn.commit()
        finally:
            conn.close()

        result = self.get("/dashboard")
        summary = result["system_summary"]
        first, second = summary["installations"]
        self.assertEqual(("6.1", "6.0", "6.1"),
                         (first["version"], first["version_parsed"], first["version_set"]))
        self.assertEqual("site alpha/version.txt", first["version_source"])
        self.assertEqual({"plugin": 2, "theme": 1}, first["extensions"])
        self.assertEqual("site beta", second["root"])
        self.assertEqual("", second["version"])
        self.assertEqual("", second["version_source"])
        self.assertEqual({"component": 1}, second["extensions"])
        self.assertEqual([
            {"id": 1, "path": "alpha export.sql", "server_version": "8.0.30"},
            {"id": 2, "path": "beta export.sql", "server_version": ""},
        ], summary["databases"])

        # The existing inventory endpoint uses the same correction policy,
        # including extension overrides, while the stored measurement stays intact.
        inventory = self.get("/cms")["installs"]
        for actual, compact in zip(inventory, summary["installations"]):
            for field in ("version", "version_parsed", "version_set", "version_source"):
                self.assertEqual(actual[field], compact[field])
        gallery = next(item for item in inventory[0]["items"] if item["slug"] == "gallery")
        self.assertEqual(("1.1", "1.0"), (gallery["version"], gallery["version_parsed"]))
        self.assertEqual("6.0", result["cms_installs"][0]["version"])

    def test_notable_preview_groups_artifacts_and_respects_current_decisions(self):
        observations = [
            ("confirmed.txt", "file", 2, "confirmed"),
            ("confirmed.txt", "file", 0, "new"),
            ("accepted.txt", "file", 0, "dismissed"),
            ("client-01", "client", 0, "reviewed"),
            ("table-01", "table", 0, "new"),
            ("export-01", "dump", 0, "new"),
            ("lower-priority.txt", "file", 2, "new"),
        ] + [(f"review-{index:02}.txt", "file", 0, "new") for index in range(8)]
        conn = db.connect(self.case)
        try:
            conn.executemany(
                "INSERT INTO findings(fingerprint,source,rule,artifact,artifact_kind,"
                "severity,triage,created,last_seen) VALUES (?,?,?,?,?,?,?,?,?)", [
                    (str(index), "synthetic", "Harmless observation", artifact, kind,
                     severity, triage, db.now(), db.now())
                    for index, (artifact, kind, severity, triage) in enumerate(observations)
                ])
            conn.commit()
        finally:
            conn.close()

        result = self.get("/dashboard")
        preview = result["notable_artifacts"]
        self.assertEqual(6, len(preview))
        self.assertEqual(6, len({row["artifact"] for row in preview}))
        self.assertEqual({"artifact": "confirmed.txt", "artifact_kind": "file",
                          "worst": 0, "triage": "confirmed"}, preview[0])
        self.assertEqual({"file", "table", "dump", "client"},
                         {row["artifact_kind"] for row in preview})
        self.assertNotIn("accepted.txt", {row["artifact"] for row in preview})
        self.assertNotIn("lower-priority.txt", {row["artifact"] for row in preview})
        self.assertEqual("reviewed", next(row for row in preview
                                          if row["artifact"] == "client-01")["triage"])

        conn = db.connect(self.case)
        try:
            conn.execute("UPDATE findings SET triage='dismissed' WHERE artifact='confirmed.txt'")
            conn.commit()
        finally:
            conn.close()
        self.assertNotIn("confirmed.txt", {row["artifact"] for row in self.get("/dashboard")["notable_artifacts"]})


if __name__ == "__main__":
    unittest.main()
