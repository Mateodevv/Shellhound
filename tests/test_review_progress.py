"""Review progress over harmless stored findings, using the real HTTP API."""
import tempfile
import unittest
from pathlib import Path

from server import db, ruleswitch, workspace
from server.app import create_app
from server.config import Config
from tests.test_scan_retry_api import LocalClient


class ReviewProgressTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="review progress ")
        self.config = Config(workspace=Path(self.temp.name), token="synthetic-test")
        self.case = workspace.create_case(self.config.workspace, "Synthetic review")
        self.client = LocalClient(create_app(self.config), {"x-token": self.config.token})
        self.url = f"/api/cases/{self.case.name}"

    def tearDown(self):
        self.client.close()
        self.temp.cleanup()

    def seed(self, items):
        conn = db.connect(self.case)
        try:
            for index, item in enumerate(items):
                values = {"fingerprint": str(index), "artifact": "sample.txt",
                          "artifact_kind": "file", "source": "webshell",
                          "rule": "Harmless marker", "severity": 1,
                          "triage": "new", "engine": "synthetic",
                          "created": db.now(), "last_seen": db.now(), **item}
                conn.execute(
                    f"INSERT INTO findings({','.join(values)}) "
                    f"VALUES ({','.join('?' for _ in values)})", list(values.values()))
            conn.commit()
        finally:
            conn.close()

    def progress(self):
        result = self.client.get(self.url + "/artifact?artifact=sample.txt")
        self.assertEqual(200, result.status_code, result.text)
        return result.json()["review_progress"]

    def test_counts_artifacts_once_and_keeps_skips_unfinished(self):
        self.seed([{}, {"triage": "confirmed"},
                   {"artifact": "dismissed.txt", "triage": "dismissed"},
                   {"artifact": "skip.txt", "triage": "reviewed"},
                   {"artifact": "new.txt"},
                   {"artifact": "info.txt", "severity": 3},
                   {"artifact": "muted.txt", "rule_id": "synthetic.muted"},
                   {"artifact": "historic.txt", "engine": "old"},
                   {"artifact": "historic-confirmed.txt", "engine": "old",
                    "triage": "confirmed"}])
        conn = db.connect(self.case)
        conn.execute("INSERT INTO meta(key,value) VALUES ('engine_done:old','1')")
        conn.commit()
        conn.close()
        ruleswitch.set_enabled(self.config.workspace, "synthetic.muted", False)
        self.assertEqual({"total": 5, "reviewed": 3, "remaining": 2, "skipped": 1},
                         self.progress())

    def test_saved_decisions_and_reopening_refresh_progress_without_changing_total(self):
        self.seed([{}, {"artifact": "second.txt", "triage": "dismissed"}])
        for state, done, skipped in [("new", 1, 0), ("reviewed", 1, 1),
                                     ("confirmed", 2, 0), ("dismissed", 2, 0),
                                     ("new", 1, 0)]:
            with self.subTest(state=state):
                result = self.client.post(self.url + "/triage", json={
                    "artifacts": ["sample.txt"], "state": state, "propagate": False})
                self.assertEqual(200, result.status_code, result.text)
                self.assertEqual({"total": 2, "reviewed": done,
                                  "remaining": 2 - done, "skipped": skipped}, self.progress())

    def test_progress_covers_the_case_beyond_list_limits_and_filters(self):
        self.seed([{}] + [{"artifact": f"item-{i}.txt", "triage": "dismissed"}
                         for i in range(2004)])
        listed = self.client.get(self.url + "/findings?hide_triage=dismissed&limit=1").json()
        self.assertEqual(1, len(listed["artifacts"]))
        self.assertEqual({"total": 2005, "reviewed": 2004, "remaining": 1, "skipped": 0},
                         self.progress())
        other = workspace.create_case(self.config.workspace, "Separate case")
        conn = db.connect(other)
        conn.execute("INSERT INTO findings(fingerprint,artifact,artifact_kind,source,rule,severity,created,last_seen) "
                     "VALUES ('other','sample.txt','file','webshell','Harmless marker',1,?,?)",
                     (db.now(), db.now()))
        conn.commit()
        conn.close()
        result = self.client.get(f"/api/cases/{other.name}/artifact?artifact=sample.txt").json()
        self.assertEqual({"total": 1, "reviewed": 0, "remaining": 1, "skipped": 0},
                         result["review_progress"])

    def test_informational_only_evidence_has_no_actionable_review_total(self):
        self.seed([{"severity": 3}])
        self.assertEqual({"total": 0, "reviewed": 0, "remaining": 0, "skipped": 0},
                         self.progress())
