"""First-sign timestamps must belong to an alert's actual requests.

Harmless URI markers replace the detection expressions in these tests. The
classification path, response gates and chronological queries stay real.
"""
import re
import sqlite3
import unittest
from unittest.mock import patch

from server.engines import logindex


class FirstSignLogAnchorTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(logindex._LOG_SCHEMA)
        self.conn.execute("CREATE INDEX idx_req_ip ON requests(ip, epoch)")
        self.conn.executemany("INSERT INTO ips(id, ip) VALUES (?, ?)", [
            (1, "203.0.113.10"), (2, "203.0.113.20"),
        ])
        self.next_string = 0
        self.strings = {}
        self.addCleanup(self.conn.close)
        for name, marker in (
                ("SQLI_URI_RE", "/sample-sqli"),
                ("TRAVERSAL_URI_RE", "/sample-traversal"),
                ("UPLOAD_PHP_RE", "/sample-upload"),
                ("CMS_DIR_PHP_RE", "/sample-cms")):
            patched = patch.object(logindex, name, re.compile(marker))
            patched.start()
            self.addCleanup(patched.stop)

    def request(self, epoch, uri="/ordinary-page", status=200,
                method="GET", tz=0, ip=1):
        if uri not in self.strings:
            self.next_string += 1
            self.strings[uri] = self.next_string
            self.conn.execute("INSERT INTO strings(id, text) VALUES (?, ?)",
                              (self.next_string, uri))
        self.conn.execute(
            "INSERT INTO requests(ip, epoch, tz, method, uri, status) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ip, epoch, tz, method, self.strings[uri], status))

    def anchors(self, *kinds):
        return logindex._first_sign_alert_anchors(self.conn, 1, kinds)

    def test_response_gates_all_uris_and_timestamp_offset_stay_together(self):
        self.request(500, "/sample-sqli-a", tz=10800)
        self.request(10, "/sample-sqli-a", status=404, tz=7200)
        self.request(1, "/ordinary-page", tz=14400)
        self.request(100, "/sample-sqli-b", tz=-7200)
        self.request(50, "/sample-sqli-b", ip=2)
        self.assertEqual({"sqli": (100, -7200, "/sample-sqli-b")},
                         self.anchors("sqli"))

    def test_all_known_response_kinds_share_the_existing_classifier(self):
        kinds = {"sqli": "sqli", "traversal": "traversal",
                 "upload_php": "upload", "cms_dir_php": "cms"}
        for n, (kind, marker) in enumerate(kinds.items(), start=1):
            self.request(n, "/sample-" + marker, status=500)
            self.request(n + 100, "/sample-" + marker, status=299)
        self.assertEqual(
            {kind: (n + 100, 0, "/sample-" + kinds[kind])
             for n, kind in enumerate(kinds, start=1)},
            self.anchors(*kinds))

    def test_login_flood_ignores_ordinary_posts_and_gets_to_login_page(self):
        self.request(1, "/wp-login.php")
        self.request(2, "/ordinary-page", method="POST")
        self.request(400, "/wp-login.php", method="POST", tz=3600)
        self.request(100, "/wp-login.php", method="POST", status=403, tz=-3600)
        self.assertEqual({"login_flood": (100, -3600, "/wp-login.php")},
                         self.anchors("login_flood"))

    def test_login_success_anchor_is_first_attempt_in_qualifying_burst(self):
        self.request(1, "/wp-login.php", method="POST", tz=7200)
        start = logindex.BF_WINDOW + 100
        for i in reversed(range(logindex.BF_THRESHOLD)):
            self.request(start + i, "/wp-login.php", method="POST", status=403,
                         tz=-3600 if i == 0 else 10800)
        self.assertEqual({"login_success": (start, -3600, "/wp-login.php")},
                         self.anchors("login_success"))

    def test_login_burst_uses_existing_exclusive_window_boundary(self):
        self.request(100, "/wp-login.php", method="POST")
        for i in range(logindex.BF_THRESHOLD - 2):
            self.request(200 + i, "/wp-login.php", method="POST")
        self.request(100 + logindex.BF_WINDOW, "/wp-login.php", method="POST")
        self.assertEqual({"login_success": None}, self.anchors("login_success"))
        self.request(101 + logindex.BF_WINDOW, "/wp-login.php", method="POST")
        self.assertEqual({"login_success": (200, 0, "/wp-login.php")},
                         self.anchors("login_success"))

    def test_undated_unknown_or_unmatched_alerts_remain_undated(self):
        self.request(0, "/sample-sqli")
        self.request(1, "/sample-sqli", tz=None)
        self.request(2, "/sample-sqli", status=404)
        self.request(3)
        self.assertEqual({"sqli": None, "scanner_ua": None, "future_kind": None},
                         self.anchors("sqli", "scanner_ua", "future_kind"))

    def test_expired_budget_returns_no_invented_anchor(self):
        self.request(100, "/sample-sqli")
        self.assertEqual({"sqli": None}, logindex._first_sign_alert_anchors(
            self.conn, 1, ["sqli"], deadline=0))

    def test_partial_query_keeps_only_already_verified_anchors(self):
        self.request(100, "/sample-sqli")
        self.request(200, "/sample-traversal")
        with patch.object(logindex.time, "monotonic", side_effect=[0, 0, 2]):
            result = logindex._first_sign_alert_anchors(
                self.conn, 1, ["sqli", "traversal"], deadline=1)
        self.assertEqual({"sqli": (100, 0, "/sample-sqli"), "traversal": None}, result)
        self.assertEqual(2, self.conn.execute(
            "SELECT count(*) FROM requests").fetchone()[0])

    def test_chain_facts_adds_verified_fields_without_reusing_example_time(self):
        self.request(10, "/sample-sqli-example", status=404, tz=7200)
        self.request(200, "/sample-sqli-other", tz=-3600)
        self.conn.execute(
            "INSERT INTO actors(ip_id, ip, requests, first_epoch, last_epoch, tz) "
            "VALUES (1, '203.0.113.10', 2, 10, 200, 7200)")
        self.conn.execute(
            "INSERT INTO alerts(ip_id, kind, severity, detail, example) "
            "VALUES (1, 'sqli', 1, 'Synthetic observation', '/sample-sqli-example')")
        with patch.object(logindex, "_open_ro", return_value=self.conn):
            result = logindex.chain_facts(None, ips=["203.0.113.10"])
        alert = result["clients"]["203.0.113.10"]["alerts"][0]
        self.assertEqual(10, alert["epoch"], "Legacy chronology field is preserved")
        self.assertEqual(200, alert["first_sign_epoch"])
        self.assertEqual(-3600, alert["first_sign_tz"])
        self.assertEqual("/sample-sqli-other", alert["first_sign_example"])


if __name__ == "__main__":
    unittest.main()
