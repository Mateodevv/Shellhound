# tests/test_engines.py
"""Do the engines still find what is demonstrably there?

This is the end-to-end test of the project: real files go in, the normal
engines run over them, and the assertions are about what came out. It
replaces the demo case that used to serve this purpose -- same coverage,
but as developer infrastructure rather than a user-facing feature.

Assertions are LOWER BOUNDS wherever the exact count is not the point. A
new rule that fires additionally must not turn the suite red; a rule that
stops firing must.
"""
import unittest

from server import db
from server.engines import cmsinventory, logindex, sqldump, webshell
from tests.fixtures import ATTACKER, BRUTE, Evidence, register


class EngineTests(unittest.TestCase):
    """One fixture for the whole class: building it is the slow part, and
    the engines only read from it."""

    @classmethod
    def setUpClass(cls):
        cls.ev = Evidence().build()
        conn = db.connect(cls.ev.case_dir)
        register(conn, cls.ev)
        conn.close()
        cls.webshell_stats = webshell.scan(cls.ev.case_dir, [str(cls.ev.webroot)])
        cls.cms_stats = cmsinventory.scan(cls.ev.case_dir, [str(cls.ev.webroot)])
        cls.sql_stats = sqldump.scan(cls.ev.case_dir, [str(cls.ev.dump)])
        cls.log_stats = logindex.build(cls.ev.case_dir, [str(cls.ev.logs)])

    @classmethod
    def tearDownClass(cls):
        cls.ev.cleanup()

    def findings(self, source=None):
        conn = db.connect(self.ev.case_dir)
        try:
            if source:
                return db.rows(conn, "SELECT * FROM findings WHERE source = ?",
                               (source,))
            return db.rows(conn, "SELECT * FROM findings")
        finally:
            conn.close()

    def assert_rule_fired(self, needle, source=None):
        rules = [f["rule"] for f in self.findings(source)]
        self.assertTrue(any(needle in r for r in rules),
                        f"no rule matching {needle!r}; got: {sorted(set(rules))}")

    # --- webshell scan ------------------------------------------------------

    def test_unguarded_upload_php_is_flagged(self):
        self.assert_rule_fired("Unguarded PHP in writable upload", "webshell")

    def test_double_extension_is_flagged(self):
        self.assert_rule_fired("Double extension", "webshell")

    def test_php_inside_image_is_flagged(self):
        self.assert_rule_fired("PHP code hidden inside image", "webshell")

    def test_decode_chain_is_flagged(self):
        self.assert_rule_fired("Obfuscation decode chain", "webshell")

    def test_file_dropper_is_flagged(self):
        self.assert_rule_fired("File dropper", "webshell")

    def test_htaccess_handler_is_flagged(self):
        self.assert_rule_fired(".htaccess", "webshell")

    def test_genuine_cms_file_is_not_flagged(self):
        """The false-positive guard: a real CMS file with its bootstrap
        guard, sitting where it belongs, must stay clean. Without this the
        suite would happily pass a scanner that flags everything."""
        flagged = {f["artifact"].replace("\\", "/")
                   for f in self.findings("webshell")}
        offenders = [p for p in flagged if p.endswith("wp-includes/functions.php")]
        self.assertEqual(offenders, [], "a genuine CMS file was flagged")

    def test_hashes_recorded_for_flagged_files(self):
        conn = db.connect(self.ev.case_dir)
        try:
            row = db.one(conn, "SELECT value FROM meta WHERE key = 'webshell_hashes'")
        finally:
            conn.close()
        self.assertIsNotNone(row, "no hashes stored for flagged files")

    def test_a_clean_rescan_clears_the_hashes(self):
        """The hash map is a measurement of the LAST run.

        Keeping the previous one when a re-scan flags nothing would hand a
        confirmation the digest of a file that is no longer there -- a hash
        in the IOC box that nothing measured. Runs against an empty webroot
        so the class fixture stays untouched."""
        import json
        import tempfile
        from pathlib import Path

        case = Path(tempfile.mkdtemp(prefix="shellhound-rescan-"))
        empty = Path(tempfile.mkdtemp(prefix="shellhound-empty-"))
        conn = db.connect(case)
        try:
            conn.execute("INSERT OR REPLACE INTO meta VALUES "
                         "('webshell_hashes', ?)",
                         (json.dumps({"C:/gone/shell.php": "deadbeef"}),))
            conn.commit()
        finally:
            conn.close()

        webshell.scan(case, [str(empty)])

        conn = db.connect(case)
        try:
            row = db.one(conn, "SELECT value FROM meta "
                               "WHERE key = 'webshell_hashes'")
        finally:
            conn.close()
        self.assertEqual({}, json.loads(row["value"]),
                         "a scan that flagged nothing kept the old hashes")

    # --- CMS inventory ------------------------------------------------------

    def test_wordpress_detected_with_version(self):
        conn = db.connect(self.ev.case_dir)
        try:
            installs = db.rows(conn, "SELECT * FROM cms_installs")
        finally:
            conn.close()
        self.assertTrue(installs, "no CMS installation detected")
        self.assertTrue(any(i["version"] == "6.4.2" for i in installs),
                        f"version not read; got {[i['version'] for i in installs]}")
        self.assertTrue(all(i["version_source"] for i in installs if i["version"]),
                        "a version without the file it was read from is not "
                        "checkable and must not be reported")

    # --- SQL dump -----------------------------------------------------------

    def test_injected_iframe_is_flagged(self):
        self.assert_rule_fired("iframe", "sqldb")

    def test_accounts_are_inventoried(self):
        conn = db.connect(self.ev.case_dir)
        try:
            accounts = db.rows(conn, "SELECT * FROM db_accounts")
        finally:
            conn.close()
        logins = {a["login"] for a in accounts}
        self.assertIn("s.keller", logins)
        self.assertIn("support-tmp", logins)

    def test_admin_flag_and_weak_hash_recognised(self):
        conn = db.connect(self.ev.case_dir)
        try:
            acc = db.one(conn, "SELECT * FROM db_accounts WHERE login = 'support-tmp'")
        finally:
            conn.close()
        self.assertIsNotNone(acc, "the planted account is missing")
        self.assertEqual(acc["admin"], 1, "administrator not recognised")
        self.assertIn("weak", acc["hash_type"],
                      f"MD5 not recognised as weak; got {acc['hash_type']!r}")

    def test_dump_classified_as_export(self):
        conn = db.connect(self.ev.case_dir)
        try:
            dumps = db.rows(conn, "SELECT * FROM db_dumps")
        finally:
            conn.close()
        self.assertTrue(dumps)
        self.assertTrue(any(d["kind"] == "export" for d in dumps),
                        "a real mysqldump was not classified as an export")

    # --- log index ----------------------------------------------------------

    def test_log_index_built(self):
        overview = logindex.overview(self.ev.case_dir)
        self.assertIsNotNone(overview, "no log index")
        self.assertGreater(overview["lines"], 50)
        self.assertGreater(overview["clients"], 2)

    def test_shell_access_alert(self):
        self.assert_rule_fired("upload/cache directory", "logs")

    def test_bruteforce_alert(self):
        rules = " ".join(f["rule"] for f in self.findings("logs"))
        self.assertTrue("brute-force" in rules or "login POST flood" in rules,
                        f"no brute-force signal; got {rules!r}")

    def test_sqli_and_traversal_alerts(self):
        self.assert_rule_fired("SQL injection", "logs")
        self.assert_rule_fired("Path traversal", "logs")

    def test_scanner_is_info_not_an_alert(self):
        """A scanner sighting happens to every host on the internet. It is
        recorded, but at INFO -- otherwise real work drowns in it."""
        scanner = [f for f in self.findings("logs")
                   if "Scanner tool User-Agent" in f["rule"]]
        self.assertTrue(scanner, "scanner sighting not recorded at all")
        for f in scanner:
            self.assertEqual(f["severity"], db.SEV_INFO,
                             "a scanner sighting must not outrank real findings")

    def test_trace_finds_the_attacker(self):
        result = logindex.trace(self.ev.case_dir, [ATTACKER])
        self.assertGreater(result["total"], 5)
        self.assertTrue(all(r["client"] == ATTACKER for r in result["rows"]))

    def test_actors_carry_behaviour(self):
        actors = logindex.actors_by_ip(self.ev.case_dir, [BRUTE, ATTACKER])
        self.assertIn(BRUTE, actors)
        self.assertGreaterEqual(actors[BRUTE]["login_posts"], 30,
                                "login flood not counted")
        self.assertGreater(actors[ATTACKER]["upload_php_ok"], 0,
                           "successful shell access not counted")

    def test_pattern_hunt_matches(self):
        match = logindex.match_pattern(self.ev.case_dir, "/uploads/*.php")
        self.assertGreater(match["hits"], 0, "pattern found nothing")
        self.assertGreater(match["ok_clients"], 0,
                           "no client recorded as successful")
        self.assertTrue(any(c["ip"] == ATTACKER for c in match["clients"]))


if __name__ == "__main__":
    unittest.main()
