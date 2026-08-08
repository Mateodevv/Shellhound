# tests/test_errorlog.py
"""The error log -- the file that names what the access log cannot see.

The interesting assertions here are the ones about restraint: a path that
does not sit under a registered webroot is NOT written (an error log mentions
every file on the server), and one file named four hundred times becomes one
finding with a count rather than four hundred rows.
"""
import shutil
import tempfile
import unittest
from pathlib import Path

from server import db
from server.engines import errorlog

APACHE = """[Fri Jun 26 05:19:59.123456 2026] [php:error] [pid 12] [client 203.0.113.5:41234] PHP Fatal error:  Uncaught Error: Call to undefined function x() in {root}/images/kb-media.php on line 12
[Fri Jun 26 05:20:01.000000 2026] [php:warn] [pid 12] [client 203.0.113.5:41235] PHP Warning:  file_get_contents(): failed in {root}/images/kb-media.php on line 30
[Fri Jun 26 06:00:00.000000 2026] [php:notice] [pid 13] PHP Notice:  Undefined index: q in {root}/index.php on line 4
[Fri Jun 26 06:01:00.000000 2026] [php:error] [pid 14] PHP Fatal error:  Uncaught Error in /etc/some/other/thing.php on line 9
[Fri Jun 26 06:02:00.000000 2026] [core:error] [pid 15] AH00124: Request exceeded the limit
"""

NGINX = """2026/06/30 11:52:26 [error] 1234#0: *5 FastCGI sent in stderr: "PHP message: PHP Parse error: syntax error in {root}/tmp/drop.php on line 1"
"""


class ParsingTests(unittest.TestCase):

    def test_both_log_shapes_are_recognised(self):
        apache = errorlog.parse_line(
            "[Fri Jun 26 05:19:59 2026] [php:error] [pid 1] [client 1.2.3.4:5] PHP Fatal error: x")
        self.assertIsNotNone(apache)
        self.assertEqual("1.2.3.4", apache["client"])
        nginx = errorlog.parse_line(
            '2026/06/30 11:52:26 [error] 1#0: PHP message: PHP Warning: y')
        self.assertIsNotNone(nginx)

    def test_the_client_survives_both_address_families(self):
        """Apache brackets an IPv6 client, and a group that stops at the
        first `]` hands back half an address."""
        for raw, want in (
                ("[client 1.2.3.4:41234]", "1.2.3.4"),
                ("[client [2001:db8::1]:41234]", "2001:db8::1"),
                ("[client 10.0.0.1]", "10.0.0.1")):
            line = f"[Fri Jun 26 05:19:59 2026] [php:error] [pid 1] {raw} PHP Fatal error: x"
            self.assertEqual(want, errorlog.parse_line(line)["client"], raw)

    def test_an_access_log_line_is_not_an_error_line(self):
        self.assertIsNone(errorlog.parse_line(
            '1.2.3.4 - - [26/Jun/2026:05:19:59 +0200] "GET / HTTP/1.1" 200 5 "-" "curl"'))

    def test_time_reads_the_same_way_as_the_rest_of_the_toolkit(self):
        """Otherwise an error-log time could not be compared with an
        access-log time, and the chronology would drift by a time zone."""
        from server.chain import stamp_to_local
        self.assertEqual(stamp_to_local("2026-06-26 05:19:59"),
                         errorlog.parse_time("Fri Jun 26 05:19:59 2026"))

    def test_junk_time_is_none_not_an_exception(self):
        self.assertIsNone(errorlog.parse_time("nonsense"))
        self.assertIsNone(errorlog.parse_time(""))

    def test_the_path_and_line_are_extracted(self):
        hits = errorlog.paths_in(
            "PHP Fatal error: Uncaught Error in /var/www/html/x.php on line 42")
        self.assertEqual([("/var/www/html/x.php", 42)], hits)

    def test_a_message_without_a_php_file_yields_nothing(self):
        self.assertEqual([], errorlog.paths_in("AH00124: Request exceeded"))
        self.assertEqual([], errorlog.paths_in("something in /var/log/x.log"))


class ScanTests(unittest.TestCase):

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix="shellhound-elcase-"))
        self.root = Path(tempfile.mkdtemp(prefix="shellhound-elroot-"))
        self.logs = Path(tempfile.mkdtemp(prefix="shellhound-ellogs-"))
        (self.root / "images").mkdir()
        (self.root / "tmp").mkdir()
        (self.root / "images" / "kb-media.php").write_text("<?php", encoding="utf-8")
        (self.root / "index.php").write_text("<?php", encoding="utf-8")
        (self.root / "tmp" / "drop.php").write_text("<?php", encoding="utf-8")
        posix_root = str(self.root).replace("\\", "/")
        (self.logs / "error.log").write_text(
            APACHE.replace("{root}", "/var/www/html"), encoding="utf-8")
        (self.logs / "error2.log").write_text(
            NGINX.replace("{root}", "/var/www/html"), encoding="utf-8")
        self.posix_root = posix_root
        conn = db.connect(self.case)
        try:
            conn.execute("INSERT INTO evidence (kind, path, added) VALUES "
                         "('webroot', ?, ?)", (str(self.root), db.now()))
            conn.commit()
        finally:
            conn.close()

    def _findings(self):
        conn = db.connect(self.case)
        try:
            return db.rows(conn,
                           "SELECT * FROM findings WHERE source = 'errorlog'")
        finally:
            conn.close()

    def test_a_named_file_becomes_a_finding_on_that_artifact(self):
        errorlog.scan(self.case, [str(self.logs)])
        names = {Path(f["artifact"]).name for f in self._findings()}
        self.assertIn("kb-media.php", names)
        self.assertIn("drop.php", names, "the nginx form was not read")
        for f in self._findings():
            self.assertEqual("file", f["artifact_kind"])

    def test_a_path_outside_the_evidence_is_not_written(self):
        """An error log mentions every file on the server. A case must not
        fill up with findings about paths nobody can open."""
        stats = errorlog.scan(self.case, [str(self.logs)])
        artifacts = {f["artifact"].replace("\\", "/") for f in self._findings()}
        self.assertFalse(any("/etc/some/other" in a for a in artifacts))
        self.assertGreater(stats["unresolved"], 0,
                           "the unresolvable path was not counted")

    def test_one_file_named_twice_is_one_finding_with_a_count(self):
        errorlog.scan(self.case, [str(self.logs)])
        hits = [f for f in self._findings()
                if Path(f["artifact"]).name == "kb-media.php"]
        self.assertEqual(1, len(hits), "one file produced several findings")
        self.assertIn("2×", hits[0]["evidence"])

    def test_a_fatal_weighs_more_than_a_notice(self):
        errorlog.scan(self.case, [str(self.logs)])
        by_name = {Path(f["artifact"]).name: f for f in self._findings()}
        self.assertEqual(db.SEV_MEDIUM, by_name["kb-media.php"]["severity"])
        self.assertEqual(db.SEV_LOW, by_name["index.php"]["severity"],
                         "a notice must not weigh like a fatal")

    def test_nothing_is_written_without_a_registered_webroot(self):
        """Every path would be unresolvable, and a run that writes findings
        nobody can open is worse than one that says it did nothing."""
        bare = Path(tempfile.mkdtemp(prefix="shellhound-elbare-"))
        db.connect(bare).close()
        stats = errorlog.scan(bare, [str(self.logs)])
        self.assertEqual(0, stats["findings"])
        self.assertGreater(stats["skipped"], 0, "the skip was not reported")

    def test_an_access_log_is_not_treated_as_an_error_log(self):
        other = Path(tempfile.mkdtemp(prefix="shellhound-elacc-"))
        (other / "access.log").write_text(
            '1.2.3.4 - - [26/Jun/2026:05:19:59 +0200] "GET / HTTP/1.1" 200 5 "-" "c"\n',
            encoding="utf-8")
        stats = errorlog.scan(self.case, [str(other)])
        self.assertEqual(0, stats["files"])
        self.assertEqual(0, stats["findings"])

    def test_the_evidence_keeps_the_path_as_the_log_wrote_it(self):
        """The server path is the fact; the artifact is the copy. A report
        that only shows the copy cannot be checked against the server."""
        errorlog.scan(self.case, [str(self.logs)])
        hit = next(f for f in self._findings()
                   if Path(f["artifact"]).name == "kb-media.php")
        self.assertIn("/var/www/html/images/kb-media.php", hit["evidence"])


class DocumentedRestraintTests(unittest.TestCase):
    """The reference and the engine must not promise different things.

    `docs/rules.md` advertised the deleted-file case as this engine's
    strongest -- "the log is the only remaining evidence that the path
    existed at all" -- while the paragraph a few lines below said a path is
    only written when it RESOLVES. Both cannot hold, and the code implements
    the second: `_resolver` requires `os.path.isfile`.

    So a reader reached for the error log to answer exactly that question,
    found nothing, and had no way to tell whether the shell was never there
    or the engine had declined to say.
    """

    FATAL = ("[Mon Jan 05 08:00:0{n}.000000 2026] [php:error] [pid 1] "
             "[client 192.0.2.10:52000] PHP Fatal error:  x in "
             "/var/www/html/{name} on line 1\n")

    def test_a_deleted_file_produces_no_finding_and_is_counted(self):
        case = Path(tempfile.mkdtemp(prefix="shellhound-gone-"))
        root = Path(tempfile.mkdtemp(prefix="shellhound-goneroot-"))
        logs = Path(tempfile.mkdtemp(prefix="shellhound-gonelogs-"))
        for d in (case, root, logs):
            self.addCleanup(shutil.rmtree, d, True)
        # The present file is the CONTROL: it proves the engine ran and
        # resolved paths in this case, so the ghost's silence is a property
        # of the ghost and not of a job that never started.
        (root / "here.php").write_text("<?php\n", encoding="utf-8")
        (logs / "error.log").write_text(
            self.FATAL.format(n=0, name="here.php")
            + self.FATAL.format(n=1, name="gone.php"), encoding="utf-8")
        conn = db.connect(case)
        try:
            conn.execute("INSERT INTO evidence (kind, path, added) "
                         "VALUES ('webroot', ?, ?)", (str(root), db.now()))
            conn.commit()
        finally:
            conn.close()
        stats = errorlog.scan(case, [str(logs)])
        self.assertEqual(1, stats["findings"], "the control did not fire")
        self.assertEqual(1, stats["unresolved"],
                         "the absent path was dropped instead of counted")

    def test_the_reference_no_longer_promises_it(self):
        """The documentation half. If the sentence is ever restored, this
        says so before an analyst believes it."""
        docs = (Path(__file__).resolve().parent.parent
                / "docs" / "rules.md").read_text(encoding="utf-8")
        section = docs.split("# Error log", 1)[-1].split("\n# ", 1)[0]
        self.assertIn("produces no finding", section,
                      "the reference does not say what becomes of a path "
                      "whose file is gone")
        self.assertNotIn("only remaining evidence", section)

    def test_the_engine_says_the_same_as_the_reference(self):
        """Fixing only the reference would leave the contradiction in the
        source, where the next person to read it starts."""
        self.assertIn("produces NOTHING", errorlog.__doc__)


if __name__ == "__main__":
    unittest.main()
