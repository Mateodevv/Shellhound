# tests/test_regressions.py
"""Bugs that were in a release, with the case that exposed each one.

These are not unit tests of a design; they are the specific inputs that once
produced a wrong answer. Every one of them was verified by putting the defect
back and watching the test fail -- a regression test that passes against the
broken code guards nothing.
"""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from server import db, iocs as ioclib, workspace
from server.artifacts import MUTED_CLAUSE, art_sql


class FilterPrecedenceTests(unittest.TestCase):
    """The artifact filters and the muted-rule clause.

    `active > 0 OR triage != 'new'` was appended to an AND-chain WITHOUT
    brackets. SQL binds AND tighter, so the whole thing read
    `(chips AND active > 0) OR triage != 'new'` and every DECIDED artifact
    walked past every chip. Asking to hide the confirmed ones returned them.
    """

    def _case(self):
        case = Path(tempfile.mkdtemp(prefix="shellhound-prec-"))
        conn = db.connect(case)
        # A high, undecided one and a low, confirmed one.
        db.upsert_finding(conn, "webshell", db.SEV_HIGH, "r.high", "file",
                          "/w/shell.php", line=1, evidence="x",
                          rule_id="r.high")
        db.upsert_finding(conn, "logs", db.SEV_INFO, "r.low", "client",
                          "203.0.113.9", line=0, evidence="y", rule_id="r.low")
        conn.execute("UPDATE findings SET triage = 'confirmed' "
                     "WHERE artifact = '203.0.113.9'")
        conn.commit()
        return case, conn

    def _query(self, conn, where, params=()):
        # MUTED_CLAUSE, not a copy of it: a guard that re-types the string it
        # is guarding passes against the broken server.
        art = art_sql(())
        clause = " AND ".join(where + [MUTED_CLAUSE])
        return [r["artifact"] for r in conn.execute(
            f"WITH art AS ({art}) SELECT artifact FROM art WHERE {clause}",
            list(params)).fetchall()]

    def test_hiding_a_severity_also_hides_it_when_decided(self):
        case, conn = self._case()
        try:
            got = self._query(conn, ["worst NOT IN (?,?,?)"], [1, 2, 3])
            self.assertNotIn("203.0.113.9", got,
                             "a decided artifact ignored the severity chip")
        finally:
            conn.close()

    def test_hiding_a_triage_state_actually_hides_it(self):
        """The plainest case: ask for confirmed to be hidden, and the
        confirmed one came back."""
        case, conn = self._case()
        try:
            got = self._query(conn, ["triage NOT IN (?)"], ["confirmed"])
            self.assertNotIn("203.0.113.9", got,
                             "the filter returned exactly what it was told "
                             "to hide")
        finally:
            conn.close()

    def test_hiding_a_kind_does_not_leak_another_kind(self):
        case, conn = self._case()
        try:
            got = self._query(conn, ["artifact_kind = ?"], ["file"])
            self.assertEqual(["/w/shell.php"], got,
                             "a client appeared in a file-filtered list")
        finally:
            conn.close()


class ArchiveMemberTests(unittest.TestCase):
    """The zip-slip guard.

    ':' was only checked in the FIRST path segment. `sub/C:/evil.txt` passed,
    and `Path(*parts)` then folded it into `C:evil.txt` -- a drive-relative
    path pointing outside the workspace altogether.
    """

    def test_a_drive_letter_in_a_later_segment_is_refused(self):
        with self.assertRaises(workspace.ImportError_):
            workspace._safe_member("sub/C:/evil.txt")

    def test_a_drive_letter_in_the_first_segment_is_still_refused(self):
        with self.assertRaises(workspace.ImportError_):
            workspace._safe_member("C:/evil.txt")

    def test_an_alternate_data_stream_is_refused(self):
        """On NTFS `notes.txt:hidden` writes a stream no listing shows."""
        with self.assertRaises(workspace.ImportError_):
            workspace._safe_member("sub/notes.txt:hidden")

    def test_traversal_is_still_refused(self):
        with self.assertRaises(workspace.ImportError_):
            workspace._safe_member("../evil.txt")

    def test_an_ordinary_member_still_passes(self):
        """The guard has to keep letting real archives through."""
        self.assertEqual(Path("sub", "notes.txt"),
                         workspace._safe_member("sub/notes.txt"))

    def test_no_accepted_member_ever_escapes_the_destination(self):
        """The property the function exists for, stated once."""
        dest = Path("D:/Cases/ws/case-1")
        for name in ("a.txt", "sub/a.txt", "sub/deeper/a.txt", "./a.txt"):
            member = workspace._safe_member(name)
            if member is None:
                continue
            target = (dest / member).as_posix().lower()
            self.assertTrue(target.startswith(dest.as_posix().lower()),
                            f"{name!r} escaped to {target}")


class ExportPathTests(unittest.TestCase):
    """No absolute path of the analyst's machine may leave in an export.

    The IOC values were relativised from the start. The chronology was added
    later and passed `artifact` straight through, so the JSON export carried
    `C:\\Cases\\...\\webroot\\...\\shell.php` -- the analyst's directory
    layout, in a file meant to be handed to somebody else.
    """

    CHAIN = {
        "span": {"first": 1780000000, "last": 1780003600},
        "events": [{
            "at": 1780000000, "kind": "erfolg", "title": "t", "detail": "d",
            "source": "log", "artifact": r"C:\Cases\2026-05\webroot\x\shell.php",
            "artifact_rel": "x/shell.php", "artifact_kind": "file",
            "ip": "", "severity": 0,
        }],
        "gaps": [],
        "undated": [{
            "artifact": r"C:\Cases\2026-05\webroot\x\other.php",
            "artifact_rel": "x/other.php", "artifact_kind": "file",
            "why": "no measured time",
        }],
        "offsets": {"logs": 0, "dump": 0},
    }

    def _exported(self):
        return json.loads(ioclib.to_json([], case_name="c", chain=self.CHAIN))

    def test_the_host_path_does_not_appear_anywhere_in_the_export(self):
        text = json.dumps(self._exported())
        self.assertNotIn("Cases", text)
        self.assertNotIn("webroot", text)

    def test_the_event_carries_the_webroot_relative_path(self):
        self.assertEqual("x/shell.php",
                         self._exported()["chain"]["events"][0]["artifact"])

    def test_undated_artifacts_are_relativised_too(self):
        """They name files as much as the events do."""
        self.assertEqual("x/other.php",
                         self._exported()["chain"]["undated"][0]["artifact"])

    def test_the_helper_key_does_not_travel(self):
        """`artifact_rel` is internal plumbing; the export states one path."""
        self.assertNotIn("artifact_rel",
                         self._exported()["chain"]["events"][0])

    def test_a_client_artifact_survives_unchanged(self):
        """An IP is not a path and must not be mangled by the relativising."""
        chain = json.loads(json.dumps(self.CHAIN))
        chain["events"][0].update(artifact="203.0.113.9",
                                  artifact_rel="203.0.113.9",
                                  artifact_kind="client")
        out = json.loads(ioclib.to_json([], case_name="c", chain=chain))
        self.assertEqual("203.0.113.9", out["chain"]["events"][0]["artifact"])


class ExportedFrameTests(unittest.TestCase):
    """What frame the exported timestamps are in.

    Every time in the export is a bare integer, so the note beside them is
    the only thing that makes them mean anything -- and it was one fixed
    sentence: "naive local times of the respective source (log server resp.
    database server)". Exported in UTC, the file said that about times that
    were UTC, and nothing else in the file contradicted it. A number carrying
    the wrong frame is worse than no number, because it is quotable.
    """

    BASE = {
        "span": {"first": 1780000000, "last": 1780003600},
        "events": [], "gaps": [], "undated": [],
        "offsets": {"logs": 0, "dump": 0},
    }

    def _note(self, **chain):
        merged = dict(self.BASE, **chain)
        out = json.loads(ioclib.to_json([], case_name="c", chain=merged))
        return out["chain"]

    def test_a_utc_export_does_not_claim_local_times(self):
        note = self._note(tz_mode="utc", zone="UTC",
                          tz_offsets=["UTC+02:00"])["note"]
        self.assertIn("UTC", note)
        self.assertNotIn("local", note)

    def test_a_log_time_export_names_the_offset_it_is_in(self):
        note = self._note(tz_mode="log", zone="UTC+02:00",
                          tz_offsets=["UTC+02:00"])["note"]
        self.assertIn("local", note)
        self.assertIn("UTC+02:00", note)

    def test_several_offsets_are_named_rather_than_reduced(self):
        """No single one labels the period, so the file lists what it has and
        says which export can be compared instead."""
        note = self._note(tz_mode="log", zone="",
                          tz_offsets=["UTC+01:00", "UTC+02:00"])["note"]
        self.assertIn("UTC+01:00", note)
        self.assertIn("UTC+02:00", note)
        self.assertIn("more than one", note)

    def test_the_frame_travels_as_data_not_only_as_prose(self):
        """A sentence is for the human reader. Anything reading this file
        needs the same fact in a field it can branch on."""
        block = self._note(tz_mode="utc", zone="UTC", tz_offsets=["UTC+02:00"])
        self.assertEqual("utc", block["tz_mode"])
        self.assertEqual("UTC", block["zone"])
        self.assertEqual(["UTC+02:00"], block["tz_offsets"])

    def test_a_chain_without_the_fields_still_exports(self):
        """`to_json` is called from more than one place and the chain dict
        has grown twice. A missing key must not take the export down."""
        block = self._note()
        self.assertEqual("log", block["tz_mode"])
        self.assertTrue(block["note"])


class ChainRelativePathTests(unittest.TestCase):
    """The other half of the export fix: `case_chain` has to PRODUCE the
    relative path. The export test above hands the key in by construction and
    would keep passing if the chain stopped emitting it."""

    @classmethod
    def setUpClass(cls):
        from tests.fixtures import Evidence, register
        from server.engines import logindex, webshell
        cls.ev = Evidence().build()
        conn = db.connect(cls.ev.case_dir)
        register(conn, cls.ev)
        conn.close()
        webshell.scan(cls.ev.case_dir, [str(cls.ev.webroot)])
        logindex.build(cls.ev.case_dir, [str(cls.ev.logs)])
        conn = db.connect(cls.ev.case_dir)
        conn.execute("UPDATE findings SET triage = 'confirmed'")
        conn.commit()
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.ev.cleanup()

    def _file_events(self):
        from server.chain import case_chain
        chain = case_chain(self.ev.case_dir)
        return [e for e in chain["events"] if e["artifact_kind"] == "file"]

    def test_every_file_event_carries_a_relative_path(self):
        events = self._file_events()
        self.assertTrue(events, "the fixture produced no file events")
        for e in events:
            self.assertIn("artifact_rel", e)
            self.assertNotIn(str(self.ev.root), e["artifact_rel"],
                             "the relative path still contains the host root")

    def test_the_absolute_path_stays_for_the_interface(self):
        """It is the identity the window is opened with -- removing it would
        break the click, which is why the export strips it instead."""
        for e in self._file_events():
            self.assertTrue(e["artifact"].startswith(str(self.ev.root)))

    def test_an_export_built_from_a_real_chain_carries_no_host_path(self):
        """The end-to-end statement, on measured data rather than a literal."""
        from server.chain import case_chain
        text = ioclib.to_json([], case_name="c",
                              chain=case_chain(self.ev.case_dir))
        self.assertNotIn(str(self.ev.root), text)
        self.assertNotIn(str(self.ev.root).replace("\\", "\\\\"), text)


class SqlDumpTests(unittest.TestCase):
    """A dump is evidence. Rows that vanish and rows that double are both
    statements about the database that are not true."""

    DDL = ("CREATE TABLE `wp_options` (`id` int, `k` varchar(60), "
           "`v` longtext);\n")

    def _scan(self, text, name="dump.sql"):
        import shutil
        from server.engines import sqldump
        root = Path(tempfile.mkdtemp(prefix="shellhound-sqlreg-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        case = root / "case"
        case.mkdir()
        path = root / name
        path.write_text(text, encoding="utf-8")
        db.connect(case).close()
        sqldump.scan(case, [str(path)])
        return case

    def _tables(self, case):
        conn = db.connect(case)
        try:
            return {r["name"]: r["rows"] for r in
                    db.rows(conn, "SELECT name, rows FROM db_tables")}
        finally:
            conn.close()

    def test_ddl_text_inside_a_value_is_not_a_create_statement(self):
        """A wp_options row holding a schema backup used to swallow the whole
        INSERT: its rows never reached the inventory or the scanner, and a
        table that exists nowhere in the database appeared instead."""
        case = self._scan(self.DDL + (
            "INSERT INTO `wp_options` VALUES "
            "(1,'backup','CREATE TABLE `x` (`c` int)'),(2,'other','plain');\n"))
        self.assertEqual({"wp_options": 2}, self._tables(case))

    def test_a_dump_that_starts_with_comments_still_parses(self):
        """The guard against over-tightening the anchor: a real mysqldump
        opens with `-- MySQL dump ...` before the first CREATE."""
        case = self._scan("-- MySQL dump 10.13\n-- Host: localhost\n--\n\n"
                          + self.DDL + "INSERT INTO `wp_options` VALUES "
                                       "(1,'a','b');\n")
        self.assertEqual({"wp_options": 1}, self._tables(case))

    def test_a_prefix_placeholder_in_data_is_not_a_schema_file(self):
        """`#__users` marks a shipped SCHEMA by its table NAME. Looking for
        it anywhere in the text filed a real export as a template as soon as
        one row mentioned it -- which CMS documentation tables do."""
        case = self._scan(self.DDL + (
            "INSERT INTO `wp_options` VALUES "
            "(1,'doc','the table is called #__content in templates');\n"))
        conn = db.connect(case)
        try:
            self.assertEqual("export",
                             db.one(conn, "SELECT kind FROM db_dumps")["kind"])
        finally:
            conn.close()

    def test_an_escaped_backslash_stays_a_backslash(self):
        """In a dump `\\\\` is ONE literal backslash, so 'C:\\\\new' means
        C:\\new -- backslash, then the letter n. A chain of replaces turned it
        into a line break."""
        from server.engines.sqldump import _decode
        self.assertEqual("C:\\new", _decode(r"'C:\\new'"))
        self.assertEqual("a\nb", _decode(r"'a\nb'"))
        self.assertEqual("a\\", _decode(r"'a\\'"))
        self.assertEqual("it's", _decode(r"'it\'s'"))
        self.assertEqual("it's", _decode("'it''s'"))

    def test_rescanning_a_dump_does_not_double_its_accounts(self):
        """With a second dump in the case the rowid is not reused, so the old
        children were never deleted and the chronology -- which does not join
        db_dumps -- read the same account twice."""
        import shutil
        from server.engines import sqldump
        users = ("CREATE TABLE `wp_users` (`ID` bigint, `user_login` varchar(60),"
                 " `user_pass` varchar(255), `user_nicename` varchar(50),"
                 " `user_email` varchar(100), `user_url` varchar(100),"
                 " `user_registered` datetime, `user_activation_key` varchar(255),"
                 " `user_status` int, `display_name` varchar(250));\n")
        root = Path(tempfile.mkdtemp(prefix="shellhound-sqlre-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        case = root / "case"
        case.mkdir()
        db.connect(case).close()
        paths = []
        for who in ("alice", "bob"):
            path = root / f"{who}.sql"
            path.write_text(users + (
                f"INSERT INTO `wp_users` VALUES (1,'{who}','x','{who}',"
                f"'{who}@example.test','','2026-01-08 03:17:00','',0,'{who}');\n"),
                encoding="utf-8")
            paths.append(path)
            sqldump.scan(case, [str(path)])
        sqldump.scan(case, [str(paths[0])])          # the re-scan
        conn = db.connect(case)
        try:
            logins = sorted(r["login"] for r in
                            db.rows(conn, "SELECT login FROM db_accounts"))
            orphans = db.one(conn, "SELECT count(*) c FROM db_accounts a "
                                   "LEFT JOIN db_dumps d ON d.id = a.dump_id "
                                   "WHERE d.id IS NULL")["c"]
        finally:
            conn.close()
        self.assertEqual(["alice", "bob"], logins)
        self.assertEqual(0, orphans)

    def test_a_finding_names_every_dump_it_was_seen_in(self):
        """Two dumps sharing a table, a row number and a rule are ONE finding
        -- the fingerprint deliberately stays source|rule|artifact|line, since
        widening it would orphan every decision already made. The evidence
        therefore has to name both, or the second host silently overwrites the
        first."""
        import shutil
        from server.engines import sqldump
        body = ("CREATE TABLE `wp_posts` (`ID` bigint, `post_content` longtext);\n"
                "INSERT INTO `wp_posts` VALUES "
                "(1,'<iframe src=\"//evil.test/t.js\" width=\"0\"></iframe>');\n")
        root = Path(tempfile.mkdtemp(prefix="shellhound-sqlfp-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        case = root / "case"
        case.mkdir()
        db.connect(case).close()
        for who in ("site-a", "site-b"):
            path = root / f"{who}.sql"
            path.write_text(body, encoding="utf-8")
            sqldump.scan(case, [str(path)])
        conn = db.connect(case)
        try:
            rows = db.rows(conn, "SELECT evidence FROM findings "
                                 "WHERE source = 'sqldb'")
        finally:
            conn.close()
        self.assertEqual(1, len(rows))
        self.assertIn("site-a.sql", rows[0]["evidence"])
        self.assertIn("site-b.sql", rows[0]["evidence"])


class BruteForceEvidenceTests(unittest.TestCase):
    """What a log can and cannot prove about a login.

    Both halves of this were wrong on real traffic, and both accused somebody.

    A REDIRECT IS NOT A SUCCESS. Joomla answers every login POST with a 303 --
    plain POST-Redirect-GET -- whether the credentials were right or wrong. On
    a real case a client whose 121 attempts ALL failed was reported at HIGH as
    a break-in, and the 100 % redirect rate that proves the opposite was the
    very thing that triggered it.

    AND A POST TO THE BACKEND IS NOT A LOGIN ATTEMPT. `/administrator/index.php`
    is the URL of Joomla's whole admin application: saving an article,
    reordering a menu, running a backup. The site's own administrator was
    credited with 127 login attempts -- 8 real, 119 article edits and backup
    jobs -- and reported as an intruder.

    What an unauthenticated client cannot obtain is a 2xx from the backend
    with a component named. That, after a flood, is worth saying.
    """

    @staticmethod
    def _line(ip, when, uri, status, method="GET"):
        import time
        stamp = time.strftime("%d/%b/%Y:%H:%M:%S +0200", time.gmtime(when))
        return (f'{ip} - - [{stamp}] "{method} {uri} HTTP/1.1" {status} 512 '
                f'"-" "Mozilla/5.0"\n')

    def _actors(self, rows):
        import shutil
        from server.engines import logindex
        root = Path(tempfile.mkdtemp(prefix="shellhound-bf-"))
        self.addCleanup(shutil.rmtree, root, True)
        case = root / "case"
        case.mkdir()
        logs = root / "logs"
        logs.mkdir()
        (logs / "access.log").write_text("".join(rows), encoding="utf-8")
        db.connect(case).close()
        logindex.build(case, [str(logs)])
        conn = logindex.open_readonly(case)
        try:
            return {r["ip"]: dict(r) for r in conn.execute(
                """SELECT a.ip, a.login_posts, a.admin_ok,
                          (SELECT count(*) FROM alerts al
                           WHERE al.ip_id = a.ip_id AND al.kind = 'login_success')
                          AS success,
                          (SELECT count(*) FROM alerts al
                           WHERE al.ip_id = a.ip_id AND al.kind = 'login_flood')
                          AS flood
                   FROM actors a""")}
        finally:
            conn.close()

    LOGIN = "/index.php/component/users/?task=user.login"
    BACKEND = "/administrator/index.php?option=com_content&view=articles"

    def test_a_flood_answered_only_with_redirects_is_not_a_break_in(self):
        rows = [self._line("203.0.113.5", 1780000000 + i * 60, self.LOGIN,
                           303, "POST") for i in range(60)]
        actors = self._actors(rows)
        self.assertEqual(1, actors["203.0.113.5"]["flood"],
                         "the flood itself must still be reported")
        self.assertEqual(0, actors["203.0.113.5"]["success"],
                         "121 failed attempts were called a successful login")

    def test_a_flood_followed_by_the_backend_is_a_break_in(self):
        """The guard against silencing the rule altogether: this is the shape
        of the one real intrusion in the case material."""
        rows = [self._line("203.0.113.6", 1780000000 + i * 60, self.LOGIN,
                           303, "POST") for i in range(60)]
        rows += [self._line("203.0.113.6", 1780004000 + i * 60, self.BACKEND,
                            200) for i in range(5)]
        actors = self._actors(rows)
        self.assertEqual(1, actors["203.0.113.6"]["success"])
        self.assertEqual(5, actors["203.0.113.6"]["admin_ok"])

    def test_working_in_the_backend_is_not_attempting_to_log_in(self):
        """An administrator saving fifty articles. Every save is a POST to
        the admin URL answered with a redirect -- the exact shape the old
        rule read as a brute-force flood followed by a break-in."""
        rows = []
        for i in range(50):
            rows.append(self._line(
                "192.0.2.10", 1780000000 + i * 120,
                f"/administrator/index.php?option=com_content&layout=edit&id={i}",
                303, "POST"))
            rows.append(self._line("192.0.2.10", 1780000060 + i * 120,
                                   self.BACKEND, 200))
        actors = self._actors(rows)
        self.assertEqual(0, actors["192.0.2.10"]["login_posts"],
                         "article saves were counted as login attempts")
        self.assertEqual(0, actors["192.0.2.10"]["flood"])
        self.assertEqual(0, actors["192.0.2.10"]["success"])

    def test_the_bare_backend_url_is_still_a_login_endpoint(self):
        """The other direction: a real backend login carries no component,
        and dropping it would blind the rule to admin brute force."""
        rows = [self._line("203.0.113.7", 1780000000 + i * 60,
                           "/administrator/index.php", 200, "POST")
                for i in range(40)]
        self.assertEqual(40, self._actors(rows)["203.0.113.7"]["login_posts"])


class JoomlaGenerationTests(unittest.TestCase):
    """Joomla answers "is this an administrator?" in two different places,
    and only one of them was ever read.

    From 3.0 the answer is a row in `#__user_usergroup_map`. In 1.x and 2.5
    there is no such table: the permission sits on the account itself, in
    `gid` and in `usertype`. A 1.5 export therefore reported no
    administrators at all -- and old installations are disproportionately the
    compromised ones, which is the whole population this tool is for.

    The same shift moves the DATE columns. 1.x carries `usertype` and `gid`
    between the password and the timestamps, so reading by position gave the
    sendEmail flag as the registration date and the group id as the last
    login. The chronology then dropped the account entirely, because "1" is
    not a timestamp -- an administrator created during the incident, gone
    from the story without a word.

    Read by COLUMN NAME now, which is what makes both generations work
    without the code having to guess which one it is looking at.
    """

    HEAD_15 = ("CREATE TABLE `jos_users` (`id` int, `name` varchar(255),"
               " `username` varchar(150), `email` varchar(100),"
               " `password` varchar(100), `usertype` varchar(25),"
               " `block` tinyint, `sendEmail` tinyint, `gid` tinyint,"
               " `registerDate` datetime, `lastvisitDate` datetime,"
               " `activation` varchar(100), `params` text);\n")
    HEAD_3 = ("CREATE TABLE `j_users` (`id` int, `name` varchar(255),"
              " `username` varchar(150), `email` varchar(100),"
              " `password` varchar(100), `block` tinyint,"
              " `sendEmail` tinyint, `registerDate` datetime,"
              " `lastvisitDate` datetime, `activation` varchar(100),"
              " `params` text);\n")
    # Two marker tables, or the dump is not recognised as Joomla at all and
    # the generic reader takes over -- which is what made an earlier check of
    # this defect come out clean against a one-table fixture.
    MARKERS_15 = ("CREATE TABLE `jos_content` (`id` int, `title` text);\n"
                  "INSERT INTO `jos_content` VALUES (1,'Home');\n"
                  "CREATE TABLE `jos_session` (`session_id` varchar(200));\n"
                  "INSERT INTO `jos_session` VALUES ('abc');\n")
    MARKERS_3 = ("CREATE TABLE `j_content` (`id` int, `title` text);\n"
                 "INSERT INTO `j_content` VALUES (1,'Home');\n"
                 "CREATE TABLE `j_session` (`session_id` varchar(200));\n"
                 "INSERT INTO `j_session` VALUES ('abc');\n")

    JOOMLA_15 = HEAD_15 + (
        "INSERT INTO `jos_users` VALUES (62,'Administrator','admin',"
        "'admin@example.test','x','Super Administrator',0,1,25,"
        "'2019-03-04 09:12:00','2026-01-08 03:17:00','','');\n"
        "INSERT INTO `jos_users` VALUES (64,'Support','support-tmp',"
        "'tmp@example.test','y','Registered',0,0,18,"
        "'2026-01-06 12:00:00','2026-01-06 12:30:00','','');\n") + MARKERS_15
    JOOMLA_3 = HEAD_3 + (
        "INSERT INTO `j_users` VALUES (62,'Administrator','admin',"
        "'admin@example.test','x',0,1,'2019-03-04 09:12:00',"
        "'2026-01-08 03:17:00','','');\n"
        "CREATE TABLE `j_user_usergroup_map` (`user_id` int, `group_id` int);\n"
        "INSERT INTO `j_user_usergroup_map` VALUES (62,8);\n") + MARKERS_3

    def _accounts(self, text):
        import shutil
        from server.engines import sqldump
        root = Path(tempfile.mkdtemp(prefix="shellhound-joomla-"))
        self.addCleanup(shutil.rmtree, root, True)
        case = root / "case"
        case.mkdir()
        dump = root / "dump.sql"
        dump.write_text(text, encoding="utf-8")
        db.connect(case).close()
        sqldump.scan(case, [str(dump)])
        conn = db.connect(case)
        try:
            cms = db.one(conn, "SELECT cms FROM db_dumps")["cms"]
            rows = {r["login"]: dict(r) for r in db.rows(
                conn, "SELECT login, registered, last_login, admin, blocked "
                      "FROM db_accounts")}
        finally:
            conn.close()
        return cms, rows

    def test_a_joomla_15_export_is_recognised_as_joomla(self):
        """The premise of everything below. Without two marker tables the
        generic reader runs instead and the positional bug cannot be seen."""
        self.assertEqual("Joomla", self._accounts(self.JOOMLA_15)[0])

    def test_a_joomla_15_super_administrator_is_flagged(self):
        _cms, rows = self._accounts(self.JOOMLA_15)
        self.assertEqual(1, rows["admin"]["admin"])

    def test_an_ordinary_joomla_15_account_is_not(self):
        """The guard against flagging everyone: an account list in which
        everybody is an administrator says nothing."""
        _cms, rows = self._accounts(self.JOOMLA_15)
        self.assertEqual(0, rows["support-tmp"]["admin"])

    def test_the_joomla_15_dates_are_dates(self):
        """Read positionally these came back as `1` and `25` -- the sendEmail
        flag and the group id."""
        _cms, rows = self._accounts(self.JOOMLA_15)
        self.assertEqual("2019-03-04 09:12:00", rows["admin"]["registered"])
        self.assertEqual("2026-01-08 03:17:00", rows["admin"]["last_login"])

    def test_the_login_is_the_username_not_the_display_name(self):
        """`name` is 'Administrator', `username` is 'admin'. Only the second
        one can be looked for in a log."""
        _cms, rows = self._accounts(self.JOOMLA_15)
        self.assertIn("admin", rows)
        self.assertNotIn("Administrator", rows)

    def test_a_joomla_3_export_still_reads_the_same_way(self):
        """The generation that already worked has to keep working -- it
        answers the admin question in a different table entirely."""
        cms, rows = self._accounts(self.JOOMLA_3)
        self.assertEqual("Joomla", cms)
        self.assertEqual(1, rows["admin"]["admin"])
        self.assertEqual("2019-03-04 09:12:00", rows["admin"]["registered"])
        self.assertEqual("2026-01-08 03:17:00", rows["admin"]["last_login"])


class EngineHonestyTests(unittest.TestCase):
    """Smaller engine claims that each made the tool say something false."""

    def test_three_bytes_of_pixel_data_are_not_a_php_tag(self):
        """`<?=` is three bytes, and in compressed image data any given
        three-byte sequence turns up about once per 16 MB.

        On a photograph of a little over a megabyte this rule announced "PHP
        code hidden inside image file" -- at HIGH -- because the file's only
        `<?=` sat between two runs of pixel data. A forensic tool that
        accuses a holiday photo teaches the analyst to skim past the rule
        that matters.

        The bytes below are constructed, not sampled from any image: the
        only property that decides the case is that the tag is surrounded by
        data that does not read as source, and a run of high bytes around it
        reproduces that exactly."""
        noise = b"<?=" + bytes(range(0x80, 0x89))
        self.assertEqual([], self._image(b"\x89PNG\r\n\x1a\n" + noise * 40))

    def test_a_short_tag_followed_by_source_is_still_a_finding(self):
        """The other half: `<?=` IS a PHP tag, and a shell may well use it.
        What separates the two is whether what follows reads as code."""
        self.assertIn("webshell.php_in_image", self._image(
            b"\x89PNG\r\n\x1a\n<?= system($_GET['c']); ?>\n"))

    def _image(self, body):
        import shutil
        from server.engines import webshell
        root = Path(tempfile.mkdtemp(prefix="shellhound-imgfp-"))
        self.addCleanup(shutil.rmtree, root, True)
        path = root / "x.png"
        path.write_bytes(body)
        findings, _skip, _inert = webshell.scan_file(str(path))
        return [f[0] for f in findings]

    def test_a_shouting_php_tag_in_an_image_is_found(self):
        import shutil
        from server.engines import webshell
        root = Path(tempfile.mkdtemp(prefix="shellhound-img-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        for tag in (b"<?php", b"<?PHP", b"<?Php"):
            path = root / "x.png"
            path.write_bytes(b"\x89PNG\r\n\x1a\n" + tag + b" echo 1; ?>\n")
            findings, _skip, _inert = webshell.scan_file(str(path))
            self.assertTrue([f for f in findings
                             if f[0] == "webshell.php_in_image"],
                            f"{tag!r} was not recognised as PHP")

    def _htaccess(self, body):
        import shutil
        from server.engines import webshell
        root = Path(tempfile.mkdtemp(prefix="shellhound-ht-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        path = root / ".htaccess"
        path.write_bytes(body)
        findings, _skip, _inert = webshell.scan_file(str(path))
        return [f[0] for f in findings]

    def test_an_ordinary_php_version_handler_is_not_a_finding(self):
        """cPanel and Plesk write this into the default .htaccess of every
        account. The rule fired on it and called `.php .php8 .phtml`
        "non-PHP extensions" -- the opposite of what stands in the line."""
        self.assertEqual([], self._htaccess(
            b"<IfModule mime_module>\n"
            b"  AddHandler application/x-httpd-ea-php81 .php .php8 .phtml\n"
            b"</IfModule>\n"))

    def test_an_image_extension_mapped_to_php_is_still_a_finding(self):
        """The guard against narrowing the rule into uselessness."""
        for body in (b"AddType application/x-httpd-php .jpg\n",
                     b"AddHandler application/x-httpd-php .png\n",
                     b"<FilesMatch \"\\.(jpg|png)$\">\n"
                     b"  SetHandler application/x-httpd-php\n"
                     b"</FilesMatch>\n"):
            self.assertIn("webshell.htaccess_handler", self._htaccess(body),
                          body.decode())

    def test_two_unrelated_directives_are_not_one_finding(self):
        """The rule's second branch was `$set_all and $files_image`, and
        YARA's `and` means only that both strings appear SOMEWHERE in the
        file. Neither block below is remarkable, `robots.txt` is why every
        webroot has a <Files> block at all, and `txt` was in the image list
        -- so the ordinary case scored HIGH under a sentence that was true
        of neither block."""
        self.assertEqual([], self._htaccess(
            b'<Files "robots.txt">\n  Require all granted\n</Files>\n'
            b'<FilesMatch "\\.php$">\n'
            b"  SetHandler application/x-httpd-php\n"
            b"</FilesMatch>\n"))

    def _php(self, body):
        import shutil
        from server.engines import webshell
        root = Path(tempfile.mkdtemp(prefix="shellhound-php-"))
        self.addCleanup(shutil.rmtree, root, True)
        path = root / "x.php"
        path.write_bytes(body)
        findings, _skip, _inert = webshell.scan_file(str(path))
        return {f[0]: f[1] for f in findings}

    def test_the_documented_upload_idiom_is_not_a_dropper(self):
        """`move_uploaded_file($_FILES[...]['tmp_name'], $target)` is the one
        correct way to accept an upload in PHP -- the function exists to
        REFUSE a path that was not uploaded. Every CMS with an upload form
        contains it, and each one was answered with HIGH and "that is how
        the next shell arrives"."""
        self.assertNotIn("webshell.dropper", self._php(
            b"<?php move_uploaded_file($_FILES['f']['tmp_name'], $target);"))

    def test_request_content_written_to_a_file_is_still_a_dropper(self):
        """The half that does carry the claim, kept."""
        self.assertIn("webshell.dropper", self._php(
            b"<?php file_put_contents('s.php', $_POST['c']);"))

    def test_an_upload_destination_from_the_request_is_reported_lower(self):
        """The narrow case worth keeping: the request picks the path, so it
        picks the extension. A form that keeps the browser's filename looks
        the same from here, which is why it is not high."""
        found = self._php(
            b"<?php move_uploaded_file($_FILES['f']['tmp_name'], $_POST['p']);")
        self.assertEqual(db.SEV_MEDIUM, found.get("webshell.upload_dest"))
        self.assertEqual(db.SEV_HIGH, self._php(
            b"<?php file_put_contents('s.php', $_POST['c']);")
            ["webshell.dropper"])

    def test_create_function_does_not_claim_request_input(self):
        """The rule was named "create_function / callback on request input"
        and fired on either half -- but `create_function('$a', 'return 1;')`
        names no superglobal. It is how a library written before PHP 7.2
        built a closure, and it was reported at HIGH under a sentence about
        request input that no part of the file supports."""
        found = self._php(b"<?php create_function('$a', 'return 1;');")
        self.assertNotIn("webshell.callback_input", found)
        self.assertEqual(db.SEV_MEDIUM, found.get("webshell.create_function"))

    def test_a_callback_named_by_the_request_stays_high(self):
        found = self._php(b"<?php call_user_func_array($_POST['f'], []);")
        self.assertEqual(db.SEV_HIGH, found.get("webshell.callback_input"))

    def test_a_reordered_query_string_still_matches_the_bundled_pattern(self):
        """HTTP query order carries no meaning, so a hunt pattern must not
        depend on it. The shipped JCE rule was one literal string and missed
        `?task=...&option=...`."""
        import shutil
        from server import patterns
        from server.engines import logindex
        root = Path(tempfile.mkdtemp(prefix="shellhound-jce-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        case = root / "case"
        case.mkdir()
        logs = root / "logs"
        logs.mkdir()
        uris = ["/index.php?option=com_jce&task=profiles.import",
                "/index.php?task=profiles.import&option=com_jce",
                "/index.php?option=com_jce&view=x&task=profiles.import"]
        (logs / "a.log").write_text("".join(
            f'203.0.113.{i + 1} - - [06/Jan/2026:08:00:00 +0000] '
            f'"GET {u} HTTP/1.1" 200 5 "-" "c"\n'
            for i, u in enumerate(uris)), encoding="utf-8")
        db.connect(case).close()
        logindex.build(case, [str(logs)])
        entry = patterns.bundled()[0]
        out = logindex.match_patterns(case, entry["patterns"], entry["match"])
        self.assertEqual(3, len({c["ip"] for c in out["clients"]}),
                         "a reordered query string was missed")

    def test_a_different_jce_task_is_not_a_hit(self):
        """The guard against widening it into a rule about com_jce alone."""
        import shutil
        from server import patterns
        from server.engines import logindex
        root = Path(tempfile.mkdtemp(prefix="shellhound-jce2-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        case = root / "case"
        case.mkdir()
        logs = root / "logs"
        logs.mkdir()
        (logs / "a.log").write_text(
            '203.0.113.1 - - [06/Jan/2026:08:00:00 +0000] '
            '"GET /index.php?option=com_jce&task=something.else HTTP/1.1" '
            '200 5 "-" "c"\n', encoding="utf-8")
        db.connect(case).close()
        logindex.build(case, [str(logs)])
        entry = patterns.bundled()[0]
        out = logindex.match_patterns(case, entry["patterns"], entry["match"])
        self.assertEqual([], out["clients"])

    def test_every_attacker_controlled_csv_field_is_escaped(self):
        """The export exists to be opened in a spreadsheet, and a user agent
        of `=cmd|'/c calc'!A1` executed when it was. Only the URI was
        guarded."""
        from server.app import _csv_safe
        for payload in ("=cmd|'/c calc'!A1", "+1+1", "-2+3", "@SUM(A1)"):
            self.assertTrue(_csv_safe(payload).startswith("'"), payload)
        self.assertEqual("Mozilla/5.0", _csv_safe("Mozilla/5.0"))
        self.assertEqual("", _csv_safe(None))

    def test_the_phpmyadmin_export_date_is_readable(self):
        """phpMyAdmin is the most common export on shared hosting and none of
        its date forms parsed, so the reference date was simply missing."""
        from datetime import datetime
        from server.app import _find_web_dist          # noqa: F401 (import app)
        import server.app as appmod
        import inspect
        source = inspect.getsource(appmod.create_app)
        start = source.index("_STAMP_FORMATS = (")
        formats = eval(source[source.index("(", start):
                              source.index(")", source.index("(", start)) + 1])
        for raw in ("Jan 06, 2026 at 08:00 AM", "06. Jan 2026 um 08:00",
                    "2026-01-06 08:00:00"):
            self.assertTrue(
                any(_parses(raw, f) for f in formats),
                f"no format reads {raw!r}")

    def test_editing_a_pattern_into_a_duplicate_is_refused(self):
        """add() refuses a copy because it would run twice and be reported
        twice; editing an entry INTO that copy has the same effect."""
        import shutil
        from server import patterns
        root = Path(tempfile.mkdtemp(prefix="shellhound-patreg-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        ws = root / "ws"
        ws.mkdir()
        patterns.add(ws, ["*com_jce*"], name="JCE", match="any")
        other = patterns.add(ws, ["*com_fabrik*"], name="Fabrik", match="any")
        with self.assertRaises(patterns.PatternError):
            patterns.update(ws, other["id"], patterns_in=["*com_jce*"])

    def test_saving_a_pattern_unchanged_is_still_allowed(self):
        """The guard against a duplicate check that refuses every edit."""
        import shutil
        from server import patterns
        root = Path(tempfile.mkdtemp(prefix="shellhound-patreg2-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        ws = root / "ws"
        ws.mkdir()
        entry = patterns.add(ws, ["*com_jce*"], name="JCE", match="any")
        patterns.update(ws, entry["id"], name="JCE editor RCE")
        self.assertEqual("JCE editor RCE", patterns.load(ws)[0]["name"])

    def test_the_identical_count_is_never_negative(self):
        """`modified` is produced in two places and only one of them came out
        of the same-size set; subtracting all of them took off rows that had
        never been added."""
        import shutil
        from server.engines import webrootdiff

        class Ctx:
            def __init__(self, case_dir):
                self.case_dir = case_dir

            def cancelled(self):
                return False

            def progress(self, *a, **k):
                pass

        root = Path(tempfile.mkdtemp(prefix="shellhound-diffreg-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        case = root / "case"
        case.mkdir()
        live = root / "webroot"
        ref = root / "reference"
        live.mkdir()
        ref.mkdir()
        (live / "same.php").write_text("AAAA", encoding="utf-8")
        (ref / "same.php").write_text("BBBB", encoding="utf-8")
        for i in range(3):
            (live / f"big{i}.php").write_text("A" * (10 + i), encoding="utf-8")
            (ref / f"big{i}.php").write_text("B" * (99 + i), encoding="utf-8")
        for i in range(2):
            (live / f"ok{i}.php").write_text("SAME", encoding="utf-8")
            (ref / f"ok{i}.php").write_text("SAME", encoding="utf-8")
        conn = db.connect(case)
        for kind, path in (("webroot", live), ("webroot_reference", ref)):
            conn.execute("INSERT INTO evidence (kind, path, added) "
                         "VALUES (?,?,?)", (kind, str(path), db.now()))
        rows = db.rows(conn, "SELECT id, kind FROM evidence")
        conn.commit()
        conn.close()
        ids = {r["kind"]: r["id"] for r in rows}
        out = webrootdiff.run(Ctx(case), ids["webroot"], str(live),
                              ids["webroot_reference"], str(ref))
        self.assertEqual(2, out["identical"])
        self.assertEqual(4, out["modified"])


class CoverageClockTests(unittest.TestCase):
    """The coverage block and the chronology stand one above the other and
    have to be on the same clock.

    The quiet windows are stored as UTC epochs and were rendered at offset 0
    whatever the switcher said, while the chronology below them rendered
    log-local time and labelled it. The same instant, hours apart, on one
    screen -- and the coverage block named no zone at all.
    """

    @classmethod
    def setUpClass(cls):
        import time
        from server.engines import logindex
        base = 1780000000
        root = Path(tempfile.mkdtemp(prefix="shellhound-covclock-"))
        cls.root = root
        cls.case = root / "case"
        cls.case.mkdir()
        logs = root / "logs"
        logs.mkdir()

        def line(epoch):
            stamp = time.strftime("%d/%b/%Y:%H:%M:%S +0200", time.gmtime(epoch))
            return (f'203.0.113.5 - - [{stamp}] "GET /a HTTP/1.1" 200 12 '
                    f'"-" "curl"\n')

        rows = [line(base + i * 5) for i in range(100)]
        rows += [line(base + 4 * 3600 + i * 5) for i in range(100)]
        (logs / "a.log").write_text("".join(rows), encoding="utf-8")
        db.connect(cls.case).close()
        logindex.build(cls.case, [str(logs)])

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.root, ignore_errors=True)

    def _note(self, mode):
        from server import coverage
        notes = coverage.report(self.case, "en", mode)["notes"]
        self.assertTrue(notes, "the fixture produced no quiet window")
        return notes[0]

    def test_the_log_offset_travels_to_the_interface(self):
        """The block draws the windows itself and needs the same offset the
        chronology uses."""
        from server import coverage
        self.assertEqual(7200, coverage.report(self.case, "en", "log")["tz"])

    def test_log_mode_names_the_offset(self):
        self.assertIn("UTC+02:00", self._note("log"))

    def test_utc_mode_says_utc(self):
        note = self._note("utc")
        self.assertIn("UTC", note)
        self.assertNotIn("UTC+", note)

    def test_the_two_modes_are_exactly_the_offset_apart(self):
        import re
        stamps = {}
        for mode in ("log", "utc"):
            found = re.findall(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
                               self._note(mode))
            stamps[mode] = found[0]
        from datetime import datetime
        delta = (datetime.strptime(stamps["log"], "%Y-%m-%d %H:%M:%S")
                 - datetime.strptime(stamps["utc"], "%Y-%m-%d %H:%M:%S"))
        self.assertEqual(7200, delta.total_seconds())


class UriAttributionTests(unittest.TestCase):
    """Which requests belong to which file.

    Matching the tail of the URI is right for a site served out of a
    subdirectory. For a file sitting directly in the webroot the tail is a
    single segment -- a NAME -- and `endswith` then accepted every index.php
    on the site. Customers browsing /shop/index.php were reported as clients
    that had touched a confirmed webshell.
    """

    def test_a_root_level_file_matches_only_its_own_path(self):
        from server.artifacts import uri_targets
        self.assertTrue(uri_targets("/index.php", "index.php"))
        for other in ("/shop/index.php", "/wp-admin/index.php",
                      "/a/b/index.php"):
            self.assertFalse(uri_targets(other, "index.php"), other)

    def test_a_nested_file_still_matches_by_tail(self):
        """A site served from /shop/ turns wp-content/x.php into
        /shop/wp-content/x.php, and that has to keep working."""
        rel = "wp-content/uploads/2026/01/kb-media.php"
        self.assertTrue(uri_targets_helper("/" + rel, rel))
        self.assertTrue(uri_targets_helper("/shop/" + rel, rel))

    def test_a_nested_file_does_not_match_a_different_directory(self):
        rel = "wp-content/uploads/2026/01/kb-media.php"
        self.assertFalse(uri_targets_helper("/other/kb-media.php", rel))

    def test_the_query_string_is_ignored(self):
        self.assertTrue(uri_targets_helper("/index.php?cmd=id", "index.php"))

    def test_case_does_not_decide_it(self):
        """A URL is not the file system: /Images/Shell.php and
        /images/shell.php are the same request."""
        self.assertTrue(uri_targets_helper("/Images/Shell.php",
                                           "images/shell.php"))


def uri_targets_helper(uri, rel):
    from server.artifacts import uri_targets
    return uri_targets(uri, rel)


def _parses(raw, fmt):
    from datetime import datetime
    try:
        datetime.strptime(raw, fmt)
        return True
    except ValueError:
        return False


class LogIndexHonestyTests(unittest.TestCase):
    """Numbers the log index reports about itself."""

    BASE = 1780000000

    @staticmethod
    def _line(epoch, ip="203.0.113.5", uri="/a.php"):
        import time
        stamp = time.strftime("%d/%b/%Y:%H:%M:%S +0200", time.gmtime(epoch))
        return (f'{ip} - - [{stamp}] "GET {uri} HTTP/1.1" 200 12 "-" "curl"\n')

    def _case(self, text, extra=None):
        root = Path(tempfile.mkdtemp(prefix="shellhound-lix-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(root,
                                                            ignore_errors=True))
        case = root / "case"
        case.mkdir()
        logs = root / "logs"
        logs.mkdir()
        (logs / "access.log").write_text(text, encoding="utf-8")
        for name, body in (extra or {}).items():
            (logs / name).write_text(body, encoding="utf-8")
        db.connect(case).close()
        return case, logs

    def test_a_line_without_a_readable_time_is_counted(self):
        """It used to be filed under 1970 and counted nowhere -- neither as a
        request the case can place nor as one it cannot."""
        from server.engines import logindex
        bad = ('203.0.113.9 - - [06/Xxx/2026:08:00:00 +0200] '
               '"GET /a.php HTTP/1.1" 200 5 "-" "curl"\n')
        case, logs = self._case(bad + "".join(
            self._line(self.BASE + i * 5) for i in range(20)))
        stats = logindex.build(case, [str(logs)])
        self.assertEqual(1, stats["undated"])
        self.assertEqual(1, logindex.overview(case)["undated"])

    def test_one_unreadable_line_does_not_invent_a_second_time_zone(self):
        """It used to store offset 0 for such a line, so a log with exactly
        one offset made the chronology announce mixed time zones."""
        from server.engines import logindex
        bad = ('203.0.113.9 - - [06/Xxx/2026:08:00:00 +0200] '
               '"GET /a.php HTTP/1.1" 200 5 "-" "curl"\n')
        case, logs = self._case(bad + "".join(
            self._line(self.BASE + i * 5) for i in range(20)))
        logindex.build(case, [str(logs)])
        self.assertEqual([7200], logindex.overview(case)["tz_offsets"])

    def test_a_skipped_file_does_not_make_the_index_stale_forever(self):
        """An Apache error log lying in the access-log directory is skipped
        on purpose -- and was then missing from the freshness fingerprint, so
        no rebuild could ever satisfy the comparison."""
        from server.engines import logindex
        case, logs = self._case(
            "".join(self._line(self.BASE + i * 5) for i in range(50)),
            {"error.log": "[Mon Jan 06 08:00:00 2026] [php:error] [pid 1] "
                          "PHP Fatal error:  x in /var/www/a.php on line 3\n"
                          * 40})
        logindex.build(case, [str(logs)])
        for run in (1, 2):
            self.assertTrue(logindex.status(case, [str(logs)])["fresh"],
                            f"reported stale on run {run} with nothing changed")

    def test_a_cancelled_build_says_it_is_a_fragment(self):
        """Everything after the break still runs and commits, so the index
        looked complete and the dashboard read its numbers as the whole
        truth."""
        from server.engines import logindex

        class Ctx:
            def __init__(self):
                self.seen = 0

            def cancelled(self):
                self.seen += 1
                return self.seen > 1

            def progress(self, *a, **k):
                pass

        body = "".join(self._line(self.BASE + i * 5) for i in range(50))
        case, logs = self._case(body, {"b.log": body, "c.log": body})
        self.assertTrue(logindex.build(case, [str(logs)], ctx=Ctx())["partial"])
        self.assertTrue(logindex.overview(case)["partial"])

    def test_a_complete_build_is_not_marked_partial(self):
        from server.engines import logindex
        case, logs = self._case(
            "".join(self._line(self.BASE + i * 5) for i in range(20)))
        self.assertFalse(logindex.build(case, [str(logs)])["partial"])
        self.assertFalse(logindex.overview(case)["partial"])

    def test_the_hunt_counts_every_client_not_just_the_listed_ones(self):
        """`clients_total` was len() of the capped list, so a pattern that
        matched a mass-exploitation campaign reported the cap."""
        from server.engines import logindex
        rows = []
        for i in range(250):
            rows.append(self._line(self.BASE, ip=f"198.51.{i // 254}."
                                                 f"{i % 254 + 1}",
                                   uri="/index.php?option=com_jce"))
        case, logs = self._case("".join(rows))
        logindex.build(case, [str(logs)])
        out = logindex.match_pattern(case, "*com_jce*")
        self.assertEqual(250, out["clients_total"])
        self.assertEqual(250, out["ok_clients"])
        self.assertEqual(250, out["hits"])
        self.assertTrue(out["clients_truncated"],
                        "the list was capped and did not say so")

    def test_an_informational_sighting_is_not_an_alerted_client(self):
        """A scanner announcing itself says something about the internet, not
        about this server -- and the Actors filter has always excluded it."""
        from server.engines import logindex
        rows = []
        for i in range(4):
            rows.append('198.51.100.9 - - [06/Jan/2026:03:0%d:00 +0200] '
                        '"GET /wp-admin/x.php HTTP/1.1" 404 5 "-" '
                        '"Nikto/2.5.0"\n' % i)
        rows += [self._line(self.BASE + i * 5) for i in range(20)]
        case, logs = self._case("".join(rows))
        logindex.build(case, [str(logs)])
        self.assertEqual(0, logindex.overview(case)["alerted_clients"])


class ChainTimeTests(unittest.TestCase):
    """The chronology on a log that is NOT in UTC.

    Everything here is about +0200, because every bug in this family hid
    perfectly on a +0000 fixture -- which is what the suite had.
    """

    SHELL = "wp-content/uploads/2026/01/kb-media.php"

    @classmethod
    def _line(cls, ip, day, hour, uri, status):
        return (f'{ip} - - [0{day}/Jan/2026:{hour:02d}:00:00 +0200] '
                f'"GET {uri} HTTP/1.1" {status} 512 "-" "curl/8"\n')

    @classmethod
    def setUpClass(cls):
        from server.engines import logindex, webshell
        root = Path(tempfile.mkdtemp(prefix="shellhound-chaintz-"))
        cls.root = root
        cls.case = root / "case"
        cls.case.mkdir()
        webroot = root / "webroot"
        logs = root / "logs"
        logs.mkdir()
        shell = webroot / cls.SHELL
        shell.parent.mkdir(parents=True, exist_ok=True)
        shell.write_text("<?php\n@system($_GET['cmd']);\n", encoding="utf-8")

        rows = []
        for hour in (7, 12, 18):
            rows.append(cls._line("192.0.2.10", 5, hour, "/", 200))
            rows.append(cls._line("192.0.2.10", 7, hour, "/", 200))
        # The failed probe an hour BEFORE the first success: the sentence
        # under test names its time.
        rows.append(cls._line("203.0.113.42", 6, 8, "/" + cls.SHELL, 404))
        rows.append(cls._line("203.0.113.42", 6, 9, "/" + cls.SHELL, 200))
        (logs / "access.log").write_text("".join(rows), encoding="utf-8")

        conn = db.connect(cls.case)
        for kind, path in (("webroot", webroot), ("access_logs", logs)):
            conn.execute("INSERT OR IGNORE INTO evidence (kind, path, added) "
                         "VALUES (?,?,?)", (kind, str(path), db.now()))
        conn.commit()
        conn.close()
        webshell.scan(cls.case, [str(webroot)])
        logindex.build(cls.case, [str(logs)])
        conn = db.connect(cls.case)
        conn.execute("UPDATE findings SET triage = 'confirmed'")
        conn.commit()
        conn.close()

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.root, ignore_errors=True)

    @staticmethod
    def _clock(text):
        import re
        m = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", text or "")
        return m.group(1) if m else None

    def _chain(self, mode):
        from server.chain import case_chain
        return case_chain(self.case, "en", mode)

    def test_prose_and_event_agree_in_utc_mode(self):
        """The sentence about the earlier probe used to be two hours off from
        the timestamp of the very event it hangs on."""
        from datetime import datetime, timezone
        chain = self._chain("utc")
        event = next(e for e in chain["events"]
                     if "kb-media" in e["title"] and self._clock(e["detail"]))
        # The failed probe was 08:00 +0200 = 06:00 UTC; the success 09:00
        # +0200 = 07:00 UTC. The prose names the first, the event the second.
        self.assertEqual("2026-01-06 06:00:00", self._clock(event["detail"]))
        self.assertEqual("2026-01-06 07:00:00",
                         datetime.fromtimestamp(event["at"], tz=timezone.utc)
                         .strftime("%Y-%m-%d %H:%M:%S"))

    def test_prose_and_event_agree_in_log_mode(self):
        from datetime import datetime, timezone
        chain = self._chain("log")
        event = next(e for e in chain["events"]
                     if "kb-media" in e["title"] and self._clock(e["detail"]))
        self.assertEqual("2026-01-06 08:00:00", self._clock(event["detail"]))
        self.assertEqual("2026-01-06 09:00:00",
                         datetime.fromtimestamp(event["at"], tz=timezone.utc)
                         .strftime("%Y-%m-%d %H:%M:%S"))

    def test_the_two_modes_stay_exactly_the_offset_apart(self):
        """The property behind both: switching the toggle moves every
        timestamp by the offset and by nothing else."""
        log_events = {e["title"]: e["at"] for e in self._chain("log")["events"]}
        utc_events = {e["title"]: e["at"] for e in self._chain("utc")["events"]}
        self.assertEqual(set(log_events), set(utc_events),
                         "the toggle changed WHICH events exist")
        for title, at in log_events.items():
            self.assertEqual(7200, at - utc_events[title], title)

    def test_the_gap_note_names_the_span_it_describes(self):
        for mode, expect in (("log", "2026-01-05 07:00:00"),
                             ("utc", "2026-01-05 05:00:00")):
            chain = self._chain(mode)
            dated = [g for g in chain["gaps"] if self._clock(g)]
            if not dated:
                continue
            self.assertEqual(expect, self._clock(dated[0]),
                             f"{mode} mode: the note disagrees with the span")


class ChainAccountWindowTests(unittest.TestCase):
    """Which accounts belong to the case must not depend on a DISPLAY toggle.

    The window came from the log period and followed the mode; the dump
    timestamps are naive wall-clock readings and followed nothing. Near the
    edges, switching to UTC therefore added or dropped created accounts.
    """

    DUMP = """CREATE TABLE `wp_users` (
  `ID` bigint NOT NULL,
  `user_login` varchar(60) NOT NULL,
  `user_pass` varchar(255) NOT NULL,
  `user_nicename` varchar(50) NOT NULL,
  `user_email` varchar(100) NOT NULL,
  `user_url` varchar(100) NOT NULL,
  `user_registered` datetime NOT NULL,
  `user_activation_key` varchar(255) NOT NULL,
  `user_status` int NOT NULL,
  `display_name` varchar(250) NOT NULL
);
INSERT INTO `wp_users` VALUES
(1,'edge','x','edge','e@example.test','','2026-01-05 06:00:00','',0,'Edge'),
(2,'inside','x','inside','i@example.test','','2026-01-06 12:00:00','',0,'In');
"""

    @classmethod
    def setUpClass(cls):
        from server.engines import logindex, sqldump
        root = Path(tempfile.mkdtemp(prefix="shellhound-acctwin-"))
        cls.root = root
        cls.case = root / "case"
        cls.case.mkdir()
        logs = root / "logs"
        logs.mkdir()
        rows = []
        for day, hour in ((5, 7), (5, 18), (7, 12), (7, 18)):
            rows.append(f'192.0.2.10 - - [0{day}/Jan/2026:{hour:02d}:00:00 '
                        f'+0200] "GET / HTTP/1.1" 200 5 "-" "curl"\n')
        (logs / "access.log").write_text("".join(rows), encoding="utf-8")
        dump = root / "dump.sql"
        dump.write_text(cls.DUMP, encoding="utf-8")
        conn = db.connect(cls.case)
        for kind, path in (("access_logs", logs), ("sql_dump", dump)):
            conn.execute("INSERT OR IGNORE INTO evidence (kind, path, added) "
                         "VALUES (?,?,?)", (kind, str(path), db.now()))
        conn.commit()
        conn.close()
        logindex.build(cls.case, [str(logs)])
        sqldump.scan(cls.case, [str(dump)])
        conn = db.connect(cls.case)
        conn.execute("UPDATE findings SET triage = 'confirmed'")
        conn.commit()
        conn.close()

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.root, ignore_errors=True)

    def _accounts(self, mode):
        from server.chain import case_chain
        return sorted(e["title"] for e in case_chain(self.case, "en", mode)
                      ["events"] if e["kind"] == "konto")

    def test_the_same_accounts_in_both_modes(self):
        self.assertEqual(self._accounts("log"), self._accounts("utc"),
                         "a display toggle changed which accounts belong "
                         "to the case")

    def test_an_account_inside_the_period_is_there_at_all(self):
        """The guard against making both modes equally empty."""
        self.assertTrue(any("inside" in a for a in self._accounts("log")))


class ChainUndatedTests(unittest.TestCase):
    """A confirmed file whose only log lines carry unreadable timestamps.

    The index keeps those at epoch 0 rather than dropping the request, so
    `hits` existed while not one of them had a time -- and `min()` over the
    empty result took the whole chronology down, not just the one event.
    """

    @classmethod
    def setUpClass(cls):
        from server.engines import logindex, webshell
        root = Path(tempfile.mkdtemp(prefix="shellhound-undated-"))
        cls.root = root
        cls.case = root / "case"
        cls.case.mkdir()
        webroot = root / "webroot"
        logs = root / "logs"
        logs.mkdir()
        rel = "wp-content/uploads/2026/01/kb-media.php"
        shell = webroot / rel
        shell.parent.mkdir(parents=True, exist_ok=True)
        shell.write_text("<?php\n@system($_GET['cmd']);\n", encoding="utf-8")
        rows = [f'203.0.113.9 - - [06/Xxx/2026:08:00:00 +0200] '
                f'"GET /{rel} HTTP/1.1" 200 5 "-" "curl"\n']
        for hour in (9, 10, 11):
            rows.append(f'192.0.2.10 - - [06/Jan/2026:{hour}:00:00 +0200] '
                        f'"GET / HTTP/1.1" 200 5 "-" "curl"\n')
        (logs / "access.log").write_text("".join(rows), encoding="utf-8")
        conn = db.connect(cls.case)
        for kind, path in (("webroot", webroot), ("access_logs", logs)):
            conn.execute("INSERT OR IGNORE INTO evidence (kind, path, added) "
                         "VALUES (?,?,?)", (kind, str(path), db.now()))
        conn.commit()
        conn.close()
        webshell.scan(cls.case, [str(webroot)])
        logindex.build(cls.case, [str(logs)])
        conn = db.connect(cls.case)
        conn.execute("UPDATE findings SET triage = 'confirmed'")
        conn.commit()
        conn.close()

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_the_chronology_is_produced_at_all(self):
        from server.chain import case_chain
        chain = case_chain(self.case, "en", "log")     # used to raise
        self.assertIsInstance(chain["events"], list)

    def test_the_file_is_named_as_undated_rather_than_dropped(self):
        """Every confirmed artifact has to show up somewhere -- one that
        quietly disappears is the more dangerous half of a lie."""
        from server.chain import case_chain
        chain = case_chain(self.case, "en", "log")
        self.assertTrue(any("kb-media" in u["artifact"]
                            for u in chain["undated"]))


class SigmaTranslationTests(unittest.TestCase):
    """Four ways a loaded SIGMA rule could not fire.

    All four shared a shape: the rule parsed, the catalogue listed it, the
    switch showed it as on -- and it could never match. That is the object the
    module's own docstring calls the worst one in a forensic tool, because it
    looks like evidence of absence.

    Every test runs the compiled SQL against a real index rather than
    asserting on the generated string: what matters is what comes back.
    """

    @classmethod
    def setUpClass(cls):
        from server import sigma
        cls.sigma = sigma
        cls.conn = sqlite3.connect(":memory:")
        cls.conn.row_factory = sqlite3.Row
        cls.conn.executescript("""
        CREATE TABLE strings (id INTEGER PRIMARY KEY, text TEXT);
        CREATE TABLE ips (id INTEGER PRIMARY KEY, ip TEXT);
        CREATE TABLE requests (id INTEGER PRIMARY KEY, uri INT, agent INT,
                               ip INT, method TEXT, status INT, epoch INT);
        INSERT INTO strings VALUES (1, '/shell.php?cmd=id'), (2, '/index.php'),
                                   (3, 'curl/8');
        INSERT INTO ips VALUES (1, '203.0.113.5');
        INSERT INTO requests VALUES (1, 1, 3, 1, 'GET', 200, 1780000000),
                                    (2, 2, 3, 1, 'GET', 200, 1780000005),
                                    (3, 2, NULL, 1, 'POST', 404, 1780000009);
        """)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()

    def _hits(self, rule):
        meta, where, params = self.sigma.compile_rule(rule)
        return len(self.sigma.clients_matching(self.conn, where, params))

    def _rule(self, detection):
        return ("id: t\ntitle: t\nlevel: high\ndetection:\n" + detection)

    def test_a_trailing_wildcard_is_a_prefix_match(self):
        """`*` was compared as the character it is, so every rule written the
        way the SIGMA repository writes them matched nothing."""
        self.assertEqual(1, self._hits(self._rule(
            "  sel:\n    c-uri: '/shell.php*'\n  condition: sel\n")))

    def test_a_single_character_wildcard_matches_one_character(self):
        self.assertEqual(1, self._hits(self._rule(
            "  sel:\n    c-uri: '/inde?.php'\n  condition: sel\n")))

    def test_a_literal_percent_is_still_literal(self):
        """URLs are full of `%`. It must not become a wildcard just because
        SQL would read it as one."""
        self.assertEqual(0, self._hits(self._rule(
            "  sel:\n    c-uri: '%'\n  condition: sel\n")))

    def test_an_escaped_asterisk_is_a_literal_asterisk(self):
        self.assertEqual(0, self._hits(self._rule(
            "  sel:\n    c-uri: '/shell.php\\\\*'\n  condition: sel\n")))

    def test_and_binds_tighter_than_or(self):
        """`a or b and c` with a true and c false. SIGMA reads it as
        `a or (b and c)` and must fire; left-to-right reads `(a or b) and c`
        and stays silent."""
        self.assertEqual(1, self._hits(self._rule(
            "  a:\n    c-uri|contains: '/shell.php'\n"
            "  b:\n    c-uri|contains: '/never'\n"
            "  c:\n    cs-method: POST\n"
            "  condition: a or b and c\n")))

    def test_brackets_still_override_the_precedence(self):
        self.assertEqual(0, self._hits(self._rule(
            "  a:\n    c-uri|contains: '/shell.php'\n"
            "  b:\n    c-uri|contains: '/never'\n"
            "  c:\n    cs-method: POST\n"
            "  condition: (a or b) and c\n")))

    def test_the_stem_ignores_the_query_string(self):
        """`cs-uri-stem` is the PATH. `/shell.php?cmd=id` has the stem
        `/shell.php`, and a rule about the stem must not be defeated by
        whatever the attacker hung off the end."""
        self.assertEqual(1, self._hits(self._rule(
            "  sel:\n    cs-uri-stem: '/shell.php'\n  condition: sel\n")))

    def test_the_stem_endswith_ignores_the_query_string_too(self):
        self.assertEqual(1, self._hits(self._rule(
            "  sel:\n    cs-uri-stem|endswith: '.php'\n  condition: sel\n")))

    def test_the_query_field_sees_only_the_query(self):
        self.assertEqual(1, self._hits(self._rule(
            "  sel:\n    c-uri-query: 'cmd=id'\n  condition: sel\n")))

    def test_a_null_field_matches_the_requests_that_lack_it(self):
        """`field: null` means ABSENT. `column = NULL` is never true, so the
        rule loaded and could not fire."""
        self.assertEqual(1, self._hits(self._rule(
            "  sel:\n    c-useragent: null\n  condition: sel\n")))

    def test_the_refusals_still_refuse(self):
        """The fixes must not have widened what this backend claims to
        answer -- an unsupported rule is still rejected at load."""
        for detection, why in (
            ("  sel:\n    c-uri|re: '.*'\n  condition: sel\n", "|re"),
            ("  sel:\n    nonesuch: 'x'\n  condition: sel\n", "unknown field"),
            ("  sel:\n    c-uri: 'x'\n  timeframe: 5m\n  condition: sel\n",
             "timeframe"),
        ):
            with self.assertRaises(self.sigma.SigmaError, msg=why):
                self.sigma.compile_rule(self._rule(detection))


class CmsDirPhpTests(unittest.TestCase):
    """A PHP file lying DIRECTLY in a directory the CMS owns.

    Joomla puts nothing there: a template is `templates/<name>/...`, a module
    `modules/mod_<name>/...`, a plugin `plugins/<group>/<name>/...`. A bare
    `.php` one level in is not a shape the CMS ships.

    Nothing reported it. On a compromised Joomla the log held
    `/templates/x.php` answered 2xx five times -- the post-compromise
    phase of the intrusion, and every view of the case was silent about it.
    Widening the upload-directory rule to cover these four folders was the
    obvious move and the wrong one: measured on that webroot it would have
    added 29 findings about vendor autoloaders and CHANGELOG.php against the
    one real hit. THE DEPTH is what carries the claim -- 615 PHP files under
    those four directories, not one of them directly inside.
    """

    def _alerts(self, *uris):
        import shutil
        from datetime import datetime, timedelta, timezone
        from server.engines import logindex
        case = Path(tempfile.mkdtemp(prefix="shellhound-cmsdir-"))
        logs = Path(tempfile.mkdtemp(prefix="shellhound-cmsdirlogs-"))
        self.addCleanup(shutil.rmtree, case, True)
        self.addCleanup(shutil.rmtree, logs, True)
        db.connect(case).close()
        when = datetime(2026, 1, 5, 8, 0, tzinfo=timezone.utc)
        rows = []
        for i, (uri, status) in enumerate(uris):
            stamp = (when + timedelta(seconds=i * 5)).strftime(
                "%d/%b/%Y:%H:%M:%S +0000")
            rows.append(f'192.0.2.7 - - [{stamp}] "GET {uri} HTTP/1.1" '
                        f'{status} 512 "-" "Mozilla/5.0"\n')
        (logs / "access.log").write_text("".join(rows), encoding="utf-8")
        logindex.build(case, [str(logs)])
        conn = sqlite3.connect(db.log_db_path(case))
        try:
            return {row[0] for row in conn.execute(
                "SELECT kind FROM alerts")}
        finally:
            conn.close()

    def test_a_bare_php_in_templates_answered_2xx_is_reported(self):
        self.assertIn("cms_dir_php",
                      self._alerts(("/templates/x.php", 200)))

    def test_the_shape_the_cms_actually_ships_is_not(self):
        """One directory deeper is where every legitimate template, module
        and plugin file lives. A rule that fired here would bury itself."""
        self.assertNotIn("cms_dir_php", self._alerts(
            ("/templates/cassiopeia/index.php", 200),
            ("/modules/mod_menu/mod_menu.php", 200),
            ("/plugins/system/cache/cache.php", 200),
            ("/components/com_content/content.php", 200),
            ("/administrator/components/com_akeeba/restore.php", 200)))

    def test_a_probe_that_found_nothing_is_not_an_incident(self):
        """The outcome gate the whole engine works by: a 404 means the file
        was not there, and a scanner asking for it proves nothing."""
        self.assertNotIn("cms_dir_php",
                         self._alerts(("/plugins/shell.php", 404)))

    def test_a_query_string_does_not_hide_the_path(self):
        self.assertIn("cms_dir_php",
                      self._alerts(("/templates/x.php?cmd=id", 200)))


class ActorTagTests(unittest.TestCase):
    """The tags a collected client carries out of the tool.

    `login_redirects` proves NOTHING. Joomla answers every login POST with a
    303 -- right credentials or wrong, it is a plain POST-Redirect-GET. The
    engine used to read that as a break-in, stopped, and gates on `admin_ok`
    instead: a 2xx on the backend itself, which an unauthenticated session
    does not get.

    The collector did not follow, and went on tagging clients "successful"
    that the case no longer accused. A tag on an indicator LEAVES THE
    MACHINE: it travels into the CSV, the JSON and the STIX bundle, where
    nobody can see which gate produced it.

    The real defect was that two places decided one thing. It is one function
    now, and this asks it about shapes rather than about a case -- the
    fixture that would have caught this has no login traffic at all, so an
    end-to-end test of it passed while saying nothing.
    """

    THRESHOLD = 30

    def _tags(self, **actor):
        base = {"scanner_uas": "[]", "login_posts": 0, "login_redirects": 0,
                "admin_ok": 0, "login_burst": 0}
        return set(ioclib.actor_tags({**base, **actor}, self.THRESHOLD))

    def test_a_redirect_alone_is_not_a_successful_login(self):
        """The site's own administrator: signs in every day, gets a redirect
        every time, and never once broke in."""
        self.assertNotIn(ioclib.TAG_SUCCESS,
                         self._tags(login_posts=200, login_redirects=200))

    def test_a_2xx_on_the_backend_after_a_burst_is(self):
        self.assertIn(ioclib.TAG_SUCCESS,
                      self._tags(login_posts=200, login_redirects=200,
                                 login_burst=70, admin_ok=3))

    def test_a_2xx_on_the_backend_without_a_burst_is_not(self):
        """The gap this class had and locked in. Pulling the decision out of
        the endpoint fixed the gate that had drifted and left this one WIDER
        than the alert beside it -- `admin_ok` alone, no flood, no burst. So
        an operator who never attracted a single finding still went into the
        box tagged "successful", and a tag on an indicator leaves the machine
        in the CSV, the JSON and the STIX bundle.

        Two hundred sign-ins over nine weeks, never more than a handful in
        any one day, and the backend answered them all -- because they are
        the administrator."""
        self.assertNotIn(ioclib.TAG_SUCCESS,
                         self._tags(login_posts=200, login_burst=6,
                                    admin_ok=344))

    def test_the_flood_is_counted_separately_from_the_success(self):
        """Two different statements. A flood that got nowhere is still a
        flood, and it must not imply the other."""
        flood = self._tags(login_posts=self.THRESHOLD)
        self.assertIn(ioclib.TAG_BRUTE, flood)
        self.assertNotIn(ioclib.TAG_SUCCESS, flood)

    def test_the_threshold_includes_its_own_value(self):
        self.assertNotIn(ioclib.TAG_BRUTE,
                         self._tags(login_posts=self.THRESHOLD - 1))

    def test_a_scanner_sighting_says_scanner_and_nothing_else(self):
        tags = self._tags(scanner_uas='["Nikto/2.5.0"]')
        self.assertEqual({ioclib.TAG_ACTOR, ioclib.TAG_SCANNER}, tags)

    def test_an_ordinary_visitor_carries_only_that_it_is_one(self):
        self.assertEqual({ioclib.TAG_ACTOR}, self._tags())


class UnknownResponseSizeTests(unittest.TestCase):
    """A dash in the size field is not a zero, and the export said it was.

    `-` means the server did not record how much it sent. It is not rare:
    measured on a real log, 23,859 of 1,188,820 requests carry one — 2.0 % —
    and 1,079 of those were answered 2xx, where a body certainly went out.
    The same log contains NOT ONE genuine zero, so every `0` the trace export
    printed in that column was false.

    Coerced at parse time the dash became a measured number, and a measured
    number in an exhibit is quotable. "This request returned nothing" is the
    opposite of what the log said, which was "I did not write it down".
    """

    def _index(self, *sizes):
        import shutil
        from server.engines import logindex
        root = Path(tempfile.mkdtemp(prefix="shellhound-size-"))
        self.addCleanup(shutil.rmtree, root, True)
        case, logs = root / "case", root / "logs"
        case.mkdir()
        logs.mkdir()
        (logs / "a.log").write_text("".join(
            f'192.0.2.{i + 1} - - [05/Jan/2026:08:00:0{i} +0000] '
            f'"GET /x HTTP/1.1" 200 {s} "-" "M"\n'
            for i, s in enumerate(sizes)), encoding="utf-8")
        db.connect(case).close()
        logindex.build(case, [str(logs)])
        return case

    def _rows(self, case):
        conn = sqlite3.connect(db.log_db_path(case))
        try:
            return [r[0] for r in conn.execute(
                "SELECT size FROM requests ORDER BY epoch")]
        finally:
            conn.close()

    def test_a_dash_is_unknown_and_not_zero(self):
        self.assertEqual([None], self._rows(self._index("-")))

    def test_a_real_zero_survives_as_a_zero(self):
        """The other half. A server that genuinely wrote 0 said something,
        and turning THAT into unknown would lose a measurement."""
        self.assertEqual([0], self._rows(self._index("0")))

    def test_the_byte_total_counts_only_what_was_recorded(self):
        case = self._index("100", "-", "200", "-")
        conn = sqlite3.connect(db.log_db_path(case))
        try:
            got = list(conn.execute(
                "SELECT SUM(bytes), SUM(bytes_unknown) FROM actors"))[0]
        finally:
            conn.close()
        self.assertEqual((300, 2), got,
                         "an unrecorded size was averaged in as zero")

    def test_the_trace_hands_the_export_an_unknown_and_not_a_zero(self):
        """The whole point, at the seam the export reads from. `trace` is
        what the CSV writer iterates, so if a dash arrives here as 0 the
        exhibit asserts that nothing came back -- and no formatting fix
        downstream can recover what the parser already threw away."""
        from server.engines import logindex
        case = self._index("-", "4096")
        rows = logindex.trace(case, ["192.0.2.1", "192.0.2.2"])["rows"]
        by_client = {r["client"]: r["size"] for r in rows}
        self.assertIsNone(by_client["192.0.2.1"])
        self.assertEqual(4096, by_client["192.0.2.2"])


class WordPressAuthenticatedAreaTests(unittest.TestCase):
    """The only HIGH log rule about a break-in could not fire on WordPress.

    `wp-login.php` is a recognised login endpoint, so the flood half worked
    normally. The success half was spelled in Joomla's URL grammar alone --
    `/administrator/index.php?option=com_...` -- and no WordPress admin URL
    matches it. On the most widely deployed CMS there is, the case reported a
    login flood at MEDIUM and stopped.

    THE EXCLUSIONS ARE THE RULE. `wp-admin/admin.php` calls `auth_redirect()`,
    so its pages answer an unauthenticated request with a 302 -- but a good
    part of `wp-admin/` is reachable without a session by design, and one
    piece of it is loaded by every single visitor to the login page:
    `wp-login.php` pulls `/wp-admin/css/login.min.css`. A rule that took any
    2xx under `/wp-admin/` as proof would have read that stylesheet as a
    guessed password, which is the bug this rule was just fixed for.
    """

    SESSION_ONLY = (
        "/wp-admin/",
        "/wp-admin/index.php",
        "/wp-admin/users.php",
        "/wp-admin/user-new.php",
        "/wp-admin/post.php?post=1&action=edit",
        "/wp-admin/options.php",
        "/wp-admin/network/sites.php",
        "/wp-admin/user/profile.php",
    )

    NO_SESSION_NEEDED = (
        "/wp-admin/admin-ajax.php?action=contact_form",
        "/wp-admin/admin-post.php?action=x",
        "/wp-admin/load-scripts.php?load=jquery",
        "/wp-admin/load-styles.php?load=buttons",
        "/wp-admin/install.php",
        "/wp-admin/upgrade.php",
        "/wp-admin/setup-config.php",
        "/wp-admin/async-upload.php",
        "/wp-admin/css/login.min.css",
        "/wp-admin/js/common.min.js",
        "/wp-admin/images/wordpress-logo.svg",
        "/wp-admin/includes/file.php",
        "/wp-admin/maint/repair.php",
        "/wp-json/wp/v2/users",
    )

    def _line(self, when, uri, method="GET", status=200):
        from datetime import datetime, timedelta, timezone
        stamp = (datetime(2026, 1, 5, tzinfo=timezone.utc)
                 + timedelta(seconds=when)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        return (f'192.0.2.7 - - [{stamp}] "{method} {uri} HTTP/1.1" '
                f'{status} 512 "-" "Mozilla/5.0"\n')

    def _after_a_flood(self, *tail):
        """Seventy POSTs to wp-login.php in half an hour, then `tail`."""
        import shutil
        from server.engines import logindex
        root = Path(tempfile.mkdtemp(prefix="shellhound-wp-"))
        self.addCleanup(shutil.rmtree, root, True)
        case, logs = root / "case", root / "logs"
        case.mkdir()
        logs.mkdir()
        lines = [self._line(i * 25, "/wp-login.php", "POST", 200)
                 for i in range(70)]
        lines += list(tail)
        (logs / "a.log").write_text("".join(lines), encoding="utf-8")
        db.connect(case).close()
        logindex.build(case, [str(logs)])
        conn = sqlite3.connect(db.log_db_path(case))
        try:
            kinds = {r[0] for r in conn.execute("SELECT kind FROM alerts")}
            ok = conn.execute("SELECT MAX(admin_ok) FROM actors").fetchone()[0]
        finally:
            conn.close()
        return kinds, ok

    def test_a_wordpress_flood_that_reached_the_backend_is_a_break_in(self):
        kinds, ok = self._after_a_flood(
            self._line(2000, "/wp-admin/users.php"),
            self._line(2010, "/wp-admin/user-new.php"))
        self.assertEqual(2, ok)
        self.assertIn("login_success", kinds,
                      "a WordPress break-in went unreported")

    def test_a_wordpress_flood_that_never_got_in_is_only_a_flood(self):
        kinds, ok = self._after_a_flood()
        self.assertEqual(0, ok)
        self.assertIn("login_flood", kinds)
        self.assertNotIn("login_success", kinds)

    def test_the_pages_served_without_a_session_prove_nothing(self):
        """The guard that stops this fix from re-creating the bug the
        redirect version had. Each of these answers 2xx to a client that
        never logged in."""
        for uri in self.NO_SESSION_NEEDED:
            with self.subTest(uri=uri):
                kinds, ok = self._after_a_flood(
                    *[self._line(2000 + i, uri) for i in range(6)])
                self.assertEqual(0, ok, uri)
                self.assertNotIn("login_success", kinds, uri)

    def test_every_page_that_needs_one_counts(self):
        for uri in self.SESSION_ONLY:
            with self.subTest(uri=uri):
                _kinds, ok = self._after_a_flood(self._line(2000, uri))
                self.assertEqual(1, ok, uri)

    def test_a_redirect_out_of_the_backend_is_not_a_2xx(self):
        """The outcome gate, not the URL, is what decides. An anonymous
        request to /wp-admin/ is answered with a 302 to the login page."""
        kinds, ok = self._after_a_flood(
            self._line(2000, "/wp-admin/", status=302))
        self.assertEqual(0, ok)
        self.assertNotIn("login_success", kinds)

    def test_adding_a_second_cms_did_not_widen_the_first(self):
        from server.engines import logindex
        self.assertTrue(logindex.AUTHENTICATED_AREA_RE.search(
            "/administrator/index.php?option=com_content&view=articles"))
        self.assertFalse(logindex.AUTHENTICATED_AREA_RE.search(
            "/administrator/index.php?option=com_login"))
        self.assertFalse(logindex.WP_AUTHENTICATED_AREA_RE.search(
            "/administrator/index.php?option=com_content"))


class LoginBurstTests(unittest.TestCase):
    """The site's own administrator, reported at HIGH as a break-in.

    Thirty login POSTs with no window is a threshold on how long somebody
    kept their logs, not on how anybody behaved. One operator, one office
    address, one sign-in every working morning, each answered on the first
    try:

        log covers 6 days   ~4 logins   nothing, correctly
        log covers 6 weeks  ~30         a flood, MEDIUM
        log covers 9 weeks  ~46         plus a possible break-in, HIGH

    Nothing about the site changed. The finding appeared because the case
    covers a longer period.

    `admin_ok` was the previous correction and it was right: a redirect
    proves nothing, a 2xx on the backend proves somebody got in. But it
    cannot say WHO, and the operator matches it precisely BECAUSE they are
    the operator. What the two do not share is the shape of the attempts
    before the success -- a burst, or a working habit.

    The MEDIUM flood is deliberately left alone. Removing it was measured at
    ten of thirteen real flood findings, because slow credential stuffing
    looks exactly like a long-running operator in count-per-window terms;
    and since the rate landed in its sentence the flood no longer says
    anything untrue.
    """

    def _case(self, *lines):
        import shutil
        from server.engines import logindex
        root = Path(tempfile.mkdtemp(prefix="shellhound-burst-"))
        self.addCleanup(shutil.rmtree, root, True)
        case, logs = root / "case", root / "logs"
        case.mkdir()
        logs.mkdir()
        (logs / "a.log").write_text("".join(lines), encoding="utf-8")
        db.connect(case).close()
        logindex.build(case, [str(logs)])
        conn = sqlite3.connect(db.log_db_path(case))
        try:
            kinds = {r[0] for r in conn.execute("SELECT kind FROM alerts")}
            burst = conn.execute(
                "SELECT MAX(login_burst) FROM actors").fetchone()[0]
        finally:
            conn.close()
        return kinds, burst

    def _line(self, when, uri="/administrator/index.php?option=com_login",
              method="POST", status=303):
        from datetime import datetime, timedelta, timezone
        stamp = (datetime(2026, 1, 5, tzinfo=timezone.utc)
                 + timedelta(seconds=when)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        return (f'192.0.2.7 - - [{stamp}] "{method} {uri} HTTP/1.1" '
                f'{status} 512 "-" "Mozilla/5.0"\n')

    BACKEND = "/administrator/index.php?option=com_content&view=articles"

    def test_the_operator_of_the_site_is_not_a_break_in(self):
        """Forty-six sign-ins over nine weeks, every one of them answered,
        and the backend used afterwards -- because it is their backend."""
        lines = []
        for day in range(46):
            at = day * 86400 + 8 * 3600
            lines.append(self._line(at))
            lines.append(self._line(at + 60, self.BACKEND, "GET", 200))
        kinds, burst = self._case(*lines)
        self.assertIn("login_flood", kinds, "the flood itself still holds")
        self.assertNotIn("login_success", kinds,
                         "the site's own operator was reported as a break-in")
        self.assertEqual(1, burst, "a working habit is not a burst")

    def test_a_burst_that_got_in_still_is(self):
        """The case the rule exists for: seventy attempts inside an hour,
        then the backend answers."""
        lines = [self._line(i * 30) for i in range(70)]
        lines += [self._line(70 * 30 + 60, self.BACKEND, "GET", 200)]
        kinds, burst = self._case(*lines)
        self.assertIn("login_flood", kinds)
        self.assertIn("login_success", kinds, "a real break-in went unreported")
        self.assertEqual(70, burst)

    def test_a_burst_that_never_got_in_is_only_a_flood(self):
        """The previous correction, still holding: without a 2xx on the
        backend there is nothing to say a password was guessed."""
        kinds, _burst = self._case(*[self._line(i * 30) for i in range(70)])
        self.assertIn("login_flood", kinds)
        self.assertNotIn("login_success", kinds)

    def test_the_window_does_not_move_with_the_length_of_the_log(self):
        """The whole complaint in one assertion: the same behaviour, twice
        as much of it, must not change what the case concludes."""
        def habit(days):
            lines = []
            for day in range(days):
                at = day * 86400 + 8 * 3600
                lines.append(self._line(at))
                lines.append(self._line(at + 60, self.BACKEND, "GET", 200))
            return self._case(*lines)[0]
        self.assertNotIn("login_success", habit(31))
        self.assertNotIn("login_success", habit(62))


class Helix3PatternTests(unittest.TestCase):
    """The second pattern the toolkit ships, and the trap beside it.

    A bundled pattern runs on EVERY installation, so a false positive here
    does not cost one analyst a look -- it costs all of them a filled work
    list. Measured on a real site that has the Helix3 template installed,
    1.19 million log lines:

        plugin=helix3        1 URI          3 clients
        helix3              11 URIs    11,183 clients   <- every visitor
        option=com_ajax       8 URIs        29 clients   <- Joomla core

    The gap between the right token and the obvious wrong one is three
    against eleven thousand, and it is the whole reason the entry is one
    token and not the template's name.
    """

    ENTRY = "joomla-helix3-comajax"

    def _entry(self):
        from server import patterns
        for row in patterns.bundled():
            if row["id"] == self.ENTRY:
                return row
        self.fail(f"{self.ENTRY} does not ship")

    def _clients(self, *uris):
        import shutil
        from server.engines import logindex
        root = Path(tempfile.mkdtemp(prefix="shellhound-helix-"))
        self.addCleanup(shutil.rmtree, root, True)
        case, logs = root / "case", root / "logs"
        case.mkdir()
        logs.mkdir()
        (logs / "a.log").write_text("".join(
            f'203.0.113.{i + 1} - - [06/Jan/2026:08:00:00 +0000] '
            f'"GET {u} HTTP/1.1" 200 5 "-" "c"\n'
            for i, u in enumerate(uris)), encoding="utf-8")
        db.connect(case).close()
        logindex.build(case, [str(logs)])
        entry = self._entry()
        out = logindex.match_patterns(case, entry["patterns"], entry["match"])
        return {c["ip"] for c in out["clients"]}

    def test_the_query_order_does_not_decide(self):
        """HTTP query order carries no meaning. The JCE entry was one literal
        string and missed `?task=...&option=...`; this one must not repeat
        it, which is why it is a single token rather than two paths joined."""
        self.assertEqual(4, len(self._clients(
            "/index.php?option=com_ajax&plugin=helix3&format=json",
            "/index.php?plugin=helix3&option=com_ajax&format=json",
            "/index.php?format=json&option=com_ajax&plugin=helix3",
            "/index.php?plugin=helix3&format=raw&option=com_ajax")))

    def test_the_templates_own_assets_are_not_a_hit(self):
        """The 11,183-client trap: every visitor loads these."""
        self.assertEqual(set(), self._clients(
            "/templates/shaper_helix3/css/template.css",
            "/templates/shaper_helix3/js/main.js",
            "/media/templates/site/shaper_helix3/images/logo.png"))

    def test_the_ajax_frame_alone_is_not_a_hit(self):
        """`com_ajax` is Joomla core and is requested in normal operation."""
        self.assertEqual(set(), self._clients(
            "/index.php?option=com_ajax&module=login&format=json",
            "/index.php?option=com_ajax&plugin=privacy&format=json"))

    def test_it_says_what_a_hit_does_not_prove(self):
        """This endpoint answers 200 whether the handler accepted the input
        or refused it, so the outcome gate the hunt applies is meaningless
        here. The description is the only place that can say so."""
        text = self._entry()["description"].lower()
        self.assertIn("200", text)
        self.assertTrue("does not prove" in text or "settles nothing" in text,
                        "the entry does not disclaim its own status code")

    def test_the_name_claims_no_upload(self):
        """It was proposed as "Arbitrary JSON-File Upload". There is no
        upload: the suffix is appended by the template, and one variant
        writes no file at all. The name is inside the finding's rule string
        and therefore inside the fingerprint -- the first release is the only
        cheap moment to get it right."""
        name = self._entry()["name"].lower()
        self.assertNotIn("upload", name)


class ExecutableExtensionNotLastTests(unittest.TestCase):
    """`up.php.json` -- and three engines say nothing, each for its own reason.

    `mod_mime` dispatches on ANY extension present in a name, which is exactly
    why an exploit whose target appends its own suffix writes the file in that
    shape. The server runs it as PHP. The tool did not:

      * the content rules never opened it, because whether to open a file was
        decided on its SUFFIX;
      * the error-log path capture stopped at `.php`, so a fatal naming
        `.../up.php.json` was read as `.../up.php`.

    The second is the worse one and it is not a miss. The stem an attacker
    picks is meant to look plausible, so `up.php` frequently exists beside
    `up.php.json` -- and then the resolver finds it and the tool writes a
    finding onto an innocent file, with evidence naming a path the log never
    contained, printed next to the log line that contradicts it.

    NOT COVERED HERE, deliberately: `DOUBLE_EXT_RE` stays one-directional.
    Making it symmetric costs three HIGH findings on 32-byte checksum
    sidecars in a real webroot, and whether "Double extension disguise" is a
    true thing to say about a hex digest is a judgement, not a measurement.
    """

    def _scan(self, name, body=b"<?php @system($_GET['c']);"):
        import shutil
        from server.engines import webshell
        root = Path(tempfile.mkdtemp(prefix="shellhound-extany-"))
        self.addCleanup(shutil.rmtree, root, True)
        (root / name).write_bytes(body)
        found, skip, _inert = webshell.scan_file(str(root / name),
                                                 root=str(root))
        return [f[0] for f in found], skip

    def test_a_file_the_server_runs_as_php_is_read_as_php(self):
        rules, skip = self._scan("up.php.json")
        self.assertIsNone(skip)
        self.assertIn("webshell.cmd_input", rules)

    def test_the_same_body_under_the_plain_name_is_found_as_before(self):
        """The control: "nothing was found" must not be confusable with "the
        engine never ran"."""
        self.assertIn("webshell.cmd_input", self._scan("up.php")[0])

    def test_the_double_extension_rule_is_left_alone(self):
        """It stays one-directional. Changing its wording to cover both
        directions would orphan every decision made on it."""
        self.assertNotIn("webshell.double_ext", self._scan("up.php.json")[0])
        self.assertIn("webshell.double_ext",
                      self._scan("logo.jpg.php")[0])

    def test_a_name_that_merely_contains_php_is_not_opened(self):
        """`.phpfoo` is not an extension the server dispatches on."""
        rules, skip = self._scan("notes.phpfoo", body=b"<?php @system($_GET['c']);")
        self.assertEqual([], rules)
        self.assertIsNone(skip)

    # --- the error log ---------------------------------------------------

    def _paths(self, message):
        from server.engines import errorlog
        return errorlog.paths_in(message)

    def test_the_whole_name_is_captured_with_its_line(self):
        self.assertEqual(
            [("/var/www/html/up.php.json", 3)],
            self._paths("PHP Fatal error: x in /var/www/html/up.php.json:3"))
        self.assertEqual(
            [("/var/www/html/up.php.json", 3)],
            self._paths("PHP Fatal error: x in /var/www/html/up.php.json "
                        "on line 3"))

    def test_an_ordinary_path_is_unchanged(self):
        self.assertEqual(
            [("/var/www/html/up.php", 3)],
            self._paths("PHP Fatal error: x in /var/www/html/up.php on line 3"))
        self.assertEqual(
            [("/var/www/a.php.b.php", 9)],
            self._paths("PHP Warning: x in /var/www/a.php.b.php on line 9"))

    def test_the_capture_still_stops_at_the_punctuation_around_it(self):
        """A trailing `, referer: ...` is not part of the path, and neither
        is the line number that follows a colon."""
        self.assertEqual(
            [("/var/www/x.php", None)],
            self._paths("PHP Fatal error: x in /var/www/x.php, referer: http://a/"))
        self.assertEqual(
            [("/var/www/x.php", None)],
            self._paths("PHP Fatal error: x in /var/www/x.php (deprecated)"))

    def test_the_finding_lands_on_the_file_the_log_named(self):
        """The sharp one. With `up.php` present beside `up.php.json`, the
        truncated capture resolved to the innocent neighbour and the tool
        made a MEDIUM statement about a file nothing had happened to."""
        import shutil
        from server.engines import errorlog
        case = Path(tempfile.mkdtemp(prefix="shellhound-ghost-"))
        root = Path(tempfile.mkdtemp(prefix="shellhound-ghostroot-"))
        logs = Path(tempfile.mkdtemp(prefix="shellhound-ghostlogs-"))
        for d in (case, root, logs):
            self.addCleanup(shutil.rmtree, d, True)
        (root / "up.php").write_text("<?php\n", encoding="utf-8")
        (root / "up.php.json").write_text("<?php\n", encoding="utf-8")
        (logs / "error.log").write_text(
            "[Mon Jan 05 08:00:00.000000 2026] [php:error] [pid 1] "
            "[client 192.0.2.10:52000] PHP Fatal error:  Uncaught Error in "
            "/var/www/html/up.php.json:3\n", encoding="utf-8")
        conn = db.connect(case)
        try:
            conn.execute("INSERT INTO evidence (kind, path, added) "
                         "VALUES ('webroot', ?, ?)", (str(root), db.now()))
            conn.commit()
        finally:
            conn.close()
        errorlog.scan(case, [str(logs)])
        conn = db.connect(case)
        try:
            names = {Path(r["artifact"]).name for r in db.rows(
                conn, "SELECT artifact FROM findings WHERE source = 'errorlog'")}
        finally:
            conn.close()
        self.assertEqual({"up.php.json"}, names,
                         "the finding names a file the log never mentioned")


class ByteOrderMarkTests(unittest.TestCase):
    """Three bytes at the head of a file, and four things go wrong.

    A byte-order mark is what a file gets from being opened and saved in a
    Windows editor -- an ordinary thing to happen to evidence between the
    server and the analysis machine. `open_text_auto` decoded as plain
    `utf-8`, so the mark survived as U+FEFF at the head of the first line.

    It is not whitespace. `^(?P<ip>\\S+)` ate it into the client address, so
    the actor list gained a client that never existed and a real visitor lost
    its earliest request -- the earliest one, which is what a chronology reads
    first.

    The quiet consequences were worse than the visible one, which is why
    there is a test per consequence rather than one on the client count: an
    error log carrying a mark stopped being RECOGNISED as an error log, so
    every finding it would have produced disappeared without a word, and it
    then entered the access-log index instead -- where the coverage report
    called it truncated, a statement about a file that is not true of it.
    """

    BOM = b"\xef\xbb\xbf"

    def _logs(self, *lines, mark=False, name="access.log"):
        import shutil
        root = Path(tempfile.mkdtemp(prefix="shellhound-bom-"))
        self.addCleanup(shutil.rmtree, root, True)
        body = "".join(lines).encode("utf-8")
        (root / name).write_bytes((self.BOM if mark else b"") + body)
        return root

    ACCESS = (
        '192.0.2.10 - - [05/Jan/2026:08:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "M"\n',
        '192.0.2.10 - - [05/Jan/2026:08:00:05 +0000] "GET /a HTTP/1.1" 200 512 "-" "M"\n',
        '192.0.2.11 - - [05/Jan/2026:08:00:10 +0000] "GET /b HTTP/1.1" 200 512 "-" "M"\n',
    )

    def _clients(self, root):
        from server.engines import logindex
        case = Path(tempfile.mkdtemp(prefix="shellhound-bomcase-"))
        import shutil
        self.addCleanup(shutil.rmtree, case, True)
        db.connect(case).close()
        logindex.build(case, [str(root)])
        conn = sqlite3.connect(db.log_db_path(case))
        try:
            return case, [r[0] for r in conn.execute(
                "SELECT ip FROM ips ORDER BY ip")]
        finally:
            conn.close()

    def test_the_mark_does_not_invent_a_client(self):
        _c, plain = self._clients(self._logs(*self.ACCESS))
        _c, marked = self._clients(self._logs(*self.ACCESS, mark=True))
        self.assertEqual(plain, marked)
        self.assertFalse([ip for ip in marked if ip.startswith("﻿")],
                         "a client address begins with the byte-order mark")

    def test_the_first_visitor_keeps_its_earliest_request(self):
        """The half that is easy to miss: the phantom does not only appear,
        it TAKES a request -- the first one, from the client that made it."""
        from server.engines import logindex
        case, _ips = self._clients(self._logs(*self.ACCESS, mark=True))
        conn = sqlite3.connect(db.log_db_path(case))
        try:
            got = dict(conn.execute(
                "SELECT i.ip, a.requests FROM actors a JOIN ips i "
                "ON i.id = a.ip_id"))
        finally:
            conn.close()
        self.assertEqual(2, got.get("192.0.2.10"),
                         "the first client lost a request to the mark")

    def test_a_compressed_log_is_read_the_same_way(self):
        """The compressed path is a different opener and deserves its own
        assertion -- one default serves both, and only one was measured."""
        import gzip
        import shutil
        root = Path(tempfile.mkdtemp(prefix="shellhound-bomgz-"))
        self.addCleanup(shutil.rmtree, root, True)
        body = self.BOM + "".join(self.ACCESS).encode("utf-8")
        with gzip.open(root / "access.log.gz", "wb") as fh:
            fh.write(body)
        _case, ips = self._clients(root)
        self.assertEqual(["192.0.2.10", "192.0.2.11"], ips)

    ERROR_LINES = {
        "apache": "[Mon Jan 05 08:00:00.000000 2026] [php:error] [pid 1] "
                  "[client 192.0.2.10:52000] PHP Fatal error:  Uncaught "
                  "Error in /var/www/html/x.php:3\n",
        "nginx": "2026/01/05 08:00:00 [error] 1#1: *1 FastCGI sent in stderr: "
                 "\"PHP message: PHP Fatal error:  x in /var/www/html/x.php "
                 "on line 3\" while reading, client: 192.0.2.10\n",
    }

    def test_a_marked_error_log_is_still_an_error_log(self):
        """The finding-losing half. `looks_like_error_log` matches on the
        FIRST line, and the mark sits in front of it."""
        from server.engines import errorlog
        for flavour, line in self.ERROR_LINES.items():
            root = self._logs(line, mark=True, name="error.log")
            self.assertTrue(errorlog.looks_like_error_log(str(root / "error.log")),
                            f"{flavour}: a marked error log is not recognised")

    def test_a_marked_error_log_is_kept_out_of_the_access_log_index(self):
        """And the consequence of the previous one. Unrecognised, the file
        was indexed AS AN ACCESS LOG, where not one line parses -- and the
        coverage report then described it as a log whose head was cut off."""
        from server.engines import accesslog
        from server.engines.fsutil import open_text_auto
        root = self._logs(self.ERROR_LINES["apache"], mark=True, name="error.log")
        self.assertTrue(
            accesslog.sniff_error_log(str(root / "error.log"), open_text_auto),
            "a marked error log would be indexed as an access log")

    def test_an_ordinary_log_is_unchanged(self):
        """utf-8-sig is a superset, and the overwhelmingly common case must
        not move a byte."""
        _c, ips = self._clients(self._logs(*self.ACCESS))
        self.assertEqual(["192.0.2.10", "192.0.2.11"], ips)


class LoginRateTests(unittest.TestCase):
    """A count of login POSTs without the window it ran in.

    The sentence read "92 POSTs against login endpoints" and stopped there.
    On a real case four clients crossed the threshold: 92 POSTs spread over
    twenty-three days, 714 over eight, and two that fired 40 and 32 inside
    the same minute. Same word, same shape of number, and nothing on screen
    told a person signing in apart from a person guessing.

    The THRESHOLD deliberately stays a plain count. Putting a rate into the
    condition would silently drop findings on a case whose logs are thin,
    and a count is what an analyst can check by hand. What was missing was
    not a filter but a fact.
    """

    class _Actor:
        def __init__(self, posts, first, last):
            self.login_posts, self.login_first, self.login_last = (
                posts, first, last)

    def _rate(self, posts, seconds):
        from server.engines import logindex
        return logindex._login_rate(
            self._Actor(posts, 1767582000, 1767582000 + seconds))

    def test_a_burst_and_a_trickle_do_not_read_alike(self):
        self.assertNotEqual(self._rate(40, 71), self._rate(40, 23 * 86400))

    def test_the_rate_is_readable_rather_than_exponential(self):
        """`%g` renders a real burst as `2.03e+03/h`, and a number in that
        shape is one a reader skips -- which is the whole failure this fixes,
        one step further along."""
        fast = self._rate(40, 71)
        self.assertIn("2,028/h", fast)
        self.assertNotIn("e+", fast)

    def test_a_trickle_keeps_the_fraction_that_is_the_statement(self):
        """`0.16/h` IS the finding: somebody signing in now and then."""
        self.assertIn("0.164/h", self._rate(92, 560 * 3600))

    def test_all_in_one_second_is_said_and_not_divided(self):
        """A rate off a zero-length window is a number about the log's
        granularity, not about the client."""
        self.assertEqual("within one second ", self._rate(40, 0))

    def test_without_a_readable_time_it_says_nothing(self):
        """An invented rate would be worse than a missing one."""
        from server.engines import logindex
        self.assertEqual("", logindex._login_rate(self._Actor(40, None, None)))
        self.assertEqual("", logindex._login_rate(self._Actor(40, 0, 0)))

    def test_the_span_uses_one_unit_and_the_biggest_that_fits(self):
        from server.engines import logindex as li
        self.assertEqual("89 s", li._span_words(89))
        self.assertEqual("1 min", li._span_words(90))
        self.assertEqual("59 min", li._span_words(3599))
        self.assertEqual("2 h", li._span_words(5400))
        self.assertEqual("48 h", li._span_words(172799))
        self.assertEqual("2 d", li._span_words(172800))


class DoorwayPageTests(unittest.TestCase):
    """The site's own homepage, replaced, and nothing said so.

    On a compromised Joomla the webroot's `index.php` was 893 KB of a
    foreign-language spam page -- valid HTML, not one `<?` in it. That is the
    most visible fact about the whole case: whoever opens the site does not
    get the site. Every rule stayed quiet, because every rule was looking for
    CODE and there was none.
    """

    PAGE = (b'<!DOCTYPE html>\n<html lang="id">\n'
            b"<head><title>x</title></head>\n"
            b'<body><a href="http://elsewhere.example">buy</a></body>\n'
            b"</html>\n")

    def _rules(self, body, name="index.php"):
        import shutil
        from server.engines import webshell
        root = Path(tempfile.mkdtemp(prefix="shellhound-door-"))
        self.addCleanup(shutil.rmtree, root, True)
        (root / name).write_bytes(body)
        found, _skip, _inert = webshell.scan_file(str(root / name),
                                                  root=str(root))
        return [f[0] for f in found]

    def test_a_php_file_that_is_only_a_page_is_reported(self):
        self.assertIn("webshell.no_php", self._rules(self.PAGE))

    def test_it_is_reported_once_and_not_per_tag(self):
        """A property of the FILE has no line to point at, and the engine
        emits one finding per rule per LINE. Anchored on both `<!DOCTYPE
        html>` and `<html>` the rule produced two findings for one fact, on
        the two lines they happen to sit on -- and the analyst decided twice
        about one file."""
        self.assertEqual(1, self._rules(self.PAGE).count("webshell.no_php"))

    def test_an_ordinary_php_page_is_not(self):
        """Almost every CMS entry point mixes HTML and PHP. If that fired,
        the rule would report the whole webroot."""
        self.assertNotIn("webshell.no_php", self._rules(
            b"<?php defined('_JEXEC') or die; ?>\n" + self.PAGE))

    def test_a_short_tag_is_still_something_to_interpret(self):
        """The absence has to be COMPLETE. A short tag, and even an XML
        prolog, mean the file is read as more than a document."""
        for prefix in (b"<?= $x ?>", b'<?xml version="1.0"?>'):
            self.assertNotIn("webshell.no_php",
                             self._rules(prefix + b"\n" + self.PAGE),
                             prefix.decode())

    def test_a_text_file_carrying_the_extension_is_not_a_page(self):
        """A changelog named .php is a small untidiness, not a doorway -- and
        it was the one other file in that webroot without a `<?`."""
        self.assertNotIn("webshell.no_php", self._rules(
            b"CHANGELOG\n=========\n\n1.2.3  fixed a thing\n",
            name="CHANGELOG.php"))


class DetectOfferTests(unittest.TestCase):
    """The guided scan proposes what is in the folder -- or used to skip it.

    Recognising a CMS cleared the walk list and jumped to the next directory
    to avoid descending through thousands of shipped files. It jumped over
    the dump loop as well, so a database export lying IN the webroot was
    offered nowhere. On a real case that export was 31 MB, publicly
    downloadable, and held the account the intruder had added: the exact
    file the Database view exists for, and the guided flow never named it.
    """

    def _webroot(self, *files):
        import shutil
        from server.engines import detect
        root = Path(tempfile.mkdtemp(prefix="shellhound-detect-"))
        self.addCleanup(shutil.rmtree, root, True)
        (root / "administrator").mkdir()
        (root / "templates").mkdir()
        (root / "media" / "system").mkdir(parents=True)
        (root / "configuration.php").write_text("<?php\n", encoding="utf-8")
        for name in files:
            (root / name).write_text(
                "-- MySQL dump 10.13\n"
                "CREATE TABLE `x` (`a` int);\nINSERT INTO `x` VALUES (1);\n",
                encoding="utf-8")
        return root, detect.scan(str(root))

    def test_a_dump_inside_a_recognised_webroot_is_offered(self):
        root, out = self._webroot("export.sql")
        self.assertEqual([str(root)],
                         [c["path"] for c in out["candidates"]["webroot"]])
        self.assertEqual([str(root / "export.sql")],
                         [c["path"] for c in out["candidates"]["sql_dump"]])

    def test_the_walk_still_stops_at_the_webroot(self):
        """The reason the branch existed is still honoured: a CMS has
        thousands of directories and none of them is a second webroot."""
        root, _ = self._webroot()
        inner = root / "administrator" / "components"
        inner.mkdir(parents=True)
        (inner / "configuration.php").write_text("<?php\n", encoding="utf-8")
        for name in ("administrator", "templates", "media"):
            (inner / name).mkdir()
        from server.engines import detect
        out = detect.scan(str(root))
        self.assertEqual([str(root)],
                         [c["path"] for c in out["candidates"]["webroot"]])


if __name__ == "__main__":
    unittest.main()
