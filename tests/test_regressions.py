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


if __name__ == "__main__":
    unittest.main()
