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


if __name__ == "__main__":
    unittest.main()
