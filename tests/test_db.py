# tests/test_db.py
"""The case database: opening, migrating, and not locking each other out.

The locking test is a regression guard for a real incident: opening a
connection used to write unconditionally, so a read-only request that
arrived while an engine held the write lock died with "database is locked".
It reproduced every time; it must never come back silently.
"""
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from server import db


class ConnectTests(unittest.TestCase):

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix="shellhound-db-"))

    def test_fresh_database_gets_schema_and_version(self):
        conn = db.connect(self.case)
        try:
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'")}
            self.assertIn("findings", tables)
            self.assertIn("iocs", tables)
            version = db.one(
                conn, "SELECT value FROM meta WHERE key = 'schema_version'")
            self.assertEqual(int(version["value"]), db.CASE_SCHEMA_VERSION)
        finally:
            conn.close()

    def test_opening_leaves_no_open_transaction(self):
        """A connection that arrives holding a write transaction turns every
        reader into a writer -- that was one half of the incident."""
        db.connect(self.case).close()
        for _ in range(5):
            conn = db.connect(self.case)
            try:
                self.assertFalse(
                    conn.in_transaction,
                    "connect() must not leave a transaction open")
            finally:
                conn.close()

    def test_opening_an_up_to_date_case_writes_nothing(self):
        """The other half, and the one that actually caused the crash:
        opening must not WRITE. `total_changes` counts rows inserted,
        updated or deleted on this connection -- on a case that is already
        at the current version it has to stay at zero, otherwise every
        read-only request is a writer competing for the lock."""
        db.connect(self.case).close()          # erste Verbindung richtet ein
        for i in range(3):
            conn = db.connect(self.case)
            try:
                self.assertEqual(
                    conn.total_changes, 0,
                    f"open #{i + 1} wrote {conn.total_changes} row(s); opening "
                    f"an up-to-date case must be read-only")
            finally:
                conn.close()

    def test_reads_survive_a_writing_engine(self):
        """The reported crash: an engine holds the write lock, the UI polls
        the job list. Reading must come through.

        The busy timeout is turned down to a fraction of a second on
        purpose. At the production value this test would not fail when the
        bug is present -- it would sit there for two and a half minutes
        waiting the lock out and then pass, which is the least useful thing
        a regression test can do. Short timeout, and a read that has to
        wait at all is a failure."""
        original = db.BUSY_TIMEOUT_MS
        db.BUSY_TIMEOUT_MS = 200
        try:
            db.connect(self.case).close()
            engine = db.connect(self.case)
            engine.execute(
                "INSERT INTO jobs (kind, state, created) "
                "VALUES ('webshell','running',?)", (db.now(),))
            try:
                for i in range(5):
                    conn = db.connect(self.case)
                    try:
                        conn.execute("SELECT count(*) FROM jobs").fetchone()
                    except sqlite3.OperationalError as e:
                        self.fail(
                            f"read {i + 1} died while an engine was writing: {e}")
                    finally:
                        conn.close()
            finally:
                engine.rollback()
                engine.close()
        finally:
            db.BUSY_TIMEOUT_MS = original

    def test_old_database_is_upgraded_once(self):
        """A case from before the versioning: the pending data fix still
        runs, and the version is stamped afterwards so it runs only once."""
        conn = db.connect(self.case)
        conn.execute("DELETE FROM meta WHERE key = 'schema_version'")
        conn.execute(
            "INSERT INTO findings (fingerprint, source, severity, rule,"
            " artifact_kind, artifact, created, last_seen) VALUES"
            " ('fp','logs',?,'Scanner tool User-Agent nikto','client',"
            "'198.51.100.9',?,?)",
            (db.SEV_LOW, db.now(), db.now()))
        conn.commit()
        conn.close()

        conn = db.connect(self.case)
        try:
            row = db.one(conn, "SELECT severity FROM findings WHERE fingerprint = 'fp'")
            self.assertEqual(row["severity"], db.SEV_INFO,
                             "the pending re-grade did not run")
            version = db.one(
                conn, "SELECT value FROM meta WHERE key = 'schema_version'")
            self.assertEqual(int(version["value"]), db.CASE_SCHEMA_VERSION)
        finally:
            conn.close()

    def test_writing_still_works(self):
        conn = db.connect(self.case)
        try:
            db.add_ioc(conn, "203.0.113.42", "ip", ["analyst"])
            conn.commit()
            self.assertEqual(
                conn.execute("SELECT count(*) FROM iocs").fetchone()[0], 1)
        finally:
            conn.close()

    def test_ioc_links_survive_deletion_of_an_endpoint(self):
        conn = db.connect(self.case)
        try:
            a = db.add_ioc(conn, "webroot/shell.php", "path", ["analyst"])
            b = db.add_ioc(conn, "a" * 64, "hash", ["derived"])
            db.link_iocs(conn, b, a, "hash-of")
            conn.commit()
            self.assertEqual(len(db.ioc_links(conn)), 1)
            conn.execute("DELETE FROM ioc_links WHERE src = ? OR dst = ?", (a, a))
            conn.execute("DELETE FROM iocs WHERE id = ?", (a,))
            conn.commit()
            self.assertEqual(db.ioc_links(conn), [],
                             "a link to a deleted indicator must not survive")
        finally:
            conn.close()


class RelativePathTests(unittest.TestCase):
    """What a path indicator says, and what it must not say.

    The value has to be what the WEB SERVER would call the file, because
    that is the only spelling anyone receiving it can look for. Everything
    above the evidence root -- including the root's own folder name -- is a
    fact about the analyst's laptop.
    """

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix="shellhound-relpath-"))
        self.addCleanup(shutil.rmtree, self.case, True)
        conn = db.connect(self.case)
        try:
            conn.execute(
                "INSERT INTO evidence (kind, path, added) VALUES (?,?,?)",
                ("webroot", r"D:\Work\case-42\webroot-copy", db.now()))
            conn.commit()
        finally:
            conn.close()

    def _relative(self, path):
        conn = db.connect(self.case)
        try:
            return db.case_relative_path(conn, path)
        finally:
            conn.close()

    def test_the_evidence_folder_name_is_not_part_of_the_indicator(self):
        self.assertEqual(
            "images/x.phtml",
            self._relative(r"D:\Work\case-42\webroot-copy\images\x.phtml"))

    def test_the_case_of_the_root_does_not_have_to_match(self):
        """Registered with one spelling, walked with another -- Windows hands
        both out for the same directory."""
        self.assertEqual(
            "images/x.phtml",
            self._relative(r"d:/work/CASE-42/Webroot-Copy/images/x.phtml"))

    def test_a_path_below_no_root_is_handed_back_unchanged(self):
        """Better an absolute path than an invented relative one."""
        other = r"D:\Elsewhere\notes.txt"
        self.assertEqual(other, self._relative(other))

    def test_the_root_itself_is_named_by_its_own_folder(self):
        self.assertEqual("webroot-copy",
                         self._relative(r"D:\Work\case-42\webroot-copy"))

    def test_the_more_specific_root_wins(self):
        conn = db.connect(self.case)
        try:
            conn.execute(
                "INSERT INTO evidence (kind, path, added) VALUES (?,?,?)",
                ("webroot", r"D:\Work\case-42", db.now()))
            conn.commit()
        finally:
            conn.close()
        self.assertEqual(
            "images/x.phtml",
            self._relative(r"D:\Work\case-42\webroot-copy\images\x.phtml"))

    def test_an_older_case_is_brought_along(self):
        """A case collected before this changed carries
        `webroot-copy/images/x.phtml` -- no longer absolute, so the
        migration that strips roots walks straight past it. It gets a second
        pass, and the pass has to be idempotent and leave the edges alone."""
        conn = db.connect(self.case)
        try:
            stale = db.add_ioc(conn, "webroot-copy/images/x.phtml", "path",
                               ["confirmed"])
            digest = db.add_ioc(conn, "b" * 64, "hash", ["derived"])
            db.link_iocs(conn, digest, stale, "hash-of")
            conn.execute("UPDATE meta SET value = '3' "
                         "WHERE key = 'schema_version'")
            conn.commit()
        finally:
            conn.close()

        for _ in range(2):
            conn = db.connect(self.case)
            try:
                values = [r[0] for r in conn.execute(
                    "SELECT value FROM iocs WHERE type = 'path'")]
                self.assertEqual(["images/x.phtml"], values)
                self.assertEqual(1, len(db.ioc_links(conn)))
            finally:
                conn.close()

    def test_a_collision_leaves_the_older_entry_alone(self):
        """Two spellings of one file, and the target already taken. Losing
        the analyst's tags would be worse than carrying two rows."""
        conn = db.connect(self.case)
        try:
            db.add_ioc(conn, "images/x.phtml", "path", ["analyst"])
            db.add_ioc(conn, "webroot-copy/images/x.phtml", "path",
                       ["confirmed"])
            conn.execute("UPDATE meta SET value = '3' "
                         "WHERE key = 'schema_version'")
            conn.commit()
        finally:
            conn.close()
        conn = db.connect(self.case)
        try:
            values = sorted(r[0] for r in conn.execute(
                "SELECT value FROM iocs WHERE type = 'path'"))
            self.assertEqual(
                ["images/x.phtml", "webroot-copy/images/x.phtml"], values)
        finally:
            conn.close()


class AbsoluteFromEvidenceTests(unittest.TestCase):
    """The way back: from the indicator's spelling to the file in the
    registered copy. Only a file that EXISTS is an answer -- the caller
    wants to open it, and the copy in the evidence may be partial."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="shellhound-abspath-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        (self.root / "images").mkdir()
        (self.root / "images" / "x.phtml").write_text("<?php ?>")

    def test_the_forward_direction_round_trips(self):
        roots = [str(self.root).replace("\\", "/")]
        absolute = str(self.root / "images" / "x.phtml")
        rel = db.relative_to_evidence(roots, absolute)
        self.assertEqual("images/x.phtml", rel)
        self.assertEqual(absolute, db.absolute_from_evidence(roots, rel))

    def test_a_file_the_copy_does_not_hold_is_none(self):
        self.assertIsNone(
            db.absolute_from_evidence([str(self.root)], "images/gone.php"))

    def test_a_relative_value_never_resolves_against_the_cwd(self):
        """`tests/__init__.py` exists relative to the working directory the
        suite runs from -- and is exactly the kind of file the resolver must
        not answer with."""
        self.assertIsNone(db.absolute_from_evidence([], "tests/__init__.py"))

    def test_an_absolute_value_no_root_matched_is_honoured(self):
        """The forward direction hands a path below no root back unchanged,
        so the box can carry absolute values -- the way back reads them."""
        absolute = str(self.root / "images" / "x.phtml")
        self.assertIsNone(db.absolute_from_evidence([], "images/x.phtml"))
        self.assertEqual(absolute, db.absolute_from_evidence([], absolute))


if __name__ == "__main__":
    unittest.main()
