# tests/test_db.py
"""The case database: opening, migrating, and not locking each other out.

The locking test is a regression guard for a real incident: opening a
connection used to write unconditionally, so a read-only request that
arrived while an engine held the write lock died with "database is locked".
It reproduced every time; it must never come back silently.
"""
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


if __name__ == "__main__":
    unittest.main()
