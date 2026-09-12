"""Closing a case must preserve committed data, including uncheckpointed WAL."""
import sqlite3
import json
import tempfile
import unittest
import zipfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from server import db, workspace


class ArchiveIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ws = self.root / "cases"
        self.case = workspace.create_case(self.ws, "Archive acceptance", "QA-ARCHIVE")

    def test_committed_wal_survives_a_reader_blocking_checkpoint(self):
        writer = db.connect(self.case)
        self.addCleanup(writer.close)
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        reader = sqlite3.connect(self.case / db.CASE_DB)
        self.addCleanup(reader.close)
        reader.execute("BEGIN")
        reader.execute("SELECT * FROM meta").fetchall()
        writer.execute("INSERT INTO meta(key,value) VALUES('acceptance','last committed decision')")
        writer.commit()
        # Hold the old reader until after ZIP creation; release real Windows
        # handles only at the retirement boundary so rename can succeed.
        rename = Path.rename
        def release_and_rename(path, target):
            if path == self.case:
                reader.close()
                writer.close()
            return rename(path, target)
        with patch.object(Path, "rename", release_and_rename):
            archive, _ = workspace.archive_case(self.ws, self.case)
        restored = Path(workspace.import_archive(self.root / "restored", archive)["dir"])
        conn = sqlite3.connect(restored / db.CASE_DB)
        try:
            self.assertEqual(("last committed decision",),
                             conn.execute("SELECT value FROM meta WHERE key='acceptance'").fetchone())
        finally:
            conn.close()

    def test_failed_zip_write_leaves_case_and_no_published_archive(self):
        with patch.object(zipfile.ZipFile, "write", side_effect=OSError("Synthetic disk full")):
            with self.assertRaises(OSError):
                workspace.archive_case(self.ws, self.case)
        self.assertEqual("QA-ARCHIVE", workspace.case_info(self.case)["reference"])
        self.assertEqual([], workspace.list_archives(self.ws))

    def test_repeated_close_in_same_second_does_not_overwrite_archive(self):
        with patch("server.workspace.datetime") as clock:
            clock.now.return_value = datetime(2026, 9, 12, 12)
            first, _ = workspace.archive_case(self.ws, self.case)
            original = first.read_bytes()
            restored = Path(workspace.import_archive(self.ws, first)["dir"])
            workspace.update_case(restored, notes="Second closure")
            second, _ = workspace.archive_case(self.ws, restored)
        self.assertNotEqual(first, second)
        self.assertEqual(original, first.read_bytes())
        self.assertEqual(2, len(workspace.list_archives(self.ws)))


    def test_cleanup_failure_cannot_leave_a_half_deleted_open_case(self):
        def partial_cleanup(retired):
            (retired / workspace.CASE_FILE).unlink()
            raise PermissionError("Synthetic Windows file lock")
        with patch.object(workspace, "_remove_case_dir", side_effect=partial_cleanup):
            archive, _ = workspace.archive_case(self.ws, self.case)
        self.assertFalse(self.case.exists())
        self.assertEqual([], workspace.list_cases(self.ws))
        result = workspace.import_archive(self.ws, archive)
        self.assertEqual("QA-ARCHIVE", workspace.case_info(result["dir"])["reference"])

    def test_archive_verification_failure_keeps_original_case(self):
        with patch.object(zipfile.ZipFile, "testzip", return_value=db.CASE_DB):
            with self.assertRaisesRegex(OSError, "verification failed"):
                workspace.archive_case(self.ws, self.case)
        self.assertEqual("QA-ARCHIVE", workspace.case_info(self.case)["reference"])
        self.assertEqual([], workspace.list_archives(self.ws))

    def test_corrupt_database_is_not_published_as_restored_case(self):
        archive = self.root / "damaged.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr(workspace.CASE_FILE, json.dumps({"name": "Damaged", "reference": "QA-BROKEN"}))
            zf.writestr(db.CASE_DB, b"This is not a SQLite database")
        target = self.root / "restore-target"
        with self.assertRaisesRegex(workspace.ImportError_, "database is damaged"):
            workspace.import_archive(target, archive)
        self.assertEqual([], workspace.list_cases(target))
        self.assertEqual([], list(target.iterdir()))

    def test_locked_retirement_keeps_open_case_and_verified_archive(self):
        with patch.object(Path, "rename", side_effect=PermissionError("Synthetic directory lock")):
            with self.assertRaises(PermissionError):
                workspace.archive_case(self.ws, self.case)
        self.assertEqual("QA-ARCHIVE", workspace.case_info(self.case)["reference"])
        archives = workspace.list_archives(self.ws)
        self.assertEqual(1, len(archives))
        path = self.ws / workspace.ARCHIVE_DIR / archives[0]["file"]
        restored = workspace.import_archive(self.root / "other", path)
        self.assertEqual("QA-ARCHIVE", workspace.case_info(restored["dir"])["reference"])

if __name__ == "__main__":
    unittest.main()
