"""The local reveal action never opens evidence or escapes registered roots."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from server import db, workspace
import server.app as app_module
from server.app import create_app
from server.config import Config


class RevealFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = Config(workspace=self.root / "workspace", token="test-token")
        self.case_dir = workspace.create_case(self.config.workspace, "Synthetic reveal")
        self.slug = self.case_dir.name
        self.evidence = self.root / "registered-evidence"
        self.evidence.mkdir()
        self.file = self.evidence / "hostile.php"
        self.file.write_text("<?php echo 'synthetic';", encoding="utf-8")
        conn = db.connect(self.case_dir)
        try:
            conn.execute(
                "INSERT INTO evidence (kind, path, added, scanned_at) VALUES (?,?,?,?)",
                ("webroot", str(self.evidence), db.now(), db.now()))
            conn.commit()
        finally:
            conn.close()
        app = create_app(self.config)
        self.reveal = next(
            route.endpoint for route in app.routes
            if getattr(route, "path", "") == "/api/cases/{slug}/reveal-file")

    def tearDown(self):
        self.temp.cleanup()

    def _call(self, path):
        return self.reveal(self.slug, SimpleNamespace(path=str(path)), "en")

    def test_valid_file_uses_an_argument_array_without_a_shell(self):
        with patch.object(app_module.subprocess, "Popen") as launch:
            self.assertEqual({"ok": True}, self._call(self.file))

        command = launch.call_args.args[0]
        self.assertIsInstance(command, list)
        self.assertFalse(launch.call_args.kwargs["shell"])
        if os.name == "nt":
            self.assertEqual("explorer.exe", command[0])
            self.assertEqual(f"/select,{self.file.resolve()}", command[1])
        elif sys.platform == "darwin":
            self.assertEqual(["open", "-R", str(self.file.resolve())], command)
        else:
            self.assertEqual(["xdg-open", str(self.evidence.resolve())], command)

    def test_outside_traversal_directory_and_missing_targets_are_rejected(self):
        outside = self.root / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        traversal = self.evidence / ".." / outside.name

        for target, status in [
            (outside, 403), (traversal, 403), (self.evidence, 400),
            (self.evidence / "missing.php", 404),
        ]:
            with self.subTest(target=target):
                with patch.object(app_module.subprocess, "Popen") as launch:
                    with self.assertRaises(HTTPException) as raised:
                        self._call(target)
                self.assertEqual(status, raised.exception.status_code)
                launch.assert_not_called()

    def test_symlink_escaping_a_registered_root_is_rejected(self):
        outside = self.root / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        link = self.evidence / "escape.php"
        try:
            link.symlink_to(outside)
        except OSError as error:
            self.skipTest(f"symlinks unavailable: {error}")

        with patch.object(app_module.subprocess, "Popen") as launch:
            with self.assertRaises(HTTPException) as raised:
                self._call(link)
        self.assertEqual(403, raised.exception.status_code)
        launch.assert_not_called()

    def test_launcher_failure_is_reported_as_a_local_service_error(self):
        with patch.object(app_module.subprocess, "Popen", side_effect=OSError("unavailable")):
            with self.assertRaises(HTTPException) as raised:
                self._call(self.file)
        self.assertEqual(503, raised.exception.status_code)
        self.assertIn("file manager", raised.exception.detail)


if __name__ == "__main__":
    unittest.main()
