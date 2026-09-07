"""Long evidence paths work without changing stored identities or scope."""
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from server import db, workspace
from server.app import create_app
from server.config import Config
from server.engines import cmsinventory, webshell, yarascan
from server.paths import display_path, io_path


@unittest.skipUnless(os.name == "nt", "Windows extended paths")
class WindowsEvidencePathTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=io_path(tempfile.gettempdir()))
        self.addCleanup(self.temp.cleanup)
        # Hosted Windows runners use an 8.3 alias such as RUNNER~1 for TEMP.
        # The evidence fence resolves aliases, so compare canonical paths.
        self.root = Path(self.temp.name).resolve()
        self.evidence = self.root / "Evidence #123 ä"
        self.deep = self.evidence
        while len(display_path(self.deep)) < 290:
            self.deep /= "nested-directory-with-a-long-name"
        self.deep.mkdir(parents=True)
        self.file = self.deep / "sample.jpg.php"
        self.file.write_text("<?php echo 'synthetic';", encoding="utf-8")
        self.normal_file = display_path(self.file)
        config = Config(workspace=self.root / "cases", token="test")
        self.case = workspace.create_case(config.workspace, "Long paths")
        conn = db.connect(self.case)
        conn.execute("INSERT INTO evidence (kind,path,added) VALUES (?,?,?)",
                     ("webroot", display_path(self.evidence), db.now()))
        conn.commit()
        conn.close()
        self.endpoints = {route.path: route.endpoint for route in create_app(config).routes
                          if hasattr(route, "endpoint")}

    def test_view_reveal_browse_and_manual_review_keep_the_original_path(self):
        content = self.endpoints["/api/cases/{slug}/file"](
            self.case.name, self.normal_file, lang="en")
        self.assertEqual(self.normal_file, content["path"])
        self.assertIn("synthetic", content["lines"][0])
        self.assertTrue(content["hashes"]["sha256"])
        with patch("server.app.subprocess.Popen") as launch:
            self.endpoints["/api/cases/{slug}/reveal-file"](
                self.case.name, SimpleNamespace(path=self.normal_file), "en")
        self.assertEqual(["explorer.exe", f"/select,{self.normal_file}"], launch.call_args.args[0])
        listing = self.endpoints["/api/cases/{slug}/browse"](
            self.case.name, display_path(self.deep), "en")
        self.assertEqual(self.normal_file, listing["files"][0]["path"])
        self.endpoints["/api/cases/{slug}/files/review"](
            self.case.name, SimpleNamespace(path=self.normal_file, state="reviewed",
                                            classification="webshell", note="Synthetic"), "en")
        conn = db.connect(self.case)
        try:
            self.assertEqual(self.normal_file, conn.execute("SELECT artifact FROM findings").fetchone()[0])
        finally:
            conn.close()

    def test_scanners_read_deep_files_and_preserve_identity(self):
        version = self.deep / "wp-includes" / "version.php"
        version.parent.mkdir()
        version.write_text("<?php $wp_version = '6.5';", encoding="utf-8")
        stats = webshell.scan(self.case, [display_path(self.evidence)])
        self.assertEqual(2, stats["scanned"])
        self.assertEqual(0, stats["skipped"])
        self.assertGreater(stats["findings"], 0)
        inventory = cmsinventory.scan(self.case, [display_path(self.evidence)])
        self.assertEqual(1, inventory["installs"])
        conn = db.connect(self.case)
        try:
            self.assertEqual(self.normal_file, conn.execute("SELECT artifact FROM findings LIMIT 1").fetchone()[0])
            self.assertEqual(display_path(self.deep), conn.execute("SELECT root FROM cms_installs").fetchone()[0])
        finally:
            conn.close()

    def test_extended_paths_do_not_bypass_the_registered_root(self):
        outside = self.root / "outside.php"
        outside.write_text("synthetic", encoding="utf-8")
        for path in (str(outside), str(self.evidence / ".." / "outside.php")):
            with self.subTest(path=path), self.assertRaises(HTTPException) as raised:
                self.endpoints["/api/cases/{slug}/file"](self.case.name, path, lang="en")
            self.assertEqual(403, raised.exception.status_code)

    def test_custom_yara_reads_long_unicode_paths(self):
        rules = self.root / "yara"
        rules.mkdir()
        (rules / "synthetic.yar").write_text(
            'rule synthetic { strings: $s = "synthetic" condition: $s }', encoding="utf-8")
        stats = yarascan.scan(self.case, [display_path(self.evidence)], workspace=self.root)
        self.assertEqual(1, stats["scanned"])
        self.assertEqual(0, stats["skipped"])
        self.assertEqual(1, stats["findings"])

    def test_unc_and_drive_prefixes_round_trip(self):
        for path in (r"C:\Evidence #123\nested\file.php", r"\\server\share\Evidence #123\file.php"):
            self.assertEqual(path, display_path(io_path(path)))
            self.assertEqual(io_path(path), io_path(io_path(path)))
