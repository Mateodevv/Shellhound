"""Structural release checks use invented fixtures and never contact providers."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import unittest
import zipfile

from tools import check_release_privacy as privacy


class ReleasePrivacyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def archive(self, members, name="sample.whl"):
        path = self.root / name
        with zipfile.ZipFile(path, "w") as package:
            for member, content in members.items():
                package.writestr(member, content)
        return path

    def kinds(self, path, catalog=None):
        return {item.kind for item in privacy.check_archive(path, catalog or {}).violations}

    def git(self, *args, env=None):
        return subprocess.run(["git", "-C", str(self.root), *args], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

    def test_good_wheel_and_sdist(self):
        package = self.archive({"server/__init__.py": b"", "server/data/iso3166-1.json": b"[]",
                                "server/static/index.html": b"<html></html>",
                                "shellhound-1.dist-info/METADATA": b"Name: shellhound\n"})
        self.assertFalse(self.kinds(package))
        path = self.root / "sample.tar.gz"
        with tarfile.open(path, "w:gz") as package:
            for name, data in {"shellhound-1/server/main.py": b"# synthetic\n", "shellhound-1/PKG-INFO": b"Name: shellhound\n"}.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                package.addfile(entry, io.BytesIO(data))
        self.assertFalse(self.kinds(path))

    def test_archive_paths_are_portable_and_cannot_escape(self):
        for name in ("../private.txt", "/absolute.txt", "C:/absolute.txt", "C:relative.txt",
                     "\\\\server\\share\\file.txt", "server/../../file.txt", "server/file.txt:stream",
                     "server/./../file.txt", "server/settings.json."):
            with self.subTest(name=name):
                self.assertIn("unsafe-path", self.kinds(self.archive({name: b"marker"})))

    def test_runtime_data_is_rejected_under_any_package_prefix(self):
        for name in ("server/settings.json", "shellhound-1/settings.json.bak", "server/.env",
                     "server/private.key", "server/case.json", "server/backup.db",
                     "server/report.sql", "server/debug.log.1", "server/.git/config",
                     "server/workspace/results.txt", "server/evidence/note.txt",
                     "server/privacy-audit-2026/report.md", "server/remediation/plan.md",
                     "server/archive/case.zip", "server/static/nested.zip"):
            with self.subTest(name=name):
                self.assertTrue(self.kinds(self.archive({name: b"marker"})))

    def test_sqlite_and_archives_cannot_hide_behind_text_extensions(self):
        self.assertIn("sqlite-content", self.kinds(self.archive({"server/data/reference.txt": b"SQLite format 3\x00" + b"x" * 128})))
        for magic in (b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c"):
            self.assertIn("archive-content", self.kinds(self.archive({"server/data/reference.txt": magic + b"marker"})))

    def test_zip_and_tar_links_are_rejected_without_following_them(self):
        path = self.root / "linked.whl"
        with zipfile.ZipFile(path, "w") as package:
            entry = zipfile.ZipInfo("server/shortcut")
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            package.writestr(entry, "../outside.txt")
        self.assertIn("linked-or-special-entry", self.kinds(path))
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
            path = self.root / "linked.tar.gz"
            with tarfile.open(path, "w:gz") as package:
                entry = tarfile.TarInfo("server/shortcut")
                entry.type = kind
                entry.linkname = "../outside.txt"
                package.addfile(entry)
            self.assertIn("linked-or-special-entry", self.kinds(path))
        self.assertFalse((self.root / "outside.txt").exists())

    def test_changed_and_new_binary_assets_require_review(self):
        data = b"wOF2\x00synthetic font fixture"
        digest = hashlib.sha256(data).hexdigest()
        catalog = {"web/public/assets/fonts/demo.woff2": digest}
        for name in ("server/static/assets/fonts/demo.woff2", "shellhound-1/server/static/assets/fonts/demo.woff2"):
            self.assertFalse(self.kinds(self.archive({name: data}), catalog))
            self.assertIn("unreviewed-binary-asset", self.kinds(self.archive({name: data + b"changed"}), catalog))
        self.assertIn("unreviewed-binary-asset", self.kinds(self.archive({"server/data/unknown.txt": b"\x00binary"})))
        self.assertIn("unreviewed-binary-asset", self.kinds(self.archive({"server/static/new.png": b"plain"})))

    def test_source_scan_respects_sparse_entries_and_inspects_working_files(self):
        self.git("init", "-q")
        (self.root / "module.py").write_text("# synthetic\n", encoding="utf-8")
        (self.root / "excluded.txt").write_text("marker", encoding="utf-8")
        self.git("add", "module.py", "excluded.txt")
        self.git("update-index", "--skip-worktree", "excluded.txt")
        (self.root / "excluded.txt").unlink()
        result = privacy.check_source(self.root, {})
        self.assertFalse(result.violations)
        self.assertEqual(1, result.skipped_sparse)
        (self.root / "module.py").write_bytes(b"SQLite format 3\x00marker")
        self.assertEqual(["sqlite-content"], [item.kind for item in privacy.check_source(self.root, {}).violations])
        self.assertFalse((self.root / "excluded.txt").exists())

    def test_history_checks_raw_author_committer_and_annotated_tag_emails(self):
        self.git("init", "-q")
        env = {**os.environ, "GIT_AUTHOR_NAME": "Demo", "GIT_AUTHOR_EMAIL": "author@example.test",
               "GIT_COMMITTER_NAME": "Demo", "GIT_COMMITTER_EMAIL": "42+demo@users.noreply.github.com"}
        self.git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-m", "Synthetic", env=env)
        result = privacy.check_history(self.root)
        self.assertEqual(["author-email"], [item.kind for item in result.violations])
        env["GIT_COMMITTER_EMAIL"] = "release@example.test"
        self.git("-c", "tag.gpgsign=false", "tag", "-a", "v-test", "-m", "Synthetic release", env=env)
        self.assertIn("tagger-email", [item.kind for item in privacy.check_history(self.root).violations])
        self.assertTrue(privacy.identity_allowed("Demo", "42+demo@users.noreply.github.com"))
        self.assertTrue(privacy.identity_allowed("GitHub", "noreply@github.com"))
        self.assertFalse(privacy.identity_allowed("GitHub", "private@example.test"))
        self.assertFalse(privacy.identity_allowed("Unrelated", "codex@openai.com"))

    def test_cli_never_prints_sensitive_names_and_private_details_are_opt_in(self):
        package = self.archive({"workspace/private-customer@example.test.txt": b"marker"}, "private-customer.whl")
        catalog = self.root / "catalog.json"
        catalog.write_text(json.dumps({"schema": 1, "assets": []}), encoding="utf-8")
        details = self.root / "private-details.json"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = privacy.main(["archives", str(package), "--catalog", str(catalog), "--details", str(details)])
        self.assertEqual(1, code)
        self.assertNotIn("private-customer", output.getvalue())
        self.assertNotIn(str(self.root), output.getvalue())
        self.assertIn("private-directory", output.getvalue())
        self.assertIn("private-customer", details.read_text(encoding="utf-8"))

    def test_invalid_arguments_do_not_echo_private_values(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output), self.assertRaises(SystemExit):
            privacy.main(["archives", "--private-customer@example.test"])
        self.assertNotIn("private-customer", output.getvalue())
        self.assertIn("invalid-arguments", output.getvalue())

    def test_invalid_archive_and_catalog_fail_closed(self):
        path = self.root / "broken.whl"
        path.write_bytes(b"not an archive")
        self.assertIn("invalid-or-oversized-archive", self.kinds(path))
        catalog = self.root / "catalog.json"
        catalog.write_text(json.dumps({"schema": 1, "assets": [{"path": "../outside.png", "sha256": "a" * 64, "review": "test"}]}), encoding="utf-8")
        with self.assertRaises(ValueError):
            privacy.load_catalog(catalog)


if __name__ == "__main__":
    unittest.main()
