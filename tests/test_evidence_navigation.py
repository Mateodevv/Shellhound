"""Finding navigation stays scoped to the case and its registered evidence."""

import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from server import db, workspace
import server.app as app_module
from server.app import create_app
from server.config import Config


class EvidenceNavigationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="shellhound-navigation-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = Config(workspace=self.root / "workspace", token="test-token")
        self.case = workspace.create_case(self.config.workspace, "Synthetic navigation")
        self.slug = self.case.name
        self.evidence = self.root / "evidence with spaces"
        self.evidence.mkdir()
        self.counter = 0
        app = create_app(self.config)
        endpoints = {getattr(route, "path", ""): route.endpoint for route in app.routes
                     if hasattr(route, "endpoint")}
        self.row = endpoints["/api/cases/{slug}/database/row"]
        self.context = endpoints["/api/cases/{slug}/artifact"]

    def register(self, path, *, case=None, kind="sql_dump"):
        with closing(db.connect(case or self.case)) as conn:
            conn.execute("INSERT INTO evidence (kind,path,added) VALUES (?,?,?)",
                         (kind, str(path), db.now()))
            conn.commit()

    def dump(self, filename, *, table="items", value="example", case=None,
             register=True):
        case = case or self.case
        path = self.evidence / filename
        path.write_text(
            f"INSERT INTO `{table}` (`id`,`label`) VALUES (1,'first'),(2,'{value}');",
            encoding="utf-8")
        with closing(db.connect(case)) as conn:
            dump_id = conn.execute("INSERT INTO db_dumps (path) VALUES (?)",
                                   (str(path),)).lastrowid
            conn.execute("INSERT INTO db_tables (dump_id,name,rows,col_list) VALUES (?,?,?,?)",
                         (dump_id, table, 2, '["id","label"]'))
            conn.commit()
        if register:
            self.register(path, case=case)
        return dump_id, path

    def finding(self, artifact="items", *, kind="table", source="sqldb", row=2,
                case=None):
        self.counter += 1
        with closing(db.connect(case or self.case)) as conn:
            fingerprint = db.upsert_finding(
                conn, source, 1, f"Harmless observation {self.counter}",
                kind, str(artifact), row, "Recorded harmless excerpt")
            finding_id = conn.execute("SELECT id FROM findings WHERE fingerprint = ?",
                                      (fingerprint,)).fetchone()[0]
            conn.execute("UPDATE findings SET triage = ?, triage_note = ?, triaged_at = ? "
                         "WHERE id = ?", ("confirmed", "Keep this analyst note", db.now(),
                                         finding_id))
            conn.commit()
        return finding_id

    def finding_snapshot(self, finding_id):
        with closing(db.connect(self.case)) as conn:
            return db.one(conn, "SELECT * FROM findings WHERE id = ?", (finding_id,))

    def assert_status(self, status, finding_id, dump_id, slug=None):
        with self.assertRaises(HTTPException) as raised:
            self.row(slug or self.slug, finding_id, dump_id, "en")
        self.assertEqual(status, raised.exception.status_code)
        return raised.exception

    def test_table_context_lists_all_exports_and_preview_requires_source_choice(self):
        first_id, first_path = self.dump("first export.sql", value="first export row")
        second_id, second_path = self.dump("second export.sql", value="second export row")
        finding_id = self.finding()
        snapshot = self.finding_snapshot(finding_id)

        context = self.context(self.slug, "items", "en")
        self.assertEqual(context["table_sources"], [
            {"dump_id": first_id, "dump_path": str(first_path)},
            {"dump_id": second_id, "dump_path": str(second_path)},
        ])
        # There is deliberately no default export when a caller omits it.
        with self.assertRaises(TypeError):
            self.row(self.slug, finding_id=finding_id, lang="en")
        for dump_id, expected in ((first_id, "first export row"),
                                   (second_id, "second export row")):
            response = self.row(self.slug, finding_id, dump_id, "en")
            self.assertEqual(response["columns"][1]["value"], expected)
            self.assertEqual(response["row"], 2)
            self.assertEqual(response["dump_id"], dump_id)
        self.assertEqual(self.finding_snapshot(finding_id), snapshot)

    def test_preview_reads_current_export_without_replacing_recorded_finding(self):
        dump_id, path = self.dump("current export.sql", value="previous contents")
        finding_id = self.finding()
        snapshot = self.finding_snapshot(finding_id)
        path.write_text("INSERT INTO `items` (`label`) VALUES ('one'),('current contents');",
                        encoding="utf-8")
        response = self.row(self.slug, finding_id, dump_id, "en")
        self.assertEqual(response["columns"],
                         [{"name": "label", "value": "current contents", "truncated": False}])
        self.assertEqual(self.finding_snapshot(finding_id), snapshot)

    def test_invalid_ids_table_source_kinds_and_row_references_are_rejected(self):
        dump_id, _path = self.dump("valid.sql")
        other_dump, _other_path = self.dump("other table.sql", table="other")
        valid = self.finding()
        for finding_id, selected_dump in ((9999, dump_id), (valid, 9999),
                                          (valid, other_dump)):
            with self.subTest(finding_id=finding_id, dump_id=selected_dump):
                self.assert_status(404, finding_id, selected_dump)
        for kind, source, row in (("file", "sqldb", 2), ("table", "webshell", 2),
                                   ("table", "sqldb", None), ("table", "sqldb", 0),
                                   ("table", "sqldb", -1), ("table", "sqldb", 1.5)):
            with self.subTest(kind=kind, source=source, row=row):
                finding_id = self.finding(kind=kind, source=source, row=row)
                self.assert_status(400, finding_id, dump_id)
        self.assert_status(400, self.finding(row=99), dump_id)

    def test_existing_unregistered_export_is_never_read(self):
        dump_id, path = self.dump("unregistered.sql", register=False)
        finding_id = self.finding()
        self.assertTrue(path.is_file())
        with patch("server.evidence_rows.read_database_row") as read:
            self.assert_status(403, finding_id, dump_id)
        read.assert_not_called()

    def test_removed_export_registration_is_never_read(self):
        dump_id, path = self.dump("removed registration.sql")
        finding_id = self.finding()
        with closing(db.connect(self.case)) as conn:
            conn.execute("DELETE FROM evidence WHERE path = ?", (str(path),))
            conn.commit()
        with patch("server.evidence_rows.read_database_row") as read:
            self.assert_status(403, finding_id, dump_id)
        read.assert_not_called()

    def test_missing_export_fails_before_reading(self):
        dump_id, path = self.dump("missing.sql")
        finding_id = self.finding()
        path.unlink()
        with patch("server.evidence_rows.read_database_row") as read:
            self.assert_status(404, finding_id, dump_id)
        read.assert_not_called()

    def test_foreign_case_ids_cannot_expose_its_evidence(self):
        local_dump, _local_path = self.dump("local.sql", value="local case row")
        local_finding = self.finding()
        other = workspace.create_case(self.config.workspace, "Other synthetic case")
        foreign_dump, _foreign_path = self.dump("foreign.sql", value="foreign case row", case=other)
        foreign_finding = self.finding(case=other)

        # SQLite IDs naturally collide across cases. They select only the
        # current case's metadata, never a file from the other case.
        self.assertEqual(local_dump, foreign_dump)
        self.assertEqual(local_finding, foreign_finding)
        result = self.row(self.slug, foreign_finding, foreign_dump, "en")
        self.assertEqual(result["columns"][1]["value"], "local case row")
        with closing(db.connect(other)) as conn:
            conn.execute("UPDATE findings SET id = 9001 WHERE id = ?", (foreign_finding,))
            conn.execute("UPDATE db_dumps SET id = 9002 WHERE id = ?", (foreign_dump,))
            conn.execute("UPDATE db_tables SET dump_id = 9002 WHERE dump_id = ?", (foreign_dump,))
            conn.commit()
        with patch("server.evidence_rows.read_database_row") as read:
            self.assert_status(404, 9001, local_dump)
            self.assert_status(404, local_finding, 9002)
        read.assert_not_called()

    def test_registered_file_context_provides_preview_and_keeps_triage(self):
        path = self.evidence / "reviewed note.txt"
        path.write_text("first line\nHarmless second line\nlast line\n", encoding="utf-8")
        self.register(path, kind="webroot")
        finding_id = self.finding(path, kind="file", source="webshell", row=2)
        snapshot = self.finding_snapshot(finding_id)
        context = self.context(self.slug, str(path), "en")
        self.assertTrue(context["file"]["available"])
        self.assertTrue(context["file"]["exists"])
        self.assertIn("Harmless second line", context["file"]["preview"]["lines"])
        self.assertEqual(context["triage_note"], "Keep this analyst note")
        self.assertEqual(self.finding_snapshot(finding_id), snapshot)

    def test_unregistered_or_removed_file_has_no_preview_or_content_reads(self):
        for removed in (False, True):
            with self.subTest(removed=removed):
                path = self.evidence / f"unavailable {removed}.txt"
                path.write_text("Harmless unavailable contents", encoding="utf-8")
                finding_id = self.finding(path, kind="file", source="webshell", row=1)
                if removed:
                    self.register(path, kind="webroot")
                    path.unlink()
                snapshot = self.finding_snapshot(finding_id)
                with patch.object(app_module, "open", wraps=open, create=True) as read:
                    context = self.context(self.slug, str(path), "en")
                self.assertFalse(context["file"]["available"])
                self.assertEqual(context["file"]["exists"], not removed)
                self.assertTrue(context["file"]["unavailable_reason"])
                self.assertNotIn("preview", context["file"])
                self.assertNotIn("hashes", context["file"])
                read.assert_not_called()
                self.assertEqual(self.finding_snapshot(finding_id), snapshot)


if __name__ == "__main__":
    unittest.main()
