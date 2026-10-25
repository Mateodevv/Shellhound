"""SQL match provenance and bounded, read-only field inspection (harmless rules)."""

import json
import os
import re
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from server import db, workspace
from server.app import create_app
from server.config import Config
from server.engines import sqldump
from server.evidence_rows import FIELD_PAGE_CHARACTERS


RULES = [("sqldb.harmless", 1, "Harmless marker", re.compile("HARMLESS_MATCH")),
         ("sqldb.second", 1, "Second marker", re.compile("SECOND_MARK"))]


class DatabaseMatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="shellhound-db-match-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = Config(workspace=self.root / "workspace", token="synthetic")
        self.case = workspace.create_case(self.config.workspace, "Synthetic SQL review")
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        with closing(db.connect(self.case)) as conn:
            conn.execute("INSERT INTO evidence(kind,path,added) VALUES(?,?,?)",
                         ("sql_dump", str(self.evidence), db.now()))
            conn.commit()
        app = create_app(self.config)
        self.endpoints = {getattr(route, "path", ""): route.endpoint for route in app.routes
                          if hasattr(route, "endpoint")}
        self.rules = patch.object(sqldump, "RULES", RULES)
        self.rules.start()
        self.addCleanup(self.rules.stop)

    def write(self, values, name="source.sql", names=None):
        names = names or [f"field{i}" for i in range(len(values))]
        def token(value):
            if value is None:
                return "NULL"
            return "'" + value.replace("\\", "\\\\").replace("'", "''").replace("\n", "\\n") + "'"
        path = self.evidence / name
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_text("CREATE TABLE `items` (`original` text);\nINSERT INTO `items` (" +
                        ",".join(f"`{name}`" for name in names) + ") VALUES (" +
                        ",".join(token(value) for value in values) + ");", encoding="utf-8")
        return path

    def scan(self, *paths, **kwargs):
        return sqldump.scan(self.case, [str(path) for path in paths], **kwargs)

    def data(self):
        with closing(db.connect(self.case)) as conn:
            return (db.rows(conn, "SELECT * FROM findings ORDER BY rule_id"),
                    db.rows(conn, "SELECT t.*,d.path AS dump_path FROM db_tables t "
                            "JOIN db_dumps d ON d.id=t.dump_id ORDER BY d.path"),
                    db.rows(conn, "SELECT * FROM sql_finding_observations "
                            "ORDER BY dump_path,column_index"))

    def row(self, table, finding=None, ordinal=1):
        return self.endpoints["/api/cases/{slug}/database/table-row"](
            self.case.name, table["id"], ordinal, "en", finding["id"] if finding else None)

    def field(self, record, column, offset=0, finding=None, **overrides):
        args = dict(slug=self.case.name, table_id=record["table_id"], row=record["row"],
                    column_index=column, record_version=record["record_version"], offset=offset,
                    finding_id=finding["id"] if finding else None, lang="en")
        args.update(overrides)
        return self.endpoints["/api/cases/{slug}/database/field"](**args)

    def test_long_unicode_match_survives_cell_and_whole_row_clipping(self):
        late = "🌸" * 9000 + "HARMLESS_MATCH" + "\nending"
        values = [None] + ["ordinary" * 1400 for _ in range(12)] + [late]
        path = self.write(values, names=["nullable"] + [f"wide{i}" for i in range(12)] + ["late"])
        self.scan(path)
        findings, tables, observations = self.data()
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["column_index"], 13)
        record = self.row(tables[0], findings[0])
        self.assertTrue(record["truncated"])
        self.assertNotIn(13, [column["index"] for column in record["columns"]])
        match = record["finding_match"]["matches"][0]
        self.assertEqual((record["finding_match"]["state"], match["column_name"], match["start"]),
                         ("recorded", "late", 9000))
        self.assertEqual(match["text"], "HARMLESS_MATCH")
        self.assertLessEqual(sum(len(match[key]) for key in ("before", "text", "after")), 1024)
        page = self.field(record, 13, match["start"] - 512, findings[0])
        self.assertEqual(page["highlight"]["text"], "HARMLESS_MATCH")
        self.assertEqual("".join(page["highlight"][key] for key in ("before", "text", "after")), page["value"])
        self.assertEqual(page["total_characters"], len(late))
        self.assertIsNone(self.field(record, 0)["value"])

    def test_field_pagination_keeps_unicode_and_escaped_text_complete(self):
        value = ("🌸\n\"\\'" * 5000) + "HARMLESS_MATCH"
        path = self.write([value])
        self.scan(path)
        findings, tables, _ = self.data()
        record = self.row(tables[0], findings[0])
        pages, offset = [], 0
        while offset is not None:
            page = self.field(record, 0, offset, findings[0])
            self.assertLessEqual(len(page["value"]), FIELD_PAGE_CHARACTERS)
            self.assertLess(len(json.dumps(page).encode()), 128 * 1024)
            pages.append(page["value"])
            offset = page["next_offset"]
        self.assertEqual("".join(pages), value)

    def test_multiple_columns_preserve_first_rule_and_insert_column_order(self):
        path = self.write(["SECOND_MARK HARMLESS_MATCH", "SECOND_MARK", None, "HARMLESS_MATCH"],
                          names=["reordered", "second", "missing", "last"])
        self.scan(path)
        findings, tables, observations = self.data()
        self.assertEqual(len(findings), 2)
        self.assertEqual(len(observations), 3)
        first = next(f for f in findings if f["rule_id"] == RULES[0][0])
        second = next(f for f in findings if f["rule_id"] == RULES[1][0])
        self.assertEqual([m["column_index"] for m in self.row(tables[0], first)["finding_match"]["matches"]], [0, 3])
        self.assertEqual([m["column_index"] for m in self.row(tables[0], second)["finding_match"]["matches"]], [1])
        self.assertEqual(self.row(tables[0], first)["columns"][0]["name"], "reordered")

    def test_three_exports_repeat_scans_deduplicate_without_losing_triage(self):
        paths = [self.write(["HARMLESS_MATCH"], f"folder{i}/export{i}.sql") for i in range(3)]
        self.scan(*paths)
        findings, _, observations = self.data()
        with closing(db.connect(self.case)) as conn:
            conn.execute("UPDATE findings SET triage='confirmed',triage_note='Keep decision'")
            conn.commit()
        self.scan(*paths)
        current, tables, saved = self.data()
        self.assertEqual(len(saved), 3)
        self.assertEqual(len(current), 1)
        self.assertEqual(current[0]["fingerprint"], findings[0]["fingerprint"])
        self.assertEqual(current[0]["triage_note"], "Keep decision")
        for path in paths:
            self.assertEqual(current[0]["evidence"].count("dump: " + path.name), 1)
        sources = self.row(tables[0], current[0])["finding_match"]["sources"]
        self.assertEqual({source["dump_path"] for source in sources}, {str(path) for path in paths})
        self.assertTrue(all(source["dump_id"] is not None and source["table_id"] is not None for source in sources))
        self.assertEqual({row["row_sha256"] for row in observations}, {row["row_sha256"] for row in saved})

    def test_same_basename_is_distinct_and_nonmatching_source_is_not_observed(self):
        first = self.write(["HARMLESS_MATCH"], "one/export.sql")
        second = self.write(["HARMLESS_MATCH"], "two/export.sql")
        ordinary = self.write(["ordinary text"], "three/export.sql")
        self.scan(first, second, ordinary)
        findings, tables, observations = self.data()
        self.assertEqual(len(observations), 2)
        self.assertIn("dump: export.sql (2 sources)", findings[0]["evidence"])
        self.assertEqual(findings[0]["evidence"].count("dump: export.sql"), 1)
        unobserved = next(table for table in tables if table["dump_path"] == str(ordinary))
        self.assertEqual(self.row(unobserved, findings[0])["finding_match"]["state"], "not_observed")
        sources = self.row(tables[0], findings[0])["finding_match"]["sources"]
        self.assertEqual(len(sources), 2)
        self.assertNotEqual(sources[0]["dump_path"], sources[1]["dump_path"])

    def test_changed_row_and_stale_or_foreign_page_versions_never_highlight(self):
        first = self.write(["HARMLESS_MATCH first"], "first.sql")
        second = self.write(["HARMLESS_MATCH first"], "second.sql")
        self.scan(first, second)
        findings, tables, _ = self.data()
        record = self.row(tables[0], findings[0])
        self.write(["HARMLESS_MATCH changed"], "first.sql")
        current = self.row(tables[0], findings[0])
        self.assertEqual(current["finding_match"]["state"], "changed")
        self.assertEqual(current["finding_match"]["matches"], [])
        self.assertNotIn("highlight", self.field(current, 0, finding=findings[0]))
        for table_id in (tables[0]["id"], tables[1]["id"]):
            with self.assertRaises(HTTPException) as raised:
                self.field(record, 0, finding=findings[0], table_id=table_id)
            self.assertEqual(raised.exception.status_code, 409)

    def test_legacy_rechecks_only_saved_rule_without_writing_findings(self):
        path = self.write(["HARMLESS_MATCH and SECOND_MARK"])
        self.scan(path)
        findings, tables, _ = self.data()
        with closing(db.connect(self.case)) as conn:
            conn.execute("DELETE FROM sql_finding_observations")
            conn.execute("UPDATE findings SET rule_id=?,rule=?", (RULES[1][0], RULES[1][2]))
            conn.commit()
            before = db.rows(conn, "SELECT * FROM findings")
        record = self.row(tables[0], findings[0])
        self.assertEqual(record["finding_match"]["state"], "current")
        self.assertEqual(record["finding_match"]["matches"][0]["text"], "SECOND_MARK")
        with closing(db.connect(self.case)) as conn:
            self.assertEqual(db.rows(conn, "SELECT * FROM findings"), before)
            self.assertEqual(db.rows(conn, "SELECT * FROM sql_finding_observations"), [])
        self.write(["ordinary text"])
        self.assertEqual(self.row(tables[0], findings[0])["finding_match"]["state"], "not_found")
        with patch.object(sqldump, "RULES", []):
            self.assertEqual(self.row(tables[0], findings[0])["finding_match"]["state"], "rule_unavailable")

    def test_legacy_source_labels_deduplicate_without_inventing_paths(self):
        path = self.write(["HARMLESS_MATCH"])
        self.scan(path)
        with closing(db.connect(self.case)) as conn:
            conn.execute("DELETE FROM sql_finding_observations")
            conn.execute("UPDATE findings SET evidence=?",
                         ("Excerpt · dump: alpha.sql, dump: beta.sql, dump: alpha.sql",))
            evidence = sqldump._with_source(conn, RULES[0][2], "items", 1, "Excerpt", "gamma.sql")
            for name in ("alpha.sql", "beta.sql", "gamma.sql"):
                self.assertEqual(evidence.count("dump: " + name), 1)
            self.assertEqual(db.rows(conn, "SELECT * FROM sql_finding_observations"), [])

    def test_failed_and_cancelled_sources_preserve_observations_and_completion(self):
        path = self.write(["HARMLESS_MATCH"])
        self.scan(path)
        before = self.data()
        with closing(db.connect(self.case)) as conn:
            marker = db.one(conn, "SELECT value FROM meta WHERE key='engine_done:sqldump'")
        path.write_text("INSERT INTO items VALUES ('unfinished", encoding="utf-8")
        self.assertEqual(self.scan(path)["skipped"], 1)
        self.assertEqual(self.data(), before)
        self.write(["SECOND_MARK"])
        class CancelAfterRead:
            calls = 0
            def cancelled(self):
                self.calls += 1
                return self.calls > 1
        self.scan(path, ctx=CancelAfterRead())
        self.assertEqual(self.data(), before)
        with path.open("a", encoding="utf-8") as stream:
            stream.write("\nINSERT INTO items VALUES ('SECOND_MARK');" * 201)
        self.scan(path, ctx=CancelAfterRead())
        self.assertEqual(self.data(), before)
        with closing(db.connect(self.case)) as conn:
            self.assertEqual(marker, db.one(conn, "SELECT value FROM meta WHERE key='engine_done:sqldump'"))

    def test_field_validation_scope_missing_registration_and_wrong_finding(self):
        path = self.write(["HARMLESS_MATCH"])
        self.scan(path)
        findings, tables, _ = self.data()
        record = self.row(tables[0], findings[0])
        for overrides in ({"offset": -1}, {"offset": 99999}, {"column_index": -1},
                          {"column_index": 100}, {"row": 2}, {"finding_id": 99999}):
            with self.subTest(overrides=overrides), self.assertRaises(HTTPException) as raised:
                self.field(record, 0, finding=findings[0], **overrides)
            self.assertIn(raised.exception.status_code, (400, 404))
        with closing(db.connect(self.case)) as conn:
            conn.execute("DELETE FROM evidence")
            conn.commit()
        with self.assertRaises(HTTPException) as raised:
            self.field(record, 0)
        self.assertEqual(raised.exception.status_code, 403)
        with closing(db.connect(self.case)) as conn:
            conn.execute("INSERT INTO evidence(kind,path,added) VALUES(?,?,?)", ("sql_dump", str(path), db.now()))
            conn.commit()
        path.unlink()
        with self.assertRaises(HTTPException) as raised:
            self.field(record, 0)
        self.assertEqual(raised.exception.status_code, 404)

    def test_upgrade_and_archive_preserve_triage_and_structured_observations(self):
        path = self.write(["HARMLESS_MATCH"])
        self.scan(path)
        with closing(db.connect(self.case)) as conn:
            conn.execute("UPDATE findings SET triage='confirmed',triage_note='Retain me'")
            conn.execute("DROP TABLE sql_finding_observations")
            conn.execute("UPDATE meta SET value='23' WHERE key='schema_version'")
            conn.commit()
        with closing(db.connect(self.case)) as conn:
            self.assertTrue(db._has_current_schema(conn))
            self.assertEqual(db.one(conn, "SELECT triage_note FROM findings")["triage_note"], "Retain me")
        self.scan(path)
        before = self.data()
        archive, _ = workspace.archive_case(self.config.workspace, self.case)
        result = workspace.import_archive(self.root / "restored", archive)
        with closing(db.connect(result["dir"])) as conn:
            restored = db.rows(conn, "SELECT * FROM sql_finding_observations ORDER BY dump_path,column_index")
            self.assertEqual(restored, before[2])
            self.assertEqual(db.one(conn, "SELECT triage_note FROM findings")["triage_note"], "Retain me")
        self.assertEqual(set(restored[0]), {"finding_fingerprint", "dump_path", "column_index",
                                          "match_start", "match_end", "row_sha256"})

    def test_reused_table_and_dump_ids_reject_stale_first_read_source_identity(self):
        path = self.evidence / "reused.sql"
        path.write_text("INSERT INTO alpha VALUES ('first');INSERT INTO beta VALUES ('second');", encoding="utf-8")
        self.scan(path)
        _, tables, _ = self.data()
        old_beta = next(table for table in tables if table["name"] == "beta")
        path.write_text("INSERT INTO beta VALUES ('second');INSERT INTO gamma VALUES ('third');", encoding="utf-8")
        self.scan(path)
        endpoint = self.endpoints["/api/cases/{slug}/database/table-row"]
        with self.assertRaises(HTTPException) as raised:
            endpoint(self.case.name, old_beta["id"], 1, "en", None, str(path), "beta")
        self.assertEqual(raised.exception.status_code, 409)
        self.assertEqual(endpoint(self.case.name, old_beta["id"], 1, "en")["table"], "gamma")
        # Paths are assertions about case metadata, never alternate files to read.
        with self.assertRaises(HTTPException) as raised:
            endpoint(self.case.name, old_beta["id"], 1, "en", None, str(path.parent / "foreign.sql"), "gamma")
        self.assertEqual(raised.exception.status_code, 409)
        expected = str(path).replace("\\", "/")
        if os.name == "nt":
            expected = expected.upper()
        self.assertEqual(endpoint(self.case.name, old_beta["id"], 1, "en", None, expected, "gamma")["table"], "gamma")


if __name__ == "__main__":
    unittest.main()
