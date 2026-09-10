"""On-demand database finding previews use row ordinals, never SQL lines."""

import bz2
import gzip
import json
import lzma
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from server.evidence_rows import RowReadError, read_database_row


class DatabaseRowPreviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="shellhound-row-preview-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def write(self, text, name="example export.sql"):
        path = self.directory / name
        path.write_text(text, encoding="utf-8-sig")
        return path

    def test_row_ordinal_across_inserts_and_interleaved_tables(self):
        path = self.write("""-- Harmless example export
CREATE TABLE `items` (`id` int, `label` text, PRIMARY KEY (`id`));
INSERT INTO `items` VALUES (1,'first'),(2,'second');
INSERT INTO `other` VALUES (99,'unrelated');

INSERT INTO `items` VALUES
(3,'third'),
(4,'fourth');
""")
        self.assertEqual(read_database_row(path, "items", 3), {
            "table": "items", "row": 3, "truncated": False,
            "columns": [
                {"name": "id", "value": "3", "truncated": False},
                {"name": "label", "value": "third", "truncated": False},
            ],
        })

    def test_named_inserts_override_schema_order_and_keep_null(self):
        path = self.write("""CREATE TABLE `items` (`id` int, `label` text, `note` text);
INSERT INTO `items` (`label`,`id`,`note`) VALUES ('first',1,NULL);
INSERT INTO `items` (`note`,`label`) VALUES ('memo','second');
""")
        first = read_database_row(path, "items", 1)
        self.assertEqual([(c["name"], c["value"]) for c in first["columns"]],
                         [("label", "first"), ("id", "1"), ("note", None)])
        second = read_database_row(path, "items", 2)
        self.assertEqual([(c["name"], c["value"]) for c in second["columns"]],
                         [("note", "memo"), ("label", "second")])

    def test_generic_columns_and_sql_escapes_match_scanner(self):
        path = self.write(r"""/* Example with punctuation */
INSERT INTO `items` VALUES ('a;b,c (d)','it''s fine','line\nnext','C:\\notes',NULL);
""")
        columns = read_database_row(path, "items", 1)["columns"]
        self.assertEqual([c["name"] for c in columns],
                         ["col1", "col2", "col3", "col4", "col5"])
        self.assertEqual([c["value"] for c in columns],
                         ["a;b,c (d)", "it's fine", "line\nnext", "C:\\notes", None])

    def test_first_named_insert_supplies_fallback_when_schema_is_missing(self):
        path = self.write("""INSERT INTO `items` (`id`,`label`) VALUES (1,'first');
INSERT INTO `items` VALUES (2,'second');
""")
        self.assertEqual([c["name"] for c in read_database_row(path, "items", 2)["columns"]],
                         ["id", "label"])

    def test_chunk_boundaries_keep_quotes_and_statement_limits_consistent(self):
        path = self.write(r"INSERT INTO `items` VALUES ('a\';b','it''s fine');"
                          "INSERT INTO `items` VALUES ('later','value');")
        with patch("server.evidence_rows._CHUNK_SIZE", 7), \
                patch("server.evidence_rows.MAX_STATEMENT_BYTES", 60):
            first = read_database_row(path, "items", 1)
            self.assertEqual([c["value"] for c in first["columns"]],
                             ["a';b", "it's fine"])
            second = read_database_row(path, "items", 2)
            self.assertEqual([c["value"] for c in second["columns"]], ["later", "value"])

    def test_compressed_exports(self):
        content = b"\xef\xbb\xbfINSERT INTO `items` (`label`) VALUES ('hello');"
        for suffix, compress in (("gz", gzip.compress), ("bz2", bz2.compress),
                                 ("xz", lzma.compress)):
            with self.subTest(suffix=suffix):
                path = self.directory / f"export.sql.{suffix}"
                path.write_bytes(compress(content))
                self.assertEqual(read_database_row(path, "items", 1)["columns"],
                                 [{"name": "label", "value": "hello", "truncated": False}])

    def test_missing_row_and_invalid_request(self):
        path = self.write("INSERT INTO `items` VALUES (1);")
        for table, row in (("items", 2), ("absent", 1)):
            with self.subTest(table=table), self.assertRaisesRegex(RowReadError, "not found"):
                read_database_row(path, table, row)
        for table, row in (("bad table", 1), ("items", 0), ("items", -1),
                           ("items", 1.5), ("items", True)):
            with self.subTest(table=table, row=row), self.assertRaises(RowReadError):
                read_database_row(path, table, row)

    def test_unavailable_or_damaged_archive_has_readable_error(self):
        with self.assertRaisesRegex(RowReadError, "could not be read"):
            read_database_row(self.directory / "missing.sql", "items", 1)
        path = self.directory / "damaged.sql.xz"
        path.write_bytes(b"This is not an archive")
        with self.assertRaisesRegex(RowReadError, "could not be read"):
            read_database_row(path, "items", 1)

    def test_malformed_insert_does_not_present_partial_statement(self):
        for values in ("('unfinished", "(1),('unfinished", "(1", "invalid"):
            with self.subTest(values=values):
                path = self.write("INSERT INTO `items` VALUES " + values)
                with self.assertRaisesRegex(RowReadError, "incomplete|unreadable"):
                    read_database_row(path, "items", 1)

    def test_cell_and_serialized_row_output_are_bounded(self):
        path = self.write("INSERT INTO `items` VALUES ('" + "🌟" * 3000 + "','ordinary');")
        result = read_database_row(path, "items", 1)
        self.assertTrue(result["truncated"])
        self.assertTrue(result["columns"][0]["truncated"])
        self.assertLessEqual(len(result["columns"][0]["value"].encode("utf-8")), 8192)
        self.assertEqual(result["columns"][1]["value"], "ordinary")
        many_values = ",".join("'" + r"\n" * 1000 + "'" for _ in range(100))
        path = self.write(f"INSERT INTO `items` VALUES ({many_values});")
        result = read_database_row(path, "items", 1)
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(json.dumps(result, ensure_ascii=False).encode("utf-8")),
                             64 * 1024)

    def test_statement_input_and_time_limits(self):
        path = self.write("INSERT INTO `items` VALUES ('" + "a" * 1000 + "');")
        with patch("server.evidence_rows.MAX_STATEMENT_BYTES", 256):
            with self.assertRaisesRegex(RowReadError, "statement is too large"):
                read_database_row(path, "items", 1)
        # The read budget applies after decompression, including other tables.
        compressed = self.directory / "large.sql.gz"
        compressed.write_bytes(gzip.compress(
            ("INSERT INTO `other` VALUES (1);" * 100).encode()))
        with patch("server.evidence_rows.MAX_INPUT_BYTES", 256):
            with self.assertRaisesRegex(RowReadError, "read limit"):
                read_database_row(compressed, "items", 1)
        with patch("server.evidence_rows.time.monotonic", side_effect=[0, 11]):
            with self.assertRaisesRegex(RowReadError, "too long"):
                read_database_row(path, "items", 1)


if __name__ == "__main__":
    unittest.main()
