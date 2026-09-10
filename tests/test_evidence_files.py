"""Evidence line links reach the source without reading whole files into memory."""
import io
import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException

from server import db, workspace
from server.app import create_app
from server.config import Config
from server.evidence_files import read_raw_page


class RawPageTests(unittest.TestCase):
    def page(self, content, **kwargs):
        return read_raw_page(io.BytesIO(content), size=len(content),
                             window=kwargs.pop("window", 16), **kwargs)

    def test_line_lookup_beyond_first_window_and_scan_chunk(self):
        content = b"earlier\n" * 40000 + "selected café\r\nfollowing\r\n".encode()
        page = self.page(content, line=40001, window=64)
        self.assertTrue(page.focus_found)
        self.assertEqual(320000, page.offset)
        self.assertEqual(40001, page.from_line)
        self.assertFalse(page.starts_mid_line)
        self.assertEqual("selected café\r", page.chunk.decode().split("\n")[0])

    def test_forward_pages_preserve_utf8_and_real_line_numbers(self):
        content = "first\r\nsecond café 🌟\r\nthird\n".encode()
        offset = 0
        recovered = []
        while offset < len(content):
            page = self.page(content, offset=offset, window=18)
            self.assertEqual(offset, page.offset)
            self.assertGreater(len(page.chunk), 0)
            self.assertEqual(1 + content[:offset].count(b"\n"), page.from_line)
            self.assertEqual(offset > 0 and content[offset - 1:offset] != b"\n",
                             page.starts_mid_line)
            recovered.append(page.chunk.decode("utf-8"))
            offset += len(page.chunk)
        self.assertEqual(content.decode(), "".join(recovered))

    def test_backward_offset_inside_utf8_rewinds_character(self):
        content = "first\néclair\n".encode()
        page = self.page(content, offset=7)
        self.assertEqual(6, page.offset)
        self.assertEqual(2, page.from_line)
        self.assertFalse(page.starts_mid_line)
        self.assertTrue(page.chunk.decode().startswith("éclair"))

    def test_long_lines_and_boundary_newlines_use_bounded_reads(self):
        content = b"a" * (64 * 1024 - 1) + b"\n" + b"b" * 300000 + b"\nlast"

        class BoundedStream(io.BytesIO):
            def read(self, size=-1):
                if not 0 <= size <= 64 * 1024:
                    raise AssertionError("Unbounded evidence read")
                return super().read(size)

        page = read_raw_page(BoundedStream(content), size=len(content),
                             window=32, line=3)
        self.assertEqual(b"last", page.chunk)
        self.assertEqual(3, page.from_line)
        self.assertEqual(64 * 1024 + 300001, page.offset)
        long_page = self.page(content, line=2)
        self.assertEqual(b"b" * 16, long_page.chunk)

    def test_missing_and_invalid_source_lines_are_explicit(self):
        for content, line in ((b"one\ntwo\n", 3), (b"one\ntwo", 3), (b"", 1)):
            with self.subTest(content=content, line=line):
                page = self.page(content, line=line)
                self.assertFalse(page.focus_found)
                self.assertEqual(0, page.offset)
                self.assertEqual(1, page.from_line)
        for line in (0, -1):
            with self.assertRaises(ValueError):
                self.page(b"one", line=line)

    def test_offset_clamping_and_malformed_utf8_remain_readable(self):
        content = b"first\ninvalid \xff tail"
        self.assertEqual(0, self.page(content, offset=-8).offset)
        end = self.page(content, offset=len(content) + 10)
        self.assertEqual(len(content), end.offset)
        self.assertEqual(b"", end.chunk)
        self.assertEqual(2, end.from_line)
        page = self.page(content, line=2)
        self.assertEqual("invalid \ufffd tail", page.chunk.decode("utf-8", errors="replace"))

    def test_malformed_continuation_bytes_do_not_rewind_forward_pages(self):
        content = b"first\n" + b"\x80" * 20 + b"tail"
        offset = 0
        recovered = b""
        while offset < len(content):
            page = self.page(content, offset=offset, window=4)
            self.assertEqual(offset, page.offset)
            recovered += page.chunk
            offset += len(page.chunk)
        self.assertEqual(content, recovered)


class EvidenceFileEndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        config = Config(workspace=self.root / "workspace", token="test-token")
        self.case_dir = workspace.create_case(config.workspace, "Synthetic file pages")
        self.file = self.root / "registered source.txt"
        self.file.write_bytes(b"earlier\r\n" * 40000 + b"selected\r\nfollowing\r\n")
        conn = db.connect(self.case_dir)
        try:
            conn.execute("INSERT INTO evidence (kind, path, added) VALUES (?, ?, ?)",
                         ("webroot", str(self.file), db.now()))
            conn.commit()
        finally:
            conn.close()
        app = create_app(config)
        self.endpoint = next(route.endpoint for route in app.routes
                             if getattr(route, "path", "") == "/api/cases/{slug}/file")

    def tearDown(self):
        self.temp.cleanup()

    def call(self, **kwargs):
        return self.endpoint(self.case_dir.name, str(self.file), lang="en", **kwargs)

    def test_line_link_returns_actual_page_and_preserves_metadata(self):
        response = self.call(line=40001)
        self.assertEqual(360000, response["offset"])
        self.assertEqual(40001, response["from_line"])
        self.assertEqual(40001, response["requested_line"])
        self.assertTrue(response["focus_found"])
        self.assertFalse(response["starts_mid_line"])
        self.assertEqual("selected\r", response["lines"][0])
        self.assertTrue(response["eof"])
        self.assertIn("sha256", response["hashes"])
        self.assertIn("modified_at", response)

    def test_normal_raw_page_has_correct_line_number_without_a_focus(self):
        response = self.call(offset=360002)
        self.assertEqual(40001, response["from_line"])
        self.assertTrue(response["starts_mid_line"])
        self.assertEqual("lected\r", response["lines"][0])
        self.assertNotIn("requested_line", response)
        self.assertNotIn("focus_found", response)

    def test_hex_uses_byte_offset_and_does_not_claim_line_navigation(self):
        response = self.call(mode="hex", offset=9, line=40001)
        self.assertEqual(9, response["offset"])
        self.assertEqual(9, response["rows"][0]["offset"])
        self.assertNotIn("from_line", response)
        self.assertNotIn("requested_line", response)
        self.assertNotIn("focus_found", response)

    def test_missing_line_and_invalid_line_have_explicit_results(self):
        response = self.call(line=90000)
        self.assertFalse(response["focus_found"])
        self.assertEqual(90000, response["requested_line"])
        for line in (0, -9):
            with self.assertRaises(HTTPException) as raised:
                self.call(line=line)
            self.assertEqual(400, raised.exception.status_code)

    def test_line_lookup_cannot_escape_registered_evidence(self):
        outside = self.root / "unregistered.txt"
        outside.write_text("Harmless unregistered marker", encoding="utf-8")
        with self.assertRaises(HTTPException) as raised:
            self.endpoint(self.case_dir.name, str(outside), lang="en", line=1)
        self.assertEqual(403, raised.exception.status_code)


if __name__ == "__main__":
    unittest.main()
