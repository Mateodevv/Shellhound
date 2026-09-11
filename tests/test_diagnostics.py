import json
import tempfile
import unittest
import logging
from unittest.mock import patch
from pathlib import Path

from server import diagnostics


class DiagnosticsTests(unittest.TestCase):
    def test_record_strips_credentials_paths_and_query_values(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            diagnostics.record(workspace, "error", "opencti",
                               "token=secret C:\\Cases\\client\\evidence.php https://cti.test/graphql?token=secret",
                               target="C:\\Cases\\client\\evidence.php")
            events = diagnostics.read(workspace)
            self.assertEqual(1, len(events))
            saved = json.dumps(events[0])
            self.assertNotIn("secret", saved)
            self.assertNotIn("evidence.php", saved)
            self.assertIn("[redacted]", saved)
            self.assertIn("[local path]", saved)

    def test_read_ignores_damaged_log_lines_and_returns_newest_first(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            diagnostics.record(workspace, "warning", "browser", "first")
            diagnostics.record(workspace, "error", "job", "second")
            path = diagnostics._file(workspace)
            with path.open("a", encoding="utf-8") as handle:
                handle.write("not-json\n")
            self.assertEqual(["second", "first"], [event["message"] for event in diagnostics.read(workspace)])

    def test_rotation_preserves_previous_events(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            with patch.object(diagnostics, "_MAX_BYTES", 500):
                for number in range(4):
                    diagnostics.record(workspace, "debug", "test", "x" * 150, ordinal=number)
            files = list((workspace / "logs").glob("shellhound.log*"))
            self.assertGreater(len(files), 1)
            events = [json.loads(line) for file in files for line in file.read_text().splitlines()]
            self.assertEqual([0, 1, 2, 3], sorted(event["ordinal"] for event in events))

    def test_library_logs_and_exception_frames_reach_file_without_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            cleanup = diagnostics.configure(workspace, "synthetic-private-token")
            try:
                logger = logging.getLogger("shellhound.test")
                logger.debug('Authorization: Bearer abc-secret')
                try:
                    raise ValueError('password="long secret value" synthetic-private-token')
                except ValueError:
                    logger.exception("Operation failed")
            finally:
                cleanup()
            events = diagnostics.read(workspace)
            self.assertEqual(2, len(events))
            self.assertTrue(events[0]["exceptions"][0]["frames"])
            text = json.dumps(events)
            for secret in ("abc-secret", "long secret value", "synthetic-private-token"):
                self.assertNotIn(secret, text)

    def test_request_failures_are_correlated_and_log_api_is_absent(self):
        from tests.test_scan_retry_api import LocalClient
        from server.app import create_app
        from server.config import Config
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            app = create_app(Config(workspace=workspace, token="synthetic-token"))

            @app.get("/synthetic-failure")
            def fail():
                raise RuntimeError("synthetic request failure")

            client = LocalClient(app, headers={"x-token": "synthetic-token"})
            try:
                response = client.get("/synthetic-failure?token=synthetic-token")
                self.assertEqual(500, response.status_code)
                events = diagnostics.read(workspace)
                failed = next(event for event in events if event.get("exceptions"))
                completed = next(event for event in events if event.get("message") == "Request completed")
                self.assertEqual(failed["request_id"], completed["request_id"])
                self.assertEqual(500, completed["status"])
                self.assertNotIn("synthetic-token", json.dumps(events))
                for path in ("/api/diagnostics", "/api/diagnostics/download"):
                    self.assertEqual(404, client.get(path, headers={"x-token": "synthetic-token"}).status_code)
                response = client.post("/api/diagnostics/client-error", headers={"x-token": "synthetic-token"},
                                       json={"action": "file-content-open", "message": "file unavailable",
                                             "target": "C:\\private\\file.txt", "stack": "frame 1\nframe 2"})
                self.assertEqual(200, response.status_code)
                self.assertTrue(any(event.get("action") == "file-content-open" for event in diagnostics.read(workspace)))
            finally:
                client.close()
