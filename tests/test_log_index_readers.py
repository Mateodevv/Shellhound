import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from server import db
from server.engines import logindex


class IndexReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.case = Path(self.temp.name, 'case')
        self.case.mkdir()
        self.log = Path(self.temp.name, 'access.log')
        self.log.write_text('192.0.2.8 - - [04/Nov/2026:08:00:00 +0000] "GET /safe HTTP/1.1" 200 12 "-" "demo"\n')
        db.connect(self.case).close()
        logindex.build(self.case, [str(self.log)])

    @unittest.skipUnless(os.name == 'nt', 'Windows SQLite file locking')
    def test_rebuild_waits_for_current_reader_to_close(self):
        waiting = threading.Event()
        class Context:
            def cancelled(self): return False
            def progress(self, *_): waiting.set()
        reader = logindex._open_ro(self.case)
        with ThreadPoolExecutor(max_workers=1) as pool:
            work = pool.submit(logindex.build, self.case, [str(self.log)], Context())
            try:
                self.assertTrue(waiting.wait(2))
            finally:
                reader.close()
            self.assertFalse(work.result(timeout=5)['partial'])
        self.assertTrue(logindex.status(self.case, [str(self.log)])['fresh'])

    def test_cancellation_while_waiting_keeps_previous_index(self):
        original = db.log_db_path(self.case).read_bytes()
        class Context:
            stop = False
            def cancelled(self): return self.stop
            def progress(self, *_): self.stop = True
        with patch.object(Path, 'unlink', side_effect=PermissionError('busy')):
            result = logindex.build(self.case, [str(self.log)], Context())
        self.assertTrue(result['partial'])
        self.assertEqual(original, db.log_db_path(self.case).read_bytes())

    def test_timeout_keeps_previous_index_and_has_recovery_action(self):
        original = db.log_db_path(self.case).read_bytes()
        with patch.object(Path, 'unlink', side_effect=PermissionError('busy')), \
             patch.object(logindex.time, 'monotonic', side_effect=[0, 6]):
            with self.assertRaisesRegex(PermissionError, 'Close other log views'):
                logindex.build(self.case, [str(self.log)])
        self.assertEqual(original, db.log_db_path(self.case).read_bytes())
