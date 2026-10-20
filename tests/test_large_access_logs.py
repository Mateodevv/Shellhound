"""Bounded import state and cancellation without discarding forensic data."""
import asyncio
from contextlib import closing, nullcontext
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException
from server.app import _access_query
from server.engines import logindex


def request(n, *, client=None, uri=None, agent=None, seconds=None):
    stamp = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=n if seconds is None else seconds)
    return (f'198.51.100.{n % 7 + 1 if client is None else client} - - '
            f'[{stamp.strftime("%d/Jan/%Y:%H:%M:%S +0000")}] '
            f'"POST {uri or "/wp-login.php?marker=" + str(n % 11)} HTTP/1.1" '
            f'{200 if n % 3 else 404} {"-" if n % 5 else 123} '
            f'"https://sample.test/{n % 9}" "{agent or "sqlmap/Synthetic-" + str(n % 17)}"\n')


class LargeAccessLogTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.source = self.root / 'access.log'

    def build(self, name, **limits):
        case = self.root / name
        case.mkdir()
        with patch.multiple(logindex, **limits) if limits else nullcontext():
            stats = logindex.build(case, [str(self.source)])
        return case, stats

    def snapshot(self, case):
        with closing(sqlite3.connect(logindex.db.log_db_path(case))) as conn:
            return {table: sorted(json.dumps(row) for row in conn.execute(f'SELECT * FROM {table}'))
                    for table in ('requests', 'strings', 'ips', 'actors', 'actor_hours', 'days', 'alerts')}

    def test_eviction_and_batch_flush_preserve_complete_index(self):
        # Revisit clients/strings after eviction, out of timestamp order.
        self.source.write_text(''.join(request(n, seconds=(n * 7919) % 172800) for n in range(240)), encoding='utf-8')
        reference, _ = self.build('reference')
        bounded, stats = self.build('bounded', _BUILD_CACHE=3, _BUILD_ACTORS=2, _BATCH=5)
        self.assertEqual(240, stats['lines'])
        self.assertEqual(self.snapshot(reference), self.snapshot(bounded))
        with closing(sqlite3.connect(logindex.db.log_db_path(bounded))) as conn:
            self.assertEqual(0, conn.execute('SELECT count(*) FROM (SELECT text FROM strings GROUP BY text HAVING count(*)>1)').fetchone()[0])
            stored = json.loads(conn.execute("SELECT value FROM meta WHERE key='access_summary'").fetchone()[0])
            conn.execute("DELETE FROM meta WHERE key='access_summary'")
            conn.commit()
        logindex._ACCESS_CACHE.clear()
        recomputed = logindex.access_search(bounded)
        self.assertEqual(stored, {'total': recomputed['total'], **recomputed['summary']})

    def test_hash_collisions_do_not_merge_distinct_evidence_strings(self):
        self.source.write_text(''.join(request(n) for n in range(40)), encoding='utf-8')
        reference, _ = self.build('reference')
        with patch.object(logindex.hashlib, 'sha256', return_value=SimpleNamespace(digest=lambda: b'collision')):
            collided, _ = self.build('collided', _BUILD_CACHE=2, _BATCH=3)
        self.assertEqual(self.snapshot(reference), self.snapshot(collided))

    def test_ascii_prefilter_preserves_all_uri_detectors_and_unicode_case_matching(self):
        rules = ((logindex.LOGIN_POST_ENDPOINTS.search, logindex.F_LOGIN),
                 (logindex.SQLI_URI_RE.search, logindex.F_SQLI),
                 (logindex.TRAVERSAL_URI_RE.search, logindex.F_TRAVERSAL),
                 (logindex.CMS_DIR_PHP_RE.match, logindex.F_CMS_DIR_PHP),
                 (logindex.UPLOAD_PHP_RE.search, logindex.F_UPLOAD_PHP),
                 (logindex.AUTHENTICATED_AREA_RE.search, logindex.F_ADMIN_AREA),
                 (logindex.WP_AUTHENTICATED_AREA_RE.search, logindex.F_ADMIN_AREA))
        examples = ('/catalog/item?query=' + 'x' * 10000, '/wp-login.php', '/xmlrpc.php',
                    '/administrator/', '/administrator/index.php?option=com_jce',
                    '/?option=com_login', '/?option=com_users', '/?task=user.login',
                    '/wp-admin/', '/wp-admin/network/', '/wp-admin/admin.php', 'UNION SELECT', 'information_schema',
                    'concat (', '%27 or 1=1', "' or 1=1", 'benchmark (', 'sleep (',
                    '../../', '%2e%2e%2f%2e%2e%2f', '/images/marker.php',
                    '/templates/marker.php', 'ſleep(1)', 'İNFORMATİON_SCHEMA')
        for example in examples:
            for text in (example, example.upper(), '/prefix/' + example + '?suffix=x'):
                expected = 0
                for matches, flag in rules:
                    if matches(text):
                        expected |= flag
                self.assertEqual(expected, logindex._uri_flags(text), text[:100])

    def test_one_client_keeps_all_agents_and_exact_login_burst_across_flushes(self):
        # Two requests exactly a day apart must not share a login burst.
        times = [logindex.BF_WINDOW] * 4 + [0] * 3 + [logindex.BF_WINDOW - 1] * 2
        self.source.write_text(''.join(request(n, client=1, seconds=epoch,
            agent=f'sqlmap/Synthetic-{n}', uri='/wp-login.php') for n, epoch in enumerate(times)), encoding='utf-8')
        case, stats = self.build('single', _BUILD_CACHE=2, _BUILD_ACTORS=1, _BATCH=2)
        with closing(sqlite3.connect(logindex.db.log_db_path(case))) as conn:
            actor = conn.execute('SELECT requests,agents,login_burst,scanner_uas FROM actors').fetchone()
            self.assertEqual((9, 9, 6), actor[:3])
            self.assertEqual(5, len(json.loads(actor[3])))
            self.assertEqual(9, conn.execute("SELECT count(*) FROM alerts WHERE kind='scanner_ua'").fetchone()[0])
        self.assertEqual(9, stats['lines'])


class AccessQueryCancellationTests(unittest.IsolatedAsyncioTestCase):
    async def test_disconnect_interrupts_sqlite_and_joins_the_worker(self):
        started, stopped = threading.Event(), threading.Event()

        class Request:
            async def is_disconnected(self):
                return started.is_set()

        def expensive(*, cancelled):
            conn = sqlite3.connect(':memory:')
            conn.set_progress_handler(lambda: int(cancelled()), 1000)
            started.set()
            try:
                conn.execute('WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<100000000) SELECT sum(x) FROM n').fetchone()
                raise AssertionError('The disconnected query ran to completion')
            finally:
                conn.close()
                stopped.set()

        with self.assertRaises(HTTPException) as error:
            await asyncio.wait_for(_access_query(Request(), expensive), timeout=3)
        self.assertEqual(499, error.exception.status_code)
        self.assertTrue(stopped.is_set())
