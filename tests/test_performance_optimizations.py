import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from server import db, workspace
from server.casework.performance_case import generate, Scale
from server.engines import logindex, webshell
from tests.test_performance_case import Context


class PerformanceOptimizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = workspace.create_case(self.root, 'Synthetic cache validation')
        generate(self.case, Context(), Scale(requests=100, files=40, clients=10,
                 sql_rows=40, suspicious_files=10, extensions=2, days=2))
        self.logs = self.case / 'training-evidence/logs'
        logindex.build(self.case, [str(self.logs)])

    def test_cached_aggregates_are_isolated_from_consumers_and_rebuilds(self):
        overview = logindex.access_overview(self.case)
        expected = logindex.access_search(self.case)
        overview['facets']['clients'].clear()
        expected['summary']['ok'] = -1
        with patch.object(logindex, '_prepare_access_conn', side_effect=AssertionError('cached overview recomputed')):
            self.assertTrue(logindex.access_overview(self.case)['facets']['clients'])
        self.assertGreaterEqual(logindex.access_search(self.case)['summary']['ok'], 0)
        log = next(self.logs.glob('*.log'))
        line = log.read_text().splitlines()[0]
        with log.open('a') as stream:
            stream.write(line + '\n')
        logindex.build(self.case, [str(self.logs)])
        self.assertEqual(101, logindex.access_search(self.case)['total'])
        self.assertEqual(101, logindex.access_overview(self.case)['total'])

    def test_cached_totals_do_not_reuse_pages_or_other_filter_scopes(self):
        first = logindex.access_search(self.case, limit=5)
        second = logindex.access_search(self.case, {'cursor': first['next_cursor']}, limit=5)
        self.assertEqual(first['summary'], second['summary'])
        self.assertFalse({r['request_id'] for r in first['rows']} & {r['request_id'] for r in second['rows']})
        self.assertEqual(0, logindex.access_search(self.case, {'search': 'nonexistent synthetic term'})['total'])

    def test_overview_preserves_equal_count_facet_membership(self):
        result = logindex.access_overview(self.case)
        conn = logindex._open_ro(self.case)
        try:
            for field, facet, limit in [('uri', 'paths', 12), ('agent', 'agents', 10)]:
                expected = [dict(row) for row in conn.execute(
                    f"SELECT s.text AS value,count(*) AS count FROM requests r "
                    f"LEFT JOIN strings s ON s.id=r.{field} WHERE s.text != '' "
                    f"GROUP BY r.{field} ORDER BY count DESC LIMIT {limit}")]
                self.assertEqual(expected, result['facets'][facet])
        finally:
            conn.close()
        self.assertEqual(100, logindex.access_search(self.case)['total'])

    def test_search_interning_preserves_literal_wildcards_and_all_fields(self):
        all_rows = logindex.access_search(self.case, limit=200)['rows']
        for search in ('Synthetic', 'example.invalid', '198.18.', 'com_jce', '%', '_', '\\'):
            expected = [r for r in all_rows if any(search.lower() in str(r.get(k) or '').lower()
                        for k in ('uri', 'agent', 'referrer', 'client'))]
            result = logindex.access_search(self.case, {'search': search}, limit=200)
            self.assertEqual({r['request_id'] for r in expected}, {r['request_id'] for r in result['rows']}, search)
            self.assertEqual(len(expected), result['total'])

    def test_parallel_scan_has_bounded_workers_and_serial_findings(self):
        root = self.case / 'training-evidence/wordpress'
        lock = threading.Lock()
        active = peak = 0
        original = webshell.scan_file
        def measured(*args, **kwargs):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                time.sleep(.01)
                return original(*args, **kwargs)
            finally:
                with lock:
                    active -= 1
        with patch.object(webshell, 'scan_file', side_effect=measured):
            stats = webshell.scan(self.case, [str(root)])
        self.assertGreater(peak, 1)
        self.assertLessEqual(peak, 4)
        self.assertEqual(0, active)
        self.assertEqual(sum(p.is_file() for p in root.rglob('*')), stats['scanned'])
        conn = db.connect(self.case)
        self.assertEqual(stats['findings'], conn.execute("SELECT count(*) FROM findings WHERE source='webshell'").fetchone()[0])
        conn.close()
