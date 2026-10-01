import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from server import db, workspace, patterns
from server.casework import performance_case as perf
from server.engines import cmsinventory, logindex, sqldump, webshell
from server.jobs import JobManager, CaseBusy


class Context:
    def __init__(self):
        self.stopped = False
        self.updates = []
    def cancelled(self):
        return self.stopped
    def phase_progress(self, *args):
        self.updates.append(args)


SCALE = perf.Scale(requests=2000, files=150, clients=50, sql_rows=200,
                   suspicious_files=20, extensions=10, days=3)


class PerformanceCaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = workspace.create_case(self.root, 'Synthetic performance')

    def test_deterministic_streamed_evidence_and_real_analysis(self):
        first = perf.generate(self.case, Context(), SCALE)
        other = workspace.create_case(self.root, 'Synthetic repeat')
        perf.generate(other, Context(), SCALE)
        def digests(case):
            root = case / 'training-evidence'
            return {str(p.relative_to(root)): (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns)
                    for p in root.rglob('*') if p.is_file()}
        self.assertEqual(digests(self.case), digests(other))
        root = self.case / 'training-evidence'
        self.assertEqual(SCALE.files, sum(p.is_file() for site in ('wordpress', 'joomla') for p in (root / site).rglob('*')))
        self.assertEqual(SCALE.requests, sum(len(p.read_text().splitlines()) for p in (root / 'logs').glob('*.log')))
        self.assertEqual(20, first['suspicious_requests'])
        logindex.build(self.case, [str(root / 'logs')], workspace=self.root)
        webroots = [str(root / site) for site in ('wordpress', 'joomla')]
        webshell.scan(self.case, webroots, workspace=self.root)
        cmsinventory.scan(self.case, webroots)
        sqldump.scan(self.case, [str(p) for p in root.glob('*.sql')], workspace=self.root)
        conn = db.connect(self.case)
        try:
            self.assertGreater(conn.execute('SELECT count(*) FROM findings').fetchone()[0], 0)
            self.assertEqual(0, conn.execute("SELECT count(*) FROM findings WHERE triage IN ('confirmed','dismissed')").fetchone()[0])
            self.assertEqual(5, conn.execute('SELECT count(*) FROM evidence').fetchone()[0])
            self.assertEqual(2, conn.execute('SELECT count(*) FROM cms_installs').fetchone()[0])
            self.assertEqual(SCALE.extensions, conn.execute('SELECT count(*) FROM cms_items').fetchone()[0])
            self.assertEqual(SCALE.sql_rows, conn.execute('SELECT sum(rows) FROM db_tables').fetchone()[0])
        finally:
            conn.close()
        rules = patterns.bundled()
        self.assertEqual(4, len(rules))
        # Shipped rules must exercise actual indexed requests, not seeded hits.
        for rule in rules:
            if rule.get('rule'):
                result = logindex.match_rule(self.case, rule['rule'])
                self.assertGreater(result['hits'], 0, rule['name'])

    def test_cancel_never_registers_partial_evidence(self):
        ctx = Context()
        ctx.stopped = True
        with self.assertRaises(InterruptedError):
            perf.generate(self.case, ctx, SCALE)
        conn = db.connect(self.case)
        self.assertEqual(0, conn.execute('SELECT count(*) FROM evidence').fetchone()[0])
        conn.close()

    def test_write_failure_does_not_register_evidence(self):
        with patch.object(Path, 'write_bytes', side_effect=OSError('Synthetic disk full')):
            with self.assertRaises(OSError):
                perf.generate(self.case, Context(), SCALE)
        conn = db.connect(self.case)
        self.assertEqual(0, conn.execute('SELECT count(*) FROM evidence').fetchone()[0])
        conn.close()

    def test_async_handoff_and_duplicate_protection(self):
        manager = JobManager()
        gate, entered = threading.Event(), threading.Event()
        analyses = []
        def generated(case, ctx):
            entered.set()
            gate.wait(5)
            return {'files': 0}
        try:
            with patch.object(perf, 'generate', side_effect=generated):
                result = perf.enqueue(self.root, manager, lambda slug: analyses.append(slug))
                self.assertTrue(entered.wait(2))
                with self.assertRaises(CaseBusy):
                    perf.enqueue(self.root, manager, lambda _: None)
                with self.assertRaises(CaseBusy):
                    with manager.case_operation(self.root / result['slug']):
                        pass
                gate.set()
                manager.wait_for(self.root / result['slug'], [result['job_id']], timeout=5)
            self.assertEqual([result['slug']], analyses)
        finally:
            gate.set()
            manager.pool.shutdown(wait=True)

    def test_no_analysis_and_restart(self):
        manager = JobManager()
        try:
            with patch.object(perf, 'generate', return_value={}), patch('builtins.print'):
                result = perf.enqueue(self.root, manager, lambda _: self.fail('analysis requested'), run_analysis=False)
                case = self.root / result['slug']
                manager.wait_for(case, [result['job_id']], timeout=5)
            conn = db.connect(case)
            conn.execute("UPDATE jobs SET state='running'")
            conn.commit()
            conn.close()
            manager.recover_interrupted(case)
            self.assertEqual('interrupted', json.loads((case / 'testcase-generation.json').read_text())['state'])
        finally:
            manager.pool.shutdown(wait=True)

    def test_background_cancel_and_failure_do_not_start_analysis(self):
        for fail in (False, True):
            with self.subTest(write_failure=fail):
                manager = JobManager()
                entered, release = threading.Event(), threading.Event()
                def generate(case, ctx):
                    entered.set()
                    release.wait(5)
                    if fail:
                        raise OSError('Synthetic disk full')
                    if ctx.cancelled():
                        raise InterruptedError('Cancelled')
                    return {}
                try:
                    with patch.object(perf, 'generate', side_effect=generate):
                        result = perf.enqueue(self.root, manager, lambda _: self.fail('analysis must not start'))
                        case = self.root / result['slug']
                        self.assertTrue(entered.wait(2))
                        if not fail:
                            manager.cancel(case, result['job_id'])
                        release.set()
                        manager.wait_for(case, [result['job_id']], timeout=5)
                    expected = 'failed' if fail else 'cancelled'
                    self.assertEqual(expected, json.loads((case / 'testcase-generation.json').read_text())['state'])
                    conn = db.connect(case)
                    self.assertEqual(expected, conn.execute('SELECT state FROM jobs').fetchone()[0])
                    self.assertEqual(0, conn.execute('SELECT count(*) FROM evidence').fetchone()[0])
                    conn.close()
                finally:
                    release.set()
                    manager.pool.shutdown(wait=True)


class PerformanceCaseApiTests(unittest.TestCase):
    def test_background_job_uses_regular_analysis_and_legacy_endpoint_still_works(self):
        from server.app import create_app
        from server.config import Config
        from tests.test_scan_retry_api import LocalClient
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = JobManager()
            original = perf.generate
            try:
                with patch('server.app.manager', manager), patch.object(perf, 'generate', side_effect=lambda case, ctx: original(case, ctx, SCALE)):
                    client = LocalClient(create_app(Config(workspace=root, token='synthetic')), {'x-token': 'synthetic'})
                    try:
                        self.assertEqual(400, client.post('/api/testcase/jobs', json={'size': 'invalid'}).status_code)
                        response = client.post('/api/testcase/jobs', json={'size': 'large', 'run_analysis': True})
                        self.assertEqual(200, response.status_code)
                        result = response.json()
                        case = root / result['slug']
                        manager.wait_for(case, [result['job_id']], timeout=10)
                        conn = db.connect(case)
                        jobs = db.rows(conn, 'SELECT id,kind FROM jobs')
                        conn.close()
                        self.assertTrue({'index_logs', 'webshell', 'cms', 'sqldb'} <= {j['kind'] for j in jobs})
                        manager.wait_for(case, [j['id'] for j in jobs], timeout=20)
                        conn = db.connect(case)
                        self.assertEqual(0, conn.execute("SELECT count(*) FROM jobs WHERE state != 'done'").fetchone()[0])
                        conn.close()
                        self.assertEqual(200, client.post('/api/testcase', json={}).status_code)
                    finally:
                        client.close()
            finally:
                manager.pool.shutdown(wait=True)
