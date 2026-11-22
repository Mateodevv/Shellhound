"""The analysis window and dashboard share source-level warning decisions."""
import json
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from server import db, log_evidence, log_parsers, workspace
from server.app import create_app
from server.config import Config
from server.jobs import JobManager
from tests.test_http import _LiveServer


class LogWarningReviewHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ws = self.root / 'workspace'
        self.case = workspace.create_case(self.ws, 'Synthetic warning review')
        self.sources = self.root / 'logs'
        self.sources.mkdir()
        (self.sources / 'manual.log').write_text('A harmless observation\n', encoding='utf-8')
        (self.sources / 'generated.db').write_bytes(b'generated\x00database')
        (self.sources / 'generated.html').write_text('x' * (log_parsers.MAX_LINE + 1), encoding='utf-8')
        conn = db.connect(self.case)
        try:
            conn.execute("INSERT INTO evidence(kind,path,added) VALUES ('logs',?,?)",
                         (str(self.sources), db.now()))
            conn.commit()
        finally:
            conn.close()
        self.manager = JobManager()
        self.addCleanup(self.manager.pool.shutdown, wait=True)
        self.job = self.manager.submit(self.case, 'log_events',
                                      lambda ctx: log_evidence.build(self.case, ctx))
        self.assertEqual([], self.manager.wait_for(self.case, [self.job]))
        self.server = _LiveServer(create_app(Config(workspace=self.ws, token='synthetic-local-token')))
        self.base = self.server.start()
        self.addCleanup(self.server.stop)
        self.route = '/api/cases/' + self.case.name

    def request(self, method, path, body=None):
        request = urllib.request.Request(self.base + self.route + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Content-Type': 'application/json', 'X-Token': 'synthetic-local-token'})
        try:
            response = urllib.request.urlopen(request, timeout=10)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            return response.status, json.loads(response.read())

    def selections(self):
        status, result = self.request('GET', '/log-sources')
        self.assertEqual(200, status)
        return [{'source_id': source['id'], 'warning_key': source['warning_key']}
                for source in result['sources'] if source['warning']]

    def test_review_updates_jobs_dashboard_and_reopen_without_reanalysis(self):
        status, details = self.request('GET', f'/jobs/{self.job}/skipped?group=all&status=pending')
        self.assertEqual(200, status)
        self.assertEqual(3, details['total'])
        self.assertEqual({'manual_review', 'unsupported', 'processing_error'},
                         {row['group'] for row in details['items']})
        selections = self.selections()
        with patch.object(log_parsers, 'records', side_effect=AssertionError('Review must not parse logs')):
            status, result = self.request('POST', '/log-sources/review-warnings',
                                          {'decision': 'accept', 'selections': selections})
        self.assertEqual((200, 3), (status, result.get('updated')))
        status, jobs = self.request('GET', '/jobs')
        self.assertEqual(200, status)
        job = next(row for row in jobs if row['id'] == self.job)
        self.assertEqual((0, 3), (job['current_warning_count'], job['current_accepted_count']))
        self.assertEqual(3, job['stats']['log_warnings'])
        status, dashboard = self.request('GET', '/dashboard')
        self.assertEqual(200, status)
        self.assertEqual((0, 3), (dashboard['analysis_warnings'], dashboard['analysis_accepted']))
        self.assertEqual(0, self.request('GET', f'/jobs/{self.job}/skipped?group=all&status=pending')[1]['total'])
        self.assertEqual(3, self.request('GET', f'/jobs/{self.job}/skipped?group=all&status=accepted')[1]['total'])
        self.assertEqual(200, self.request('POST', '/log-sources/review-warnings',
            {'decision': 'reopen', 'selections': selections[:1]})[0])
        self.assertEqual((1, 2), log_evidence.warning_counts(self.case))

    def test_stale_bulk_selection_changes_nothing(self):
        selections = self.selections()
        (self.sources / 'manual.log').write_text('A changed harmless observation\n', encoding='utf-8')
        status, _ = self.request('POST', '/log-sources/review-warnings',
                                 {'decision': 'accept', 'selections': selections})
        self.assertEqual(409, status)
        self.assertFalse(any(source['accepted'] for source in log_evidence.source_status(self.case)))
        conn = db.connect(self.case)
        try:
            self.assertEqual(0, conn.execute("SELECT count(*) FROM meta WHERE key LIKE 'log_warning_review:%'").fetchone()[0])
        finally:
            conn.close()

    def test_warning_reads_use_saved_classification_without_parsing_sources(self):
        with patch.object(log_parsers, 'text_lines', side_effect=AssertionError('Review must not parse logs')):
            for route in ('/log-sources', '/jobs', f'/jobs/{self.job}/skipped?group=all&status=pending'):
                with self.subTest(route=route):
                    self.assertEqual(200, self.request('GET', route)[0])

    def test_existing_jobs_expose_explicit_current_warning_review(self):
        conn = db.connect(self.case)
        try:
            conn.execute("UPDATE jobs SET scan_context='{}' WHERE id=?", (self.job,))
            conn.commit()
        finally:
            conn.close()
        status, details = self.request('GET', f'/jobs/{self.job}/skipped?group=all&status=pending')
        self.assertEqual(200, status)
        self.assertEqual(3, details['total'])
        self.assertTrue(all(row['current_source_warning'] for row in details['items']))
        status, jobs = self.request('GET', '/jobs')
        self.assertEqual(200, status)
        self.assertEqual(3, next(row for row in jobs if row['id'] == self.job)['current_warning_count'])
