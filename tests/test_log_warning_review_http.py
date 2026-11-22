"""The analysis window and dashboard share source-level warning decisions."""
import json
import os
import tempfile
import threading
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
        selections = self.selections()
        self.assertEqual(200, self.request('POST', '/log-sources/review-warnings',
            {'decision': 'accept', 'selections': selections[:1]})[0])
        routes = ('/log-sources', '/jobs', f'/jobs/{self.job}/skipped?group=all&status=pending', '/dashboard')
        # Let fixture metadata settle without making the test sleep.
        with patch.object(log_evidence, 'time_ns', return_value=log_evidence.time_ns() + 1_000_000_000):
            for route in routes:
                self.assertEqual(200, self.request('GET', route)[0])
            with patch.object(log_parsers, 'text_lines', side_effect=AssertionError('An idle read opened a log')), \
                    patch.object(log_evidence, 'fingerprint', side_effect=AssertionError('An idle read hashed a log')):
                for route in routes:
                    with self.subTest(route=route):
                        self.assertEqual(200, self.request('GET', route)[0])

    @unittest.skipUnless(os.name == 'nt', 'Windows change-time behavior')
    def test_warning_rechecks_bytes_when_change_time_is_unavailable(self):
        manual = self.sources / 'manual.log'
        original = self.selections()
        mtime = manual.stat().st_mtime_ns
        with patch.object(log_evidence, 'windows_change_time', return_value=None):
            manual.write_bytes(manual.read_bytes().replace(b'harmless', b'changed!'))
            os.utime(manual, ns=(mtime, mtime))
            self.assertNotEqual(original, self.selections())

    def test_recent_metadata_cannot_cache_an_edit_within_one_clock_tick(self):
        manual = self.sources / 'manual.log'
        source = next(s for s in log_evidence.inventory(self.case, detect=False) if Path(s['path']).name == manual.name)
        change_time = log_evidence.time_ns()
        signature = (*log_evidence._file_signature(manual)[:-1], change_time)
        with patch.object(log_evidence, '_file_signature', return_value=signature), \
                patch.object(log_evidence, 'time_ns', return_value=change_time):
            original = log_evidence.current_fingerprint(source)
            manual.write_bytes(manual.read_bytes().replace(b'harmless', b'changed!'))
            self.assertNotEqual(original, log_evidence.current_fingerprint(source))

    def test_transient_detection_error_is_retried(self):
        with patch.object(log_evidence, 'time_ns', return_value=log_evidence.time_ns() + 1_000_000_000):
            with patch.object(log_parsers, 'text_lines', side_effect=OSError('Synthetic transient access error')):
                sources = log_evidence.inventory(self.case)
                self.assertTrue(all(source['detected']['error'] for source in sources))
            sources = log_evidence.inventory(self.case, cache_detection=True)
            manual = next(source for source in sources if Path(source['path']).name == 'manual.log')
            self.assertEqual('', manual['detected']['error'])

    def test_failed_fresh_warning_read_cannot_repopulate_an_older_digest(self):
        manual = self.sources / 'manual.log'
        source = next(s for s in log_evidence.inventory(self.case, detect=False) if Path(s['path']).name == manual.name)
        original = log_evidence.fingerprint(source['path'], source['settings'])
        change_time = log_evidence.time_ns()
        signature = (*log_evidence._file_signature(manual)[:-1], change_time)
        started = threading.Event()
        release = threading.Event()

        def delayed_read(*args):
            if threading.current_thread() is passive:
                started.set()
                release.wait(5)
                return original
            raise OSError('Synthetic transient access error')

        passive = threading.Thread(target=log_evidence.current_fingerprint, args=(source,), daemon=True)
        with patch.object(log_evidence, '_file_signature', return_value=signature), \
                patch.object(log_evidence, 'time_ns', return_value=change_time + 1_000_000_000):
            with patch.object(log_evidence, 'fingerprint', side_effect=delayed_read):
                passive.start()
                try:
                    self.assertTrue(started.wait(5))
                    self.assertEqual('unreadable', log_evidence.current_fingerprint(source, verify=True))
                finally:
                    release.set()
                    passive.join(5)
            manual.write_bytes(manual.read_bytes().replace(b'harmless', b'changed!'))
            self.assertNotEqual(original, log_evidence.current_fingerprint(source))

    def test_same_marker_changes_block_accept_reopen_and_retry(self):
        manual = self.sources / 'manual.log'
        _, result = self.request('GET', '/log-sources')
        selections = [{'source_id': source['id'], 'warning_key': source['warning_key']}
                      for source in result['sources'] if Path(source['path']).name != 'generated.db']
        selected_ids = {row['source_id'] for row in selections}
        manual_id = next(source['id'] for source in result['sources'] if Path(source['path']).name == manual.name)
        old_key = next(selection['warning_key'] for selection in selections if selection['source_id'] == manual_id)
        real_signature = log_evidence._file_signature
        signature = real_signature(manual)

        def fixed_signature(path, **kwargs):
            return signature if Path(path).name == manual.name else real_signature(path, **kwargs)

        with patch.object(log_evidence, '_file_signature', side_effect=fixed_signature), \
                patch.object(log_evidence, 'time_ns', return_value=log_evidence.time_ns() + 1_000_000_000):
            self.selections()  # Fill the cache before simulating an unchanged metadata token.
            saved_text = manual.read_text(encoding='utf-8')
            manual.write_text(saved_text.replace('A harmless', 'B harmless'), encoding='utf-8')
            self.assertEqual(selections, [s for s in self.selections() if s['source_id'] in selected_ids])
            with patch.object(log_evidence, 'fingerprint', wraps=log_evidence.fingerprint) as fingerprint:
                status, _ = self.request('POST', '/log-sources/review-warnings',
                                         {'decision': 'accept', 'selections': selections})
                self.assertEqual(409, status)
                self.assertCountEqual(['generated.html', manual.name],
                                      [Path(call.args[0]).name for call in fingerprint.call_args_list])
            self.assertNotEqual(old_key, next(selection['warning_key'] for selection in self.selections()
                                              if selection['source_id'] == manual_id))

            status, _ = self.request('POST', '/log-sources/analyze',
                {'source_ids': [s['source_id'] for s in selections], 'warning_selections': selections})
            self.assertEqual(409, status)
            manual.write_text(saved_text, encoding='utf-8')
            self.assertEqual(200, self.request('POST', '/log-sources/review-warnings',
                {'decision': 'accept', 'selections': selections})[0])
            manual.write_text(saved_text.replace('A harmless', 'C harmless'), encoding='utf-8')
            self.assertEqual(409, self.request('POST', '/log-sources/review-warnings',
                {'decision': 'reopen', 'selections': selections})[0])

        conn = db.connect(self.case)
        try:
            self.assertEqual(1, conn.execute("SELECT count(*) FROM jobs").fetchone()[0])
            self.assertEqual(2, conn.execute("SELECT count(*) FROM log_sources WHERE accepted_fingerprint!=''").fetchone()[0])
            decisions = [json.loads(row[0])['decision'] for row in
                         conn.execute("SELECT value FROM meta WHERE key LIKE 'log_warning_review:%'")]
            self.assertEqual(['accept', 'accept'], decisions)
        finally:
            conn.close()

    def test_bulk_review_rechecks_earlier_file_after_all_digests_are_read(self):
        early = self.sources / 'generated.html'
        selections = self.selections()
        real_signature = log_evidence._file_signature
        signature = real_signature(early)
        fingerprint = log_evidence.fingerprint
        changed = False

        def fixed_marker(path, **kwargs):
            if Path(path).name == early.name:
                # The persistent warning marker is unchanged, while change time advances.
                return (*signature[:-1], signature[-1] + int(changed))
            return real_signature(path, **kwargs)

        def change_earlier_source(path, *args):
            nonlocal changed
            result = fingerprint(path, *args)
            if Path(path).name == 'manual.log':
                early.write_bytes(early.read_bytes().replace(b'x', b'y'))
                changed = True
            return result

        with patch.object(log_evidence, '_file_signature', side_effect=fixed_marker), \
                patch.object(log_evidence, 'fingerprint', side_effect=change_earlier_source):
            self.assertEqual(409, self.request('POST', '/log-sources/review-warnings',
                {'decision': 'accept', 'selections': selections})[0])
        self.assertTrue(changed)
        self.assertFalse(any(source['accepted'] for source in log_evidence.source_status(self.case)))

    def test_idle_polls_keep_accepted_counts_without_reading_log_content_again(self):
        accepted = self.selections()
        self.assertEqual(200, self.request('POST', '/log-sources/review-warnings',
                                          {'decision': 'accept', 'selections': accepted})[0])
        self.assertEqual(200, self.request('GET', '/dashboard')[0])
        with patch.object(log_evidence, 'fingerprint', wraps=log_evidence.fingerprint) as digest, \
             patch.object(log_parsers, 'text_lines', wraps=log_parsers.text_lines) as preview:
            for _ in range(2):
                status, jobs = self.request('GET', '/jobs')
                self.assertEqual(200, status)
                self.assertEqual(3, next(j['current_accepted_count'] for j in jobs if j['id'] == self.job))
                status, summary = self.request('GET', '/dashboard')
                self.assertEqual(200, status)
                self.assertEqual((0, 3), (summary['analysis_warnings'], summary['analysis_accepted']))
            self.assertEqual((0, 0), (digest.call_count, preview.call_count))

        (self.sources / 'manual.log').write_text('Changed synthetic observation\n', encoding='utf-8')
        status, summary = self.request('GET', '/dashboard')
        self.assertEqual(200, status)
        self.assertEqual((1, 2), (summary['analysis_warnings'], summary['analysis_accepted']))

    @unittest.skipUnless(os.name == 'nt', 'Windows metadata change-time regression')
    def test_dashboard_reopens_warning_after_clock_preserving_edit(self):
        accepted = self.selections()
        self.assertEqual(200, self.request('POST', '/log-sources/review-warnings',
                                          {'decision': 'accept', 'selections': accepted})[0])
        self.assertEqual((0, 3), log_evidence.warning_counts(self.case))
        path = self.sources / 'manual.log'
        stat = path.stat()
        path.write_bytes(path.read_bytes().replace(b'harmless', b'changed!'))
        os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        self.assertEqual((stat.st_size, stat.st_mtime_ns), (path.stat().st_size, path.stat().st_mtime_ns))
        status, summary = self.request('GET', '/dashboard')
        self.assertEqual(200, status)
        self.assertEqual((1, 2), (summary['analysis_warnings'], summary['analysis_accepted']))

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
