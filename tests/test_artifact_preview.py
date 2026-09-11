"""Bounded code navigation and exact-path requester periods for artifact review."""
import sqlite3
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from server import db, workspace
from server.app import create_app
from server.config import Config
from server.engines import logindex


class ArtifactPreviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.config = Config(workspace=root / 'workspace', token='synthetic')
        self.case = workspace.create_case(self.config.workspace, 'Preview')
        self.evidence = root / 'evidence'
        self.evidence.mkdir()
        self.file = self.evidence / 'example.txt'
        self.file.write_text('\n'.join(f'Safe line {i}' for i in range(1, 101)), encoding='utf-8')
        conn = db.connect(self.case)
        conn.execute('INSERT INTO evidence (kind,path,added,scanned_at) VALUES (?,?,?,?)',
                     ('webroot', str(self.evidence), db.now(), db.now()))
        db.upsert_finding(conn, 'webshell', 0, 'Synthetic review rule', 'file', str(self.file), line=2)
        conn.commit()
        conn.close()
        app = create_app(self.config)
        self.endpoints = {getattr(route, 'path', ''): route.endpoint for route in app.routes if hasattr(route, 'endpoint')}

    def preview(self, path, line=1):
        return self.endpoints['/api/cases/{slug}/file-preview'](self.case.name, str(path), line, 'en')

    def decide(self, classes=None, **overrides):
        endpoint = self.endpoints['/api/cases/{slug}/triage']
        body = endpoint.__annotations__['body'](artifacts=[str(self.file)], state='confirmed',
            classifications=classes, propagate=False, **overrides)
        return endpoint(self.case.name, body)

    def test_multiple_classes_roundtrip_to_ioc_labels_and_opencti_without_erasing_notes(self):
        from server import ioc_model, opencti_graph
        conn = db.connect(self.case)
        conn.execute('UPDATE findings SET triage_note=?', ('Existing analyst note',))
        conn.commit()
        conn.close()
        self.decide(['webshell', 'dropper'])
        ctx = self.endpoints['/api/cases/{slug}/artifact'](self.case.name, str(self.file), 'en')
        self.assertEqual(['webshell', 'dropper'], ctx['file']['classifications'])
        self.assertEqual('Existing analyst note', ctx['triage_note'])
        conn = db.connect(self.case)
        rows = ioc_model.enrich_rows(conn, db.rows(conn, 'SELECT * FROM iocs'))
        for row in rows:
            if row['type'] in ('path', 'hash', 'file'):
                self.assertTrue({'Webshell', 'Dropper'} <= set(json.loads(row['tags'])))
        conn.close()
        preview = opencti_graph.build_preview(self.case)
        file = next(obj for obj in preview['objects'] if obj['type'] == 'file')
        self.assertTrue({'Webshell', 'Dropper'} <= set(file['labels']))
        self.decide(['seo-spam'])
        preview = opencti_graph.build_preview(self.case)
        file = next(obj for obj in preview['objects'] if obj['type'] == 'file')
        self.assertIn('SEO-Spam', file['labels'])
        self.assertNotIn('Webshell', file['labels'])
        self.assertNotIn('Dropper', file['labels'])
        self.assertFalse(any(obj['type'] == 'malware' and 'webshell' in obj.get('malware_types', []) for obj in preview['objects']))
        self.decide([])
        ctx = self.endpoints['/api/cases/{slug}/artifact'](self.case.name, str(self.file), 'en')
        self.assertEqual([], ctx['file']['classifications'])
        conn = db.connect(self.case)
        self.assertGreaterEqual(conn.execute("SELECT count(*) FROM triage_events WHERE note LIKE 'File classifications:%'").fetchone()[0], 3)
        conn.close()

    def test_invalid_classification_does_not_change_decision(self):
        with self.assertRaises(HTTPException):
            self.decide(['unsupported'])
        ctx = self.endpoints['/api/cases/{slug}/artifact'](self.case.name, str(self.file), 'en')
        self.assertEqual('new', ctx['triage'])
        self.assertIsNone(ctx['file']['classifications'])

    def test_selected_distant_line_has_a_bounded_inert_excerpt(self):
        result = self.preview(self.file, 90)
        self.assertEqual(90, result['focus'])
        self.assertLessEqual(len(result['lines']), 29)
        self.assertEqual('Safe line 90', result['lines'][90 - result['from_line']])
        self.assertIn('error', self.preview(self.file, 200))

    def test_preview_rejects_outside_missing_directory_and_invalid_line(self):
        outside = self.evidence.parent / 'outside.txt'
        outside.write_text('safe outside text', encoding='utf-8')
        for path, line, status in [(outside, 1, 403), (self.evidence, 1, 400),
                                   (self.evidence / 'missing.txt', 1, 404), (self.file, 0, 400)]:
            with self.subTest(status=status), self.assertRaises(HTTPException) as error:
                self.preview(path, line)
            self.assertEqual(status, error.exception.status_code)

    def test_linked_ip_periods_aggregate_only_exact_file_requests(self):
        rows = [
            dict(ip='192.0.2.1', uri='/example.txt', hits=2, ok_hits=1, first_epoch=20, last_epoch=40),
            dict(ip='192.0.2.1', uri='/example.txt?q=1', hits=1, ok_hits=1, first_epoch=10, last_epoch=30),
            dict(ip='192.0.2.1', uri='/other/example.txt', hits=50, ok_hits=50, first_epoch=1, last_epoch=99),
        ]
        with patch.object(logindex, 'requests_for_names', return_value=rows):
            result = self.endpoints['/api/cases/{slug}/artifact'](self.case.name, str(self.file), 'en')
        ip = result['related_ips'][0]
        self.assertEqual((3, 10, 40), (ip['hits'], ip['first_epoch'], ip['last_epoch']))

    def test_request_query_supplies_periods_per_ip_and_uri(self):
        conn = sqlite3.connect(':memory:')
        conn.row_factory = sqlite3.Row
        conn.executescript('''
            CREATE TABLE requests (ip INTEGER, leaf INTEGER, uri INTEGER, status INTEGER, epoch REAL);
            CREATE TABLE ips (id INTEGER, ip TEXT);
            CREATE TABLE strings (id INTEGER, text TEXT);
            INSERT INTO ips VALUES (1, '192.0.2.1');
            INSERT INTO strings VALUES (1, 'example.txt'), (2, '/example.txt');
            INSERT INTO requests VALUES (1, 1, 2, 200, 20), (1, 1, 2, 404, 10);
        ''')
        with patch.object(logindex, '_open_ro', return_value=conn):
            rows = logindex.requests_for_names(self.case, ['example.txt'])
        self.assertEqual((2, 1, 10, 20), tuple(rows[0][key] for key in ('hits', 'ok_hits', 'first_epoch', 'last_epoch')))
