"""Real HTTP regression coverage for the OpenCTI boundary and IOC identity."""
import hashlib
import json
import os
import tempfile
import unittest
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from server import backups, db, workspace
from server.app import create_app
from server.config import Config
from server.jobs import manager
from tests.test_http import _LiveServer


class OpenCTIHTTPTests(unittest.TestCase):
    def test_duplicate_check_serializes_concurrent_creates(self):
        base = f'/api/cases/{self.slug}/iocs'
        def create(note):
            return self.request('POST', base, {'value': 'race.test', 'type': 'domain', 'note': note, 'reject_duplicate': True})
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(create, ('one', 'two')))
        self.assertEqual([200, 200], [status for status, _ in results])
        self.assertEqual([False, True], sorted(result['ok'] for _, result in results))
        rows = self.request('GET', base)[1]
        self.assertEqual(1, len(rows))
        self.assertIn(rows[0]['note'], ('one', 'two'))

    def test_manual_ioc_suggestions_duplicates_and_atomic_type_edit(self):
        base = f'/api/cases/{self.slug}/iocs'
        suggest = '/api/iocs/suggest'
        self.assertEqual({'type': 'path', 'ambiguous': True}, self.request('POST', suggest, {'value': 'example.test'})[1])
        self.assertEqual({'type': 'ip', 'ambiguous': False}, self.request('POST', suggest, {'value': '192.0.2.1'})[1])
        self.assertEqual(400, self.request('POST', base, {'value': 'z' * 64, 'type': 'hash'})[0])
        first = self.request('POST', base, {'value': 'Example.test', 'type': 'domain', 'note': 'original'})[1]['id']
        result = self.request('POST', base, {'value': 'example.test', 'type': 'domain', 'note': 'draft', 'reject_duplicate': True})[1]
        self.assertEqual({'ok': False, 'existing_id': first, 'type': 'domain'}, result)
        self.assertEqual('original', self.request('GET', f'{base}/{first}/detail')[1]['object']['note'])
        path = self.request('POST', base, {'value': 'Example.test', 'type': 'path'})[1]['id']
        edit = {'value': 'Example.test', 'note': 'draft', 'type': 'domain', 'expected_type': 'path',
                'expected_value': 'Example.test', 'expected_note': '', 'assessment': 'malicious',
                'expected_assessment': 'malicious', 'reason': 'Correction'}
        self.assertEqual(400, self.request('POST', f'{base}/{path}/edit', edit)[0])
        self.assertEqual('', self.request('GET', f'{base}/{path}/detail')[1]['object']['note'])
        edit['value'] = 'another.test'
        self.assertEqual(200, self.request('POST', f'{base}/{path}/edit', edit)[0])
        self.assertEqual(400, self.request('POST', f'{base}/{path}/edit', edit)[0])
        obj = self.request('GET', f'{base}/{path}/detail')[1]['object']
        self.assertEqual(('domain', 'another.test', 'draft'), (obj['type'], obj['value'], obj['note']))

    def test_retype_preserves_links_and_invalidates_lookup(self):
        base = f'/api/cases/{self.slug}/iocs'
        path = self.request('POST', base, {'value': 'example.test', 'type': 'path'})[1]['id']
        ip = self.request('POST', base, {'value': '192.0.2.9', 'type': 'ip'})[1]['id']
        conn = db.connect(self.case)
        try:
            db.link_iocs(conn, ip, path, 'requested')
            conn.execute("INSERT INTO opencti_lookups VALUES(?,?,?,?,?)", (path, 'old', db.now(), '{}', 'local'))
            conn.commit()
        finally:
            conn.close()
        edit = {'value': 'example.test', 'note': '', 'type': 'domain', 'expected_type': 'path',
                'expected_value': 'example.test', 'expected_note': '', 'assessment': 'malicious',
                'expected_assessment': 'malicious', 'reason': 'Correction'}
        self.assertEqual(400, self.request('POST', f'{base}/{path}/edit', edit)[0])
        conn = db.connect(self.case)
        try:
            conn.execute('UPDATE ioc_links SET active=0')
            conn.commit()
        finally:
            conn.close()
        self.assertEqual(200, self.request('POST', f'{base}/{path}/edit', edit)[0])
        conn = db.connect(self.case)
        try:
            self.assertIsNone(db.one(conn, 'SELECT * FROM opencti_lookups WHERE ioc_id=?', (path,)))
        finally:
            conn.close()

    def test_wizard_archive_refuses_active_work_without_cancelling_it(self):
        conn = db.connect(self.case)
        try:
            conn.execute("INSERT INTO jobs(kind,state,created) VALUES('opencti-export','running',?)", (db.now(),))
            conn.commit()
        finally:
            conn.close()
        path = f'/api/cases/{self.slug}/archive?require_idle=true'
        with patch('server.app.manager.cancel') as cancel, patch('server.app.workspace.archive_case') as archive:
            self.assertEqual(401, self.request('POST', path, {}, token='bad')[0])
            self.assertEqual(409, self.request('POST', path, {})[0])
            cancel.assert_not_called()
            archive.assert_not_called()
            conn = db.connect(self.case)
            try:
                self.assertEqual('running', db.one(conn, "SELECT state FROM jobs")["state"])
                conn.execute("UPDATE jobs SET state='done'")
                conn.commit()
            finally:
                conn.close()
            archive.return_value = (self.root / 'closed.zip', {})
            status, result = self.request('POST', path, {})
            self.assertEqual(200, status)
            self.assertEqual(0, result['cancelled_jobs'])
            archive.assert_called_once()
            cancel.assert_not_called()

    def test_removed_features_and_retired_export_options_are_unavailable(self):
        prefix = f"/api/cases/{self.slug}/opencti"
        for suffix in ('lookup', 'enrich', 'enrichment/preview', 'enrichment/status', 'activity/clear'):
            self.assertEqual(404, self.request('POST', prefix + '/' + suffix, {})[0])
        self.assertEqual(404, self.request('GET', prefix + '/profile-changes')[0])
        for route in ('/api/organizations', '/api/opencti/sectors', '/api/profile/geography'):
            self.assertEqual(404, self.request('GET', route)[0])
        self.assertEqual(422, self.request('POST', prefix + '/preview', {'sample_ids': []})[0])
        self.assertEqual(422, self.request('PATCH', '/api/opencti/settings', {'sample_uploads': True})[0])


    def test_edit_ioc_is_atomic_validated_and_records_assessment_and_value_history(self):
        base = f'/api/cases/{self.slug}/iocs'
        ioc_id = self.request('POST', base, {'value': '192.0.2.1', 'type': 'ip'})[1]['id']
        other = self.request('POST', base, {'value': '192.0.2.2', 'type': 'ip'})[1]['id']
        body = {'value': '192.0.2.3', 'note': 'Corrected record', 'expected_value': '192.0.2.1', 'expected_note': '',
                'assessment': 'suspicious', 'expected_assessment': 'malicious', 'reason': 'Analyst correction', 'add_tags': ['reviewed']}
        url = f'{base}/{ioc_id}/edit'
        self.assertEqual(401, self.request('POST', url, body, token='bad')[0])
        for change in ({'value': 'bad-ip'}, {'value': '192.0.2.2'}, {'reason': ''}, {'add_tags': ['']}):
            self.assertEqual(400, self.request('POST', url, {**body, **change})[0])
            current = self.request('GET', f'{base}/{ioc_id}/detail')[1]
            self.assertEqual('192.0.2.1', current['object']['value'])
            self.assertEqual('malicious', current['object']['assessment'])
            self.assertFalse(current['edits'])
        status, result = self.request('POST', url, body)
        self.assertEqual(200, status, result)
        current = self.request('GET', f'{base}/{ioc_id}/detail')[1]
        self.assertEqual('192.0.2.3', current['object']['value'])
        self.assertEqual('suspicious', current['object']['assessment'])
        self.assertIn('reviewed', current['object']['tags'])
        self.assertEqual('192.0.2.1', current['edits'][0]['previous_value'])
        self.assertEqual('Analyst correction', current['assessments'][0]['reason'])
        self.assertEqual(400, self.request('POST', url, body)[0])
        self.assertEqual('192.0.2.2', self.request('GET', f'{base}/{other}/detail')[1]['object']['value'])

    def test_bulk_delete_is_authenticated_scoped_and_validated(self):
        base = f'/api/cases/{self.slug}/iocs'
        ids = [self.request('POST', base, {'value': value, 'type': 'ip'})[1]['id']
               for value in ('192.0.2.1', '192.0.2.2', '192.0.2.3')]
        self.assertEqual(401, self.request('POST', base + '/delete', {'ids': ids}, token='bad')[0])
        self.assertEqual(422, self.request('POST', base + '/delete', {'ids': [True]})[0])
        self.assertEqual(422, self.request('POST', base + '/delete', {'ids': []})[0])
        status, result = self.request('POST', base + '/delete', {'ids': ids[:2]})
        self.assertEqual(200, status)
        self.assertEqual(ids[:2], result['deleted_ids'])
        self.assertEqual([ids[2]], [row['id'] for row in self.request('GET', base)[1]])

    def test_database_user_keeps_registration_local_without_exporting_notes(self):
        conn = db.connect(self.case)
        try:
            account_id = conn.execute("INSERT INTO db_accounts(dump_id,cms,tbl,user_id,login,email,registered) "
                "VALUES(1,'joomla','cms_users','42','account-test','account@example.invalid','2024-02-03 04:05:06')").lastrowid
            conn.commit()
        finally:
            conn.close()
        base = f"/api/cases/{self.slug}"
        for _ in range(2):
            status, result = self.request("POST", base + "/database/accounts/flag", {"account_id": account_id})
            self.assertEqual(200, status, result)
        _, rows = self.request("GET", base + "/iocs")
        user = next(row for row in rows if row["type"] == "user")
        self.assertEqual(2, len(rows))
        self.assertEqual(1, len(user["account_sources"]))
        self.assertEqual("2024-02-03 04:05:06", user["account_sources"][0]["registered"])
        self.assertIsNone(user["first_seen"])
        self.assertIsNone(user["last_seen"])
        _, detail = self.request("GET", base + f"/iocs/{user['id']}/detail")
        self.assertEqual(user["account_sources"], detail["object"]["account_sources"])
        self.assertEqual("account-of", detail["relationships"][0]["kind"])
        _, preview = self.request("POST", base + "/opencti/preview", {})
        notes = [obj["content"] for obj in preview["objects"] if obj["type"] == "note"]
        from server.casework.profile_options import context_defaults
        self.assertEqual([{'schema': 'shellhound.case-context/v1', **context_defaults()}],
                         [json.loads(content) for content in notes])
        for private in ('account-test', 'account@example.invalid', '2024-02-03 04:05:06'):
            self.assertNotIn(private, json.dumps(preview))

    def test_structured_ioc_api_validation_and_offline_details(self):
        base = f"/api/cases/{self.slug}"
        for value, kind in (("198.51.100.9", "ip"), ("CVE-2026-12345", "vulnerability")):
            self.assertEqual(200, self.request("POST", base + "/iocs", {"value": value, "type": kind})[0])
        rows = self.request("GET", base + "/iocs")[1]
        ip = next(r["id"] for r in rows if r["type"] == "ip")
        cve = next(r["id"] for r in rows if r["type"] == "vulnerability")
        self.assertEqual(401, self.request("POST", base + f"/iocs/{ip}/assessments", {"state": "malicious", "reason": "Finding 1"}, token="bad")[0])
        self.assertEqual(400, self.request("POST", base + f"/iocs/{ip}/assessments", {"state": "malicious", "reason": " "})[0])
        self.assertEqual(200, self.request("POST", base + f"/iocs/{ip}/assessments", {"state": "suspicious", "reason": "Finding 1"})[0])
        code, link = self.request("POST", base + "/ioc-relationships", {"src": ip, "dst": cve, "kind": "exploit-attempt", "reference": "Access log line 5"})
        self.assertEqual(200, code)
        with patch("server.integrations.opencti.service.OpenCTIClient", side_effect=AssertionError("Unexpected network")):
            code, detail = self.request("GET", base + f"/iocs/{ip}/detail")
        self.assertEqual(200, code)
        self.assertEqual("suspicious", detail["object"]["assessment"])
        self.assertEqual("manual", detail["relationships"][0]["origin"])
        self.assertEqual(200, self.request("POST", base + f"/ioc-relationships/{link['id']}/withdraw", {"reason": "Wrong attribution"})[0])
        self.assertEqual(404, self.request("GET", base + "/iocs/999999/detail")[0])

    def test_ioc_tags_are_authenticated_local_deltas(self):
        base = f"/api/cases/{self.slug}/iocs"
        _, created = self.request("POST", base, {"value": "198.51.100.9", "type": "ip"})
        url = base + f"/{created['id']}/tags"
        self.assertEqual(401, self.request("POST", url, {"add": ["test"]}, token="bad")[0])
        with patch("server.integrations.opencti.service.OpenCTIClient", side_effect=AssertionError("Unexpected network")):
            status, payload = self.request("POST", url, {"add": [" IOC ", "ioc", "true positive"]})
            self.assertEqual(200, status)
            self.assertEqual(1, sum(t.casefold() == "ioc" for t in payload["tags"]))
            self.assertNotIn("analyst", payload["tags"])
            self.request("POST", url, {"add": ["scanner"]})
            _, payload = self.request("POST", url, {"remove": ["IOC"], "add": ["OpenCTI label"]})
            self.assertIn("scanner", payload["tags"])
            self.assertIn("OpenCTI label", payload["tags"])
            self.assertNotIn("IOC", payload["tags"])
            _, detail = self.request("GET", base + f"/{created['id']}/detail")
            self.assertEqual("malicious", detail["object"]["assessment"])
            self.assertEqual([], detail["assessments"])
        for invalid in (" ", "x" * 129, "two\nlines"):
            self.assertEqual(400, self.request("POST", url, {"add": [invalid]})[0])
        self.assertEqual(422, self.request("POST", url, {"add": ["tag"] * 101})[0])
        self.assertEqual(404, self.request("POST", base + "/999999/tags", {"add": ["tag"]})[0])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = workspace.create_case(self.root, "Integration test", "PIM-LOCAL-1")
        self.slug = self.case.name
        self.server = _LiveServer(create_app(Config(workspace=self.root, token="local-test")))
        self.base = self.server.start()
        self.addCleanup(self.server.stop)

    def request(self, method, path, body=None, token="local-test"):
        req = urllib.request.Request(self.base + path,
            data=json.dumps(body).encode() if body is not None else None,
            method=method, headers={"Content-Type": "application/json", "X-Token": token})
        try:
            response = urllib.request.urlopen(req, timeout=10)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            return response.status, json.loads(response.read())

    def test_offline_reads_auth_and_unconfigured_providers(self):
        with patch("server.integrations.opencti.service.OpenCTIClient", side_effect=AssertionError("network")):
            for path in ["/api/opencti/settings", "/api/profile/sectors", f"/api/cases/{self.slug}/opencti"]:
                self.assertEqual(401, self.request("GET", path, token="bad")[0])
                self.assertEqual(200, self.request("GET", path)[0])
            self.assertEqual(200, self.request("POST", "/api/settings/key",
                {"service": "virustotal", "key": "not-a-key"})[0])
            self.assertEqual(400, self.request("POST", f"/api/cases/{self.slug}/enrich",
                {"service": "abuseipdb", "value": "198.51.100.7"})[0])

    def test_read_only_match_is_explicit_and_does_not_need_a_transfer_ingester(self):
        url = f'/api/cases/{self.slug}/opencti/matches'
        value = {'kind': 'ip', 'value': '192.0.2.42'}
        query = url + '?kind=ip&value=192.0.2.42'
        self.assertEqual(401, self.request('POST', url, value, token='wrong')[0])
        self.assertEqual(401, self.request('GET', query, token='wrong')[0])
        self.assertEqual((200, {'result': None}), self.request('GET', query))
        self.assertEqual(400, self.request('POST', url, value)[0])
        status, config = self.request('PATCH', '/api/opencti/settings',
                                      {'url': 'https://cti.example.test', 'token': 'offline-lookup-test'})
        self.assertEqual(200, status)
        self.assertTrue(config['lookup_configured'])
        self.assertFalse(config['configured'])
        prior = {'id': 'prior', 'name': 'Prior case', 'entity_type': 'Case-Incident'}
        page = {'hasNextPage': False}
        observed = {'entity_type': 'IPv4-Addr', 'observable_value': value['value'],
                    'containers': {'edges': [{'node': prior}], 'pageInfo': page}}
        reply = {'data': {'stixCyberObservables': {'edges': [{'node': observed}], 'pageInfo': page}}}
        with patch('server.integrations.opencti.client.OpenCTIClient._request', return_value=reply) as transport:
            self.assertEqual(400, self.request('POST', url, {'kind': 'hash', 'value': 'x'})[0])
            self.assertEqual(400, self.request('POST', url, {**value, 'expected_url': 'https://old.example.test'})[0])
            self.assertEqual((200, {'result': None}), self.request('GET', query))
            transport.assert_not_called()
            status, match = self.request('POST', url, value)
            self.assertEqual(200, status, match)
            self.assertTrue(match['known'])
            self.assertEqual('https://cti.example.test/dashboard/id/prior', match['cases'][0]['url'])
            self.assertEqual((200, {'result': match}), self.request('GET', query))
            transport.assert_called_once()
            target, payload = transport.call_args.args
            self.assertEqual('/graphql', target)
            self.assertTrue(payload['query'].startswith('query '))
            self.assertNotIn('PIM-LOCAL-1', json.dumps(payload))

    def test_opencti_is_an_optional_follow_up_and_cannot_fail_local_analysis(self):
        base = f'/api/cases/{self.slug}'
        source = self.root / 'sample.sql'
        source.write_text("CREATE TABLE sample (id int);\n", encoding='utf-8')
        self.assertEqual(200, self.request('POST', base + '/evidence', {'kind': 'sql_dump', 'path': str(source)})[0])

        def run(options):
            status, result = self.request('POST', base + '/analyze', options)
            self.assertEqual(200, status, result)
            ids = [entry['job'] for entry in result['started']]
            self.assertFalse(manager.wait_for(self.case.resolve(), ids, timeout=10))
            return {j['kind']: j for j in self.request('GET', base + '/jobs')[1] if j['id'] in ids}

        with patch('server.integrations.opencti.matches.OpenCTIClient') as client:
            self.assertEqual({'sqldb'}, set(run({})))
            unconfigured = run({'opencti_matches': True})
            self.assertTrue(unconfigured['opencti-matches']['stats']['partial'])
            self.assertEqual('done', unconfigured['sqldb']['state'])
            self.request('PATCH', '/api/opencti/settings',
                         {'url': 'https://cti.example.test', 'token': 'offline-lookup-test'})
            self.assertEqual({'sqldb'}, set(run({})))
            changed = run({'opencti_matches': True, 'opencti_url': 'https://old.example.test'})
            self.assertTrue(changed['opencti-matches']['stats']['partial'])
            with patch('server.app.sqldump.scan', return_value={'partial': True}):
                incomplete = run({'opencti_matches': True})
            self.assertEqual('done', incomplete['sqldb']['state'])
            self.assertIn('incomplete', incomplete['opencti-matches']['stats']['reason'])
            client.assert_not_called()
            with closing(db.connect(self.case)) as conn:
                db.upsert_finding(conn, 'logs', 1, 'Test observation', 'client', '192.0.2.42')
                conn.commit()
            from server.integrations.opencti.client import OpenCTIError
            client.return_value.case_matches.side_effect = OpenCTIError('Offline', code='network')
            jobs = run({'opencti_matches': True})
            self.assertEqual('done', jobs['sqldb']['state'])
            self.assertEqual(1, jobs['opencti-matches']['stats']['failed'])
            self.assertTrue(jobs['opencti-matches']['stats']['partial'])
            client.return_value.case_matches.assert_called_once()
            with closing(db.connect(self.case)) as conn:
                evidence = db.one(conn, 'SELECT scanned_at,stats FROM evidence')
                self.assertTrue(evidence['scanned_at'])
                self.assertEqual('complete', json.loads(evidence['stats'])['last_attempt']['status'])

    def test_scan_checks_identical_flagged_files_once_after_hashes_are_published(self):
        base = f'/api/cases/{self.slug}'
        folder = self.root / 'synthetic-site'
        folder.mkdir()
        content = b'Harmless detector marker\n'
        for name in ('original.php', 'copy.php'):
            (folder / name).write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        self.assertEqual(200, self.request('POST', base + '/evidence', {'kind': 'webroot', 'path': str(folder)})[0])
        self.assertEqual(200, self.request('PATCH', '/api/opencti/settings',
                         {'url': 'https://cti.example.test', 'token': 'offline-lookup-test'})[0])
        marker = [('fixture.marker', 1, 'Harmless test observation', 1, 'marker')]
        prior = {'id': 'prior', 'name': 'Prior case'}
        with patch('server.app.webshell._yara_findings', return_value=marker), \
                patch('server.integrations.opencti.matches.OpenCTIClient') as remote:
            remote.return_value.case_matches.return_value = {'known': True, 'cases': [prior], 'truncated': False}
            status, result = self.request('POST', base + '/analyze', {'opencti_matches': True})
            self.assertEqual(200, status, result)
            self.assertFalse(manager.wait_for(self.case.resolve(), [e['job'] for e in result['started']], timeout=15))
            remote.return_value.case_matches.assert_called_once_with('hash', digest, exclude_reference='PIM-LOCAL-1')
            stats = next(j['stats'] for j in self.request('GET', base + '/jobs')[1] if j['kind'] == 'opencti-matches')
            self.assertEqual([{'kind': 'hash', 'value': digest}], stats['linked_values'])
            self.assertEqual((1, 1, 0), (stats['checked'], stats['linked'], stats['missing_hashes']))
            self.assertEqual('prior', self.request('GET', base + '/opencti/matches?kind=hash&value='
                             + digest)[1]['result']['cases'][0]['id'])

    def test_direct_provider_api_auth_cache_and_opencti_precedence(self):
        path = f"/api/cases/{self.slug}/enrich"
        body = {"service": "abuseipdb", "value": "1.1.1.1", "kind": "ip"}
        with patch("server.integrations.enrich._get", return_value={"data": {"abuseConfidenceScore": 7}}) as remote:
            self.assertEqual(401, self.request("POST", "/api/settings/key", {"service":"abuseipdb","key":"test-private-key"}, token="bad")[0])
            self.assertEqual(401, self.request("POST", path, body, token="bad")[0])
            self.assertEqual(400, self.request("POST", path, body)[0])
            self.assertEqual(200, self.request("POST", "/api/settings/key", {"service":"abuseipdb","key":"test-private-key"})[0])
            self.assertNotIn("test-private-key", json.dumps(self.request("GET", "/api/settings")[1]))
            self.assertEqual(404, self.request("POST", "/api/cases/missing/enrich", body)[0])
            remote.assert_not_called()
            code, result = self.request("POST", path, body)
            self.assertEqual(200, code); self.assertEqual(7, result["result"]["score"])
            self.assertEqual(200, self.request("POST", path, body)[0]); self.assertEqual(1, remote.call_count)
            from server import settings
            settings.set_opencti(self.root, {"url":"https://cti.example","token":"test-token","ingester_id":"dba5717c-b7d1-474f-8aad-bf9c2d61312c"})
            self.assertEqual(200, self.request("POST", path, {**body,"refresh":True})[0]); self.assertEqual(2, remote.call_count)

    def test_profile_sector_catalogue_is_authenticated_local_and_read_only(self):
        self.assertEqual(401, self.request('GET', '/api/profile/sectors', token='bad')[0])
        with patch('server.integrations.opencti.service.OpenCTIClient', side_effect=AssertionError('Unexpected network')):
            code, result = self.request('GET', '/api/profile/sectors')
        self.assertEqual(200, code)
        self.assertIn('Healthcare', result['sectors'])
        self.assertIn('Technology', result['sectors'])
        self.assertIn('Hospitals', result['subsectors']['Healthcare'])
        self.assertNotIn('Software', result['subsectors']['Healthcare'])
        before = self.request('GET', f'/api/cases/{self.slug}')[1]['profile']
        code, _ = self.request('PATCH', f'/api/cases/{self.slug}', {'profile': {'sectors': ['Healthcare'], 'subsectors': [{'name': 'Software', 'sector': 'Healthcare'}]}})
        self.assertEqual(400, code)
        self.assertEqual(before, self.request('GET', f'/api/cases/{self.slug}')[1]['profile'])


    def test_manual_profile_and_preview_are_reviewable_without_opencti_credentials(self):
        code, case = self.request('PATCH', f'/api/cases/{self.slug}', {'profile': {
            'organization_name': 'Manually entered organisation', 'summary': 'Synthetic test only',
            'vulnerabilities': [{'name': 'CVE-2026-1234', 'status': 'suspected'}]}})
        self.assertEqual(200, code, case)
        self.assertEqual('Manually entered organisation', case['profile']['organization_name'])
        code, preview = self.request('POST', f'/api/cases/{self.slug}/opencti/preview', {})
        self.assertEqual(200, code, preview)
        self.assertTrue(preview['preview_id'])
        self.assertIn('x-opencti-case-incident', {obj['type'] for obj in preview['objects']})
        self.assertEqual(400, self.request('POST', f'/api/cases/{self.slug}/opencti/export', {'preview_id': preview['preview_id']})[0])

    def test_case_context_api_roundtrip_validation_and_offline_preview(self):
        from tests.test_case_context import CONTEXT
        path = f'/api/cases/{self.slug}'
        with patch('server.integrations.opencti.service.OpenCTIClient', side_effect=AssertionError('Unexpected network')):
            code, saved = self.request('PATCH', path, {'profile': CONTEXT})
            self.assertEqual(200, code, saved)
            self.assertEqual(CONTEXT, {key: saved['profile'][key] for key in CONTEXT})
            self.assertEqual(400, self.request('PATCH', path, {'profile': {'data_exfiltration': False}})[0])
            self.assertEqual(saved['profile'], self.request('GET', path)[1]['profile'])
            code, preview = self.request('POST', path + '/opencti/preview', {'ioc_ids': []})
            self.assertEqual(200, code, preview)
            note = next(obj for obj in preview['objects'] if obj['type'] == 'note')
            self.assertEqual(CONTEXT['discovered_by'], json.loads(note['content'])['discovered_by'])
            catalogue = self.request('GET', '/api/profile/sectors')[1]['context_options']
            self.assertIn('not_observed', catalogue['data_exfiltration'])
            self.assertIn('Hetzner', catalogue['hosting_providers'])
            self.assertIn('SH Größe: 10–49', preview['case_labels'])
            self.assertFalse(any(label.startswith('shellhound:profile:') for label in preview['case_labels']))


    def test_wizard_creates_complete_profile_before_any_transfer(self):
        profile = {
            "organization_name": "Manual organisation",
            "summary": "Synthetic incident for wizard acceptance",
            "sectors": ["Technology", "Manufacturing"], "countries": ["de", "AT"],
            "first_seen": "2026-09-01", "last_seen": "2026-09-08",
            "software": [{"name": "Example CMS", "version": "5.2"}],
            "vulnerabilities": [
                {"name": "CVE-2026-12345", "status": "confirmed", "description": "Verified locally"},
                {"name": "Custom plugin flaw", "status": "suspected", "description": "Upload validation under investigation"},
            ], "marking": "TLP:AMBER+STRICT",
        }
        with patch("server.integrations.opencti.service.OpenCTIClient", side_effect=AssertionError("Unexpected network")):
            status, created = self.request("POST", "/api/cases", {
                "name": "Wizard acceptance", "reference": "PIM-WIZARD-1", "profile": profile,
            })
            self.assertEqual(200, status, created)
            _, saved = self.request("GET", f"/api/cases/{created['slug']}")
        from server.casework.profile import defaults
        expected = {**defaults(), **profile, "countries": ["DE", "AT"], "organization_name": "Manual organisation", "organization_id": saved["profile"]["organization_id"], "pseudonym": "Manual organisation", "subsectors": [], "state": "", "city": ""}
        self.assertEqual(expected, saved["profile"])
        self.assertEqual("PIM-WIZARD-1", saved["reference"])
        _, state = self.request("GET", f"/api/cases/{created['slug']}/opencti")
        self.assertEqual([], state["exports"])
        self.assertEqual([], state["jobs"])
        status, preview = self.request("POST", f"/api/cases/{created['slug']}/opencti/preview", {})
        self.assertEqual(200, status, preview)
        types = {obj["type"] for obj in preview["objects"]}
        self.assertTrue({"incident", "x-opencti-case-incident", "identity", "location", "vulnerability"} <= types)

    def test_keys_are_masked_and_case_id_collision_is_validation_error(self):
        code, response = self.request("PATCH", "/api/opencti/settings", {
            "url": "https://cti.example", "token": "private-test-secret",
            "ingester_id": "dba5717c-b7d1-474f-8aad-bf9c2d61312c"})
        self.assertEqual(200, code, response)
        self.assertNotIn("private-test-secret", json.dumps(response))
        self.assertEqual(400, self.request("POST", "/api/cases",
            {"name": "Duplicate", "reference": "pim-local-1"})[0])

    def test_ioc_delete_removes_provenance_and_reused_id_gets_new_identity(self):
        conn = db.connect(self.case)
        try:
            ioc_id = db.add_ioc(conn, "198.51.100.7", "ip")
            other = db.add_ioc(conn, "example.invalid", "domain")
            db.link_iocs(conn, other, ioc_id, "related-to")
            conn.execute("INSERT INTO ioc_sources(ioc_id,artifact,role,active,added) VALUES(?,?,?,?,?)",
                         (ioc_id, "synthetic.txt", "direct", 1, db.now()))
            source = conn.execute("SELECT source_uid FROM iocs WHERE id=?", (ioc_id,)).fetchone()[0]
            conn.commit()
        finally:
            conn.close()
        self.assertEqual(200, self.request("DELETE", f"/api/cases/{self.slug}/iocs/{ioc_id}")[0])
        conn = db.connect(self.case)
        try:
            self.assertEqual(0, conn.execute("SELECT count(*) FROM ioc_sources WHERE ioc_id=?", (ioc_id,)).fetchone()[0])
            self.assertEqual(0, conn.execute("SELECT count(*) FROM ioc_links").fetchone()[0])
            conn.execute("INSERT INTO iocs(id,value,type,added) VALUES(?,?,?,?)",
                         (ioc_id, "203.0.113.8", "ip", db.now()))
            replacement = conn.execute("SELECT source_uid FROM iocs WHERE id=?", (ioc_id,)).fetchone()[0]
            self.assertTrue(replacement)
            self.assertNotEqual(source, replacement)
        finally:
            conn.close()

    def _inert_evidence(self):
        evidence = self.root / "evidence"
        evidence.mkdir()
        sample = evidence / "example.txt"
        sample.write_bytes(b"Synthetic inert sample, no executable code.\n")
        conn = db.connect(self.case)
        try:
            conn.execute("INSERT INTO evidence(kind,path,added) VALUES(?,?,?)",
                         ("webroot", str(evidence), db.now()))
            conn.commit()
        finally:
            conn.close()
        with closing(db.connect(self.case)) as prepared:
            backups.index_content(prepared)
            prepared.commit()
        return sample

    def test_file_hashes_survive_windows_path_and_handle_ctime_difference(self):
        sample = self._inert_evidence()
        original = os.fstat
        def handle_stat(fd):
            value = original(fd)
            return SimpleNamespace(st_dev=value.st_dev, st_ino=value.st_ino,
                st_size=value.st_size, st_mtime_ns=value.st_mtime_ns,
                st_ctime_ns=value.st_ctime_ns + 1_000_000_000)
        with patch("server.app.os.fstat", side_effect=handle_stat):
            code, detail = self.request("GET", f"/api/cases/{self.slug}/file?path=" +
                                        urllib.parse.quote(str(sample), safe=""))
        self.assertEqual(200, code, detail)
        self.assertEqual(hashlib.sha256(sample.read_bytes()).hexdigest(), detail["hashes"]["sha256"])

    def test_explicit_file_classifications_reach_preview_and_can_be_corrected(self):
        sample = self._inert_evidence()
        route = f"/api/cases/{self.slug}/files/review"
        self.assertEqual(200, self.request("POST", route, {"path": str(sample),
            "state": "confirmed", "classification": "malware"})[0])
        self.assertEqual(400, self.request("POST", route, {"path": str(sample),
            "state": "confirmed", "classification": "c2", "note": "Invalid classification"})[0])
        for classification, malware_type in (("webshell", "webshell"), ("malware", "unknown")):
            with self.subTest(classification=classification):
                code, decision = self.request("POST", route, {"path": str(sample),
                    "state": "confirmed", "classification": classification,
                    "note": "Synthetic analyst confirmation for integration testing."})
                self.assertEqual(200, code, decision)
                self.assertEqual(classification, decision["review"]["classification"])
                code, preview = self.request("POST", f"/api/cases/{self.slug}/opencti/preview", {})
                self.assertEqual(200, code, preview)
                self.assertEqual([], preview["errors"])
                self.assertFalse(any(o["type"] == "malware" for o in preview["objects"]))
                labels = {label for obj in preview['objects'] if obj['type'] == 'file' for label in obj.get('labels', [])}
                self.assertIn('Webshell' if classification == 'webshell' else 'Malware', labels)
                self.assertFalse(any(obj['type'] in ('malware', 'indicator', 'artifact') for obj in preview['objects']))
        conn = db.connect(self.case)
        try:
            event = db.one(conn, "SELECT note FROM triage_events ORDER BY id DESC LIMIT 1")
            self.assertIn("File classifications: Malware", event["note"])
        finally:
            conn.close()
        self.assertEqual(200, self.request("POST", route, {"path": str(sample),
            "state": "dismissed", "note": "Synthetic correction."})[0])
        code, preview = self.request("POST", f"/api/cases/{self.slug}/opencti/preview", {})
        self.assertEqual(200, code, preview)
        self.assertFalse(any(o["type"] == "malware" for o in preview["objects"]))

    def test_manual_review_of_changed_bytes_retires_old_hash_provenance(self):
        sample = self._inert_evidence()
        route = f"/api/cases/{self.slug}/files/review"
        old_hash = hashlib.sha256(sample.read_bytes()).hexdigest()
        self.assertEqual(200, self.request("POST", route, {"path": str(sample),
            "state": "confirmed", "note": "First synthetic file review."})[0])
        conn = db.connect(self.case)
        try:
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('webshell_hashes',?)",
                         (json.dumps({str(sample): old_hash}),))
            conn.commit()
        finally:
            conn.close()
        sample.write_bytes(b"Different inert bytes at the same relative path.\n")
        new_hash = hashlib.sha256(sample.read_bytes()).hexdigest()
        with closing(db.connect(self.case)) as prepared:
            prepared.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('webshell_hashes',?)",
                             (json.dumps({str(sample): new_hash}),))
            prepared.commit()
            backups.index_content(prepared)
            prepared.commit()
        code, result = self.request("POST", route, {"path": str(sample), "state": "confirmed",
            "classification": "malware", "note": "Reviewed the changed synthetic bytes."})
        self.assertEqual(200, code, result)
        self.assertIn(new_hash, [i["value"] for i in result["collected"]])
        self.assertNotIn(old_hash, [i["value"] for i in result["collected"]])
        conn = db.connect(self.case)
        try:
            active = {r["value"]: r["active"] for r in db.rows(conn,
                "SELECT i.value,s.active FROM iocs i JOIN ioc_sources s ON s.ioc_id=i.id WHERE i.type='hash'")}
            self.assertEqual({old_hash: 0, new_hash: 1}, active)
        finally:
            conn.close()
        code, preview = self.request("POST", f"/api/cases/{self.slug}/opencti/preview", {})
        self.assertEqual(200, code, preview)
        files = [obj for obj in preview['objects'] if obj['type'] == 'file']
        self.assertTrue(any(obj['hashes'].get('SHA-256') == new_hash for obj in files))
        self.assertFalse(any(obj['type'] in ('malware', 'indicator', 'artifact') for obj in preview['objects']))

    def test_profile_edit_rejects_stale_revision_without_overwriting_newer_data(self):
        route = f"/api/cases/{self.slug}"
        _, initial = self.request("GET", route)
        code, changed = self.request("PATCH", route, {"name": "Updated name", "profile": {"summary": "First editor"},
            "expected_profile_revision": initial["profile_revision"]})
        self.assertEqual(200, code, changed)
        self.assertNotEqual(initial["profile_revision"], changed["profile_revision"])
        code, error = self.request("PATCH", route, {"profile": {"summary": "Stale editor"},
            "expected_profile_revision": initial["profile_revision"]})
        self.assertEqual(409, code, error)
        _, saved = self.request("GET", route)
        self.assertEqual("First editor", saved["profile"]["summary"])
        self.assertEqual("Updated name", saved["name"])
        with patch("server.integrations.opencti.service.OpenCTIClient", side_effect=AssertionError("Unexpected network")):
            code, changes = self.request("GET", route + "/opencti/profile-changes")
        self.assertEqual(404, code, changes)

if __name__ == "__main__":
    unittest.main()
