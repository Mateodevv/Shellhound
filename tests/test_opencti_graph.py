"""Only explicit profile data, IP labels, CVEs and hash identities leave a case."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from server import db, workspace
from server.integrations.opencti import graph


class OpenCTIGraphTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.case = workspace.create_case(Path(self.temporary.name), 'Local case name', 'EXPORT-1',
            notes='LOCAL-ONLY-NOTE', profile={'organization_name': 'Manual organisation',
            'summary': 'Manually entered summary', 'sectors': ['Healthcare'],
            'subsectors': [{'name': 'Manual laboratory', 'sector': 'Healthcare'}],
            'countries': ['DE'], 'state': 'Manual region', 'city': 'Manual city',
            'software': [{'name': 'Manual software', 'version': '1.2'}],
            'vulnerabilities': [{'name': 'CVE-2026-12345', 'status': 'suspected',
                                 'description': 'Manual CVE context'},
                                {'name': 'Legacy non-CVE', 'status': 'suspected'}]})
        self.conn = db.connect(self.case)
        self.addCleanup(self.conn.close)
        self.ids = {}
        for kind, value in [('ip', '198.51.100.4'), ('ip', '2001:db8::4'),
                            ('vulnerability', 'CVE-2026-12345'), ('hash', 'a' * 64),
                            ('domain', 'example.invalid'), ('url', 'https://example.invalid/'),
                            ('path', '/local/private.txt'), ('user', 'private-user')]:
            self.ids[value] = db.add_ioc(self.conn, value, kind, ['manual-tag'] if kind == 'ip' else (), note='LOCAL-ONLY-IOC-NOTE')
        self.conn.commit()

    def test_preview_never_reads_evidence_or_builds_retired_objects(self):
        with patch.object(graph, '_snapshot', side_effect=AssertionError('Unexpected file read')):
            result = graph.build_preview(self.case)
        self.assertEqual({row['type'] for row in result['iocs']}, {'ip', 'vulnerability', 'hash'})
        types = {obj['type'] for obj in result['objects']}
        self.assertFalse(types & {'indicator', 'artifact', 'malware', 'note', 'domain-name', 'url', 'user-account'})
        wire = json.dumps(result)
        for private in ('LOCAL-ONLY-NOTE', 'LOCAL-ONLY-IOC-NOTE', 'example.invalid', 'private-user', str(self.case)):
            self.assertNotIn(private, wire)
        for address in ('198.51.100.4', '2001:db8::4'):
            obj = next(obj for obj in result['objects'] if obj.get('value') == address)
            self.assertEqual(obj['labels'], ['manual-tag'])
        for name in ('Manual organisation', 'Manual laboratory', 'Manual region',
                     'Manual software', 'Manual CVE context'):
            self.assertIn(name, wire)
        self.assertTrue(result['warnings'])
        self.assertNotIn('Legacy non-CVE', wire)
        self.assertTrue(any(obj['type'] == 'relationship' and 'Manual CVE context' in obj.get('description', '')
                            for obj in result['objects']))
        self.assertEqual(result['fingerprint'], graph.build_preview(self.case)['fingerprint'])

    def test_unsupported_selection_and_retired_options_are_rejected(self):
        for value in ('example.invalid', '/local/private.txt'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                graph.build_preview(self.case, {'ioc_ids': [self.ids[value]]})
        for option in ('sample_ids', 'indicator_ids', 'include_notes', 'include_evidence'):
            with self.subTest(option=option), self.assertRaises(ValueError):
                graph.build_preview(self.case, {option: []})
        with self.assertRaises(ValueError):
            graph.build_preview(self.case, {'ioc_ids': [99999]})

    def test_profile_only_transfer_has_no_iocs_and_selection_changes_fingerprint(self):
        profile = graph.build_preview(self.case, {'ioc_ids': []})
        self.assertFalse(any(obj['type'] in graph.OBSERVABLE_TYPES for obj in profile['objects']))
        self.assertTrue(any(obj['type'] == 'x-opencti-case-incident' for obj in profile['objects']))
        selected = graph.build_preview(self.case, {'ioc_ids': [self.ids['198.51.100.4']]})
        self.assertNotEqual(profile['fingerprint'], selected['fingerprint'])

    def test_malformed_supported_value_blocks_transfer(self):
        self.conn.execute('UPDATE iocs SET value=? WHERE id=?', ('bad-address', self.ids['198.51.100.4']))
        self.conn.commit()
        self.assertTrue(graph.build_preview(self.case)['errors'])

    def test_manual_region_and_city_do_not_require_an_inferred_country(self):
        workspace.update_case(self.case, profile={'countries': []})
        locations = [obj for obj in graph.build_preview(self.case)['objects'] if obj['type'] == 'location']
        self.assertEqual({'Manual region', 'Manual city'}, {obj['name'] for obj in locations})
        self.assertTrue(all('country' not in obj for obj in locations))
