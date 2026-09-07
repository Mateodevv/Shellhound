"""Historical reputation remains readable; retired provider paths cannot send data."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from server import db, enrich, ruleswitch, settings


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ws = Path(self.temp.name)

    def test_unconfigured_defaults_are_offline(self):
        self.assertFalse(settings.opencti_public(self.ws)['configured'])
        self.assertFalse(settings.opencti_public(self.ws)['sample_uploads'])
        self.assertFalse(settings.path(self.ws).exists())

    def test_token_never_leaves_public_settings(self):
        token = 'integration-private-token-for-tests'
        settings.set_opencti(self.ws, {'url': 'https://cti.example', 'token': token,
            'ingester_id': 'dba5717c-b7d1-474f-8aad-bf9c2d61312c'})
        self.assertTrue(settings.opencti_public(self.ws)['configured'])
        self.assertNotIn(token, json.dumps(settings.public(self.ws)))
        self.assertNotIn('token', settings.opencti_public(self.ws))
        self.assertEqual(token, settings.opencti_config(self.ws)['token'])

    def test_new_destination_cannot_receive_old_token(self):
        settings.set_opencti(self.ws, {'url': 'https://cti.example', 'token': 'old-token'})
        settings.set_opencti(self.ws, {'url': 'https://different.example'})
        self.assertEqual('', settings.opencti_config(self.ws)['token'])

    def test_bad_transport_settings_and_header_injection_rejected(self):
        for url in ['http://cti.example', 'https://user:pass@cti.example',
                    'https://cti.example?token=x', 'https://cti.example#secret',
                    'https://cti.example:wrong', 'https://cti.example:0', 'https://bad host.example']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                settings.set_opencti(self.ws, {'url': url})
        for changes in [{'token': 'abc\nAuthorization: other'}, {'ingester_id': '../bad'},
                        {'external_file_uploads': True}, {'sample_uploads': 'yes'}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                settings.set_opencti(self.ws, changes)

    def test_rule_settings_preserve_integration(self):
        settings.set_opencti(self.ws, {'url': 'https://cti.example', 'token': 'test-token'})
        ruleswitch.set_enabled(self.ws, 'test-rule', False)
        settings.set_yara_disabled(self.ws, ['test.yar'])
        self.assertEqual('test-token', settings.opencti_config(self.ws)['token'])
        settings.set_opencti(self.ws, {'sample_uploads': True})
        self.assertIn('test-rule', ruleswitch.disabled_ids(self.ws))
        self.assertIn('test.yar', settings.yara_disabled(self.ws))

    def test_legacy_keys_never_released_and_next_save_drops_them(self):
        settings.path(self.ws).write_text(json.dumps({'keys': {'virustotal': 'legacy-secret'},
            'enrichment_ack': True}), encoding='utf-8')
        self.assertEqual('', settings.for_service(self.ws, 'virustotal'))
        self.assertEqual({}, settings.public(self.ws)['services'])
        settings.set_opencti(self.ws, {'url': 'https://cti.example'})
        self.assertNotIn('legacy-secret', settings.path(self.ws).read_text())
        with self.assertRaises(ValueError):
            settings.set_key(self.ws, 'virustotal', 'new-secret')

    def test_corrupt_settings_fail_closed(self):
        settings.path(self.ws).write_text('{bad', encoding='utf-8')
        self.assertFalse(settings.opencti_public(self.ws)['configured'])


class HistoricalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.case = Path(self.temp.name)

    def test_cache_is_readable_without_network_or_triage_changes(self):
        conn = db.connect(self.case)
        self.addCleanup(conn.close)
        conn.execute('INSERT INTO enrichment(service,value,kind,fetched,payload) VALUES(?,?,?,?,?)',
            ('virustotal', 'a'*64, 'hash', '2026-01-01T00:00:00', json.dumps({'known': True, 'score': 7})))
        conn.commit()
        with patch('urllib.request.urlopen', side_effect=AssertionError('network')):
            result = enrich.all_for(conn, ['a'*64, 'unknown'])
        self.assertEqual(7, result['a'*64]['virustotal']['result']['score'])
        self.assertEqual('2026-01-01T00:00:00', result['a'*64]['virustotal']['fetched'])
        self.assertEqual(0, conn.execute('SELECT count(*) FROM findings').fetchone()[0])

    def test_retired_lookups_fail_before_any_network_request(self):
        with patch('urllib.request.urlopen') as network:
            for provider in ['virustotal', 'abuseipdb']:
                with self.assertRaises(enrich.EnrichError):
                    enrich.lookup(self.case, self.case, provider, '198.51.100.7', refresh=True)
            network.assert_not_called()


if __name__ == '__main__':
    unittest.main()
