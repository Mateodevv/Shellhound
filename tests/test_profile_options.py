import unittest
from unittest.mock import patch

from server import profile_options as options
from server.opencti_client import OpenCTIError


class ProfileOptionsTests(unittest.TestCase):
    def setUp(self):
        options._CACHE.clear()
        self.addCleanup(options._CACHE.clear)

    def test_geography_prioritizes_countries_and_keeps_states_in_country(self):
        geo = options.geography()
        self.assertEqual(['Germany', 'Austria'], [c['name'] for c in geo['countries'][:2]])
        self.assertEqual(249, len(geo['countries']))
        self.assertEqual(16, len(geo['states']['DE']))
        self.assertEqual(9, len(geo['states']['AT']))
        self.assertTrue(all(s['code'].startswith(country + '-')
                            for country, states in geo['states'].items() for s in states))

    def test_sector_cache_is_scoped_to_connection_and_recovers_from_outage(self):
        config = {'url': 'https://cti.example', 'token': 'synthetic-token'}
        entries = [{'id': 's', 'name': 'Technology', 'parents': [], 'subsector': False}]
        with patch.object(options.settings, 'opencti_config', return_value=config), \
                patch.object(options, 'OpenCTIClient') as client, \
                patch.object(options.time, 'monotonic', return_value=0) as clock:
            client.return_value.sectors.return_value = entries
            self.assertEqual({'sectors': entries, 'stale': False}, options.sectors('unused'))
            options.sectors('unused')
            client.return_value.sectors.assert_called_once()
            clock.return_value = 1000
            client.return_value.sectors.side_effect = OpenCTIError('Unavailable')
            self.assertEqual({'sectors': entries, 'stale': True}, options.sectors('unused'))
            config['token'] = 'different-token'
            with self.assertRaises(OpenCTIError):
                options.sectors('unused')

    def test_unconfigured_connection_never_contacts_provider(self):
        with patch.object(options.settings, 'opencti_config', return_value={}), \
                patch.object(options, 'OpenCTIClient') as client:
            self.assertEqual({'sectors': [], 'stale': False}, options.sectors('unused'))
            client.assert_not_called()
