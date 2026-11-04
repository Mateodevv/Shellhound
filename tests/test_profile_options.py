"""Main sectors are local; remaining profile values are manual."""
import tempfile
import unittest
from pathlib import Path

from server.casework import profile, profile_options


class ProfileOptionsTests(unittest.TestCase):
    def test_catalogue_and_manual_subsectors_preserve_existing_profiles(self):
        self.assertEqual(len(profile_options.SECTORS), len(set(profile_options.SECTORS)))
        self.assertIn('Healthcare', profile_options.SECTORS)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            saved = profile.normalize({'sectors': ['Technology'], 'subsectors': [
                {'name': 'Manual specialist activity', 'sector': 'Technology'}],
                'countries': ['DE'], 'state': 'Manually entered region'}, root)
            self.assertEqual(saved['state'], 'Manually entered region')
            self.assertEqual(saved['subsectors'][0]['name'], 'Manual specialist activity')
            with self.assertRaisesRegex(ValueError, 'catalogue'):
                profile.normalize({'sectors': ['Unlisted main sector']}, root)
            self.assertEqual(profile.normalize({'summary': 'Updated manually'}, root,
                             {'sectors': ['Legacy sector']})['sectors'], ['Legacy sector'])
