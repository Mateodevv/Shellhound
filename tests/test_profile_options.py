"""Sector catalogues restrict new values and preserve saved legacy values."""
import tempfile
import unittest
from pathlib import Path

from server.casework import profile, profile_options


class ProfileOptionsTests(unittest.TestCase):
    def test_catalogue_and_selected_subsectors_preserve_existing_profiles(self):
        self.assertEqual(len(profile_options.SECTORS), len(set(profile_options.SECTORS)))
        self.assertIn('Healthcare', profile_options.SECTORS)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            saved = profile.normalize({'sectors': ['Technology'], 'subsectors': [
                {'name': 'Software', 'sector': 'Technology'}],
                'countries': ['DE'], 'state': 'Manually entered region'}, root)
            self.assertEqual(saved['state'], 'Manually entered region')
            self.assertEqual(saved['subsectors'][0]['name'], 'Software')
            with self.assertRaisesRegex(ValueError, 'catalogue'):
                profile.normalize({'sectors': ['Unlisted main sector']}, root)
            self.assertEqual(profile.normalize({'summary': 'Updated manually'}, root,
                             {'sectors': ['Legacy sector']})['sectors'], ['Legacy sector'])

    def test_new_subsectors_are_restricted_to_their_main_sector_and_old_values_survive(self):
        self.assertEqual(set(profile_options.SECTORS), set(profile_options.SUBSECTORS))
        for entries in profile_options.SUBSECTORS.values():
            self.assertTrue(entries)
            self.assertEqual(len(entries), len(set(entries)))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old = {'sectors': ['Healthcare'], 'subsectors': [{'name': 'Saved clinic', 'sector': 'Healthcare'}]}
            saved = profile.normalize({'summary': 'Updated'}, root, old)
            self.assertEqual(old['subsectors'], saved['subsectors'])
            for name in ('Software', 'New arbitrary clinic'):
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'catalogue'):
                    profile.normalize({'sectors': ['Healthcare'], 'subsectors': [{'name': name, 'sector': 'Healthcare'}]}, root)
            self.assertEqual(profile.normalize({'sectors': ['Healthcare'], 'subsectors': [
                {'name': 'Hospitals', 'sector': 'Healthcare'}]}, root)['subsectors'][0]['name'], 'Hospitals')
            self.assertEqual(old['subsectors'], profile.validate(old)['subsectors'])
