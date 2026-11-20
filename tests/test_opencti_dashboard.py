"""Portable filters must resolve to real labels without seeding fake incidents."""
import base64
import json
import unittest

from server.casework.profile_options import CONTEXT_OPTIONS, SECTORS, context_labels
from tools.opencti_dashboard import (OUTPUT, TITLES, VERSION, display_label, build_catalogue,
                                     build_dashboard, label_id, label_value, options)


class OpenCTIDashboardTests(unittest.TestCase):
    def setUp(self):
        self.dashboard = build_dashboard()
        self.manifest = json.loads(base64.b64decode(self.dashboard['configuration']['manifest']))
        self.widgets = list(self.manifest['widgets'].values())

    def test_import_files_match_generator(self):
        for name, expected in [('01-shellhound-label-catalogue.stix.json', build_catalogue()),
                               ('02-shellhound-dashboard-' + VERSION + '.json', self.dashboard)]:
            self.assertEqual(json.loads((OUTPUT / name).read_text(encoding='utf-8')), expected)
        self.assertNotIn('shellhound:profile:', json.dumps(self.manifest))
        self.assertEqual(self.dashboard['type'], 'dashboard')
        self.assertEqual(self.dashboard['openCTI_version'], '7.261103.0')

    def test_seed_creates_only_metadata_and_matches_actual_profile_labels(self):
        catalogue = build_catalogue()
        self.assertEqual([o['type'] for o in catalogue['objects']], ['identity', 'grouping'])
        self.assertEqual(catalogue['objects'][1]['object_refs'], [catalogue['objects'][0]['id']])
        labels = set(catalogue['objects'][1]['labels'])
        self.assertEqual(len(labels), sum(len(v) for v in options().values()) + 1)
        self.assertIn('Webserver Compromise', labels)
        for field, values in options().items():
            for value in values:
                profile = {field: [value] if field in ('spread', 'hosting_providers') else value}
                self.assertIn(display_label(field, value), context_labels(profile))
                self.assertIn(display_label(field, value), labels)
        self.assertEqual(label_id('data_exfiltration', 'confirmed', display=False),
                         'label--225f97d0-a93c-5966-9168-741165b8cee5')

    def test_all_queries_are_scoped_and_all_references_seeded(self):
        ids = {label_id(field, value) for field, values in options().items() for value in values}
        cohort = {label_id('employee_count', value) for value in CONTEXT_OPTIONS['employee_count']}
        for widget in self.widgets:
            for data in widget['dataSelection']:
                self.assertEqual(widget['perspective'], data['perspective'])
                relationships = data['perspective'] == 'relationships'
                self.assertEqual(data['date_attribute'], 'created_at' if relationships else 'created')
                group = data['dynamicFrom'] if relationships else data['filters']
                self.assertEqual(group['mode'], 'and')
                self.assertEqual(group['filterGroups'], [])
                self.assertIn({'key': ['entity_type'], 'values': ['Case-Incident'],
                               'operator': 'eq', 'mode': 'or'}, group['filters'])
                label_filters = [f for f in group['filters'] if f['key'] == ['objectLabel']]
                self.assertEqual(set(label_filters[0]['values']), cohort)
                for item in label_filters:
                    self.assertLessEqual(set(item['values']), ids)
        charts = [w for w in self.widgets if w['type'] == 'horizontal-bar']
        self.assertEqual(len(charts), 14)
        self.assertTrue(all(w['layout']['h'] == 3 for w in charts))
        self.assertFalse(any(w['type'] in ('vertical-bar', 'line', 'area', 'timeline') for w in self.widgets))
        for field in TITLES:
            chart = next(w for w in charts if w['parameters']['title'] == TITLES[field])
            expected = {label_id(field, value, display=True) for value in options()[field]}
            self.assertEqual(len(chart['dataSelection']), 1)
            data = chart['dataSelection'][0]
            self.assertEqual(data['perspective'], 'relationships')
            self.assertEqual(data['attribute'], 'internal_id')
            self.assertTrue(data['isTo'])
            self.assertEqual(data['filters'], {'mode': 'and', 'filterGroups': [], 'filters': [
                {'key': ['entity_type'], 'values': ['object-label'], 'operator': 'eq', 'mode': 'or'},
                {'key': ['fromTypes'], 'values': ['Case-Incident'], 'operator': 'eq', 'mode': 'or'},
                {'key': ['toId'], 'values': [label_id(field, value, display=True) for value in options()[field]],
                 'operator': 'eq', 'mode': 'or'},
            ]})
            self.assertEqual(set(data['filters']['filters'][-1]['values']), expected)
            self.assertGreaterEqual(data['number'], len(expected))
        exfil_hosting = charts[-1]
        for data in exfil_hosting['dataSelection']:
            self.assertEqual(len(data['dynamicFrom']['filters']), 3)
            self.assertEqual(data['dynamicFrom']['filters'][-1]['values'],
                             [label_id('data_exfiltration', 'confirmed')])
            self.assertEqual(data['filters']['filters'][-1]['values'],
                             [label_id('hosting_model', value, display=True) for value in options()['hosting_model']])

    def test_layout_has_no_overlap_and_ids_match(self):
        occupied = set()
        for key, widget in self.manifest['widgets'].items():
            layout = widget['layout']
            self.assertEqual(key, widget['id'])
            self.assertEqual(key, layout['i'])
            self.assertTrue(0 <= layout['x'] < layout['x'] + layout['w'] <= 12)
            cells = {(x, y) for x in range(layout['x'], layout['x'] + layout['w'])
                     for y in range(layout['y'], layout['y'] + layout['h'])}
            self.assertFalse(occupied & cells, widget['parameters']['title'])
            occupied.update(cells)

    def test_statuses_replace_counters_and_map_uses_case_city_memberships(self):
        counters = [w for w in self.widgets if w['type'] == 'number']
        self.assertEqual([w['parameters']['title'] for w in counters], ['Übertragene Shellhound-Fälle'])
        for field in ('data_exfiltration', 'attacker_encryption', 'initial_access', 'initial_cve'):
            chart = next(w for w in self.widgets if w['parameters']['title'] == TITLES[field])
            self.assertLess(chart['layout']['y'], 14)
        chart = next(w for w in self.widgets if w['type'] == 'map')
        data = chart['dataSelection'][0]
        self.assertEqual(data['filters']['filters'], [
            {'key': ['entity_type'], 'values': ['object'], 'operator': 'eq', 'mode': 'or'},
            {'key': ['fromTypes'], 'values': ['Case-Incident'], 'operator': 'eq', 'mode': 'or'},
            {'key': ['toTypes'], 'values': ['City'], 'operator': 'eq', 'mode': 'or'},
        ])
        self.assertTrue(data['isTo'])
        self.assertEqual(data['attribute'], 'internal_id')
        self.assertEqual((data['centerLat'], data['centerLng'], data['zoom']), (51.1657, 10.4515, 5))
        values = options()['initial_cve']
        self.assertEqual(len(values), len(set(values)))
        self.assertIn('unknown', values)
        self.assertIn('CVE-2026-102785', values)

    def test_sectors_count_case_memberships_for_main_sectors_in_second_row(self):
        chart = next(w for w in self.widgets if w['parameters']['title'] == 'Branchen · Mehrfachnennungen')
        self.assertEqual((chart['layout']['x'], chart['layout']['y'], chart['layout']['w'], chart['layout']['h']),
                         (0, 8, 6, 3))
        data = chart['dataSelection'][0]
        self.assertEqual(data['attribute'], 'internal_id')
        self.assertTrue(data['isTo'])
        self.assertEqual(data['filters']['filters'], [
            {'key': ['entity_type'], 'values': ['object'], 'operator': 'eq', 'mode': 'or'},
            {'key': ['fromTypes'], 'values': ['Case-Incident'], 'operator': 'eq', 'mode': 'or'},
            {'key': ['toTypes'], 'values': ['Sector'], 'operator': 'eq', 'mode': 'or'},
        ])
        self.assertEqual(data['dynamicTo']['filters'], [
            {'key': ['name'], 'values': list(SECTORS), 'operator': 'eq', 'mode': 'or'},
        ])


if __name__ == '__main__':
    unittest.main()
