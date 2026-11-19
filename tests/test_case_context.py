"""Case context stays explicit, survives archives and matches the reviewed export."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from server import db, workspace
from server.casework import profile, profile_options
from server.integrations.opencti import graph, service


CONTEXT = {
    'employee_count': '10-49', 'hosting_model': 'managed_hosting',
    'hosting_providers': ['Synthetic Hosting', 'Synthetic Cloud'], 'it_operating_model': 'external',
    'initial_access': 'software_vulnerability', 'initial_access_status': 'suspected', 'initial_cve': 'CVE-2026-12345',
    'spread': ['web_application', 'web_server'], 'data_exfiltration': 'not_observed',
    'attacker_encryption': 'not_investigated', 'discovered_by': 'soc_mdr', 'discovery_method': 'monitoring',
}


class CaseContextTests(unittest.TestCase):
    def test_context_survives_partial_edits_archive_and_reviewed_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case = workspace.create_case(root / 'cases', 'Synthetic', 'CONTEXT-1', notes='LOCAL-ONLY-NOTE',
                                         profile=CONTEXT)
            saved = workspace.update_case(case, profile={'summary': 'Reviewed summary'})['profile']
            self.assertEqual(CONTEXT, {key: saved[key] for key in CONTEXT})
            preview = graph.build_preview(case, {'ioc_ids': []})
            self.assertEqual(CONTEXT, {key: preview['profile'][key] for key in CONTEXT})
            note = next(obj for obj in preview['objects'] if obj['type'] == 'note')
            self.assertEqual({'schema': 'shellhound.case-context/v1', **CONTEXT}, json.loads(note['content']))
            self.assertEqual([preview['incident_id']], note['object_refs'])
            self.assertEqual([graph.MARKINGS['TLP:AMBER+STRICT']], note['object_marking_refs'])
            container = next(obj for obj in preview['objects'] if obj['id'] == preview['case_id'])
            self.assertIn(note['id'], container['object_refs'])
            self.assertEqual(profile_options.context_labels(CONTEXT), container['labels'])
            self.assertEqual(container['labels'], preview['case_labels'])
            self.assertIn('shellhound:profile:spread:web_application', container['labels'])
            self.assertIn('shellhound:profile:hosting_providers:synthetic hosting', container['labels'])
            self.assertIn('shellhound:profile:initial_cve:cve-2026-12345', container['labels'])
            self.assertFalse(any(obj['type'] == 'vulnerability' for obj in preview['objects']))
            self.assertTrue(all(not obj.get('labels') for obj in preview['objects'] if obj['id'] != container['id']))
            self.assertNotIn('LOCAL-ONLY-NOTE', json.dumps(preview))
            workspace.update_case(case, profile={'employee_count': '50-249'})
            changed = graph.build_preview(case, {'ioc_ids': []})
            self.assertNotEqual(preview['fingerprint'], changed['fingerprint'])
            self.assertEqual(note['id'], next(obj['id'] for obj in changed['objects'] if obj['type'] == 'note'))
            archive, _ = workspace.archive_case(root / 'cases', case)
            restored = workspace.import_archive(root / 'restored', archive)
            self.assertEqual({**saved, 'employee_count': '50-249'}, workspace.case_info(restored['dir'])['profile'])

    def test_legacy_cases_and_analysis_do_not_infer_customer_or_incident_facts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case = workspace.create_case(root, 'Synthetic', 'LEGACY-1')
            identity_path = case / workspace.CASE_FILE
            identity = json.loads(identity_path.read_text())
            for key in CONTEXT:
                identity['profile'].pop(key)
            identity_path.write_text(json.dumps(identity))
            original = identity_path.read_bytes()
            conn = db.connect(case)
            try:
                db.add_ioc(conn, 'CVE-2026-12345', 'vulnerability')
                conn.execute("INSERT OR REPLACE INTO meta VALUES('first_sign_override',?)", (json.dumps({'title': 'Confirmed activity'}),))
                conn.commit()
            finally:
                conn.close()
            current = workspace.case_info(case)['profile']
            self.assertEqual(profile_options.context_defaults(), {key: current[key] for key in CONTEXT})
            self.assertEqual(original, identity_path.read_bytes())
            exported = graph.build_preview(case)
            note = next(obj for obj in exported['objects'] if obj['type'] == 'note')
            self.assertEqual({'schema': 'shellhound.case-context/v1', **profile_options.context_defaults()}, json.loads(note['content']))

    def test_clearing_context_exports_unknowns_with_the_same_note_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            case = workspace.create_case(Path(temporary), 'Synthetic', 'CLEAR-1', profile=CONTEXT)
            initial = next(obj for obj in graph.build_preview(case)['objects'] if obj['type'] == 'note')
            workspace.update_case(case, profile=profile_options.context_defaults())
            cleared = next(obj for obj in graph.build_preview(case)['objects'] if obj['type'] == 'note')
            self.assertEqual(initial['id'], cleared['id'])
            self.assertEqual({'schema': 'shellhound.case-context/v1', **profile_options.context_defaults()}, json.loads(cleared['content']))
            labels = graph.build_preview(case)['case_labels']
            self.assertEqual(len(profile_options.context_defaults()), len(labels))
            self.assertTrue(all(value.endswith(':unknown') for value in labels))

    def test_case_labels_are_stable_and_keep_fields_and_multiple_providers_separate(self):
        first = profile_options.context_labels({**CONTEXT, 'hosting_providers': ['Hetzner', 'AWS', 'hetzner']})
        second = profile_options.context_labels({**CONTEXT, 'hosting_providers': ['aws', 'Hetzner']})
        self.assertEqual(first, second)
        self.assertIn('shellhound:profile:data_exfiltration:not_observed', first)
        self.assertNotIn('shellhound:profile:data_exfiltration:unknown', first)
        self.assertNotIn('shellhound:profile:hosting_providers:unknown', first)

    def test_validation_rejects_unstructured_or_ambiguous_values(self):
        invalid = [{'employee_count': 42}, {'hosting_model': 'Guessed from IP'}, {'spread': 'web_server'},
                   {'spread': ['unknown']}, {'data_exfiltration': False}, {'attacker_encryption': 'no'},
                   {'hosting_providers': ['two\nlines']}, {'hosting_providers': ['x' * 201]},
                   {'hosting_providers': ['x'] * 21}, {'hosting_providers': [None]},
                   {'initial_access_status': 'confirmed'}, {'initial_cve': None}, {'initial_cve': ['CVE-2026-12345']},
                   {'initial_cve': 'CVE-2026-123'}, {'initial_cve': 'CVE-2026-12345 extra'},
                   {'initial_cve': 'CVE-２０２６-12345'}, {'initial_cve': 'CVE-2026-12345\nCVE-2026-99999'},
                   {'initial_cve': 'CVE-2026-' + '1' * 200}]
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                profile.validate(changes)
        saved = profile.validate({'hosting_providers': [' Synthetic Hosting ', 'synthetic hosting', 'Cloud'],
                                  'spread': ['web_server', 'web_server']})
        self.assertEqual(['Synthetic Hosting', 'Cloud'], saved['hosting_providers'])
        self.assertEqual(['web_server'], saved['spread'])
        self.assertEqual('CVE-2026-12345', profile.validate({'initial_cve': ' cve-2026-12345 '})['initial_cve'])
        self.assertEqual('', profile.validate({'initial_cve': '  '})['initial_cve'])

    def test_provider_redaction_and_owned_note_updates(self):
        with tempfile.TemporaryDirectory() as temporary:
            case = workspace.create_case(Path(temporary), 'Synthetic', 'REDACT-1',
                profile={**CONTEXT, 'hosting_providers': [r'C:\Users\Example\private api_key=synthetic-secret']})
            preview = graph.build_preview(case)
            self.assertTrue(preview['redacted'])
            self.assertNotIn('synthetic-secret', json.dumps(preview))
            note = next(obj for obj in preview['objects'] if obj['type'] == 'note')
            client = MagicMock()
            client.find_existing_shared.return_value = None
            with patch.object(service, '_save_export'):
                service._prepare_shared(client, case, {}, {**preview, 'mapping_destination': 'test'})
            self.assertNotIn(note, [call.args[0] for call in client.find_existing_shared.call_args_list])

    def test_all_context_choices_have_interface_labels(self):
        copy = (Path(__file__).resolve().parents[1] / 'web/src/i18n/en.ts').read_text(encoding='utf-8')
        for field, choices in profile_options.CONTEXT_OPTIONS.items():
            for value in choices:
                if value != 'unknown':
                    self.assertIn(f"'caseContext.option.{field}.{value}'", copy)
