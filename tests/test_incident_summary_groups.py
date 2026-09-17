"""Harmless stored observations exercise dashboard counts and their drill-downs."""
import tempfile
import unittest
from pathlib import Path

from server import db, file_classifications, ruleswitch, workspace
from server.app import create_app
from server.casework.incident_summary import summarize
from server.config import Config
from tests.test_scan_retry_api import LocalClient


class IncidentSummaryGroupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='incident summaries ')
        self.addCleanup(self.temp.cleanup)
        self.config = Config(workspace=Path(self.temp.name) / 'cases', token='synthetic-test')
        self.case = workspace.create_case(self.config.workspace, 'Synthetic summary')
        self.client = LocalClient(create_app(self.config), {'x-token': self.config.token})
        self.addCleanup(self.client.close)
        self.url = f'/api/cases/{self.case.name}'

    def seed(self, *items):
        conn = db.connect(self.case)
        try:
            for item in items:
                values = {'source': 'webshell', 'rule': 'Harmless marker',
                          'artifact_kind': 'file', 'severity': 1, 'triage': 'new',
                          'engine': 'synthetic', 'seen_run': 0, 'rule_id': '',
                          'created': db.now(), 'last_seen': db.now(), **item}
                values.setdefault('fingerprint', values['artifact'] + values['rule'])
                conn.execute(f"INSERT INTO findings({','.join(values)}) "
                             f"VALUES ({','.join('?' for _ in values)})", list(values.values()))
            conn.commit()
        finally:
            conn.close()

    def get(self, suffix):
        response = self.client.get(self.url + suffix)
        self.assertEqual(200, response.status_code, response.text)
        return response.json()

    def summary(self):
        return self.get('/dashboard')['incident_summary']

    def test_whole_case_groups_filter_before_pagination_and_keep_supporting_findings(self):
        self.seed(*[{'artifact': f'unrelated-{i:04}.txt', 'source': 'yara'} for i in range(505)],
                  *[{'artifact': f'web-item-{i:04}.txt'} for i in range(503)],
                  {'artifact': 'web-item-0502.txt', 'source': 'yara', 'rule': 'Second observation'})
        self.assertEqual(503, self.summary()['pending_malware_files'])
        page = self.get('/findings?summary_group=malware_files&offset=501&limit=2')
        self.assertEqual(503, page['total'])
        self.assertEqual(['web-item-0501.txt', 'web-item-0502.txt'],
                         [item['artifact'] for item in page['artifacts']])
        self.assertEqual(3, len(page['findings']))
        self.assertEqual(0, self.get('/findings?summary_group=unknown')['total'])
        separate = workspace.create_case(self.config.workspace, 'Separate case')
        response = self.client.get(f'/api/cases/{separate.name}/findings?summary_group=malware_files')
        self.assertEqual(0, response.json()['total'])

    def test_explicit_classes_override_fallback_including_empty_and_nonmalware(self):
        self.seed({'artifact': 'fallback.txt'}, {'artifact': 'empty.txt'},
                  {'artifact': 'modified.txt'}, {'artifact': 'classified.txt', 'source': 'yara'},
                  {'artifact': 'multi.txt', 'triage': 'confirmed'},
                  {'artifact': 'multi.txt', 'source': 'yara', 'rule': 'Second observation'},
                  {'artifact': 'old-source.txt', 'engine': 'old'},
                  {'artifact': 'old-source.txt', 'source': 'yara', 'rule': 'Current observation'})
        conn = db.connect(self.case)
        file_classifications.store(conn, 'empty.txt', [], 'new')
        file_classifications.store(conn, 'modified.txt', ['modified-file'], 'new')
        file_classifications.store(conn, 'classified.txt', ['backdoor', 'dropper'], 'new')
        file_classifications.store(conn, 'multi.txt', ['webshell', 'malware'], 'confirmed')
        conn.execute("INSERT INTO meta(key,value) VALUES ('engine_done:old','1')")
        conn.commit()
        conn.close()
        summary = self.summary()
        self.assertEqual((1, 2), (summary['malware_files'], summary['pending_malware_files']))
        page = self.get('/findings?summary_group=malware_files')
        self.assertEqual({'fallback.txt', 'classified.txt', 'multi.txt'},
                         {item['artifact'] for item in page['artifacts']})

    def test_hidden_retired_dismissed_and_reviewed_follow_findings_rules(self):
        self.seed({'artifact': 'hidden.txt', 'rule_id': 'synthetic.muted'},
                  {'artifact': 'reviewed.txt', 'rule_id': 'synthetic.muted', 'triage': 'reviewed'},
                  {'artifact': 'confirmed.txt', 'rule_id': 'synthetic.muted', 'triage': 'confirmed'},
                  {'artifact': 'dismissed.txt', 'triage': 'dismissed'},
                  {'artifact': 'historical.txt', 'triage': 'confirmed', 'engine': 'old'},
                  {'artifact': 'historical-reviewed.txt', 'triage': 'reviewed', 'engine': 'old'})
        conn = db.connect(self.case)
        conn.execute("INSERT INTO meta(key,value) VALUES ('engine_done:old','1')")
        conn.commit()
        conn.close()
        ruleswitch.set_enabled(self.config.workspace, 'synthetic.muted', False)
        summary = self.summary()
        self.assertEqual((1, 1), (summary['malware_files'], summary['pending_malware_files']))
        page = self.get('/findings?summary_group=malware_files&show_retired=1')
        self.assertEqual({'confirmed.txt', 'reviewed.txt'},
                         {item['artifact'] for item in page['artifacts']})
        # Historical decisions still exist in the ordinary evidence list.
        historical = self.get('/findings?search=historical&show_retired=1')
        self.assertEqual(2, historical['total'])

    def test_ip_counts_validate_addresses_and_match_artifact_decisions(self):
        self.seed(*[{'artifact': value, 'artifact_kind': 'client', 'source': 'logs', 'triage': state}
                    for value, state in [('192.0.2.1', 'confirmed'), ('192.0.2.2', 'new'),
                                         ('2001:db8::1', 'confirmed'),
                                         ('2001:0db8:0:0:0:0:0:1', 'confirmed'),
                                         ('2001:db8::2', 'reviewed'),
                                         ('192.0.2.3', 'dismissed'), ('not-an-ip', 'confirmed')]],
                  {'artifact': '192.0.2.1', 'artifact_kind': 'client', 'source': 'yara',
                   'rule': 'Supporting observation'})
        summary = self.summary()
        self.assertEqual((2, 3, 2), (summary['attacker_ips'], summary['confirmed_ips'], summary['pending_ips']))
        confirmed = self.get('/findings?summary_group=ips&hide_triage=new,reviewed,dismissed')
        pending = self.get('/findings?summary_group=ips&hide_triage=confirmed,dismissed')
        self.assertEqual(summary['confirmed_ips'], confirmed['total'])
        self.assertEqual(summary['pending_ips'], pending['total'])
        conn = db.connect(self.case)
        conn.execute("UPDATE findings SET triage='confirmed' WHERE artifact='192.0.2.2'")
        conn.execute("UPDATE findings SET triage='dismissed' WHERE artifact='2001:db8::2'")
        conn.commit()
        conn.close()
        summary = self.summary()
        self.assertEqual((4, 0), (summary['confirmed_ips'], summary['pending_ips']))

    def test_latest_action_anchor_is_at_the_actual_displayed_time(self):
        self.seed({'artifact': '192.0.2.1', 'artifact_kind': 'client', 'source': 'logs',
                   'triage': 'confirmed'})
        event = {'artifact': '192.0.2.1', 'artifact_kind': 'client',
                 'first_sign_selectable': True, 'first_sign_basis': 'hunt_match',
                 'first_sign_eligible': True, 'kind': 'hunt-match'}
        first = {**event, 'epoch': 100, 'activity_last_epoch': 200, 'id': 'first'}
        last = {**event, 'epoch': 200, 'id': 'last', 'first_sign_eligible': False}
        result = summarize(self.case, {'events': [first, last]})
        self.assertEqual((100, 200, 'last'),
                         (result['first_action'], result['last_action'], result['last_action_event_id']))
        self.assertIsNone(summarize(self.case, {'events': [first]})['last_action_event_id'])


if __name__ == '__main__':
    unittest.main()
