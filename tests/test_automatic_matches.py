import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from server import db, settings, workspace
from server.casework import performance_case, testcase
from server.integrations.opencti.automatic import AutomaticMatches


class AutomaticMatchingLifecycleTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.case = workspace.create_case(self.root, 'Synthetic case', 'TEST-A')
        settings.set_opencti(self.root, {'url': 'https://cti.example.test', 'token': 'test-only', 'auto_match': True})
        self.auto = AutomaticMatches(self.root)
        self.auto.configure()
        self.addCleanup(self.auto.close)

    def test_open_catchup_once_and_suspend_until_in_flight_check_stops(self):
        entered = threading.Event()
        finished = threading.Event()

        def check(_root, _case, ctx, **options):
            self.assertTrue(options['only_new'])
            entered.set()
            self.assertTrue(ctx.stop.wait(5))
            finished.set()
            return {'cancelled': True}

        with patch('server.integrations.opencti.automatic.matches.scan', side_effect=check) as remote:
            self.auto.opened_case(self.case)
            self.assertTrue(entered.wait(5))
            self.auto.opened_case(self.case)
            self.auto.changed(self.case)
            with self.auto.suspend(self.case):
                self.assertTrue(finished.is_set())
                self.auto.changed(self.case)
                self.assertEqual('idle', self.auto.status(self.case))
            self.auto.close()
            remote.assert_called_once()

    def test_disabling_cancels_queued_cases_and_leaves_later_commits_local(self):
        with patch('server.integrations.opencti.automatic.matches.scan') as remote:
            self.auto.changed(self.case)
            settings.set_opencti(self.root, {'auto_match': False})
            self.auto.configure()
            self.auto.changed(self.case)
            self.auto.close()
            remote.assert_not_called()

    def test_reopening_after_a_connection_failure_retries_uncached_values(self):
        failed = {'failed': 1}
        with patch('server.integrations.opencti.automatic.matches.scan', side_effect=[failed, {'failed': 0}]) as check:
            self.auto.opened_case(self.case)
            with self.auto.condition:
                self.assertTrue(self.auto.condition.wait_for(lambda: self.case in self.auto.failures, 5))
                self.auto.opened_case(self.case)
                self.assertNotIn(self.case, self.auto.pending)
                self.auto.failures[self.case] = 0  # Simulate the end of the cooldown.
                self.auto.opened_case(self.case)
                self.assertTrue(self.auto.condition.wait_for(lambda: self.case not in self.auto.failures, 5))
            self.assertEqual(2, check.call_count)
            self.assertTrue(all(c.kwargs['only_new'] for c in check.call_args_list))

    def test_training_and_performance_cases_keep_automatic_checks_local(self):
        training = testcase.generate(self.root, analyse=False)
        legacy = testcase.generate(self.root, analyse=False)
        (legacy / testcase.TRAINING_MARKER).unlink()
        performance = workspace.create_case(self.root, 'Performance case')
        performance_case.manifest(performance, state='ready', size='large')

        with patch('server.integrations.opencti.automatic.matches.scan') as remote:
            for case in (training, legacy, performance):
                with self.subTest(case=case.name):
                    conn = db.connect(case)
                    try:
                        db.upsert_finding(conn, 'logs', db.SEV_MEDIUM, 'Example', 'client', '192.0.2.1')
                        conn.commit()
                    finally:
                        conn.close()
                    self.auto.opened_case(case)
                    self.assertEqual('idle', self.auto.status(case))
            self.auto.close()
            remote.assert_not_called()

    def test_existing_transfer_config_and_changes_to_destination_need_activation(self):
        public = settings.set_opencti(self.root, {'url': 'https://other.example.test', 'token': 'different'})
        self.assertTrue(public['lookup_configured'])
        self.assertFalse(public['auto_match'])
        with self.assertRaises(ValueError):
            settings.set_opencti(self.root, {'token': '', 'auto_match': True})
        self.assertTrue(settings.opencti_public(self.root)['lookup_configured'])
        self.assertFalse(settings.opencti_public(self.root)['auto_match'])
