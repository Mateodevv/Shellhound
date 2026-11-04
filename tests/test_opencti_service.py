"""Explicit network actions, durable receipts, and replay boundaries."""
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from server import db
from server.integrations.opencti import service
from server import workspace
from server.integrations.opencti.client import OpenCTIClient, OpenCTIError


class _Context:
    def __init__(self):
        self.cancel_event = threading.Event()
    def cancelled(self):
        return self.cancel_event.is_set()
    def progress(self, *_args):
        pass


class _Jobs:
    def __init__(self):
        self.pending = []
    def submit(self, case_dir, kind, run, **kwargs):
        self.pending.append((run, kwargs))
        return len(self.pending)
    def run(self, index=-1):
        return self.pending[index][0](_Context())


class OpenCTIServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = workspace.create_case(self.root / "cases", "Private customer", "PIM-1234")
        self.conn = db.connect(self.case)
        self.addCleanup(self.conn.close)
        self.ip_id = db.add_ioc(self.conn, "198.51.100.4", "ip")
        self.domain_id = db.add_ioc(self.conn, "example.test", "domain")
        self.conn.commit()
        self.config = {"url": "https://cti.example.test", "token": "test-integration-token",
                       "ingester_id": "ingester", "timeout": 30}
        self.jobs = _Jobs()
        self.client = MagicMock(spec=OpenCTIClient)
        self.client.connectors.return_value = []
        self.client.find_existing_shared = MagicMock(return_value=None)
        self.client.push.return_value = {"id": "taxii-work-1"}
        self.client.taxii_status.return_value = {"status": "complete", "failure_count": 0, "pending_count": 0}
        self.client.resolve.side_effect = lambda source: {"id": "remote-" + source, "standard_id": source}
        self.client.resolve_many.side_effect = lambda ids: {source: self.client.resolve(source) for source in ids}
        for target, value in (("settings.opencti_config", lambda _root: dict(self.config)),
                              ("manager", self.jobs), ("POLL_LIMIT", 1), ("POLL_SECONDS", 0)):
            patcher = patch("server.integrations.opencti.service." + target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client_factory = patch("server.integrations.opencti.service.OpenCTIClient", return_value=self.client).start()
        self.addCleanup(patch.stopall)
        self.addCleanup(service._ACTIVE.clear)

    def preview(self, **options):
        return service.preview(self.root, self.case, options)

    def receipt(self, identifier):
        row = db.one(self.conn, "SELECT * FROM opencti_exports WHERE id=?", (identifier,))
        row["payload"] = json.loads(row["payload"])
        return row

    def export(self, **options):
        result = service.transfer(self.root, self.case, self.preview(**options)["preview_id"])
        self.jobs.run()
        return result


    def test_export_uses_batched_verification_and_records_phase_times(self):
        result = self.export()
        self.assertTrue(self.client.resolve_many.called)
        payload = self.receipt(result["export_id"])["payload"]
        self.assertEqual("complete", self.receipt(result["export_id"])["state"])
        self.assertEqual({"preflight_seconds", "import_verify_seconds"}, set(payload["timings"]))

    def test_reused_ip_tags_are_required_and_retry_does_not_reimport(self):
        self.conn.execute('UPDATE iocs SET tags=? WHERE id=?', (json.dumps(['Reviewed']), self.ip_id))
        self.conn.commit()
        self.client.find_existing_shared.side_effect = lambda obj: ({'id': 'known-ip', 'standard_id': obj['id']}
            if obj['type'] == 'ipv4-addr' else None)
        self.client.add_ip_labels.side_effect = OpenCTIError('Synthetic label permission failure')
        result = service.transfer(self.root, self.case, self.preview()['preview_id'])
        with self.assertRaisesRegex(ValueError, 'permission'):
            self.jobs.run()
        self.assertNotEqual('complete', self.receipt(result['export_id'])['state'])
        self.client.add_ip_labels.assert_called_once_with('known-ip', ['Reviewed'])
        self.client.add_ip_labels.side_effect = None
        service.retry(self.root, self.case, result['export_id'])
        self.jobs.run()
        self.client.push.assert_called_once()
        self.assertEqual('complete', self.receipt(result['export_id'])['state'])

    def test_preflight_reads_are_bounded_and_cancellation_stops_next_chunk(self):
        barrier = threading.Barrier(4)
        context = _Context()
        visited = []
        lock = threading.Lock()
        def lookup(obj):
            with lock:
                visited.append(obj["id"])
            barrier.wait(timeout=5)
            context.cancel_event.set()
            return None
        payload = {"objects": [{"id": str(i), "type": "ipv4-addr"} for i in range(20)],
                   "case_reference": "test", "mapping_destination": "test"}
        with patch.object(service, "_save_export") as save:
            service._prepare_shared(self.client, self.case, {}, payload, lookup=lookup, ctx=context)
        self.assertEqual(4, len(visited))
        self.assertNotIn("preflight_complete", payload)
        save.assert_not_called()

    def test_transfer_is_bound_to_case_data_and_destination(self):
        preview = self.preview()
        self.config["url"] = "https://different.example.test"
        with self.assertRaisesRegex(ValueError, "connection changed"):
            service.transfer(self.root, self.case, preview["preview_id"])
        self.config["url"] = "https://cti.example.test"
        self.conn.execute("UPDATE iocs SET note='changed' WHERE id=?", (self.ip_id,))
        self.conn.commit()
        with self.assertRaisesRegex(ValueError, "changed after preview"):
            service.transfer(self.root, self.case, preview["preview_id"])
        self.assertEqual([], self.jobs.pending)
        self.client.push.assert_not_called()

    def test_complete_import_requires_status_and_visible_objects_and_locks_reference(self):
        result = self.export()
        receipt = self.receipt(result["export_id"])
        self.assertEqual("complete", receipt["state"])
        self.assertEqual(len(receipt["payload"]["objects"]), self.conn.execute("SELECT count(*) FROM opencti_mappings").fetchone()[0])
        self.client.taxii_status.assert_called_once_with("taxii-work-1")
        self.assertTrue(all(r["status"] == "exported" for r in service.state(self.root, self.case)["sync"]))
        self.assertTrue(workspace.case_info(self.case)["reference_locked"])
        with self.assertRaisesRegex(ValueError, "already complete"):
            service.retry(self.root, self.case, result["export_id"])

    def test_pending_taxii_resume_checks_existing_work_without_reposting(self):
        self.client.taxii_status.return_value = {"status": "pending", "pending_count": 3}
        result = self.export()
        self.assertEqual("pending", self.receipt(result["export_id"])["state"])
        self.assertFalse(any(row["status"] == "exported" for row in service.state(self.root, self.case)["sync"]))
        self.client.taxii_status.return_value = {"status": "complete", "failure_count": 0, "pending_count": 0}
        service.retry(self.root, self.case, result["export_id"])
        self.jobs.run()
        self.assertEqual("complete", self.receipt(result["export_id"])["state"])
        self.client.push.assert_called_once()

    def test_partial_import_retries_only_failed_ids_and_keeps_success_mappings(self):
        preview = self.preview()
        failed = preview["objects"][-1]["id"]
        self.client.taxii_status.return_value = {"status": "complete", "failure_count": 1, "pending_count": 0,
                                                 "failures": [{"id": failed}]}
        result = service.transfer(self.root, self.case, preview["preview_id"])
        with self.assertRaisesRegex(ValueError, "import failed"):
            self.jobs.run()
        self.assertEqual("partial", self.receipt(result["export_id"])["state"])
        self.assertEqual(len(preview["objects"]) - 1, self.conn.execute("SELECT count(*) FROM opencti_mappings").fetchone()[0])
        self.client.taxii_status.return_value = {"status": "complete", "failure_count": 0, "pending_count": 0}
        service.retry(self.root, self.case, result["export_id"])
        self.jobs.run()
        self.assertEqual([failed], [o["id"] for o in self.client.push.call_args.args[0]])
        self.assertEqual("complete", self.receipt(result["export_id"])["state"])

    def test_invisible_object_does_not_become_complete_and_retry_never_reposts_work(self):
        self.client.resolve.return_value = None
        self.client.resolve.side_effect = None
        preview = self.preview()
        result = service.transfer(self.root, self.case, preview["preview_id"])
        with self.assertRaisesRegex(ValueError, "not visible"):
            self.jobs.run()
        self.assertEqual("failed", self.receipt(result["export_id"])["state"])
        self.client.resolve.side_effect = lambda source: {"id": "remote-" + source, "standard_id": source}
        service.retry(self.root, self.case, result["export_id"])
        self.jobs.run()
        self.client.push.assert_called_once()

    def test_partial_retry_keeps_visibility_checks_for_successful_objects_without_reposting(self):
        preview = self.preview()
        failed = preview["objects"][-1]["id"]
        invisible = preview["objects"][-2]["id"]
        self.client.taxii_status.return_value = {"status": "complete", "failure_count": 1,
                                                 "pending_count": 0, "failures": [{"id": failed}]}
        self.client.resolve.side_effect = lambda source: None if source == invisible else {
            "id": "remote-" + source, "standard_id": source}
        result = service.transfer(self.root, self.case, preview["preview_id"])
        with self.assertRaisesRegex(ValueError, "import failed"):
            self.jobs.run()
        self.client.taxii_status.return_value = {"status": "complete", "failure_count": 0, "pending_count": 0}
        service.retry(self.root, self.case, result["export_id"])
        with self.assertRaisesRegex(ValueError, "not visible"):
            self.jobs.run()
        self.assertNotEqual("complete", self.receipt(result["export_id"])["state"])
        self.assertEqual([failed], [obj["id"] for obj in self.client.push.call_args.args[0]])
        self.assertEqual(2, self.client.push.call_count)
        self.client.resolve.side_effect = lambda source: {"id": "remote-" + source, "standard_id": source}
        service.retry(self.root, self.case, result["export_id"])
        self.jobs.run()
        self.assertEqual("complete", self.receipt(result["export_id"])["state"])
        self.assertEqual(2, self.client.push.call_count)
        self.assertEqual(len(preview["objects"]), self.conn.execute("SELECT count(*) FROM opencti_mappings").fetchone()[0])


    def test_shared_preflight_is_saved_and_not_repeated_when_resuming_pending_import(self):
        self.client.taxii_status.return_value = {"status": "pending", "pending_count": 1}
        result = self.export()
        calls = self.client.find_existing_shared.call_count
        self.client.taxii_status.return_value = {"status": "complete", "failure_count": 0, "pending_count": 0}
        service.retry(self.root, self.case, result["export_id"])
        self.jobs.run()
        self.assertEqual(calls, self.client.find_existing_shared.call_count)
        self.client.push.assert_called_once()

    def test_cancel_before_worker_starts_persists_paused_receipt_and_releases_slot(self):
        result = service.transfer(self.root, self.case, self.preview()["preview_id"])
        self.jobs.pending[-1][1]["on_cancel"]()
        self.assertEqual("paused", self.receipt(result["export_id"])["state"])
        self.assertEqual(set(), service._ACTIVE)
        self.client.push.assert_not_called()
        service.retry(self.root, self.case, result["export_id"])
        self.jobs.run()
        self.assertEqual("complete", self.receipt(result["export_id"])["state"])

    def test_token_rotation_preserves_mapping_identity_but_invalidates_pending_preview(self):
        self.export()
        original = [r[0] for r in self.conn.execute("SELECT source_id FROM opencti_mappings")]
        pending = self.preview()
        self.config["token"] = "replacement-integration-token"
        with self.assertRaisesRegex(ValueError, "connection changed"):
            service.transfer(self.root, self.case, pending["preview_id"])
        self.assertTrue(all(row["status"] == "exported" for row in service.state(self.root, self.case)["sync"]))
        repeated = self.preview()
        self.assertEqual(set(original), {o["id"] for o in repeated["objects"]})
        self.assertEqual(pending["mapping_revision"], repeated["mapping_revision"])


    def test_automatic_connectors_block_transfer_before_push(self):
        self.client.connectors.return_value = [{'name': 'Automatic', 'active': True, 'auto': True}]
        service.transfer(self.root, self.case, self.preview()['preview_id'])
        with self.assertRaisesRegex(ValueError, 'manual'):
            self.jobs.run()
        self.client.push.assert_not_called()

    def test_legacy_preview_and_receipt_cannot_replay_retired_features(self):
        preview = self.preview()
        payload = dict(preview, model_version=3)
        self.conn.execute('UPDATE opencti_previews SET payload=? WHERE id=?',
                          (json.dumps(payload), preview['preview_id']))
        self.conn.commit()
        with self.assertRaisesRegex(ValueError, 'fresh export preview'):
            service.transfer(self.root, self.case, preview['preview_id'])
        result = self.export()
        receipt = self.receipt(result['export_id'])
        receipt['payload']['model_version'] = 3
        self.conn.execute("UPDATE opencti_exports SET state='failed', payload=? WHERE id=?",
                          (json.dumps(receipt['payload']), result['export_id']))
        self.conn.commit()
        self.client.push.reset_mock()
        with self.assertRaisesRegex(ValueError, 'fresh preview'):
            service.retry(self.root, self.case, result['export_id'])
        self.client.push.assert_not_called()


if __name__ == '__main__':
    unittest.main()
