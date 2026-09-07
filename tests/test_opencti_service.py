"""Explicit network actions, durable receipts, and replay boundaries."""
import hashlib
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from server import db, opencti_graph as graph, opencti_service as service, workspace
from server.opencti_client import OpenCTIClient, OpenCTIError


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
                       "ingester_id": "ingester", "sample_uploads": False, "timeout": 30}
        self.jobs = _Jobs()
        self.client = MagicMock(spec=OpenCTIClient)
        self.client.connectors.return_value = []
        self.client.find_existing_shared = MagicMock(return_value=None)
        self.client.push.return_value = {"id": "taxii-work-1"}
        self.client.taxii_status.return_value = {"status": "complete", "failure_count": 0, "pending_count": 0}
        self.client.resolve.side_effect = lambda source: {"id": "remote-" + source, "standard_id": source}
        self.client.lookup.return_value = []
        self.client.work.return_value = {"status": "complete", "errors": []}
        self.client.enrich.return_value = {"id": "enrichment-work-1"}
        self.client.upload_sample.return_value = {"id": "artifact-remote"}
        for target, value in (("settings.opencti_config", lambda _root: dict(self.config)),
                              ("manager", self.jobs), ("POLL_LIMIT", 1), ("POLL_SECONDS", 0)):
            patcher = patch("server.opencti_service." + target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client_factory = patch("server.opencti_service.OpenCTIClient", return_value=self.client).start()
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

    def add_file(self):
        root = self.root / "evidence"
        root.mkdir()
        file = root / "sample.txt"
        file.write_bytes(b"synthetic sample")
        self.conn.execute("INSERT INTO evidence(kind,path,added) VALUES('webroot',?,?)", (str(root), db.now()))
        self.hash_id = db.add_ioc(self.conn, hashlib.sha256(file.read_bytes()).hexdigest(), "hash")
        path_id = db.add_ioc(self.conn, "sample.txt", "path")
        db.link_iocs(self.conn, self.hash_id, path_id, "hash-of")
        self.conn.commit()
        return file

    def test_state_and_export_preview_are_offline(self):
        self.assertEqual([], service.state(self.root, self.case)["lookups"])
        result = self.preview()
        self.assertTrue(result["preview_id"])
        self.assertFalse(result["errors"])
        self.client_factory.assert_not_called()
        self.assertEqual(1, self.conn.execute("SELECT count(*) FROM opencti_previews").fetchone()[0])

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

    def test_no_automatic_enrichment_and_no_unselected_sample_upload(self):
        self.add_file()
        self.config["sample_uploads"] = True
        self.export()
        self.client.enrich.assert_not_called()
        self.client.upload_sample.assert_not_called()
        self.client.connectors.return_value = [{"id": "automatic", "name": "Automatic enrichment", "active": True, "auto": True, "scope": ["StixFile"]}]
        result = service.transfer(self.root, self.case, self.preview()["preview_id"])
        with self.assertRaisesRegex(ValueError, "manual"):
            self.jobs.run()
        self.assertEqual("failed", self.receipt(result["export_id"])["state"])
        self.client.push.assert_called_once()

    def test_selected_sample_is_rechecked_after_queueing_and_retry_rejects_changed_file(self):
        file = self.add_file()
        self.config["sample_uploads"] = True
        sample = next(s for s in self.preview()["samples"] if s["available"])
        preview = self.preview(sample_ids=[sample["id"]])
        result = service.transfer(self.root, self.case, preview["preview_id"])
        file.write_bytes(b"changed after scheduling")
        with self.assertRaisesRegex(ValueError, "changed|missing"):
            self.jobs.run()
        self.client.upload_sample.assert_not_called()
        self.assertEqual("partial", self.receipt(result["export_id"])["state"])
        with self.assertRaisesRegex(ValueError, "changed"):
            service.retry(self.root, self.case, result["export_id"])

    def test_classification_changes_after_queue_block_transfer_before_network_mutation(self):
        file = self.add_file()
        fingerprint = db.upsert_finding(self.conn, "analyst", db.SEV_HIGH, "Manual file review", "file", str(file),
                                         evidence="Analyst classified the file as a webshell.",
                                         rule_id="analyst.file_review")
        self.conn.execute("UPDATE findings SET triage='confirmed',triage_note='same decision',triaged_at=? WHERE fingerprint=?",
                          (db.now(), fingerprint))
        self.conn.commit()
        baseline = db.one(self.conn, "SELECT * FROM findings WHERE fingerprint=?", (fingerprint,))
        changes = {"source": "logs", "rule_id": "analyst.other",
                   "evidence": "Analyst classified the file as a malware sample.",
                   "rule": "Changed manual review", "artifact_kind": "table"}
        for field, value in changes.items():
            with self.subTest(field=field):
                result = service.transfer(self.root, self.case, self.preview()["preview_id"])
                # Triage state, note and second-resolution timestamps deliberately
                # remain unchanged while the classification inputs change.
                self.conn.execute(f"UPDATE findings SET {field}=? WHERE fingerprint=?", (value, fingerprint))
                self.conn.commit()
                with self.assertRaisesRegex(ValueError, "changed while transfer was queued"):
                    self.jobs.run()
                self.assertEqual("failed", self.receipt(result["export_id"])["state"])
                self.client.find_existing_shared.assert_not_called()
                self.client.push.assert_not_called()
                self.client.upload_sample.assert_not_called()
                self.client.enrich.assert_not_called()
                self.conn.execute(f"UPDATE findings SET {field}=? WHERE fingerprint=?", (baseline[field], fingerprint))
                self.conn.commit()

    def test_sample_upload_receipt_prevents_reupload_after_link_failure(self):
        self.add_file()
        self.config["sample_uploads"] = True
        sample = next(s for s in self.preview()["samples"] if s["available"])
        result = service.transfer(self.root, self.case, self.preview(sample_ids=[sample["id"]])["preview_id"])
        self.client.link_sample.side_effect = OpenCTIError("OpenCTI could not be reached.")
        with self.assertRaises(ValueError):
            self.jobs.run()
        self.assertEqual("uploaded", self.receipt(result["export_id"])["payload"]["samples"][0]["state"])
        self.client.link_sample.side_effect = None
        service.retry(self.root, self.case, result["export_id"])
        self.jobs.run()
        self.client.upload_sample.assert_called_once()
        self.assertEqual("complete", self.receipt(result["export_id"])["state"])

    def test_repeated_export_preserves_ids_and_deselection_does_not_revoke_indicators(self):
        self.export(indicator_ids=[self.ip_id])
        previous = [json.loads(r[0]) for r in self.conn.execute("SELECT object_json FROM opencti_mappings")]
        current = self.preview(ioc_ids=[self.domain_id])
        self.assertFalse(any(o.get("revoked") for o in current["objects"]))
        full = self.preview(indicator_ids=[self.ip_id])
        self.assertEqual({o["id"] for o in previous}, {o["id"] for o in full["objects"]})

    def test_shared_foreign_observable_is_referenced_without_overwriting_its_fields(self):
        preview = self.preview()
        source = next(o for o in preview["objects"] if o["type"] == "ipv4-addr")
        foreign = {"id": "foreign-ip-id", "standard_id": "ipv4-addr--existing-standard-id"}
        self.client.find_existing_shared.side_effect = lambda obj: foreign if obj["id"] == source["id"] else None
        result = service.transfer(self.root, self.case, preview["preview_id"])
        self.jobs.run()
        sent = self.client.push.call_args.args[0]
        self.assertNotIn(source["id"], {obj["id"] for obj in sent})
        report = next(obj for obj in sent if obj["type"] == "report")
        self.assertIn(foreign["standard_id"], report["object_refs"])
        self.assertNotIn(source["id"], report["object_refs"])
        receipt = self.receipt(result["export_id"])
        self.assertIn(source["id"], {obj["id"] for obj in receipt["payload"]["objects"]})
        mapping = db.one(self.conn, "SELECT * FROM opencti_mappings WHERE source_id=?", (source["id"],))
        self.assertEqual(foreign["id"], mapping["remote_id"])
        self.assertEqual({**source, "_shellhound_origin": "reused"}, json.loads(mapping["object_json"]))
        self.assertEqual("complete", receipt["state"])

    def test_reusing_existing_bare_observable_does_not_claim_own_origin(self):
        entity = {"id": "existing-ip", "standard_id": "ipv4-addr--existing", "entity_type": "IPv4-Addr",
                  "observable_value": "198.51.100.4", "createdBy": None}
        self.client.lookup.return_value = [entity]
        self.client.find_existing_shared.side_effect = lambda obj: entity if obj["type"] == "ipv4-addr" else None
        self.export()
        service.lookup(self.root, self.case, [self.ip_id])
        self.jobs.run()
        self.assertEqual("known", service.state(self.root, self.case)["lookups"][0]["status"])
        self.assertNotIn(entity["id"], service._mapped_ids(self.case, self.config))
        self.assertFalse(any("_shellhound_origin" in obj for obj in self.client.push.call_args.args[0]))

    def test_later_reuse_keeps_proven_own_import_origin(self):
        self.export()
        source = next(obj for obj in self.preview()["objects"] if obj["type"] == "ipv4-addr")
        entity = {"id": "remote-" + source["id"], "standard_id": source["id"], "entity_type": "IPv4-Addr",
                  "observable_value": "198.51.100.4", "createdBy": None}
        self.client.find_existing_shared.side_effect = lambda obj: entity if obj["type"] == "ipv4-addr" else None
        self.export()
        self.client.lookup.return_value = [entity]
        service.lookup(self.root, self.case, [self.ip_id])
        self.jobs.run()
        self.assertEqual("own", service.state(self.root, self.case)["lookups"][0]["status"])

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

    def test_own_mapped_observable_without_author_is_not_independent_corroboration(self):
        self.export()
        source = next(r[0] for r in self.conn.execute("SELECT source_id FROM opencti_mappings") if r[0].startswith("ipv4-addr--"))
        entity = {"id": "remote-" + source, "standard_id": source, "entity_type": "IPv4-Addr", "createdBy": None}
        self.client.lookup.return_value = [entity]
        service.lookup(self.root, self.case, [self.ip_id])
        self.jobs.run()
        self.assertEqual("own", service.state(self.root, self.case)["lookups"][0]["status"])
        entity["externalReferences"] = [{"source_name": "Independent threat feed"}]
        service.lookup(self.root, self.case, [self.ip_id])
        self.jobs.run()
        self.assertEqual("known", service.state(self.root, self.case)["lookups"][0]["status"])
        self.assertFalse(service._only_own([{**entity, "externalReferences": [], "context_truncated": True}], {source, "remote-" + source}))
        self.assertFalse(service._only_own([{**entity, "externalReferences": [], "createdBy": {"name": "Independent analyst"}}], {source, "remote-" + source}))

    def test_lookup_failure_keeps_prior_knowledge_stale_and_state_never_refreshes(self):
        entity = {"id": "known", "entity_type": "IPv4-Addr", "observable_value": "198.51.100.4",
                  "createdBy": {"name": "Independent source"}}
        self.client.lookup.return_value = [entity]
        service.lookup(self.root, self.case, [self.ip_id])
        self.jobs.run()
        self.client.lookup.side_effect = OpenCTIError("OpenCTI could not be reached.")
        service.lookup(self.root, self.case, [self.ip_id])
        self.jobs.run()
        calls = self.client.lookup.call_count
        result = service.state(self.root, self.case)["lookups"][0]
        self.assertEqual("error", result["status"])
        self.assertTrue(result["stale"])
        self.assertEqual("known", result["entities"][0]["id"])
        self.assertEqual(calls, self.client.lookup.call_count)

    def test_background_lookup_does_not_attach_to_reused_numeric_ioc_id(self):
        self.client.lookup.return_value = [{"id": "old-knowledge", "entity_type": "IPv4-Addr"}]
        service.lookup(self.root, self.case, [self.ip_id])
        self.conn.execute("DELETE FROM iocs WHERE id=?", (self.ip_id,))
        self.conn.execute("INSERT INTO iocs(id,value,type,added) VALUES(?,?,?,?)", (self.ip_id, "198.51.100.4", "ip", db.now()))
        self.conn.commit()
        self.jobs.run()
        self.assertEqual([], service.state(self.root, self.case)["lookups"])

    def connectors(self):
        self.client.connectors.return_value = [
            {"id": "ip-manual", "name": "IP context", "active": True, "auto": False, "scope": ["IPv4-Addr"]},
            {"id": "hash-manual", "name": "Hash context", "active": True, "auto": False, "scope": ["StixFile"]},
            {"id": "automatic", "name": "Automatic", "active": True, "auto": True, "scope": ["IPv4-Addr"]}]

    def test_enrichment_preview_filters_scope_and_does_not_start_work(self):
        self.connectors()
        preview = service.enrichment_preview(self.root, self.case, [self.ip_id])
        self.assertEqual(["ip-manual"], [c["id"] for c in preview["connectors"]])
        self.assertTrue(preview["entities"][0]["requires_creation"])
        self.client.create_observable.assert_not_called()
        self.client.enrich.assert_not_called()

    def test_unknown_enrichment_requires_explicit_creation_and_tracks_work(self):
        self.connectors()
        self.client.connectors.return_value = self.client.connectors.return_value[:2]
        service.enrich(self.root, self.case, [self.ip_id], ["ip-manual"])
        with self.assertRaisesRegex(ValueError, "explicit permission"):
            self.jobs.run()
        self.client.create_observable.assert_not_called()
        entity = {"id": "ip-entity", "entity_type": "IPv4-Addr", "observable_value": "198.51.100.4"}
        self.client.create_observable.return_value = entity
        self.client.lookup.side_effect = [[], [entity]]
        service.enrich(self.root, self.case, [self.ip_id], ["ip-manual"], create_missing=True)
        self.jobs.run()
        self.client.create_observable.assert_called_once()
        self.client.enrich.assert_called_once_with("ip-entity", "ip-manual")
        self.assertEqual("complete", self.conn.execute("SELECT state FROM opencti_enrichments").fetchone()[0])

    def test_refresh_enrichment_checks_pending_work_without_retrigger(self):
        self.connectors()
        self.client.lookup.return_value = [{"id": "ip-entity", "entity_type": "IPv4-Addr"}]
        self.client.work.return_value = {"status": "pending", "errors": []}
        service.enrich(self.root, self.case, [self.ip_id], ["ip-manual"])
        self.jobs.run()
        self.assertEqual("pending", self.conn.execute("SELECT state FROM opencti_enrichments").fetchone()[0])
        self.client.work.return_value = {"status": "complete", "errors": []}
        service.refresh_enrichment(self.root, self.case)
        self.jobs.run()
        self.client.enrich.assert_called_once()
        self.client.create_observable.assert_not_called()
        self.assertEqual("complete", self.conn.execute("SELECT state FROM opencti_enrichments").fetchone()[0])


if __name__ == "__main__":
    unittest.main()
