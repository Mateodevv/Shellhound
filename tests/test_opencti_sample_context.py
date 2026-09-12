import unittest
from unittest.mock import patch
from server.opencti_sample_context import context_plan, legacy_context_plans
from server.opencti_client import OpenCTIClient, OpenCTIError


class SampleContextTests(unittest.TestCase):
    def test_case_container_membership_uses_generic_domain_object_api(self):
        client = OpenCTIClient({"url": "https://cti.example", "token": "synthetic"})
        file = {"id": "file", "standard_id": "file--a", "entity_type": "StixFile", "hashes": [{"algorithm": "SHA-256", "hash": "a" * 64}]}
        artifact = {**file, "id": "artifact", "standard_id": "artifact--a", "entity_type": "Artifact"}
        case = {"id": "case", "standard_id": "case-incident--a", "entity_type": "Case-Incident"}
        target = {"id": "incident", "standard_id": "incident--a", "entity_type": "Incident"}
        with patch.object(client, "resolve", side_effect=[file, artifact, case, target, None]), patch.object(client, "_graphql") as graphql:
            graphql.side_effect = [{"stixCoreRelationshipAdd": {"id": "edge"}}, {}]
            self.assertEqual(["edge"], client.sync_sample_context("file", "artifact", "case", ["incident"]))
            self.assertIn("stixDomainObjectEdit", graphql.call_args.args[0])
            self.assertEqual("case", graphql.call_args.args[1]["id"])
        with patch.object(client, "resolve", side_effect=[file, artifact, case, None]), patch.object(client, "_graphql") as graphql:
            self.assertEqual([], client.sync_sample_context("file", "artifact", "case", [], ["missing-old-note"]))
            graphql.assert_not_called()

    def test_consolidated_content_is_inherited_but_path_context_is_not(self):
        file = {"id": "file--a", "type": "file", "hashes": {"SHA-256": "a" * 64}}
        note = {"id": "note--content", "type": "note", "object_refs": ["incident--a", "file--a"],
                "x_shellhound_context_kind": "content", "external_references": [{"source_name": "Shellhound", "external_id": "case:context:file--a"}]}
        path = {**note, "id": "note--path", "x_shellhound_context_kind": "path"}
        current = {"case_id": "case--a", "incident_id": "incident--a", "objects": [file, note, path]}
        sample = {"file_id": "file--a", "sha256": "a" * 64, "remote_id": "artifact", "state": "complete"}
        self.assertEqual(["note--content"], context_plan(current, sample)["target_ids"])
        old = {**current, "case_id": None, "report_id": "report--a", "samples": [sample], "mapping_destination": "same"}
        current["mapping_destination"] = "same"
        plans = legacy_context_plans([old, old, {**old, "mapping_destination": "other"}], current)
        self.assertEqual(1, len(plans))
        self.assertEqual("report--a", plans[0]["container_id"])
        self.assertEqual([], plans[0]["target_ids"])
        self.assertEqual(["note--content"], plans[0]["withdraw_ids"])
        self.assertEqual([], legacy_context_plans([old], old))

    def test_only_reviewed_content_context_is_selected(self):
        note = {"id": "note--content", "type": "note", "object_refs": ["file--a", "incident--a"],
                "external_references": [{"source_name": "Shellhound", "external_id": "case:ioc:123"}]}
        payload = {"incident_id": "incident--a", "objects": [
            {"id": "file--a", "type": "file", "hashes": {"SHA-256": "a" * 64}},
            {"id": "incident--a", "type": "incident"},
            {"id": "malware--a", "type": "malware", "sample_refs": ["file--a"]}, note,
            {**note, "id": "note--request", "object_refs": ["file--a", "ipv4-addr--a"]},
            {**note, "id": "note--path", "object_refs": ["file--a", "incident--a", "note--path-context"]},
            {"id": "vulnerability--a", "type": "vulnerability"},
            {"id": "ipv4-addr--a", "type": "ipv4-addr"},
            {"id": "malware--other", "type": "malware", "sample_refs": ["file--other"]},
        ]}
        sample = {"file_id": "file--a", "sha256": "a" * 64, "remote_id": "artifact"}
        self.assertEqual(["incident--a", "malware--a", "note--content"], context_plan(payload, sample)["target_ids"])
        self.assertEqual([], context_plan(payload, {**sample, "sha256": "b" * 64})["target_ids"])
        payload["objects"][2]["revoked"] = True
        self.assertEqual(["malware--a"], context_plan(payload, sample)["withdraw_ids"])
        payload["objects"] = [o for o in payload["objects"] if o["id"] != "file--a"]
        self.assertEqual([], context_plan(payload, sample)["target_ids"])

    def test_owned_edges_are_marked_repeatable_and_withdrawable(self):
        client = OpenCTIClient({"url": "https://cti.example", "token": "synthetic"})
        file = {"id": "file", "standard_id": "file--a", "entity_type": "StixFile", "hashes": [{"algorithm": "SHA-256", "hash": "a" * 64}]}
        artifact = {**file, "id": "artifact", "standard_id": "artifact--a", "entity_type": "Artifact", "objectMarking": [{"id": "strict"}]}
        report = {"id": "report", "standard_id": "report--a", "entity_type": "Report", "objectMarking": [{"id": "report-mark"}]}
        target = {"id": "malware", "standard_id": "malware--a", "entity_type": "Malware"}
        with patch.object(client, "resolve", side_effect=[file, artifact, report, target, None]), patch.object(client, "_graphql") as graphql:
            graphql.side_effect = lambda query, variables: {"stixCoreRelationshipAdd": {"id": "edge", "standard_id": variables["input"]["stix_id"]}} if 'stix_id' in variables['input'] else {}
            self.assertEqual(["edge"], client.sync_sample_context("file", "artifact", "report", ["malware"]))
            inputs = graphql.call_args_list[0].args[1]["input"]
            self.assertEqual(["report-mark", "strict"], inputs["objectMarking"])
        existing = {"id": "edge", "standard_id": "relationship--opencti-generated", "relationship_type": "related-to", "from": {"id": "artifact"}, "to": {"id": "malware"}}
        with patch.object(client, "resolve", side_effect=[file, artifact, report, target, existing]) as resolve, patch.object(client, "_graphql") as graphql:
            client.sync_sample_context("file", "artifact", "report", ["malware"])
            self.assertEqual(inputs["stix_id"], resolve.call_args.args[0])
            self.assertEqual(1, graphql.call_count)
            self.assertIn('SampleContextReport', graphql.call_args.args[0])
        with patch.object(client, "resolve", side_effect=[file, artifact, report, target, existing]), patch.object(client, "_graphql") as graphql:
            graphql.return_value = {"stixCoreRelationshipEdit": {"fieldPatch": {"id": "edge", "revoked": True}}}
            client.sync_sample_context("file", "artifact", "report", [], ["malware"])
            self.assertEqual({"id": "edge", "input": [{"key": "revoked", "value": ["true"]}]}, graphql.call_args.args[1])
        with patch.object(client, "resolve", side_effect=[file, artifact, report, {**target, "entity_type": "IPv4-Addr"}]), patch.object(client, "_graphql") as graphql:
            with self.assertRaises(OpenCTIError):
                client.sync_sample_context("file", "artifact", "report", ["ip"])
            graphql.assert_not_called()
        foreign = {**existing, "id": "foreign-edge"}
        linked_artifact = {**artifact, "relationships": [foreign]}
        with patch.object(client, "resolve", side_effect=[file, linked_artifact, report, target, None]), patch.object(client, "_graphql") as graphql:
            self.assertEqual(["foreign-edge"], client.sync_sample_context("file", "artifact", "report", ["malware"]))
            self.assertEqual(1, graphql.call_count)
            self.assertIn('SampleContextReport', graphql.call_args.args[0])
        with patch.object(client, "resolve", side_effect=[file, linked_artifact, report, target, None]), patch.object(client, "_graphql") as graphql:
            client.sync_sample_context("file", "artifact", "report", [], ["malware"])
            graphql.assert_not_called()
