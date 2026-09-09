import hashlib
import io
import json
import unittest
import urllib.error
from email import policy
from email.parser import BytesParser
from unittest.mock import Mock, patch

from server import opencti_client as api


class Response(io.BytesIO):
    def __init__(self, data, status=200):
        super().__init__(json.dumps(data).encode())
        self.status = status

    def getcode(self):
        return self.status


class OpenCTIClientTests(unittest.TestCase):
    def setUp(self):
        self.client = api.OpenCTIClient({"url": "https://ti.example/opencti", "token": "test-secret-token",
                                         "ingester_id": "ingester-123", "timeout": 10})
        self.client._opener = Mock()

    def _responses(self, *values):
        self.client._opener.open.side_effect = [Response(value) for value in values]

    def _request(self, index=-1):
        return self.client._opener.open.call_args_list[index].args[0]

    def _payload(self, index=-1):
        return json.loads(self._request(index).data)

    def test_url_and_header_validation_prevents_credential_misdirection(self):
        for value in ("http://ti.example", "https://user:pw@ti.example", "https://ti.example/?token=secret",
                      "https://ti.example/#secret", "https://ti.example\n.attacker", "https://ti.example:99999"):
            with self.subTest(url=value), self.assertRaises(ValueError):
                api.OpenCTIClient({"url": value, "token": "secret"})
        for token in ("", "secret\r\nX-Test: abc"):
            with self.assertRaises(ValueError):
                api.OpenCTIClient({"url": "https://ti.example", "token": token})
        for timeout in (0, 121, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                api.OpenCTIClient({"url": "https://ti.example", "token": "secret", "timeout": timeout})

    def test_connection_test_is_read_only_and_requires_writable_collection(self):
        self._responses({"data": {"about": {"version": "7.test"}}},
                        {"id": "ingester-123", "title": "SHELLHOUND", "can_write": True})
        self.assertEqual("7.test", self.client.test()["version"])
        request = self._request(0)
        self.assertEqual("https://ti.example/opencti/graphql", request.full_url)
        self.assertEqual("Bearer test-secret-token", request.get_header("Authorization"))
        self.assertNotIn("mutation", self._payload(0)["query"])
        self.assertEqual("GET", self._request(1).method)
        self.assertEqual("https://ti.example/opencti/taxii2/root/collections/ingester-123/",
                         self._request(1).full_url)
        self._responses({"data": {"about": {"version": "7.test"}}}, {"can_write": False})
        with self.assertRaisesRegex(api.OpenCTIError, "does not allow imports"):
            self.client.test()

    def test_connectors_never_query_secrets_and_only_return_enrichment_metadata(self):
        self._responses({"data": {"connectors": [
            {"id": "vt", "name": "VT", "connector_type": "INTERNAL_ENRICHMENT",
             "connector_scope": ["StixFile"], "auto": False, "active": True},
            {"id": "feed", "name": "Feed", "connector_type": "EXTERNAL_IMPORT", "auto": True}]}})
        values = self.client.connectors()
        self.assertEqual(["vt"], [item["id"] for item in values])
        self.assertEqual(["StixFile"], values[0]["scope"])
        self.assertFalse(values[0]["auto"])
        query = self._payload()["query"]
        for forbidden in ("connectorsForWorker", "config", "api_tokens", "password", "connector_user"):
            self.assertNotIn(forbidden, query)

    def test_http_errors_hide_upstream_bodies_url_and_credentials(self):
        for status, code in ((401, "authentication"), (403, "permission"), (404, "not_found"),
                             (429, "rate_limit"), (503, "http_error")):
            self.client._opener.open.side_effect = urllib.error.HTTPError(
                "https://ti.example/?secret=test-secret-token", status, "test-secret-token",
                {"Retry-After": "15"}, io.BytesIO(b'private customer test-secret-token'))
            with self.subTest(status=status), self.assertRaises(api.OpenCTIError) as caught:
                self.client.connectors()
            self.assertEqual(code, caught.exception.code)
            self.assertEqual(status, caught.exception.status)
            self.assertEqual(15, caught.exception.retry_after)
            self.assertNotIn("test-secret-token", str(caught.exception))
            self.assertNotIn("private customer", str(caught.exception))

    def test_connector_permission_error_names_the_required_capability(self):
        self._responses({"errors": [{"message": "test-secret-token private account",
                                    "extensions": {"code": "FORBIDDEN_ACCESS"}}]})
        with self.assertRaises(api.OpenCTIError) as caught:
            self.client.connectors()
        self.assertEqual("permission", caught.exception.code)
        self.assertIn("Access connectors", str(caught.exception))
        self.assertIn("MODULES", str(caught.exception))
        self.assertNotIn("test-secret-token", str(caught.exception))
        self.assertNotIn("private account", str(caught.exception))

    def test_graphql_errors_hide_error_details_even_with_partial_data(self):
        self._responses({"data": {"connectors": []}, "errors": [{
            "message": "secret=test-secret-token customer=Private", "extensions": {"code": "FORBIDDEN"}}]})
        with self.assertRaises(api.OpenCTIError) as caught:
            self.client.connectors()
        self.assertEqual("permission", caught.exception.code)
        self.assertNotIn("test-secret-token", str(caught.exception))

    def test_redirects_are_refused_without_followup_requests(self):
        redirect = api._NoRedirect()
        with self.assertRaisesRegex(api.OpenCTIError, "redirected"):
            redirect.redirect_request(None, None, 302, "redirect", {}, "https://attacker.example")
        self.client._opener.open.return_value = Response({}, 302)
        with self.assertRaises(api.OpenCTIError):
            self.client.connectors()
        self.assertEqual(1, self.client._opener.open.call_count)

    def test_timeout_and_invalid_json_are_sanitized_without_retry(self):
        self.client._opener.open.side_effect = TimeoutError("token=test-secret-token")
        with self.assertRaises(api.OpenCTIError) as caught:
            self.client.push([{"id": "file--123", "type": "file"}])
        self.assertEqual("timeout", caught.exception.code)
        self.assertEqual(1, self.client._opener.open.call_count)
        self.client._opener.open.side_effect = None
        self.client._opener.open.return_value = io.BytesIO(b"<html>private</html>")
        self.client._opener.open.return_value.getcode = lambda: 200
        with self.assertRaisesRegex(api.OpenCTIError, "invalid JSON"):
            self.client.connectors()

    def test_large_response_is_rejected(self):
        self.client._opener.open.return_value = Response({"large": "x" * 200})
        with patch.object(api, "MAX_RESPONSE_BYTES", 100), self.assertRaisesRegex(api.OpenCTIError, "too large"):
            self.client.connectors()

    def test_lookup_uses_exact_type_filter_and_flattens_context(self):
        entity = {"id": "remote-1", "standard_id": "file--one", "entity_type": "StixFile",
                  "observable_value": "Hash", "x_opencti_score": 80, "createdBy": {"name": "Vendor"},
                  "externalReferences": {"edges": [{"node": {"source_name": "Source"}}]},
                  "reports": {"edges": [{"node": {"id": "report", "name": "Report"}}]},
                  "stixCoreRelationships": {"edges": [{"node": {"relationship_type": "related-to",
                      "createdBy": {"name": "Source"}, "to": {"id": "malware", "entity_type": "Malware", "name": "Example"}}}],
                      "pageInfo": {"hasNextPage": True}}}
        self._responses({"data": {"stixCyberObservables": {"edges": [{"node": entity}],
                                                             "pageInfo": {"hasNextPage": False}}}})
        result = self.client.lookup("hash", "A" * 64)[0]
        variables = self._payload()["variables"]
        self.assertEqual(["StixFile", "Artifact"], variables["types"])
        self.assertEqual("hashes.SHA-256", variables["filters"]["filters"][0]["key"][0])
        self.assertEqual(["a" * 64], variables["filters"]["filters"][0]["values"])
        self.assertEqual("eq", variables["filters"]["filters"][0]["operator"])
        self.assertEqual(80, result["score"])
        self.assertEqual("Source", result["externalReferences"][0]["source_name"])
        self.assertEqual("Example", result["relationships"][0]["to"]["name"])
        self.assertEqual("Example", result["malware"][0]["name"])
        self.assertTrue(result["relationships_truncated"])
        self.assertEqual("https://ti.example/opencti/dashboard/id/remote-1", result["url"])
        self.assertNotIn("payload_bin", self._payload()["query"])
        self.assertNotIn("askEnrichment", self._payload()["query"])

    def test_lookup_paginates_but_does_not_loop_on_broken_cursors(self):
        page = {"data": {"stixCyberObservables": {"edges": [{"node": {"id": "one"}}],
                         "pageInfo": {"hasNextPage": True, "endCursor": "same"}}}}
        self._responses(page, page)
        with self.assertRaisesRegex(api.OpenCTIError, "Too many"):
            self.client.lookup("ip", "198.51.100.1")
        self.assertEqual("same", self._payload()["variables"]["after"])
        self.assertEqual(2, self.client._opener.open.call_count)

    def test_unsupported_path_and_bad_hash_never_use_network(self):
        for kind, value in (("path", "C:\\private\\shell.php"), ("hash", "not a hash"), ("ip", "999.2.3.4")):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.client.lookup(kind, value)
        self.client._opener.open.assert_not_called()

    def test_network_types_refuse_local_paths_credentials_and_invalid_values(self):
        for kind, value in (("url", "https://user:password@example.test/"),
                            ("url", "file:///C:/private/example.php"),
                            ("email", "C:\\Users\\private@example.test"),
                            ("email", "/home/private@example.test"),
                            ("domain", "C:/private/example.test"),
                            ("domain", "example.test/path"),
                            ("url", "https://example.test/C:/Users/private")):
            with self.subTest(kind=kind, value=value), self.assertRaises(ValueError):
                self.client.lookup(kind, value)
        self.client._opener.open.assert_not_called()
        self._responses({"data": {"stixCyberObservables": {"edges": [], "pageInfo": {"hasNextPage": False}}}})
        self.assertEqual([], self.client.lookup("url", "https://example.test/a.php?x=1"))
        self.assertEqual(["https://example.test/a.php?x=1"],
                         self._payload()["variables"]["filters"]["filters"][0]["values"])

    def test_generic_resolution_includes_relationships_and_markings(self):
        self._responses({"data": {"stixObjectOrStixRelationship": {
            "id": "marking", "entity_type": "Marking-Definition", "definition": "TLP:AMBER+STRICT"}}})
        self.assertEqual("marking", self.client.resolve("marking-definition--123")["id"])
        query = self._payload()["query"]
        self.assertIn("... on StixCoreRelationship", query)
        self.assertIn("... on MarkingDefinition", query)
        self.assertNotIn("payload_bin", query)

    def test_shared_cve_is_found_by_exact_name_without_mutating_its_metadata(self):
        entity = {"id": "vendor-cve", "standard_id": "vulnerability--vendor", "entity_type": "Vulnerability",
                  "name": "CVE-2026-12345"}
        self._responses({"data": {"vulnerabilities": {"edges": [{"node": entity}], "pageInfo": {"hasNextPage": False}}}})
        result = self.client.find_existing_shared({"id": "vulnerability--local", "type": "vulnerability",
                                                   "name": "CVE-2026-12345", "created_by_ref": "our-author"})
        self.assertEqual(entity, result)
        payload = self._payload()
        self.assertEqual([{ "key": ["name"], "values": ["CVE-2026-12345"], "operator": "eq", "mode": "or"}],
                         payload["variables"]["filters"]["filters"])
        for forbidden in ("mutation", "createdBy", "objectMarking", "askEnrichment", "connectorsForWorker"):
            self.assertNotIn(forbidden, payload["query"])
        self.assertNotIn("our-author", json.dumps(payload))

    def test_shared_network_observables_are_exact_and_type_specific(self):
        for stix_type, value, remote_type in (("ipv4-addr", "198.51.100.1", "IPv4-Addr"),
                ("ipv6-addr", "2001:db8::1", "IPv6-Addr"), ("domain-name", "example.test", "Domain-Name"),
                ("email-addr", "a@example.test", "Email-Addr"), ("url", "https://example.test/a", "Url")):
            entity = {"id": "known", "standard_id": stix_type + "--known", "entity_type": remote_type,
                      "observable_value": value}
            self._responses({"data": {"stixCyberObservables": {"edges": [{"node": entity}]}}})
            with self.subTest(stix_type=stix_type):
                self.assertEqual(entity, self.client.find_existing_shared({"type": stix_type, "value": value}))
                self.assertEqual([remote_type], self._payload()["variables"]["types"])
                self.assertNotIn("mutation", self._payload()["query"])

    def test_shared_file_checks_strongest_hash_and_only_reuses_file_objects(self):
        hashes = {"MD5": "a" * 32, "SHA-256": "b" * 64}
        entity = {"id": "known-file", "standard_id": "file--known", "entity_type": "StixFile",
                  "hashes": [{"algorithm": key, "hash": value} for key, value in hashes.items()]}
        response = {"data": {"stixCyberObservables": {"edges": [{"node": entity}]}}}
        self._responses(response, response)
        with patch.object(self.client, "resolve") as resolve:
            self.assertEqual(entity, self.client.find_existing_shared({"type": "file", "id": "file--md5", "hashes": hashes}))
            resolve.assert_not_called()
        self.assertEqual(["hashes.SHA-256"], self._payload(0)["variables"]["filters"]["filters"][0]["key"])
        self.assertEqual(["hashes.MD5"], self._payload(1)["variables"]["filters"]["filters"][0]["key"])
        self.assertEqual(["StixFile"], self._payload()["variables"]["types"])
        self.assertNotIn("payload_bin", self._payload()["query"])

    def test_shared_file_rejects_weak_hash_collision_or_unverifiable_strong_hash(self):
        for remote_sha in (None, "c" * 64):
            remote_hashes = [{"algorithm": "MD5", "hash": "a" * 32}]
            if remote_sha:
                remote_hashes.append({"algorithm": "SHA-256", "hash": remote_sha})
            self._responses({"data": {"stixCyberObservables": {"edges": []}}},
                            {"data": {"stixCyberObservables": {"edges": [{"node": {
                                "id": "weak-file", "standard_id": "file--weak", "entity_type": "StixFile",
                                "hashes": remote_hashes}}]}}})
            with self.subTest(remote_sha=remote_sha), self.assertRaises(api.OpenCTIError) as caught:
                self.client.find_existing_shared({"type": "file", "id": "file--md5",
                                                  "hashes": {"MD5": "a" * 32, "SHA-256": "b" * 64}})
            self.assertEqual("file_identity", caught.exception.code)

    def test_shared_file_with_only_filename_never_queries_or_reuses_source_id(self):
        with self.assertRaises(api.OpenCTIError) as caught:
            self.client.find_existing_shared({"type": "file", "id": "file--name", "name": "shell.php"})
        self.assertEqual("file_identity", caught.exception.code)
        self.client._opener.open.assert_not_called()

    def test_shared_sector_and_country_queries_are_type_scoped(self):
        for obj, collection, remote_type in (({"type": "identity", "identity_class": "class", "name": "Technology"},
                                              "identities", "Sector"),
                                             ({"type": "location", "name": "DE", "country": "de"}, "locations", "Country")):
            entity = {"id": "existing", "standard_id": obj["type"] + "--existing", "entity_type": remote_type,
                      "name": obj["name"]}
            self._responses({"data": {collection: {"edges": [{"node": entity}]}}})
            with self.subTest(collection=collection):
                self.assertEqual(entity, self.client.find_existing_shared(obj))
                self.assertEqual([remote_type], self._payload()["variables"]["types"])

    def test_shared_objects_absent_by_name_resolve_source_id_before_creating(self):
        self._responses({"data": {"vulnerabilities": {"edges": []}}},
                        {"data": {"stixObjectOrStixRelationship": None}})
        self.assertIsNone(self.client.find_existing_shared({"type": "vulnerability", "id": "vulnerability--source",
                                                            "name": "CVE-2026-12345"}))
        self.assertEqual({"id": "vulnerability--source"}, self._payload()["variables"])
        self._responses({"data": {"stixCyberObservables": {"edges": []}}})
        self.assertIsNone(self.client.find_existing_shared({"type": "file", "id": "file--md5", "hashes": {"SHA-256": "b" * 64}}))

    def test_shared_lookup_duplicate_or_incomplete_identity_fails_closed(self):
        good = {"id": "one", "standard_id": "vulnerability--one", "name": "CVE-2026-12345"}
        for connection in ({"edges": [{"node": good}, {"node": {**good, "id": "two"}}]},
                           {"edges": [{"node": {"id": "one", "name": good["name"]}}]},
                           {"edges": [{"node": {**good, "name": "CVE-2026-54321"}}]},
                           {"edges": [{}]}, None):
            self._responses({"data": {"vulnerabilities": connection}})
            with self.subTest(connection=connection), self.assertRaises(api.OpenCTIError):
                self.client.find_existing_shared({"type": "vulnerability", "name": good["name"]})

    def test_taxii_uses_objects_envelope_and_retains_pending_state(self):
        self._responses({"id": "work-1", "status": "pending", "total_count": 1,
                         "success_count": 0, "failure_count": 0, "pending_count": 1},
                        {"id": "work-1", "status": "complete", "total_count": 1,
                         "success_count": 1, "failure_count": 0, "pending_count": 0})
        objects = [{"type": "file", "id": "file--123"}]
        result = self.client.push(objects)
        self.assertEqual("pending", result["status"])
        self.assertEqual({"objects": objects}, self._payload())
        self.assertEqual(api._TAXII_TYPE, self._request().get_header("Content-type"))
        self.assertEqual("complete", self.client.taxii_status("work-1")["status"])
        self.assertEqual("GET", self._request().method)
        with self.assertRaises(ValueError):
            self.client.taxii_status("../../other")

    def test_taxii_status_requires_consistent_counts_and_matching_work_id(self):
        valid = {"id": "work-1", "status": "complete", "total_count": 3,
                 "success_count": 2, "failure_count": 1, "pending_count": 0}
        for invalid in ({}, {**valid, "id": "different"}, {**valid, "status": "running"},
                        {**valid, "success_count": "2"}, {**valid, "success_count": True},
                        {**valid, "failure_count": -1}, {**valid, "total_count": 5},
                        {**valid, "pending_count": 1, "total_count": 4}):
            self._responses(invalid)
            with self.subTest(receipt=invalid), self.assertRaises(api.OpenCTIError) as caught:
                self.client.taxii_status("work-1")
            self.assertEqual("invalid_response", caught.exception.code)
        self._responses(valid)
        self.assertEqual(valid, self.client.taxii_status("work-1"))

    def test_timestamped_work_ids_support_taxii_and_graphql_without_path_injection(self):
        work_id = "work_8559f65f-41db-5d06-90d7-d12a4111ec34_2026-09-07T19:25:55.281Z"
        status = {"id": work_id, "status": "complete", "total_count": 1,
                  "success_count": 1, "failure_count": 0, "pending_count": 0}
        self._responses(status, {"data": {"work": {"id": work_id, "status": "complete"}}})
        self.assertEqual(status, self.client.taxii_status(work_id))
        self.assertIn("19%3A25%3A55.281Z/", self._request().full_url)
        self.assertEqual(work_id, self.client.work(work_id)["id"])
        self.assertEqual(work_id, self._payload()["variables"]["id"])
        for invalid in ("../work", work_id + "/other", work_id + "?token=x", work_id + "#x", work_id + "\n"):
            for method in (self.client.taxii_status, self.client.work):
                with self.subTest(value=invalid), self.assertRaises(ValueError):
                    method(invalid)
        self.assertEqual(2, self.client._opener.open.call_count)

    def test_case_description_merge_preserves_other_authors_and_case_sections(self):
        foreign = "Existing analyst assessment.\nDo not replace."
        first = api._case_description(foreign, "PIM-1", "First case")
        second = api._case_description(first, "PIM-2", "Second case")
        updated = api._case_description(second, "PIM-1", "Revised case")
        self.assertTrue(updated.startswith(foreign))
        self.assertIn("Second case", updated)
        self.assertNotIn("First case", updated)
        self.assertEqual(updated, api._case_description(updated, "PIM-1", "Revised case"))
        removed = api._case_description(updated, "PIM-1", "")
        self.assertNotIn("Revised case", removed)
        self.assertIn("Second case", removed)
        with self.assertRaises(api.OpenCTIError):
            api._case_description(first + first, "PIM-1", "Cannot safely replace duplicates")

    def test_description_update_is_scoped_verified_and_idempotent(self):
        obj = {"id": "remote-ip", "x_opencti_description": "Other author", "objectMarking": [{"standard_id": "marking-1"}]}
        read = {"data": {"stixCyberObservable": obj}}
        desired = api._case_description("Other author", "PIM-1", "Case summary")
        self._responses(read, read, {"data": {"stixCyberObservableEdit": {"fieldPatch": {
            "id": "remote-ip", "x_opencti_description": desired}}}})
        self.assertTrue(self.client.update_case_description("source-ip", "PIM-1", "Case summary", "marking-1")["updated"])
        self.assertIn("$id:String!", self._payload(0)["query"])
        self.assertEqual([{"key": "x_opencti_description", "value": [desired]}], self._payload()["variables"]["input"])
        self._responses({"data": {"stixCyberObservable": {**obj, "x_opencti_description": desired}}})
        self.assertFalse(self.client.update_case_description("source-ip", "PIM-1", "Case summary", "marking-1")["updated"])

    def test_description_conflicts_and_marking_mismatch_never_write(self):
        obj = {"id": "remote-ip", "x_opencti_description": "Other author", "objectMarking": [{"standard_id": "marking-1"}]}
        self._responses({"data": {"stixCyberObservable": obj}},
                        {"data": {"stixCyberObservable": {**obj, "x_opencti_description": "Concurrent edit"}}})
        with self.assertRaisesRegex(api.OpenCTIError, "changed during export"):
            self.client.update_case_description("source-ip", "PIM-1", "Case summary", "marking-1")
        self.assertEqual(2, self.client._opener.open.call_count)
        self.client._opener.reset_mock()
        self._responses({"data": {"stixCyberObservable": obj}})
        with self.assertRaisesRegex(api.OpenCTIError, "different marking"):
            self.client.update_case_description("source-ip", "PIM-1", "Case summary", "stricter-marking")
        self.assertEqual(1, self.client._opener.open.call_count)

    def test_taxii_receipt_keeps_retry_ids_without_upstream_error_details(self):
        valid = {"id": "work-1", "status": "complete", "total_count": 1,
                 "success_count": 0, "failure_count": 1, "pending_count": 0}
        self._responses({**valid, "message": "private customer test-secret-token",
                         "failures": [{"id": "file--123", "message": "private path"},
                                      {"message": "private customer"}]})
        result = self.client.taxii_status("work-1")
        self.assertEqual({**valid, "failures": [{"id": "file--123"}]}, result)

    def test_manual_create_is_metadata_only_with_marking_and_no_indicator(self):
        self._responses({"data": {"stixCyberObservableAdd": {"id": "new-file", "entity_type": "StixFile"}}})
        result = self.client.create_observable("hash", "b" * 64, "marking-1")
        self.assertEqual("new-file", result["id"])
        payload = self._payload()
        self.assertIn("createIndicator:false", payload["query"])
        self.assertIn("update:false", payload["query"])
        self.assertEqual(["marking-1"], payload["variables"]["markings"])
        self.assertEqual({"hashes": [{"algorithm": "SHA-256", "hash": "b" * 64}]},
                         payload["variables"]["input"])
        self.assertNotIn("files", payload["variables"]["input"])

    def test_enrichment_is_manual_and_blocks_all_attached_content(self):
        for entity in ({"id": "sample", "entity_type": "Artifact"},
                       {"id": "sample", "entity_type": "StixFile", "obsContent": {"id": "artifact"}},
                       {"id": "sample", "entity_type": "StixFile", "importFiles": [{"id": "file"}]}):
            with patch.object(self.client, "resolve", return_value=entity), self.assertRaisesRegex(
                    api.OpenCTIError, "sample forwarding"):
                self.client.enrich("sample", "vt")
        self.client._opener.open.assert_not_called()
        connector = {"id": "vt", "active": True, "auto": False, "scope": ["StixFile"]}
        with patch.object(self.client, "resolve", return_value={"id": "file", "entity_type": "StixFile"}), \
                patch.object(self.client, "connectors", return_value=[connector]):
            self._responses({"data": {"stixCoreObjectEdit": {"askEnrichment": {"id": "work-1"}}}})
            self.assertEqual({"id": "work-1"}, self.client.enrich("file", "vt"))
            self.assertEqual({"id": "file", "connectorId": "vt"}, self._payload()["variables"])
            connector["auto"] = True
            with self.assertRaisesRegex(api.OpenCTIError, "manual"):
                self.client.enrich("file", "vt")
        self.assertEqual(1, self.client._opener.open.call_count)

    def test_sample_upload_is_explicit_multipart_marked_and_hash_acknowledged(self):
        content = b"Synthetic inert sample content"
        digest = hashlib.sha256(content).hexdigest()
        self._responses({"data": {"stixCyberObservableAdd": {"id": "artifact-1", "standard_id": "artifact--1",
                         "entity_type": "Artifact", "hashes": [{"algorithm": "SHA-256", "hash": digest}]}}})
        uploaded = self.client.upload_sample("C:\\private\\original.bin", content, "marking-1", source_id="artifact--1")
        self.assertEqual("artifact-1", uploaded["id"])
        request = self._request()
        self.assertNotIn(b"C:\\private", request.data)
        message = BytesParser(policy=policy.default).parsebytes(
            ("Content-Type: " + request.get_header("Content-type") + "\r\n\r\n").encode() + request.data)
        parts = list(message.iter_parts())
        operations = json.loads(parts[0].get_payload(decode=True))
        self.assertEqual({"0": ["variables.input.files.0"]}, json.loads(parts[1].get_payload(decode=True)))
        self.assertEqual(content, parts[2].get_payload(decode=True))
        self.assertEqual("original.bin", parts[2].get_filename())
        self.assertEqual("artifact--1", operations["variables"]["sourceId"])
        self.assertEqual([True], operations["variables"]["input"]["noTriggerImport"])
        self.assertEqual([["marking-1"]], operations["variables"]["input"]["filesMarkings"])
        self.assertEqual(["marking-1"], operations["variables"]["markings"])
        self.assertIn("createIndicator:false", operations["query"])

    def test_sample_wrong_hash_or_oversize_is_not_marked_successful(self):
        self._responses({"data": {"stixCyberObservableAdd": {"id": "artifact-1", "hashes": []}}})
        with self.assertRaisesRegex(api.OpenCTIError, "acknowledge"):
            self.client.upload_sample("sample.bin", b"bytes", "marking-1")
        self.client._opener.open.reset_mock()
        with patch.object(api, "MAX_SAMPLE_BYTES", 2), self.assertRaises(ValueError):
            self.client.upload_sample("sample.bin", b"large", "marking-1")
        self.client._opener.open.assert_not_called()

    def test_link_sample_preserves_conflicting_content_and_is_repeatable(self):
        existing = {"id": "file", "entity_type": "StixFile", "obsContent": {"id": "different"}}
        with patch.object(self.client, "resolve", return_value=existing):
            with self.assertRaisesRegex(api.OpenCTIError, "not replaced"):
                self.client.link_sample("file", "artifact", "report")
        self.client._opener.open.assert_not_called()
        existing["obsContent"] = {"id": "artifact"}
        with patch.object(self.client, "resolve", return_value=existing):
            self._responses({"data": {"reportEdit": {"relationAdd": {"id": "membership"}}}})
            self.client.link_sample("file", "artifact", "report")
        self.assertEqual(1, self.client._opener.open.call_count)
        self.assertEqual("object", self._payload()["variables"]["input"]["relationship_type"])

    def test_work_error_text_is_not_a_secret_exfiltration_channel(self):
        self._responses({"data": {"work": {"id": "work-1", "status": "complete",
                          "errors": [{"message": "Authorization:secret API_KEY=private", "sequence": 1}]}}})
        result = self.client.work("work-1")
        self.assertTrue(result["errors"])
        self.assertNotIn("API_KEY", json.dumps(result))
        self.assertNotIn("private", json.dumps(result))

    def test_work_tlp_error_uses_a_fixed_explanation_without_log_contents(self):
        self._responses({"data": {"work": {"id": "work-1", "status": "complete",
            "connector": {"id": "connector-1", "name": "AbuseIPDB"},
            "errors": [{"message": "Do not send any data, TLP of the observable is greater than MAX TLP; API_KEY=private", "sequence": 1}]}}})
        result = self.client.work("work-1")
        self.assertEqual("tlp_limit", result["errors"][0]["code"])
        self.assertIn("TLP marking exceeds", result["errors"][0]["message"])
        self.assertEqual("AbuseIPDB", result["connector"]["name"])
        self.assertNotIn("API_KEY", json.dumps(result))
        self.assertNotIn("private", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
