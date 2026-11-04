import io
import json
import unittest
import urllib.error
from unittest.mock import Mock, patch

from server.integrations.opencti import client as api


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

    def test_ip_tags_are_appended_without_changing_existing_fields(self):
        def ip(*labels):
            return {'data': {'stixCyberObservable': {'id': 'known-ip', 'entity_type': 'IPv4-Addr',
                                                     'objectLabel': [{'value': value} for value in labels]}}}
        self._responses(ip('Foreign'), {'data': {'labelAdd': {'id': 'reviewed-tag'}}},
                        {'data': {'stixCyberObservableEdit': {'relationAdd': {'id': 'relation'}}}},
                        ip('Foreign', 'Reviewed'))
        self.client.add_ip_labels('known-ip', ['foreign', 'Reviewed'])
        self.assertEqual({'input': {'value': 'Reviewed', 'update': False}}, self._payload(1)['variables'])
        self.assertEqual({'id': 'known-ip', 'input': {'toId': 'reviewed-tag', 'relationship_type': 'object-label'}},
                         self._payload(2)['variables'])
        for call in self.client._opener.open.call_args_list:
            for forbidden in ('fieldPatch', 'relationDelete', 'objectMarking', 'createdBy', 'score', 'askEnrichment'):
                self.assertNotIn(forbidden, call.args[0].data.decode())
        self.client._opener.open.reset_mock()
        self._responses(ip('Foreign', 'Reviewed'))
        self.client.add_ip_labels('known-ip', ['Reviewed'])
        self.client._opener.open.assert_called_once()

    def test_successful_label_mutation_requires_visible_tags(self):
        ip = {'data': {'stixCyberObservable': {'id': 'known-ip', 'entity_type': 'IPv6-Addr', 'objectLabel': []}}}
        self._responses(ip, {'data': {'labelAdd': {'id': 'tag'}}},
                        {'data': {'stixCyberObservableEdit': {'relationAdd': {'id': 'relation'}}}}, ip)
        with self.assertRaisesRegex(api.OpenCTIError, 'could not be verified'):
            self.client.add_ip_labels('known-ip', ['Reviewed'])

    def test_export_verification_batches_minimal_reads_and_preserves_missing(self):
        ids = [f"ipv4-addr--00000000-0000-4000-8000-{i:012d}" for i in range(51)]
        replies = []
        for offset in range(0, len(ids), 2):
            replies.append({"data": {f"o{i}": {"id": f"remote-{offset+i}", "standard_id": source}
                                     for i, source in enumerate(ids[offset:offset+2])}})
        replies[1]["data"]["o0"] = None
        self._responses(*replies)
        result = self.client.resolve_many(ids + ids[:1])
        self.assertEqual(26, self.client._opener.open.call_count)
        self.assertEqual(51, len(result))
        self.assertIsNone(result[ids[2]])
        self.assertEqual(ids[-1], result[ids[-1]]["standard_id"])
        for index in range(26):
            query = self._payload(index)["query"]
            self.assertNotIn("description", query)
            self.assertNotIn("createdBy", query)
            self.assertNotIn("mutation", query)
            self.assertLessEqual(len(self._payload(index)["variables"]), 2)

    def test_export_verification_propagates_graphql_errors(self):
        self._responses({"errors": [{"message": "denied"}]})
        with self.assertRaises(api.OpenCTIError):
            self.client.resolve_many(["ipv4-addr--00000000-0000-4000-8000-000000000001"])


    def test_location_lookup_uses_specific_opencti_type(self):
        for kind in ("Country", "Administrative-Area", "City"):
            obj = {"type": "location", "id": "location--local", "name": "Example", "country": "de", "x_opencti_location_type": kind}
            existing = {"id": "remote", "standard_id": "location--remote", "name": "Example"}
            with patch.object(self.client, "_shared_matches", return_value=[existing]) as lookup:
                self.assertEqual(existing, self.client.find_existing_shared(obj))
                self.assertEqual([kind], lookup.call_args.kwargs["types"])

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


    def test_resolution_requests_identity_without_enrichment_fields(self):
        self._responses({"data": {"stixObjectOrStixRelationship": {
            "id": "marking", "standard_id": "marking-definition--123", "entity_type": "Marking-Definition"}}})
        self.assertEqual("marking", self.client.resolve("marking-definition--123")["id"])
        query = self._payload()["query"]
        self.assertIn("... on StixCoreRelationship", query)
        self.assertNotIn("score", query)
        self.assertNotIn("description", query)
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
                ("ipv6-addr", "2001:db8::1", "IPv6-Addr")):
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
        for invalid in ("../work", work_id + "/other", work_id + "?token=x", work_id + "#x", work_id + "\n"):
            for method in (self.client.taxii_status,):
                with self.subTest(value=invalid), self.assertRaises(ValueError):
                    method(invalid)
        self.assertEqual(1, self.client._opener.open.call_count)

    def test_taxii_receipt_keeps_retry_ids_without_upstream_error_details(self):
        valid = {"id": "work-1", "status": "complete", "total_count": 1,
                 "success_count": 0, "failure_count": 1, "pending_count": 0}
        self._responses({**valid, "message": "private customer test-secret-token",
                         "failures": [{"id": "file--123", "message": "private path"},
                                      {"message": "private customer"}]})
        result = self.client.taxii_status("work-1")
        self.assertEqual({**valid, "failures": [{"id": "file--123"}]}, result)


if __name__ == "__main__":
    unittest.main()
