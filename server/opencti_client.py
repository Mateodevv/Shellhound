"""Small, server-only OpenCTI GraphQL/TAXII adapter.

Queries follow the official OpenCTI schema and Python client. The transport
verifies TLS, refuses redirects and never exposes upstream error bodies (which
can contain credentials). Reads never start enrichment. Mutations are explicit
and are not retried automatically after an uncertain network response.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import ntpath
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_SAMPLE_BYTES = 25 * 1024 * 1024
MAX_TAXII_BYTES = 90 * 1024 * 1024
_TAXII_TYPE = "application/taxii+json;version=2.1"
_HASH_ALGORITHMS = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
_CONNECTOR_FIELDS = "id name active auto connector_type connector_scope"
_BASIC_FIELDS = """
... on BasicObject { id standard_id entity_type }
... on StixCoreRelationship { id standard_id entity_type }
... on StixCyberObservable { observable_value }
... on Malware { name description confidence }
... on Report { name published }
... on Incident { name description }
... on Indicator { name pattern confidence }
... on Vulnerability { name description }
... on Organization { name }
"""
_OBSERVABLE_FIELDS = """
id standard_id entity_type x_opencti_stix_ids created_at updated_at
createdBy { id standard_id name }
objectMarking { id standard_id definition }
objectLabel { id value }
externalReferences(first: 25) {
  edges { node { id source_name external_id url description } }
  pageInfo { hasNextPage }
}
reports(first: 25) {
  edges { node {
    id standard_id name description published created_at updated_at
    createdBy { id standard_id name }
    externalReferences(first: 10) { edges { node { source_name external_id url } } pageInfo { hasNextPage } }
  } }
  pageInfo { hasNextPage }
}
importFiles(first: 1) { edges { node { id name } } }
... on StixCyberObservable { observable_value x_opencti_score x_opencti_description }
... on StixFile { file_name: name size hashes { algorithm hash } obsContent { id standard_id } }
... on Artifact { hashes { algorithm hash } }
stixCoreRelationships(first: 50) {
  edges { node {
    id standard_id relationship_type description confidence start_time stop_time
    createdBy { id name }
    from { BASIC_FIELDS }
    to { BASIC_FIELDS }
  } }
  pageInfo { hasNextPage }
}
""".replace("BASIC_FIELDS", _BASIC_FIELDS)
_ENTITY_FIELDS = _OBSERVABLE_FIELDS + """
... on Report { name description published confidence }
... on Incident { name description confidence }
... on Malware { name description confidence is_family malware_types }
... on Vulnerability { name description }
... on Organization { name }
... on Indicator { name description confidence pattern valid_from valid_until revoked }
... on Note { attribute_abstract content }
"""


class OpenCTIError(Exception):
    """A sanitized error suitable for local job status and HTTP responses."""
    def __init__(self, message, *, code="opencti_error", status=None, retryable=False,
                 retry_after=None):
        super().__init__(message)
        self.code = code
        self.status = status
        self.retryable = retryable
        self.retry_after = retry_after


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise OpenCTIError("OpenCTI redirected the request. Configure its final HTTPS URL.",
                           code="redirect", status=code)


def _identifier(value, field="identifier"):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", value):
        raise ValueError(f"Invalid OpenCTI {field}")
    return value


def _edges(connection):
    if not isinstance(connection, dict):
        return []
    return [edge["node"] for edge in connection.get("edges", [])
            if isinstance(edge, dict) and isinstance(edge.get("node"), dict)]


def _taxii_receipt(result, expected_id=None):
    """An accepted response must not accidentally become proof of completion."""
    fields = ("total_count", "success_count", "failure_count", "pending_count")
    if (not isinstance(result.get("id"), str) or not result["id"] or
            (expected_id is not None and result["id"] != expected_id) or
            result.get("status") not in ("pending", "complete") or
            any(type(result.get(key)) is not int or result[key] < 0 for key in fields)):
        raise OpenCTIError("OpenCTI returned an invalid TAXII status receipt.", code="invalid_response")
    if (result["success_count"] + result["failure_count"] + result["pending_count"] != result["total_count"] or
            (result["status"] == "complete" and result["pending_count"] != 0)):
        raise OpenCTIError("OpenCTI returned inconsistent TAXII status counts.", code="invalid_response")
    safe = {key: result[key] for key in ("id", "status", *fields)}
    if isinstance(result.get("failures"), list):
        safe["failures"] = [{"id": item["id"]} for item in result["failures"]
                            if isinstance(item, dict) and isinstance(item.get("id"), str)]
    return safe


def _observable(ioc_type, value):
    if not isinstance(value, str) or not value.strip() or len(value) > 10000 or "\x00" in value:
        raise ValueError("The IOC value is empty or invalid")
    value = value.strip()
    if ioc_type == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("Invalid IP address") from exc
        kind = "IPv4-Addr" if address.version == 4 else "IPv6-Addr"
        return kind, kind.replace("-", ""), "value", str(address)
    if ioc_type == "hash":
        if len(value) not in _HASH_ALGORITHMS or not re.fullmatch(r"[A-Fa-f0-9]+", value):
            raise ValueError("Only MD5, SHA-1 and SHA-256 hashes are supported")
        algorithm = _HASH_ALGORITHMS[len(value)]
        return "StixFile", "StixFile", "hashes." + algorithm, value.lower()
    mapping = {"domain": ("Domain-Name", "DomainName", "value"),
               "email": ("Email-Addr", "EmailAddr", "value"),
               "url": ("Url", "Url", "value"),
               "user": ("User-Account", "UserAccount", "account_login"),
               "other": ("Text", "Text", "value")}
    if ioc_type == "path":
        raise ValueError("Paths require their case context; check a linked file hash instead")
    if ioc_type not in mapping:
        raise ValueError("Unsupported IOC type")
    kind, input_name, field = mapping[ioc_type]
    if ioc_type in ("domain", "email", "url") and ("\\" in value or re.search(r"(?<![A-Za-z])[A-Za-z]:[\\/]", value)):
        raise ValueError("Local filesystem paths cannot be sent as network IOCs")
    if ioc_type == "domain":
        value = _domain(value)
    elif ioc_type == "email":
        if value.count("@") != 1:
            raise ValueError("Invalid email IOC")
        local, host = value.rsplit("@", 1)
        if not local or re.search(r"[\s/:]", local):
            raise ValueError("Invalid email IOC")
        value = local + "@" + _domain(host)
    elif ioc_type == "url":
        try:
            parsed = urllib.parse.urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Invalid URL IOC") from exc
        if (parsed.scheme not in ("http", "https") or not parsed.hostname or
                parsed.username is not None or parsed.password is not None or
                any(char.isspace() for char in value) or (port is not None and not 1 <= port <= 65535)):
            raise ValueError("URL IOCs must be HTTP(S) URLs without embedded credentials")
    return kind, input_name, field, value


def _domain(value):
    try:
        value = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid domain IOC") from exc
    if len(value) > 253 or not re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", value):
        raise ValueError("Invalid domain IOC")
    return value


class OpenCTIClient:
    def __init__(self, config):
        raw_url = config.get("url", "")
        if (not isinstance(raw_url, str) or "\\" in raw_url or
                any(char.isspace() or ord(char) < 32 for char in raw_url)):
            raise ValueError("OpenCTI requires a valid HTTPS URL")
        parsed = urllib.parse.urlsplit(raw_url)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("OpenCTI URL has an invalid port") from exc
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or
                parsed.password or parsed.query or parsed.fragment or
                (port is not None and not 1 <= port <= 65535)):
            raise ValueError("Use an HTTPS OpenCTI URL without credentials, query or fragment")
        token = config.get("token", "")
        if not isinstance(token, str) or not token or any(not 33 <= ord(c) <= 126 for c in token):
            raise ValueError("An OpenCTI integration token is required")
        try:
            timeout = float(config.get("timeout", 30))
        except (ValueError, TypeError) as exc:
            raise ValueError("OpenCTI timeout must be a number") from exc
        if not math.isfinite(timeout) or not 1 <= timeout <= 120:
            raise ValueError("OpenCTI timeout must be between 1 and 120 seconds")
        self.url = raw_url.rstrip("/")
        self._token = token
        self.timeout = timeout
        self.ingester_id = str(config.get("ingester_id") or "")
        self._opener = urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def _request(self, path, payload=None, *, content_type="application/json", raw=False):
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("OpenCTI requests must use an internal API path")
        data = payload if raw else (json.dumps(payload, ensure_ascii=False).encode("utf-8")
                                    if payload is not None else None)
        request = urllib.request.Request(self.url + path, data=data, headers={
            "Authorization": "Bearer " + self._token,
            "Accept": _TAXII_TYPE if path.startswith("/taxii2/") else "application/json",
            "Content-Type": content_type,
            "User-Agent": "Shellhound-OpenCTI/1",
            # Required by Apollo's CSRF protection for multipart requests.
            "Apollo-Require-Preflight": "true",
        }, method="POST" if payload is not None else "GET")
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                status = response.getcode()
                if status is not None and 300 <= status < 400:
                    raise OpenCTIError("OpenCTI redirected the request. Check its configured URL.",
                                       code="redirect", status=status)
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except OpenCTIError:
            raise
        except urllib.error.HTTPError as exc:
            status = exc.code
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            retry_after = int(retry_after) if str(retry_after).isdigit() else None
            messages = {401: ("authentication", "OpenCTI rejected the integration token."),
                        403: ("permission", "The OpenCTI token lacks permission for this action."),
                        404: ("not_found", "The OpenCTI resource is unavailable or not visible to this token."),
                        413: ("too_large", "OpenCTI rejected the request because it is too large."),
                        429: ("rate_limit", "OpenCTI rate limit reached. Try again later.")}
            code, message = messages.get(status, ("http_error", f"OpenCTI request failed (HTTP {status})."))
            exc.close()
            raise OpenCTIError(message, code=code, status=status,
                               retryable=status == 429 or status >= 500,
                               retry_after=retry_after) from None
        except (TimeoutError, socket.timeout):
            raise OpenCTIError("OpenCTI did not respond before the timeout.",
                               code="timeout", retryable=True) from None
        except (urllib.error.URLError, OSError, ssl.SSLError):
            raise OpenCTIError("OpenCTI could not be reached over a verified TLS connection.",
                               code="connection", retryable=True) from None
        if len(body) > MAX_RESPONSE_BYTES:
            raise OpenCTIError("OpenCTI returned a response that is too large.", code="response_size")
        try:
            result = json.loads(body)
        except (ValueError, UnicodeError):
            raise OpenCTIError("OpenCTI returned an invalid JSON response.", code="invalid_response") from None
        if not isinstance(result, dict):
            raise OpenCTIError("OpenCTI returned an unexpected response.", code="invalid_response")
        return result

    def _graphql_result(self, response):
        errors = response.get("errors")
        if errors:
            codes = {str(item["extensions"].get("code", ""))
                     for item in errors if isinstance(item, dict) and isinstance(item.get("extensions"), dict)}
            if codes & {"UNAUTHENTICATED", "AUTH_REQUIRED", "AUTHENTICATION_FAILURE"}:
                raise OpenCTIError("OpenCTI rejected the integration token.", code="authentication", status=401)
            if codes & {"FORBIDDEN", "FORBIDDEN_ACCESS", "MISSING_CAPABILITY"}:
                raise OpenCTIError("The OpenCTI token lacks permission for this action.", code="permission", status=403)
            if codes & {"GRAPHQL_VALIDATION_FAILED", "BAD_USER_INPUT"}:
                raise OpenCTIError("OpenCTI rejected the API request. Check platform compatibility and input.",
                                   code="validation")
            raise OpenCTIError("OpenCTI could not complete the API request.", code="graphql_error")
        if not isinstance(response.get("data"), dict):
            raise OpenCTIError("OpenCTI returned no API result.", code="invalid_response")
        return response["data"]

    def _graphql(self, query, variables=None):
        return self._graphql_result(self._request("/graphql", {"query": query, "variables": variables or {}}))

    def _entity(self, entity):
        if entity is None:
            return None
        if not isinstance(entity, dict) or not entity.get("id"):
            raise OpenCTIError("OpenCTI returned an incomplete object.", code="invalid_response")
        result = dict(entity)
        result["context_truncated"] = any(
            (entity.get(field) or {}).get("pageInfo", {}).get("hasNextPage")
            for field in ("externalReferences", "reports", "stixCoreRelationships"))
        for field in ("externalReferences", "reports", "importFiles"):
            result[field] = _edges(entity.get(field))
        for report in result["reports"]:
            if (report.get("externalReferences") or {}).get("pageInfo", {}).get("hasNextPage"):
                result["context_truncated"] = True
            report["externalReferences"] = _edges(report.get("externalReferences"))
        result["relationships"] = _edges(entity.get("stixCoreRelationships"))
        result["relationships_truncated"] = bool(
            (entity.get("stixCoreRelationships") or {}).get("pageInfo", {}).get("hasNextPage"))
        result.pop("stixCoreRelationships", None)
        result["score"] = result.get("x_opencti_score")
        result["labels"] = [item["value"] for item in result.get("objectLabel") or []
                            if isinstance(item, dict) and item.get("value")]
        result["sources"] = result["externalReferences"]
        result["description"] = result.get("description") or result.get("x_opencti_description") or ""
        result["name"] = (result.get("name") or result.get("file_name") or
                          result.get("observable_value") or result.get("attribute_abstract") or "")
        result["url"] = self.url + "/dashboard/id/" + urllib.parse.quote(result["id"], safe="")
        malware = {}
        for relationship in result["relationships"]:
            for side in ("from", "to"):
                related = relationship.get(side) or {}
                if related.get("entity_type") == "Malware" and related.get("id"):
                    malware[related["id"]] = {**related, "url": self.url + "/dashboard/id/" +
                                              urllib.parse.quote(related["id"], safe="")}
        result["malware"] = list(malware.values())
        return result

    def test(self):
        version = self._graphql("query ShellhoundConnection { about { version } }")["about"]["version"]
        identifier = _identifier(self.ingester_id, "TAXII collection ID")
        collection = self._request(f"/taxii2/root/collections/{identifier}/")
        if not collection.get("can_write"):
            raise OpenCTIError("The selected TAXII collection does not allow imports.", code="permission", status=403)
        return {"version": version, "collection": collection}

    def connectors(self):
        values = self._graphql("query ShellhoundConnectors { connectors { " + _CONNECTOR_FIELDS + " } }").get("connectors") or []
        return [{"id": item["id"], "name": item.get("name", ""),
                 "active": bool(item.get("active")), "auto": bool(item.get("auto")),
                 "connector_type": item.get("connector_type"),
                 "connector_scope": item.get("connector_scope") or [],
                 "scope": item.get("connector_scope") or []}
                for item in values if item.get("connector_type") == "INTERNAL_ENRICHMENT"]

    def lookup(self, ioc_type, value):
        kind, _, field, value = _observable(ioc_type, value)
        types = ["StixFile", "Artifact"] if ioc_type == "hash" else [kind]
        query = """query ShellhoundLookup($types:[String],$filters:FilterGroup,$after:ID) {
          stixCyberObservables(types:$types,filters:$filters,first:100,after:$after) {
            edges { node { FIELDS } } pageInfo { hasNextPage endCursor }
          }
        }""".replace("FIELDS", _OBSERVABLE_FIELDS)
        variables = {"types": types, "filters": {"mode": "and", "filters": [
            {"key": [field], "values": [value], "operator": "eq", "mode": "or"}],
            "filterGroups": []}, "after": None}
        results = []
        while True:
            connection = self._graphql(query, variables).get("stixCyberObservables") or {}
            results.extend(self._entity(item) for item in _edges(connection))
            page = connection.get("pageInfo") or {}
            if not page.get("hasNextPage"):
                return results
            cursor = page.get("endCursor")
            if len(results) >= 1000 or not cursor or cursor == variables["after"]:
                raise OpenCTIError("Too many matching OpenCTI objects; narrow this lookup.", code="result_limit")
            variables["after"] = cursor

    def resolve(self, source_id):
        query = """query ShellhoundResolve($id:String!) { stixObjectOrStixRelationship(id:$id) {
          ... on StixObject { id standard_id entity_type }
          ... on StixCoreObject { ENTITY_FIELDS }
          ... on MarkingDefinition { definition }
          ... on StixCoreRelationship {
            id standard_id entity_type relationship_type description confidence created_at updated_at
            createdBy { id standard_id name } from { BASIC_FIELDS } to { BASIC_FIELDS }
          }
          ... on StixSightingRelationship { id standard_id entity_type }
          ... on StixRefRelationship { id standard_id entity_type }
        } }""".replace("ENTITY_FIELDS", _ENTITY_FIELDS).replace("BASIC_FIELDS", _BASIC_FIELDS)
        data = self._graphql(query, {"id": _identifier(source_id)})
        return self._entity(data.get("stixObjectOrStixRelationship"))

    def _shared_matches(self, collection, filters, *, types=None, file=False):
        """Minimal, exact reads used before a TAXII import can deduplicate objects."""
        if collection not in ("stixCyberObservables", "vulnerabilities", "identities", "locations"):
            raise ValueError("Unsupported shared-object collection")
        fields = "id standard_id entity_type"
        if collection == "stixCyberObservables":
            fields += (" ... on StixFile { hashes { algorithm hash } }" if file else
                       " observable_value")
        else:
            fields += " name"
        typed = collection != "vulnerabilities"
        query = ("query ShellhoundShared($filters:FilterGroup" + (",$types:[String]" if typed else "") +
                 ") { " + collection + "(filters:$filters,first:2" +
                 (",types:$types" if typed else "") + ") { edges { node { " + fields +
                 " } } pageInfo { hasNextPage } } }")
        variables = {"filters": {"mode": "and", "filters": filters, "filterGroups": []}}
        if typed:
            variables["types"] = types
        connection = self._graphql(query, variables).get(collection)
        if (not isinstance(connection, dict) or not isinstance(connection.get("edges"), list) or
                any(not isinstance(edge, dict) or not isinstance(edge.get("node"), dict)
                    for edge in connection["edges"])):
            raise OpenCTIError("OpenCTI returned an incomplete shared-object lookup.", code="invalid_response")
        matches = _edges(connection)
        if len(matches) > 1 or (connection.get("pageInfo") or {}).get("hasNextPage"):
            raise OpenCTIError("Several shared OpenCTI objects match this content; resolve the duplicate before exporting.",
                               code="shared_object_conflict")
        return matches

    def find_existing_shared(self, obj):
        """Find content already in OpenCTI without changing its author or marking.

        Source STIX IDs alone are insufficient: OpenCTI also deduplicates by
        observable value, file hashes and domain-object names. In particular a
        weak File hash must not attach a case to a different file version.
        """
        def exact(field, value):
            return {"key": [field], "values": [value], "operator": "eq", "mode": "or"}

        def checked(entity):
            if entity is None:
                return None
            if (not isinstance(entity.get("id"), str) or not entity["id"] or
                    not isinstance(entity.get("standard_id"), str) or
                    not entity["standard_id"].startswith(obj["type"] + "--")):
                raise OpenCTIError("OpenCTI returned an incomplete shared-object identity.", code="invalid_response")
            return entity

        kind = obj.get("type")
        if kind == "file":
            hashes = {algorithm: str(value).lower() for algorithm, value in (obj.get("hashes") or {}).items()
                      if algorithm in _HASH_ALGORITHMS.values()}
            if not hashes:
                # A filename is not a sufficient file identity.
                raise OpenCTIError("A file needs a supported content hash before export.", code="file_identity")
            ordered = [algorithm for algorithm in ("SHA-256", "SHA-1", "MD5") if algorithm in hashes]
            for algorithm in ordered:
                _, _, field, _ = _observable("hash", hashes[algorithm])
                if field != "hashes." + algorithm:
                    raise ValueError("Invalid file hash algorithm")
            existing = None
            for algorithm in ordered:
                matches = self._shared_matches("stixCyberObservables", [exact("hashes." + algorithm, hashes[algorithm])],
                                               types=["StixFile"], file=True)
                for candidate in matches:
                    checked(candidate)
                    remote_hashes = {str(item.get("algorithm")): str(item.get("hash", "")).lower()
                                     for item in candidate.get("hashes") or [] if isinstance(item, dict)}
                    if (candidate.get("entity_type") != "StixFile" or
                            remote_hashes.get(ordered[0]) != hashes[ordered[0]] or
                            any(remote_hashes[key] != value for key, value in hashes.items() if key in remote_hashes) or
                            (existing is not None and candidate["id"] != existing["id"])):
                        raise OpenCTIError("An existing OpenCTI file has ambiguous or conflicting hashes; resolve its identity before exporting.",
                                           code="file_identity")
                    existing = candidate
            return existing
        ioc_types = {"ipv4-addr": "ip", "ipv6-addr": "ip", "domain-name": "domain",
                     "email-addr": "email", "url": "url"}
        if kind in ioc_types:
            entity_type, _, field, value = _observable(ioc_types[kind], obj.get("value"))
            matches = self._shared_matches("stixCyberObservables", [exact(field, value)], types=[entity_type])
            if not matches:
                return None
            result = checked(matches[0])
            if (result.get("entity_type") != entity_type or
                    _observable(ioc_types[kind], result.get("observable_value"))[3] != value):
                raise OpenCTIError("OpenCTI returned a different observable for an exact lookup.", code="invalid_response")
            return result
        collection = None
        types = None
        if kind == "vulnerability":
            collection = "vulnerabilities"
        elif kind == "identity":
            types = [{"class": "Sector", "organization": "Organization", "system": "System"}.get(
                obj.get("identity_class"), "Identity")]
            collection = "identities"
        elif kind == "location" and obj.get("country"):
            collection, types = "locations", ["Country"]
        if collection:
            name = str(obj.get("name") or obj.get("country") or "").strip()
            if not name:
                raise ValueError("A shared domain object needs a name")
            matches = self._shared_matches(collection, [exact("name", name)], types=types)
            if matches:
                result = checked(matches[0])
                if str(result.get("name", "")).casefold() != name.casefold():
                    raise OpenCTIError("OpenCTI returned a different name for an exact lookup.", code="invalid_response")
                return result
        return checked(self.resolve(obj["id"]))

    def push(self, objects):
        if not isinstance(objects, list) or not objects or any(not isinstance(item, dict) for item in objects):
            raise ValueError("A nonempty list of STIX objects is required")
        encoded = json.dumps({"objects": objects}, ensure_ascii=False).encode("utf-8")
        if len(encoded) > MAX_TAXII_BYTES:
            raise ValueError("The OpenCTI export is too large for one TAXII request")
        identifier = _identifier(self.ingester_id, "TAXII collection ID")
        return _taxii_receipt(self._request(f"/taxii2/root/collections/{identifier}/objects/", encoded,
                                            content_type=_TAXII_TYPE, raw=True))

    def taxii_status(self, work_id):
        return _taxii_receipt(self._request(f"/taxii2/root/status/{_identifier(work_id, 'work ID')}/"), work_id)

    def work(self, work_id):
        data = self._graphql("""query ShellhoundWork($id:ID!) { work(id:$id) {
          id status timestamp received_time processed_time completed_time
          tracking { import_expected_number import_processed_number }
          messages { timestamp message sequence } errors { timestamp message sequence }
        } }""", {"id": _identifier(work_id, "work ID")})
        result = data.get("work")
        if result is None:
            raise OpenCTIError("The OpenCTI work is unavailable or not visible.", code="not_found", status=404)
        # Connector messages are not trusted to redact their configuration.
        for field in ("messages", "errors"):
            result[field] = [{"timestamp": item.get("timestamp"), "sequence": item.get("sequence"),
                              "message": "Connector reported an error; see its OpenCTI work log."
                              if field == "errors" else "Connector progress reported."}
                             for item in result.get(field) or []]
        return result

    def create_observable(self, ioc_type, value, marking_id):
        kind, input_name, field, value = _observable(ioc_type, value)
        payload = ({"hashes": [{"algorithm": field.split(".", 1)[1], "hash": value}]}
                   if ioc_type == "hash" else {field: value})
        query = ("mutation ShellhoundCreate($input:" + input_name + "AddInput!,$markings:[String]) {"
                 "stixCyberObservableAdd(type:\"" + kind + "\"," + input_name + ":$input,"
                 "objectMarking:$markings,createIndicator:false,update:false) {"
                 "id standard_id entity_type observable_value } }")
        return self._graphql(query, {"input": payload,
                                     "markings": [_identifier(marking_id, "marking ID")]}).get("stixCyberObservableAdd")

    def enrich(self, entity_id, connector_id):
        entity_id = _identifier(entity_id)
        connector_id = _identifier(connector_id, "connector ID")
        entity = self.resolve(entity_id)
        if not entity:
            raise OpenCTIError("The observable is not visible in OpenCTI.", code="not_found", status=404)
        if entity.get("entity_type") == "Artifact" or entity.get("obsContent") or entity.get("importFiles"):
            raise OpenCTIError("Enrichment is disabled for objects with file contents to prevent sample forwarding.",
                               code="sample_forwarding")
        connector = next((item for item in self.connectors() if item["id"] == connector_id), None)
        if not connector or not connector["active"] or connector["auto"]:
            raise OpenCTIError("Choose an active connector configured for manual enrichment.", code="connector_unavailable")
        scopes = {str(value).lower() for value in connector["scope"]}
        entity_type = str(entity.get("entity_type", "")).lower()
        if entity_type not in scopes and "stix-cyber-observable" not in scopes:
            raise OpenCTIError("This connector does not support the selected observable type.", code="connector_scope")
        data = self._graphql("""mutation ShellhoundEnrich($id:ID!,$connectorId:ID!) {
          stixCoreObjectEdit(id:$id) { askEnrichment(connectorId:$connectorId) { id } }
        }""", {"id": entity_id, "connectorId": connector_id})
        return data["stixCoreObjectEdit"]["askEnrichment"]

    def upload_sample(self, filename, data, marking_id, *, source_id=None):
        if not isinstance(data, bytes) or len(data) > MAX_SAMPLE_BYTES:
            raise ValueError("Sample must be bytes and at most 25 MiB")
        filename = ntpath.basename(str(filename).replace("/", "\\"))
        if not filename or any(ord(char) < 32 or char == '"' for char in filename):
            raise ValueError("Invalid sample filename")
        filename = filename[:255]
        marking_id = _identifier(marking_id, "marking ID")
        digest = hashlib.sha256(data).hexdigest()
        query = """mutation ShellhoundSample($input:ArtifactAddInput!,$markings:[String],$sourceId:StixId) {
          stixCyberObservableAdd(type:"Artifact",Artifact:$input,objectMarking:$markings,
            stix_id:$sourceId,createIndicator:false,update:false) {
            id standard_id entity_type ... on Artifact { hashes { algorithm hash } }
          }
        }"""
        operations = {"query": query, "variables": {"sourceId": _identifier(source_id) if source_id else None,
            "markings": [marking_id], "input": {"hashes": [{"algorithm": "SHA-256", "hash": digest}],
            "mime_type": "application/octet-stream", "x_opencti_additional_names": [filename],
            "files": [None], "filesMarkings": [[marking_id]], "noTriggerImport": [True], "embedded": [False]}}}
        boundary = "shellhound-" + uuid.uuid4().hex
        parts = []
        for name, value in (("operations", operations), ("map", {"0": ["variables.input.files.0"]})):
            parts.append((f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n"
                          "Content-Type: application/json\r\n\r\n").encode("ascii") +
                         json.dumps(value, ensure_ascii=False).encode("utf-8") + b"\r\n")
        parts.append((f"--{boundary}\r\nContent-Disposition: form-data; name=\"0\"; filename=\"{filename}\"\r\n"
                      "Content-Type: application/octet-stream\r\n\r\n").encode("utf-8") + data + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode("ascii"))
        response = self._graphql_result(self._request("/graphql", b"".join(parts), raw=True,
            content_type="multipart/form-data; boundary=" + boundary))
        result = response.get("stixCyberObservableAdd") or {}
        if not result.get("id") or not any(item.get("algorithm") == "SHA-256" and
                                          item.get("hash", "").lower() == digest
                                          for item in result.get("hashes") or []):
            raise OpenCTIError("OpenCTI did not acknowledge the uploaded sample hash.", code="sample_hash")
        return result

    def link_sample(self, file_id, artifact_id, report_id):
        file_id, artifact_id, report_id = map(_identifier, (file_id, artifact_id, report_id))
        existing = self.resolve(file_id)
        if not existing or existing.get("entity_type") != "StixFile":
            raise OpenCTIError("The sample target is not a visible File observable.", code="sample_target")
        current = existing.get("obsContent")
        if current and artifact_id not in (current.get("id"), current.get("standard_id")):
            raise OpenCTIError("This File already has different artifact content; it was not replaced.", code="sample_conflict")
        if not current:
            self._graphql("""mutation ShellhoundSampleContent($id:ID!,$input:StixRefRelationshipAddInput!) {
              stixCyberObservableEdit(id:$id) { relationAdd(input:$input) { id } }
            }""", {"id": file_id, "input": {"toId": artifact_id, "relationship_type": "obs_content"}})
        # OpenCTI relationAdd upserts the existing object-ref instead of adding
        # duplicate memberships, including when replayed after a lost response.
        self._graphql("""mutation ShellhoundSampleReport($id:ID!,$input:StixRefRelationshipAddInput!) {
          reportEdit(id:$id) { relationAdd(input:$input) { id } }
        }""", {"id": report_id, "input": {"toId": artifact_id, "relationship_type": "object"}})
        return {"file_id": file_id, "artifact_id": artifact_id, "report_id": report_id}
