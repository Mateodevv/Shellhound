"""Small, server-only OpenCTI GraphQL/TAXII adapter.

Queries follow the official OpenCTI schema and Python client. The transport
verifies TLS, refuses redirects and never exposes upstream error bodies (which
can contain credentials). Reads never start enrichment. Mutations are explicit
and are not retried automatically after an uncertain network response.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import math
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from server import diagnostics

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_TAXII_BYTES = 90 * 1024 * 1024
_TAXII_TYPE = "application/taxii+json;version=2.1"
_HASH_ALGORITHMS = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
_CONNECTOR_FIELDS = "id name active auto connector_type connector_scope"

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


def _work_identifier(value):
    # OpenCTI work IDs contain the connector UUID and an ISO UTC timestamp.
    if isinstance(value, str) and re.fullmatch(
            r"work_[A-Za-z0-9_-]{1,100}_\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value):
        return value
    return _identifier(value, "work ID")


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
    if ioc_type in ("hash", "file"):
        if len(value) not in _HASH_ALGORITHMS or not re.fullmatch(r"[A-Fa-f0-9]+", value):
            raise ValueError("Only MD5, SHA-1 and SHA-256 hashes are supported")
        algorithm = _HASH_ALGORITHMS[len(value)]
        return "StixFile", "StixFile", "hashes." + algorithm, value.lower()
    raise ValueError("Only IPs and hashes are supported")


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
        diagnostics.protect_secret(token)
        self.timeout = timeout
        self.ingester_id = str(config.get("ingester_id") or "")
        self._opener = urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def _request(self, path, payload=None, *, content_type="application/json", raw=False):
        logger = logging.getLogger("shellhound.opencti.transport")
        started = time.monotonic()
        endpoint = "TAXII" if path.startswith("/taxii2/") else "GraphQL" if path == "/graphql" else "API"
        logger.debug("%s request started", endpoint)
        try:
            result = self._request_impl(path, payload, content_type=content_type, raw=raw)
            logger.info("%s request completed in %.1f ms", endpoint, (time.monotonic() - started) * 1000)
            return result
        except Exception:
            logger.exception("%s request failed", endpoint)
            raise

    def _request_impl(self, path, payload=None, *, content_type="application/json", raw=False):
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


    def test(self):
        version = self._graphql("query ShellhoundConnection { about { version } }")["about"]["version"]
        identifier = _identifier(self.ingester_id, "TAXII collection ID")
        collection = self._request(f"/taxii2/root/collections/{identifier}/")
        if not collection.get("can_write"):
            raise OpenCTIError("The selected TAXII collection does not allow imports.", code="permission", status=403)
        return {"version": version, "collection": collection}

    def connectors(self):
        try:
            values = self._graphql("query ShellhoundConnectors { connectors { " + _CONNECTOR_FIELDS + " } }").get("connectors") or []
        except OpenCTIError as exc:
            if exc.code != "permission":
                raise
            raise OpenCTIError(
                "OpenCTI denied access to connector metadata. The integration user's role needs "
                "'Access connectors' (MODULES). Check this capability in OpenCTI Settings > Security > Roles.",
                code="permission", status=exc.status, retry_after=exc.retry_after) from None
        return [{"id": item["id"], "name": item.get("name", ""),
                 "active": bool(item.get("active")), "auto": bool(item.get("auto")),
                 "connector_type": item.get("connector_type"),
                 "connector_scope": item.get("connector_scope") or [],
                 "scope": item.get("connector_scope") or []}
                for item in values if item.get("connector_type") == "INTERNAL_ENRICHMENT"]


    def resolve(self, source_id):
        query = """query ShellhoundResolve($id:String!) { stixObjectOrStixRelationship(id:$id) {
          ... on StixObject { id standard_id entity_type }
          ... on StixCoreRelationship { id standard_id entity_type }
          ... on StixSightingRelationship { id standard_id entity_type }
          ... on StixRefRelationship { id standard_id entity_type }
        } }"""
        result = self._graphql(query, {"id": _identifier(source_id)}).get("stixObjectOrStixRelationship")
        if result is None:
            return None
        if not isinstance(result, dict) or not result.get("id") or not result.get("standard_id"):
            raise OpenCTIError("OpenCTI returned an incomplete object identity.", code="invalid_response")
        return result

    def resolve_many(self, source_ids):
        """Verify visibility/identity only, in bounded GraphQL alias batches."""
        ids = list(dict.fromkeys(_identifier(value) for value in source_ids))
        result = {}
        # OpenCTI limits this root field to two calls per operation.
        for offset in range(0, len(ids), 2):
            batch = ids[offset:offset + 2]
            variables = {f"id{i}": value for i, value in enumerate(batch)}
            arguments = ",".join(f"${key}:String!" for key in variables)
            fields = " ".join(
                f"o{i}:stixObjectOrStixRelationship(id:$id{i}) {{ "
                "... on StixObject { id standard_id } "
                "... on StixCoreRelationship { id standard_id } "
                "... on StixSightingRelationship { id standard_id } "
                "... on StixRefRelationship { id standard_id } }"
                for i in range(len(batch)))
            data = self._graphql(f"query ShellhoundVerify({arguments}) {{ {fields} }}", variables)
            for i, source in enumerate(batch):
                remote = data.get(f"o{i}")
                result[source] = remote if isinstance(remote, dict) and remote.get("id") and remote.get("standard_id") else None
        return result

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
        if kind == "software":
            filters = [exact("name", obj["name"])]
            for field in ("version", "vendor"):
                filters.append(exact(field, obj.get(field, "")))
            matches = self._shared_matches("stixCyberObservables", filters, types=["Software"])
            return checked(matches[0]) if matches else None
        ioc_types = {"ipv4-addr": "ip", "ipv6-addr": "ip"}
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
            location_type = obj.get("x_opencti_location_type", "Country")
            if location_type in ("Country", "Administrative-Area", "City"):
                collection, types = "locations", [location_type]
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

    def add_ip_labels(self, identifier, labels):
        """Append reviewed IP tags without replacing another author's fields."""
        identifier = _identifier(identifier)
        if any(not isinstance(value, str) or not value.strip() or len(value) > 500 or '\x00' in value for value in labels):
            raise ValueError('Invalid IP label')
        expected = {value.casefold() for value in labels}
        query = """query ShellhoundIPLabels($id:String!) {
          stixCyberObservable(id:$id) { id entity_type objectLabel { value } }
        }"""

        def current():
            row = self._graphql(query, {'id': identifier}).get('stixCyberObservable')
            if not isinstance(row, dict) or row.get('entity_type') not in ('IPv4-Addr', 'IPv6-Addr'):
                raise OpenCTIError('The exported IP is not visible for tag verification.', code='invalid_response')
            values = row.get('objectLabel')
            if not isinstance(values, list) or any(not isinstance(item, dict) or not isinstance(item.get('value'), str) for item in values):
                raise OpenCTIError('OpenCTI returned incomplete IP labels.', code='invalid_response')
            return {item['value'].casefold() for item in values}

        known = current()
        missing = expected - known
        for value in dict.fromkeys(labels):
            if value.casefold() in known:
                continue
            label = self._graphql("""mutation ShellhoundLabel($input:LabelAddInput!) {
              labelAdd(input:$input) { id }
            }""", {'input': {'value': value, 'update': False}}).get('labelAdd')
            if not isinstance(label, dict) or not label.get('id'):
                raise OpenCTIError('OpenCTI did not return a label identity.', code='invalid_response')
            self._graphql("""mutation ShellhoundIPLabel($id:ID!, $input:StixRefRelationshipAddInput!) {
              stixCyberObservableEdit(id:$id) { relationAdd(input:$input) { id } }
            }""", {'id': identifier, 'input': {'toId': _identifier(label['id']), 'relationship_type': 'object-label'}})
            known.add(value.casefold())
        if missing and not expected <= current():
            raise OpenCTIError('The exported IP tags could not be verified.', code='invalid_response')

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
        identifier = urllib.parse.quote(_work_identifier(work_id), safe="")
        return _taxii_receipt(self._request(f"/taxii2/root/status/{identifier}/"), work_id)
