"""A narrow, analyst-driven OpenCTI 7 adapter.

There is deliberately no synchroniser here.  Shellhound asks about explicit
observables and publishes one immutable report snapshot at a time.  STIX data
uses TAXII 2.1; GraphQL is reserved for reads, capability discovery and the
file upload that TAXII cannot express without embedding the payload in JSON.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import mimetypes
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx


SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
SHELLHOUND_NAMESPACE = uuid.UUID("e4af9229-983b-54a4-9fe3-1105d63281db")
MAX_GRAPHQL_BYTES = 8 * 1024 * 1024
LOOKUP_LIMIT = 25
REQUIRED_CAPABILITIES = {"KNOWLEDGE_KNUPDATE", "KNOWLEDGE_KNUPLOAD"}
DIRECT_TYPES = {
    "Indicator", "Malware", "Threat-Actor", "Threat-Actor-Group",
    "Threat-Actor-Individual", "Intrusion-Set", "Campaign", "Report",
}
OBSERVABLE_TYPES = {
    "IPv4-Addr": "ip", "IPv6-Addr": "ip", "Domain-Name": "domain",
    "Url": "url", "Email-Addr": "email", "StixFile": "hash",
    "User-Account": "user",
}


class OpenCtiError(RuntimeError):
    """An outward-call failure safe to show without its response body."""

    def __init__(self, code: str, message: str, status: int = 502):
        super().__init__(message)
        self.code = code
        self.status = status


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z")


def validate_https_url(value: str, label: str = "OpenCTI URL") -> str:
    """External OpenCTI is HTTPS-only and credentials never belong in a URL."""
    text = str(value or "").strip().rstrip("/")
    try:
        parsed = urlsplit(text)
    except ValueError as exc:
        raise OpenCtiError("invalid_url", f"{label} is invalid", 400) from exc
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise OpenCtiError("invalid_url", f"{label} must use HTTPS", 400)
    if parsed.username or parsed.password or parsed.fragment:
        raise OpenCtiError(
            "invalid_url", f"{label} must not contain credentials or fragments", 400)
    return text


def validate_config(config: dict, require_verified: bool = True) -> dict:
    out = dict(config or {})
    out["url"] = validate_https_url(out.get("url", ""))
    out["taxii_collection_url"] = validate_https_url(
        out.get("taxii_collection_url", ""), "TAXII collection URL")
    if not out.get("token"):
        raise OpenCtiError("not_configured", "OpenCTI token is not configured", 400)
    if require_verified and not out.get("verified_at"):
        raise OpenCtiError(
            "not_verified", "Test the OpenCTI connection before using it", 409)
    return out


def _canonical(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def fingerprint(value) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _stix_id(kind: str, contributing) -> str:
    value = _canonical(contributing)
    return f"{kind}--{uuid.uuid5(SCO_NAMESPACE, value)}"


def _owned_id(kind: str, value: str) -> str:
    return f"{kind}--{uuid.uuid5(SHELLHOUND_NAMESPACE, value)}"


def normalize_value(kind: str, value: str) -> str:
    text = str(value or "").strip()
    if kind == "ip":
        return str(ipaddress.ip_address(text))
    if kind == "domain":
        return text.rstrip(".").lower()
    if kind == "email":
        local, sep, domain = text.partition("@")
        return f"{local}@{domain.lower()}" if sep else text
    if kind == "hash":
        return re.sub(r"\s+", "", text).lower()
    if kind == "path":
        return text.replace("\\", "/")
    return text


def _hash_algorithm(value: str) -> str:
    return {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}.get(
        len(value), "SHA-256")


def observable_object(item: dict) -> dict | None:
    """Map one canonical Shellhound item to an immutable STIX SCO."""
    kind = str(item.get("type") or item.get("kind") or "").lower()
    try:
        value = normalize_value(kind, item.get("value", ""))
    except ValueError:
        return None
    if not value:
        return None
    common = {"type": "", "spec_version": "2.1", "id": ""}
    if kind == "ip":
        family = ipaddress.ip_address(value).version
        common.update(type="ipv4-addr" if family == 4 else "ipv6-addr",
                      value=value)
        common["id"] = _stix_id(common["type"], {"value": value})
    elif kind == "domain":
        common.update(type="domain-name", value=value)
        common["id"] = _stix_id("domain-name", {"value": value})
    elif kind == "url":
        common.update(type="url", value=value)
        common["id"] = _stix_id("url", {"value": value})
    elif kind == "email":
        common.update(type="email-addr", value=value)
        common["id"] = _stix_id("email-addr", {"value": value})
    elif kind == "user":
        common.update(type="user-account", account_login=value)
        common["id"] = _stix_id("user-account", {"account_login": value})
    elif kind == "hash":
        hashes = {_hash_algorithm(value): value}
        common.update(type="file", hashes=hashes)
        common["id"] = _stix_id("file", {"hashes": hashes})
    elif kind == "path":
        name = value.rstrip("/").rsplit("/", 1)[-1]
        if not name:
            return None
        common.update(type="file", name=name,
                      x_opencti_description=f"Observed path: {value}")
        common["id"] = _stix_id("file", {"name": name})
    else:
        return None
    return common


def file_objects(item: dict) -> tuple[dict, dict]:
    """The forensic file and its separately uploadable OpenCTI Artefact."""
    hashes = {str(k): str(v).lower() for k, v in (item.get("hashes") or {}).items()
              if v}
    name = str(item.get("name") or Path(item.get("relative_path", "")).name)
    contributing = {"hashes": hashes} if hashes else {"name": name,
                                                       "size": item.get("size")}
    stix_file = {
        "type": "file", "spec_version": "2.1",
        "id": _stix_id("file", contributing), "name": name,
        "size": int(item.get("size") or 0), "hashes": hashes,
        "x_opencti_description": (
            f"Shellhound evidence path: {item.get('relative_path', name)}"),
    }
    for source, target in (("created_at", "ctime"), ("modified_at", "mtime"),
                           ("accessed_at", "atime")):
        if item.get(source):
            stix_file[target] = item[source]
    artifact_contributing = {"hashes": hashes} if hashes else {
        "mime_type": item.get("mime_type") or "application/octet-stream",
        "x_opencti_additional_names": [name],
    }
    artifact = {
        "type": "artifact", "spec_version": "2.1",
        "id": _stix_id("artifact", artifact_contributing),
        "mime_type": item.get("mime_type") or "application/octet-stream",
        "hashes": hashes,
        "x_opencti_additional_names": [name],
        "x_opencti_description": "Binary content selected in Shellhound",
    }
    return stix_file, artifact


def _indicator_pattern(observable: dict) -> str | None:
    kind = observable["type"]
    if "value" in observable:
        key = "value"
        value = observable["value"]
    elif kind == "user-account":
        key, value = "account_login", observable.get("account_login")
    elif kind == "file" and observable.get("hashes"):
        algorithm, value = next(iter(observable["hashes"].items()))
        key = f"hashes.'{algorithm}'"
    elif kind == "file" and observable.get("name"):
        key, value = "name", observable["name"]
    else:
        return None
    escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"[{kind}:{key} = '{escaped}']"


def build_bundle(case: dict, publication_id: str, summary: str, marking_ref: str,
                 author_ref: str, items: list[dict], at: str | None = None) -> dict:
    """Build one immutable OpenCTI report snapshot and its upload manifest."""
    at = at or utc_now()
    markings = [marking_ref] if marking_ref else []
    objects: list[dict] = []
    object_refs: list[str] = []
    local_refs: dict[str, list[str]] = {}
    uploads: list[dict] = []

    def add(obj, local_ref=""):
        if author_ref and obj["type"] not in {
                "ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr",
                "user-account", "file", "artifact"}:
            obj.setdefault("created_by_ref", author_ref)
        if markings:
            obj.setdefault("object_marking_refs", markings)
        existing = next((entry for entry in objects if entry["id"] == obj["id"]), None)
        if existing is None:
            objects.append(obj)
            object_refs.append(obj["id"])
        else:
            # A selected file and a hash IOC can intentionally identify the
            # same File SCO. Preserve one deterministic object but let the
            # evidence selection enrich it with name, size and timestamps.
            existing.update({key: value for key, value in obj.items()
                             if value not in (None, "", [], {})})
        if local_ref:
            local_refs.setdefault(local_ref, []).append(obj["id"])
        return obj["id"]

    finding_items = []
    for item in items:
        local_ref = str(item.get("local_ref") or "")
        if item.get("kind") == "finding":
            finding_items.append(item)
            continue
        if item.get("kind") == "file":
            stix_file, artifact = file_objects(item)
            file_id = add(stix_file, local_ref)
            artifact_id = add(artifact, local_ref)
            relation = {
                "type": "relationship", "spec_version": "2.1",
                "id": _owned_id("relationship", f"{publication_id}:{file_id}:{artifact_id}"),
                "created": at, "modified": at, "relationship_type": "related-to",
                "description": "Captured binary content of the forensic file",
                "source_ref": stix_file["id"], "target_ref": artifact["id"],
            }
            add(relation)
            uploads.append({
                "local_ref": local_ref, "path": item["path"],
                "relative_path": item.get("relative_path") or item.get("name"),
                "name": item.get("name") or Path(item["path"]).name,
                "size": int(item.get("size") or 0), "hashes": item.get("hashes") or {},
                "artifact_stix_id": artifact["id"],
                "mime_type": item.get("mime_type") or "application/octet-stream",
                "device": str(item.get("device") or ""),
                "inode": str(item.get("inode") or ""),
                "mtime_ns": str(item.get("mtime_ns") or ""),
            })
            indicator_target = stix_file
        else:
            observable = observable_object(item)
            if observable is None:
                continue
            add(observable, local_ref)
            indicator_target = observable
        if item.get("indicator"):
            pattern = _indicator_pattern(indicator_target)
            if pattern:
                indicator = {
                    "type": "indicator", "spec_version": "2.1",
                    "id": _owned_id("indicator", indicator_target["id"]),
                    "created": at, "modified": at,
                    "name": f"Shellhound detection: {item.get('label') or item.get('value') or item.get('name')}",
                    "description": "Explicitly marked as a detection indicator by the analyst in Shellhound.",
                    "pattern_type": "stix", "pattern": pattern,
                    "valid_from": at, "x_opencti_detection": True,
                }
                add(indicator, local_ref)

    for finding in finding_items:
        refs = []
        for ref in finding.get("object_refs") or []:
            refs.extend(local_refs.get(str(ref), []))
        if not refs:
            refs = list(dict.fromkeys(object_refs))
        if not refs and author_ref:
            # A database-only finding may have no STIX-mappable artifact.
            # The Note still needs one valid reference; its source identity
            # is a safer anchor than inventing a threat object.
            refs = [author_ref]
        note = {
            "type": "note", "spec_version": "2.1",
            "id": _owned_id("note", f"{publication_id}:{finding.get('id')}"),
            "created": at, "modified": at,
            "abstract": str(finding.get("rule") or "Shellhound finding")[:120],
            "content": str(finding.get("content") or finding.get("evidence") or "")[:8000],
            "object_refs": list(dict.fromkeys(refs)),
            "labels": ["shellhound", "confirmed-finding"],
        }
        add(note, str(finding.get("local_ref") or ""))

    report_id = f"report--{uuid.UUID(publication_id)}"
    report = {
        "type": "report", "spec_version": "2.1", "id": report_id,
        "created": at, "modified": at, "published": at,
        "name": f"Shellhound snapshot — {case.get('name') or case.get('slug')}",
        "description": str(summary or "Shellhound forensic snapshot")[:20000],
        "report_types": ["incident"], "labels": ["shellhound", "forensic-snapshot"],
        "object_refs": list(dict.fromkeys(object_refs)),
        "external_references": [{
            "source_name": "Shellhound",
            "description": f"Case reference: {case.get('reference') or case.get('slug')}",
        }],
    }
    add(report)
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}",
              "objects": objects}
    return {"bundle": bundle, "report_id": report_id, "uploads": uploads,
            "fingerprint": fingerprint({"case": case.get("slug"),
                                        "summary": summary, "marking": marking_ref,
                                        "author": author_ref, "items": items})}


CONNECTION_QUERY = """
query ShellhoundConnection {
  about { version }
  me { id name capabilities { name } }
  markingDefinitions(first: 200) {
    edges { node { id standard_id definition_type definition } }
  }
  identities(first: 200, types: ["Organization"]) {
    edges { node { id standard_id name entity_type } }
  }
}
"""

LOOKUP_QUERY = """
query ShellhoundObservableLookup($search: String!, $first: Int!) {
  stixCyberObservables(search: $search, first: $first) {
    edges { node {
      id standard_id entity_type observable_value x_opencti_score
      objectLabel { edges { node { value } } }
      objectMarking { edges { node { id standard_id definition } } }
      indicators { edges { node { id standard_id name pattern pattern_type x_opencti_score } } }
      stixCoreRelationships(first: 50) { edges { node {
        id relationship_type
        from { ... on BasicObject { id entity_type representative } }
        to { ... on BasicObject { id entity_type representative } }
      } } }
    } }
  }
}
"""

UPLOAD_MUTATION = """
mutation ShellhoundArtifactUpload($id: ID!, $file: Upload!,
  $fileMarkings: [String], $noTriggerImport: Boolean, $embedded: Boolean) {
  stixCyberObservableEdit(id: $id) {
    importPush(file: $file, fileMarkings: $fileMarkings,
      noTriggerImport: $noTriggerImport, embedded: $embedded) { id name }
  }
}
"""


def _edges(value) -> list[dict]:
    if not isinstance(value, dict):
        return []
    return [edge.get("node") for edge in value.get("edges", [])
            if isinstance(edge, dict) and isinstance(edge.get("node"), dict)]


class OpenCtiClient:
    def __init__(self, config: dict, transport=None):
        self.config = validate_config(config, require_verified=False)
        self.base_url = self.config["url"]
        self.token = self.config["token"]
        self.taxii_url = self.config["taxii_collection_url"]
        self.client = httpx.Client(
            timeout=httpx.Timeout(60.0, connect=10.0), follow_redirects=False,
            headers={"Authorization": f"Bearer {self.token}",
                     "User-Agent": "Shellhound-OpenCTI/1"},
            transport=transport,
        )

    def close(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        try:
            response = self.client.request(method, url, **kwargs)
        except httpx.TimeoutException as exc:
            raise OpenCtiError("timeout", "OpenCTI request timed out", 504) from exc
        except httpx.HTTPError as exc:
            raise OpenCtiError("unreachable", "OpenCTI is not reachable") from exc
        if 300 <= response.status_code < 400:
            raise OpenCtiError("redirect", "OpenCTI returned an unexpected redirect")
        if response.status_code == 401:
            raise OpenCtiError("unauthorized", "OpenCTI rejected the API token", 401)
        if response.status_code == 403:
            raise OpenCtiError("forbidden", "OpenCTI user lacks the required permission", 403)
        if response.status_code == 413:
            raise OpenCtiError("too_large", "OpenCTI rejected the file size", 413)
        if response.status_code >= 400:
            raise OpenCtiError(
                "remote_error", f"OpenCTI returned HTTP {response.status_code}")
        return response

    def graphql(self, query: str, variables: dict | None = None,
                files: dict | None = None) -> dict:
        url = urljoin(self.base_url + "/", "graphql")
        if files:
            operations = {"query": query, "variables": variables or {}}
            mapping = {key: [f"variables.{key}"] for key in files}
            request_files = {
                "operations": (None, json.dumps(operations), "application/json"),
                "map": (None, json.dumps(mapping), "application/json"),
            }
            for key, value in files.items():
                request_files[key] = value
            response = self._request("POST", url, files=request_files)
        else:
            response = self._request(
                "POST", url, json={"query": query, "variables": variables or {}},
                headers={"Content-Type": "application/json"})
        if len(response.content) > MAX_GRAPHQL_BYTES:
            raise OpenCtiError("response_too_large", "OpenCTI response is too large")
        try:
            payload = response.json()
        except ValueError as exc:
            raise OpenCtiError("invalid_response", "OpenCTI returned invalid JSON") from exc
        if payload.get("errors"):
            # GraphQL error text can echo variables or internal paths.  The
            # category is actionable; the untrusted body stays out of logs/UI.
            raise OpenCtiError("graphql_error", "OpenCTI rejected the GraphQL operation")
        if not isinstance(payload.get("data"), dict):
            raise OpenCtiError("invalid_response", "OpenCTI response has no data")
        return payload["data"]

    def test_connection(self) -> dict:
        data = self.graphql(CONNECTION_QUERY)
        version = str((data.get("about") or {}).get("version") or "")
        if not version.startswith("7"):
            raise OpenCtiError(
                "unsupported_version", f"OpenCTI 7.x is required (reported {version or 'unknown'})",
                409)
        me = data.get("me") or {}
        capabilities = sorted({str(row.get("name")) for row in me.get("capabilities", [])
                               if isinstance(row, dict) and row.get("name")})
        missing = sorted(REQUIRED_CAPABILITIES.difference(capabilities))
        if missing:
            raise OpenCtiError(
                "missing_capabilities",
                "OpenCTI user lacks required capabilities: " + ", ".join(missing),
                403,
            )
        markings = [{
            "id": row.get("id", ""), "standard_id": row.get("standard_id", ""),
            "name": row.get("definition", ""), "type": row.get("definition_type", ""),
        } for row in _edges(data.get("markingDefinitions"))]
        authors = [{
            "id": row.get("id", ""), "standard_id": row.get("standard_id", ""),
            "name": row.get("name", ""), "type": row.get("entity_type", ""),
        } for row in _edges(data.get("identities"))]
        # GET is non-mutating and validates the generated collection URL. A
        # standard TAXII deployment may answer 405 on the object endpoint;
        # that still proves the endpoint exists and is authenticated.
        try:
            response = self.client.get(
                self.taxii_url, params={"limit": "1"},
                headers={"Accept": "application/taxii+json;version=2.1"})
        except httpx.HTTPError as exc:
            raise OpenCtiError("unreachable", "TAXII collection is not reachable") from exc
        if response.status_code not in (200, 405):
            if response.status_code in (401, 403):
                raise OpenCtiError("taxii_forbidden", "OpenCTI rejected TAXII access", response.status_code)
            raise OpenCtiError("taxii_invalid", f"TAXII endpoint returned HTTP {response.status_code}")
        return {"verified_at": utc_now(), "version": version,
                "user": {"id": me.get("id", ""), "name": me.get("name", "")},
                "capabilities": capabilities, "markings": markings, "authors": authors}

    def read_observable(self, remote_id: str) -> dict | None:
        query = """
        query ShellhoundRelatedObservable($id: String!) {
          stixCyberObservable(id: $id) {
            id standard_id entity_type observable_value
          }
        }
        """
        data = self.graphql(query, {"id": remote_id})
        node = data.get("stixCyberObservable")
        if not isinstance(node, dict) or not node.get("observable_value"):
            return None
        ioc_type = OBSERVABLE_TYPES.get(str(node.get("entity_type")))
        if not ioc_type:
            return None
        return {"id": node.get("id"), "standard_id": node.get("standard_id"),
                "type": node.get("entity_type"), "ioc_type": ioc_type,
                "value": str(node.get("observable_value")), "promotable": True}

    def lookup(self, kind: str, value: str) -> dict:
        try:
            wanted = normalize_value(kind, value)
        except ValueError:
            return {"matched": False, "matches": [], "related": []}
        data = self.graphql(LOOKUP_QUERY, {"search": wanted, "first": LOOKUP_LIMIT})
        matches, related = [], {}
        for node in _edges(data.get("stixCyberObservables")):
            observed = str(node.get("observable_value") or "").strip()
            try:
                exact = normalize_value(kind, observed) == wanted
            except ValueError:
                exact = False
            if not exact:
                continue
            labels = [str(row.get("value")) for row in _edges(node.get("objectLabel"))
                      if row.get("value")]
            markings = [{"id": row.get("id"), "standard_id": row.get("standard_id"),
                         "name": row.get("definition")}
                        for row in _edges(node.get("objectMarking"))]
            indicators = [{key: row.get(key) for key in
                           ("id", "standard_id", "name", "pattern", "pattern_type",
                            "x_opencti_score")}
                          for row in _edges(node.get("indicators"))]
            clean = {"id": node.get("id"), "standard_id": node.get("standard_id"),
                     "entity_type": node.get("entity_type"), "value": observed,
                     "score": node.get("x_opencti_score"), "labels": labels,
                     "markings": markings, "indicators": indicators}
            matches.append(clean)
            for rel in _edges(node.get("stixCoreRelationships")):
                for endpoint in (rel.get("from"), rel.get("to")):
                    if not isinstance(endpoint, dict) or endpoint.get("id") == node.get("id"):
                        continue
                    entity_type = endpoint.get("entity_type")
                    if entity_type in DIRECT_TYPES:
                        related[str(endpoint.get("id"))] = {
                            "id": endpoint.get("id"), "type": entity_type,
                            "name": endpoint.get("representative") or "",
                            "relationship": rel.get("relationship_type") or "related-to",
                            "promotable": False,
                        }
                    elif entity_type in OBSERVABLE_TYPES:
                        candidate = self.read_observable(str(endpoint.get("id")))
                        if candidate:
                            candidate["relationship"] = (
                                rel.get("relationship_type") or "related-to")
                            related[str(endpoint.get("id"))] = candidate
        return {"matched": bool(matches), "matches": matches,
                "related": list(related.values())}

    def taxii_push(self, bundle: dict) -> dict:
        response = self._request(
            "POST", self.taxii_url,
            json={"objects": bundle.get("objects", [])},
            headers={"Content-Type": "application/taxii+json;version=2.1",
                     "Accept": "application/taxii+json;version=2.1"})
        try:
            result = response.json()
        except ValueError:
            result = {"status": "complete", "http_status": response.status_code}
        if str(result.get("status") or "").lower() in {"failed", "failure"}:
            # TAXII status bodies can contain object-level failure details
            # copied from submitted data. Keep those bodies out of errors.
            raise OpenCtiError("taxii_failed", "OpenCTI rejected the TAXII bundle")
        return result

    def find_observable_id(self, standard_id: str) -> str:
        query = """
        query ShellhoundResolve($filters: FilterGroup) {
          stixCyberObservables(filters: $filters, first: 2) {
            edges { node { id standard_id } }
          }
        }
        """
        filters = {"mode": "and", "filters": [{"key": "ids", "values": [standard_id],
                    "operator": "eq", "mode": "or"}], "filterGroups": []}
        data = self.graphql(query, {"filters": filters})
        for node in _edges(data.get("stixCyberObservables")):
            if node.get("standard_id") == standard_id:
                return str(node.get("id"))
        raise OpenCtiError("not_indexed", "OpenCTI has not indexed the uploaded artifact yet", 409)

    def upload_file(self, remote_id: str, path: str, marking_id: str = "",
                    mime_type: str = "") -> dict:
        name = os.path.basename(path)
        mime = mime_type or mimetypes.guess_type(name)[0] or "application/octet-stream"
        variables = {"id": remote_id, "file": None,
                     "fileMarkings": [marking_id] if marking_id else [],
                     "noTriggerImport": True, "embedded": True}
        with open(path, "rb") as handle:
            return self.graphql(
                UPLOAD_MUTATION, variables,
                {"file": (name, handle, mime)})
