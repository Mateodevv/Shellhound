"""Explicit OpenCTI operations with durable receipts and local, offline reads.

A preview is an immutable, destination-bound authorization snapshot. Queue
acceptance is recorded separately from completed imports. Workers resume the
same receipt instead of inventing a new case or repeating completed uploads.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from server import db, opencti_graph as graph, settings, workspace
from server.jobs import manager
from server.opencti_client import OpenCTIClient
from server.paths import io_path

_LOCK = threading.RLock()
_ACTIVE = set()
CACHE_SECONDS = 86400
PREVIEW_SECONDS = 1800
POLL_SECONDS = 2
POLL_LIMIT = 30


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value):
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _age(value):
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if not stamp.tzinfo:
            stamp = stamp.astimezone()
        return (datetime.now(timezone.utc) - stamp).total_seconds()
    except (ValueError, TypeError):
        return float("inf")


def _destination(config):
    # A new host/ingester/token invalidates saved query authority as well as
    # review consent. This digest cannot reveal a token in the local API.
    return _digest([config.get(k, "") for k in ("url", "ingester_id", "token")])


def _mapping_destination(config):
    # Source identity and terminal revocation history belong to the remote
    # collection, not to the lifetime of one replaceable API credential.
    return _digest([config.get("url", "").rstrip("/"), config.get("ingester_id", "")])


def _config(root):
    config = settings.opencti_config(root)
    if not all(config.get(k) for k in ("url", "token", "ingester_id")):
        raise ValueError("Configure the OpenCTI URL, integration token and TAXII ingester first.")
    return config


def _identity(row):
    return _digest([row.get("source_uid"), row["type"], row["value"]])


def _iocs(case_dir, ids=None):
    conn = db.connect(case_dir)
    try:
        rows = db.rows(conn, "SELECT * FROM iocs ORDER BY id")
    finally:
        conn.close()
    if ids is None:
        return rows
    wanted = set(ids)
    selected = [r for r in rows if r["id"] in wanted]
    if wanted - {r["id"] for r in selected}:
        raise ValueError("A selected IOC no longer exists. Refresh the IOC box.")
    return selected


def _revisions(case_dir):
    """Cheap local change detection; transfer still rehashes original files."""
    conn = db.connect(case_dir)
    try:
        rows = db.rows(conn, "SELECT * FROM iocs ORDER BY id")
        links = db.ioc_links(conn)
        sources = db.rows(conn, "SELECT * FROM ioc_sources ORDER BY id")
        decisions = db.rows(conn, "SELECT fingerprint,source,rule,rule_id,artifact_kind,artifact,evidence,"
                           "triage,triage_note,triaged_at,engine,seen_run "
                           "FROM findings ORDER BY id")
        meta = db.rows(conn, "SELECT key,value FROM meta WHERE key IN ('webshell_hashes','profile') OR key LIKE 'engine_done:%' ORDER BY key")
    finally:
        conn.close()
    profile = workspace.case_info(case_dir).get("profile", {})
    common_revision = _digest([decisions, meta, profile])
    by_source, by_link, file_stats = {}, {}, {}
    for source in sources:
        by_source.setdefault(source["ioc_id"], []).append(source)
    for link in links:
        for key in (link["src_id"], link["dst_id"]):
            by_link.setdefault(key, []).append(link)
    revisions = {}
    for row in rows:
        provenance = by_source.get(row["id"], [])
        stats = []
        for source in provenance:
            artifact = source["artifact"]
            if artifact not in file_stats:
                try:
                    st = Path(io_path(artifact)).stat()
                    file_stats[artifact] = [st.st_size, st.st_mtime_ns, st.st_ctime_ns]
                except (OSError, ValueError):
                    file_stats[artifact] = None
            stats.append(file_stats[artifact])
        revisions[row["id"]] = _digest([row, provenance, stats, common_revision, by_link.get(row["id"], [])])
    return revisions


def _connectors(client):
    rows = client.connectors()
    return [{**row, "scope": row.get("scope", row.get("connector_scope", []))} for row in rows]


def _manual_only(client):
    automatic = [r["name"] for r in _connectors(client) if r.get("active") and r.get("auto")]
    if automatic:
        raise ValueError("Set internal enrichment connectors to manual before transferring data: " +
                         ", ".join(automatic))


def connection_test(root):
    client = OpenCTIClient(_config(root))
    result = client.test()
    connectors = _connectors(client)
    automatic = [c["name"] for c in connectors if c.get("active") and c.get("auto")]
    return {**result, "ok": True, "connectors": connectors,
            "warnings": (["Automatic enrichment must be disabled before transfer: " +
                          ", ".join(automatic)] if automatic else []),
            "capabilities": {"lookup": True, "manual_enrichment": True,
                "transfer": not automatic and result.get("collection", {}).get("can_write", True),
                "sample_uploads": settings.opencti_config(root)["sample_uploads"],
                "external_file_uploads": False}}


def state(root, case_dir):
    """No network requests and no implicit cache refresh on page load."""
    destination = _destination(settings.opencti_config(root))
    mapping_destination = _mapping_destination(settings.opencti_config(root))
    current = {r["id"]: r for r in _iocs(case_dir)}
    revisions = _revisions(case_dir)
    conn = db.connect(case_dir)
    try:
        stored = db.rows(conn, "SELECT * FROM opencti_lookups")
        exports = db.rows(conn, "SELECT * FROM opencti_exports ORDER BY created DESC")
        jobs = db.rows(conn, "SELECT * FROM jobs WHERE kind LIKE 'opencti-%' ORDER BY id DESC LIMIT 50")
        enrichment = db.rows(conn, "SELECT * FROM opencti_enrichments ORDER BY updated DESC")
    finally:
        conn.close()
    lookups = []
    for row in stored:
        ioc = current.get(row["ioc_id"])
        if not ioc or row["identity"] != _identity(ioc):
            continue
        payload = json.loads(row["payload"])
        payload["stale"] = bool(payload.get("stale")) or row["destination"] != destination or _age(row["checked_at"]) > CACHE_SECONDS
        lookups.append(payload)
    sync = {key: {"ioc_id": key, "status": "new"} for key in current}
    receipts = []
    # Apply oldest first so a later successful retry replaces an earlier error.
    for receipt in reversed(exports):
        payload = json.loads(receipt["payload"])
        receipts.append({k: receipt[k] for k in ("id", "state", "created", "updated", "error")})
        receipts[-1]["stats"] = {"objects": len(payload.get("objects", [])),
                                "batches": payload.get("batches", []),
                                "samples": payload.get("samples", [])}
        if payload.get("mapping_destination", receipt["destination"]) != mapping_destination:
            continue
        for ioc in payload.get("iocs", []):
            key = ioc["id"]
            if key not in sync or not ioc.get("selected"):
                continue
            if ioc.get("source_uid") and ioc["source_uid"] != current[key].get("source_uid"):
                continue
            local_revision = payload.get("revisions", {}).get(str(key))
            changed = local_revision != revisions.get(key)
            status = "changed" if changed else ("exported" if receipt["state"] == "complete" else
                     "error" if receipt["state"] in ("partial", "failed") else "new")
            sync[key] = {"ioc_id": key, "status": status, "error": receipt["error"]}
    for job in jobs:
        job["stats"] = json.loads(job.get("stats") or "{}")
    return {"lookups": lookups, "exports": list(reversed(receipts)),
            "sync": list(sync.values()), "jobs": jobs, "enrichments": [e for e in enrichment
                if e["ioc_id"] in current and e["identity"] == _identity(current[e["ioc_id"]])
                and e["destination"] == destination]}


def _store_lookup(case_dir, ioc, payload, destination):
    conn = db.connect(case_dir)
    try:
        current = db.one(conn, "SELECT * FROM iocs WHERE id=?", (ioc["id"],))
        if current and _identity(current) == _identity(ioc):
            conn.execute("INSERT OR REPLACE INTO opencti_lookups VALUES (?,?,?,?,?)",
                         (ioc["id"], _identity(ioc), payload["checked_at"], _json(payload), destination))
            conn.commit()
    finally:
        conn.close()


def _entity(entity):
    """Normalize metadata from the server adapter to the UI contract."""
    return {**entity, "type": entity.get("type", entity.get("entity_type", "")),
            "name": entity.get("observable_value") or entity.get("name") or entity.get("id", ""),
            "description": entity.get("description", entity.get("x_opencti_description", "")),
            "score": entity.get("score", entity.get("x_opencti_score")),
            "labels": entity.get("labels", []), "sources": entity.get("sources", entity.get("externalReferences", [])),
            "reports": entity.get("reports", []), "malware": entity.get("malware", []),
            "relationships": entity.get("relationships", [])}


def _mapped_ids(case_dir, config):
    conn = db.connect(case_dir)
    try:
        rows = db.rows(conn, "SELECT source_id,remote_id,standard_id,object_json FROM opencti_mappings WHERE destination=?",
                       (_mapping_destination(config),))
        imported = [row for row in rows if json.loads(row["object_json"]).get("_shellhound_origin") == "imported"]
        return {row[key] for row in imported for key in ("source_id", "remote_id", "standard_id") if row[key]}
    finally:
        conn.close()


def _only_own(entities, owned_ids=()):
    # A bare matching export is not independent corroboration. Every visible
    # author/report/source must be ours before claiming 'own exports only'.
    def ours(value):
        if isinstance(value, dict):
            value = value.get("name", value.get("source_name", ""))
        return str(value).lower() == "shellhound" or str(value).endswith("— Shellhound report")
    for entity in entities:
        if entity.get("relationships_truncated") or entity.get("context_truncated"):
            return False
        author = entity.get("createdBy") or {}
        mapped = entity.get("id") in owned_ids or entity.get("standard_id") in owned_ids
        if (author and not ours(author)) or (not author and not mapped):
            return False
        if any(not ours(s) for s in entity.get("externalReferences", [])):
            return False
        if any(not ours(s) for s in entity.get("sources", [])):
            return False
        if any(not ours(r) for r in entity.get("reports", [])):
            return False
        if entity.get("relationships") or entity.get("malware"):
            # Classify conservatively unless all relationship origins are explicit.
            if any(not ours(r.get("createdBy", {})) for r in entity.get("relationships", [])):
                return False
            if any(not ours(m.get("createdBy", {})) for m in entity.get("malware", []) if isinstance(m, dict)):
                return False
    return bool(entities)


def lookup(root, case_dir, ioc_ids=None):
    config = _config(root)
    rows = _iocs(case_dir, ioc_ids)
    def run(ctx):
        client = OpenCTIClient(config)
        owned_ids = _mapped_ids(case_dir, config)
        errors = 0
        checked = 0
        for index, ioc in enumerate(rows):
            if ctx.cancelled():
                break
            payload = {"ioc_id": ioc["id"], "checked_at": db.now(), "stale": False, "entities": [], "error": ""}
            try:
                if ioc["type"] in ("path", "user", "other"):
                    payload["status"] = "unsupported"
                else:
                    entities = client.lookup(ioc["type"], ioc["value"])
                    payload["entities"] = [_entity(e) for e in entities]
                    payload["status"] = "own" if _only_own(entities, owned_ids) else ("known" if entities else "unknown")
            except Exception as exc:
                errors += 1
                payload.update(status="error", error=_error(exc))
                # Preserve historical knowledge even when refreshing it fails.
                conn = db.connect(case_dir)
                try:
                    old = db.one(conn, "SELECT * FROM opencti_lookups WHERE ioc_id=?", (ioc["id"],))
                finally:
                    conn.close()
                if old and old["identity"] == _identity(ioc) and old["destination"] == _destination(config):
                    previous = json.loads(old["payload"])
                    payload["entities"] = previous.get("entities", [])
                    payload["checked_at"] = previous["checked_at"]
                    payload["stale"] = True
            _store_lookup(case_dir, ioc, payload, _destination(config))
            checked += 1
            ctx.progress((index + 1) / max(1, len(rows)), f"Checked {index + 1} of {len(rows)} IOCs")
        return {"checked": checked, "errors": errors}
    return {"job_id": manager.submit(case_dir, "opencti-lookup", run)}


def _error(exc):
    # Adapter errors are sanitized. Unexpected exception text can contain
    # workstation paths or HTTP bodies, so expose only its class.
    if isinstance(exc, ValueError) or exc.__class__.__name__ in ("OpenCTIError", "OpenCTIClientError"):
        return str(exc)
    return "OpenCTI operation failed (" + type(exc).__name__ + ")."


def preview(root, case_dir, options=None):
    options = dict(options or {})
    result = graph.build_preview(case_dir, options)
    result["graph_fingerprint"] = result["fingerprint"]
    config = settings.opencti_config(root)
    if any(s["selected"] for s in result["samples"]) and not config["sample_uploads"]:
        result["errors"].append("Enable optional sample uploads in OpenCTI settings before selecting files.")
    # Existing own assertions missing from the current full graph are presented
    # as withdrawals. Merely excluding an IOC in this export is not withdrawal.
    conn = db.connect(case_dir)
    try:
        old = db.rows(conn, "SELECT object_json FROM opencti_mappings WHERE destination=?", (_mapping_destination(config),))
    finally:
        conn.close()
    previous = [json.loads(r["object_json"]) for r in old]
    result["mapping_revision"] = _digest(sorted([graph._stable(o) for o in previous], key=lambda o: o["id"]))
    result["mapping_destination"] = _mapping_destination(config)
    if previous:
        result["objects"] = graph.reactivate_objects(previous, result["objects"])
        remap = {o["x_shellhound_original_id"]: o["id"] for o in result["objects"] if o.get("x_shellhound_original_id")}
        for row in result["iocs"]:
            row["object_ids"] = [remap.get(key, key) for key in row["object_ids"]]
        # Disclosure exclusions are not a retraction. Compare against every
        # still-supported assertion, including earlier optional Indicators.
        full_options = {"ioc_ids": None, "include_notes": True, "include_evidence": True,
                        "indicator_ids": [r["id"] for r in result["iocs"] if r["indicator_supported"]]}
        full = graph.build_preview(case_dir, full_options)
        full_objects = graph.reactivate_objects(previous, full["objects"])
        withdrawals = graph.withdrawal_objects(previous, full_objects, result["case_reference"])
        result["objects"].extend(withdrawals)
        for report in result["objects"]:
            if report["type"] == "report":
                report["object_refs"] = list(dict.fromkeys(report["object_refs"] + [o["id"] for o in withdrawals]))
        if withdrawals:
            result["warnings"].append("Previously exported case assertions are withdrawn in this transfer. Review the generated objects.")
    result["fingerprint"] = _digest(graph._stable({k: v for k, v in result.items() if k != "fingerprint"}))
    preview_id = str(uuid.uuid4())
    result["preview_id"] = preview_id
    stored = {**result, "revisions": _revisions(case_dir)}
    conn = db.connect(case_dir)
    try:
        conn.execute("INSERT INTO opencti_previews VALUES (?,?,?,?,?,?)",
                     (preview_id, db.now(), result["graph_fingerprint"], _json(options), _json(stored), _destination(config)))
        conn.commit()
    finally:
        conn.close()
    return result


def _save_export(case_dir, receipt, payload, state=None, error=""):
    conn = db.connect(case_dir)
    try:
        conn.execute("UPDATE opencti_exports SET state=?,updated=?,error=?,payload=? WHERE id=?",
                     (state or receipt["state"], db.now(), error, _json(payload), receipt["id"]))
        conn.commit()
    finally:
        conn.close()
    if state:
        receipt["state"] = state


def _wait_taxii(client, work_id, ctx):
    status = None
    for _ in range(POLL_LIMIT):
        if ctx.cancelled():
            return None
        status = client.taxii_status(work_id)
        if status.get("status") == "complete":
            return status
        ctx.cancel_event.wait(POLL_SECONDS)
    return status


def _mapping(case_dir, obj, remote, destination, *, reused=False):
    conn = db.connect(case_dir)
    try:
        stored = obj
        if not obj.get("x_shellhound_case_reference"):
            # Existing shared content is not proof of Shellhound authorship.
            # Preserve proven imports across later reuse and token rotation;
            # older unlabelled mappings remain conservatively unproven.
            prior = db.one(conn, "SELECT object_json FROM opencti_mappings WHERE source_id=? AND destination=?",
                           (obj["id"], destination))
            imported = not reused or (prior and json.loads(prior["object_json"]).get("_shellhound_origin") == "imported")
            stored = {**obj, "_shellhound_origin": "imported" if imported else "reused"}
        conn.execute("INSERT OR REPLACE INTO opencti_mappings VALUES (?,?,?,?,?,?,?)",
                     (obj["id"], remote.get("id", ""), remote.get("standard_id", ""),
                      _digest(graph._stable(obj)), _json(stored), db.now(), destination))
        conn.commit()
    finally:
        conn.close()


def _prepare_shared(client, case_dir, receipt, payload):
    """Reuse exact shared entities without resubmitting their mutable fields.

    Keep the reviewed graph in the receipt. The wire graph only rewrites
    references and omits matched shared objects; it never imports our author,
    timestamps or marking onto somebody else's observable/CVE/identity.
    """
    if payload.get("preflight_complete"):
        return
    case_types = {"incident", "report", "note", "indicator", "relationship", "malware"}
    reused = {}
    for obj in payload["objects"]:
        if obj["type"] in case_types and obj.get("x_shellhound_case_reference") == payload["case_reference"]:
            continue
        existing = client.find_existing_shared(obj)
        if existing:
            if not existing.get("id") or not existing.get("standard_id"):
                raise ValueError("A shared OpenCTI match has no stable identity; transfer was not started.")
            reused[obj["id"]] = {"id": existing["id"], "standard_id": existing["standard_id"]}
            _mapping(case_dir, obj, existing, payload["mapping_destination"], reused=True)
    remap = {source: remote["standard_id"] for source, remote in reused.items()}

    def rewrite(value, key=""):
        if isinstance(value, dict):
            return {name: rewrite(item, name) for name, item in value.items()}
        if isinstance(value, list):
            return [rewrite(item, key) for item in value]
        if isinstance(value, str) and (key.endswith("_ref") or key.endswith("_refs")):
            return remap.get(value, value)
        return value

    wire = [rewrite(obj) for obj in payload["objects"] if obj["id"] not in reused]
    payload["reused_shared"] = reused
    payload["wire_objects"] = wire
    payload["batches"] = [{"ids": [o["id"] for o in wire[index:index + 100]], "state": "new", "work_id": ""}
                          for index in range(0, len(wire), 100)]
    payload["preflight_complete"] = True
    _save_export(case_dir, receipt, payload)


def _queue_export(root, case_dir, receipt):
    config = _config(root)
    key = (str(case_dir), receipt["id"])
    with _LOCK:
        if key in _ACTIVE:
            raise ValueError("This transfer already has a running job.")
        _ACTIVE.add(key)
    def release():
        with _LOCK:
            _ACTIVE.discard(key)
    def cancelled_before_start():
        try:
            _save_export(case_dir, receipt, json.loads(receipt["payload"]), "paused",
                         "Transfer cancelled before starting; resume the saved receipt when ready.")
        finally:
            release()
    def run(ctx):
        payload = json.loads(receipt["payload"])
        try:
            client = OpenCTIClient(config)
            if _destination(settings.opencti_config(root)) != receipt["destination"]:
                raise ValueError("OpenCTI connection changed; create a new preview.")
            if payload.get("revisions") != {str(k): v for k, v in _revisions(case_dir).items()}:
                raise ValueError("Case data changed while transfer was queued; create a fresh preview.")
            _manual_only(client)
            _save_export(case_dir, receipt, payload, "running")
            _prepare_shared(client, case_dir, receipt, payload)
            reviewed_objects = {o["id"]: o for o in payload["objects"]}
            objects = {o["id"]: o for o in payload["wire_objects"]}
            for index, batch in enumerate(payload["batches"]):
                if ctx.cancelled():
                    _save_export(case_dir, receipt, payload, "paused", "Transfer paused; completed work is retained.")
                    return {"export_id": receipt["id"], "state": "paused"}
                if batch["state"] == "complete":
                    continue
                batch_objects = [objects[key] for key in batch["ids"]]
                if not batch.get("work_id"):
                    batch["state"] = "submitting"
                    _save_export(case_dir, receipt, payload)
                    response = client.push(batch_objects)
                    batch["work_id"] = response.get("id", "")
                    if not batch["work_id"]:
                        raise ValueError("TAXII accepted no trackable work ID; completion could not be verified.")
                    batch["state"] = "pending"
                    _save_export(case_dir, receipt, payload)
                status = _wait_taxii(client, batch["work_id"], ctx)
                batch["status"] = status or {}
                if not status or status.get("status") != "complete":
                    state = "paused" if ctx.cancelled() else "pending"
                    _save_export(case_dir, receipt, payload, state, "Import is still pending. Resume to check the existing work.")
                    return {"export_id": receipt["id"], "state": state}
                if status.get("failure_count", 0):
                    batch["state"] = "failed"
                    failures = status.get("failures", [])
                    failed_ids = {f.get("id") for f in failures if isinstance(f, dict)}
                    batch["failed_ids"] = sorted(failed_ids & set(batch["ids"]))
                    batch["completed_ids"] = []
                    if batch["failed_ids"]:
                        for obj in batch_objects:
                            if obj["id"] in failed_ids:
                                continue
                            remote = client.resolve(obj["id"])
                            if remote:
                                _mapping(case_dir, reviewed_objects[obj["id"]], remote, payload["mapping_destination"])
                                batch["completed_ids"].append(obj["id"])
                    raise ValueError(f"TAXII import failed for {status['failure_count']} object(s). Review the transfer receipt and retry.")
                if int(status.get("pending_count", 0)):
                    raise ValueError("TAXII still reports pending objects; the transfer is not complete.")
                batch["state"] = "verifying"
                # Completion requires visible imported objects, not merely HTTP 202.
                for source_id in batch.get("verify_ids", batch["ids"]):
                    obj = objects[source_id]
                    remote = client.resolve(obj["id"])
                    if not remote:
                        batch["state"] = "unverified"
                        raise ValueError("Import finished but an object is not visible to the integration account. Check markings and access rights.")
                    _mapping(case_dir, reviewed_objects[obj["id"]], remote, payload["mapping_destination"])
                batch["state"] = "complete"
                _save_export(case_dir, receipt, payload)
                ctx.progress((index + 1) / (len(payload["batches"]) + 1), "Importing reviewed objects")
            for sample in payload["samples"]:
                if sample.get("state") == "complete":
                    continue
                if ctx.cancelled():
                    _save_export(case_dir, receipt, payload, "paused")
                    return {"state": "paused"}
                if not settings.opencti_config(root)["sample_uploads"]:
                    raise ValueError("Sample uploads were disabled. Metadata is retained; the sample has not been sent.")
                verified = graph.resolve_sample(case_dir, sample["id"], sample["sha256"])
                # Stable binary artifact identity and saved receipt survive retries.
                artifact_id = "artifact--" + str(uuid.uuid5(uuid.NAMESPACE_URL, "shellhound:sample:" + sample["sha256"]))
                if not sample.get("remote_id"):
                    result = client.upload_sample(verified["filename"], verified["content"],
                         payload["marking_id"], source_id=artifact_id)
                    sample["remote_id"] = result["id"]
                    sample["state"] = "uploaded"
                    _save_export(case_dir, receipt, payload)
                remote_file_id = payload.get("reused_shared", {}).get(sample["file_id"], {}).get("standard_id", sample["file_id"])
                remote_file = client.resolve(remote_file_id)
                report = client.resolve(payload["report_id"])
                if not remote_file or not report:
                    raise ValueError("Sample uploaded but file/report is not yet visible; resume to finish the links.")
                client.link_sample(remote_file["id"], sample["remote_id"], report["id"])
                sample["state"] = "complete"
                _save_export(case_dir, receipt, payload)
            _save_export(case_dir, receipt, payload, "complete")
            return {"export_id": receipt["id"], "objects": len(objects), "state": "complete"}
        except Exception as exc:
            _save_export(case_dir, receipt, payload, "partial" if any(b["state"] == "complete" or b.get("completed_ids") for b in payload["batches"]) else "failed", _error(exc))
            raise ValueError(_error(exc)) from None
        finally:
            release()
    try:
        job_id = manager.submit(case_dir, "opencti-export", run, on_cancel=cancelled_before_start)
    except Exception:
        release()
        raise
    return {"job_id": job_id, "export_id": receipt["id"]}


def transfer(root, case_dir, preview_id):
    config = _config(root)
    with workspace._CASE_LOCK:
        conn = db.connect(case_dir)
        try:
            preview_row = db.one(conn, "SELECT * FROM opencti_previews WHERE id=?", (preview_id,))
        finally:
            conn.close()
        if not preview_row or _age(preview_row["created"]) > PREVIEW_SECONDS:
            raise ValueError("The export preview expired. Review a fresh preview before transfer.")
        if preview_row["destination"] != _destination(config):
            raise ValueError("OpenCTI connection changed. Review a new export preview.")
        payload = json.loads(preview_row["payload"])
        options = json.loads(preview_row["options"])
        if payload["errors"]:
            raise ValueError("Resolve the problems shown in the export preview first.")
        fresh = graph.build_preview(case_dir, options)
        if fresh["fingerprint"] != preview_row["fingerprint"]:
            raise ValueError("Case data or a file changed after preview. Review the updated export first.")
        conn = db.connect(case_dir)
        try:
            mappings = db.rows(conn, "SELECT object_json FROM opencti_mappings WHERE destination=?", (_mapping_destination(config),))
        finally:
            conn.close()
        mapping_revision = _digest(sorted([graph._stable(json.loads(r["object_json"])) for r in mappings], key=lambda o: o["id"]))
        if mapping_revision != payload.get("mapping_revision"):
            raise ValueError("A previous transfer changed OpenCTI mappings. Review a fresh export preview.")
        if payload.get("revisions") != {str(k): v for k, v in _revisions(case_dir).items()}:
            raise ValueError("Case data changed after preview. Review the updated export first.")
        reference = workspace.case_info(case_dir)["reference"]
        payload["options"] = options
        payload["samples"] = [{**s, "state": "new"} for s in payload["samples"] if s["selected"]]
        profile = workspace.case_info(case_dir)["profile"]
        payload["marking_id"] = graph.MARKINGS[profile["marking"]]
        payload["batches"] = [{"ids": [o["id"] for o in payload["objects"][i:i+100]], "state": "new", "work_id": ""}
                              for i in range(0, len(payload["objects"]), 100)]
        receipt = {"id": str(uuid.uuid4()), "state": "queued", "created": db.now(),
                   "updated": db.now(), "error": "", "payload": _json(payload), "destination": _destination(config)}
        conn = db.connect(case_dir)
        try:
            conn.execute("INSERT INTO meta(key,value) VALUES('opencti_case_reference',?) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (reference,))
            conn.execute("INSERT INTO opencti_exports VALUES (?,?,?,?,?,?,?)", tuple(receipt.values()))
            conn.execute("DELETE FROM opencti_previews WHERE id=?", (preview_id,))
            conn.commit()
        finally:
            conn.close()
    return _queue_export(root, case_dir, receipt)


def retry(root, case_dir, export_id):
    config = _config(root)
    conn = db.connect(case_dir)
    try:
        receipt = db.one(conn, "SELECT * FROM opencti_exports WHERE id=?", (export_id,))
    finally:
        conn.close()
    if not receipt:
        raise ValueError("Unknown OpenCTI transfer.")
    if receipt["destination"] != _destination(config):
        raise ValueError("This transfer belongs to a different OpenCTI connection.")
    if receipt["state"] == "complete":
        raise ValueError("This transfer is already complete.")
    payload = json.loads(receipt["payload"])
    fresh = graph.build_preview(case_dir, payload["options"])
    if fresh["fingerprint"] != payload.get("graph_fingerprint", payload["fingerprint"]):
        raise ValueError("Case data changed. Create a new preview instead of replaying stale assertions.")
    for batch in payload["batches"]:
        if batch["state"] == "failed":
            if batch.get("failed_ids"):
                # A successful TAXII count does not prove that the account can
                # see the other objects. Retain their verification obligation
                # while resubmitting only the explicitly failed identities.
                batch.setdefault("verify_ids", list(batch["ids"]))
                batch["ids"] = batch["failed_ids"]
            batch.update(state="new", work_id="")
    receipt["payload"] = _json(payload)
    _save_export(case_dir, receipt, payload, "queued")
    return _queue_export(root, case_dir, receipt)


def enrichment_preview(root, case_dir, ioc_ids=None):
    client = OpenCTIClient(_config(root))
    rows = _iocs(case_dir, ioc_ids)
    entities = []
    warnings = []
    for row in rows:
        if row["type"] in ("path", "user", "other"):
            warnings.append(f"IOC {row['id']} is contextual and has no external enrichment target.")
            continue
        matches = client.lookup(row["type"], row["value"])
        entities.append({"ioc_id": row["id"], "id": matches[0]["id"] if matches else None,
                         "value": row["value"], "type": row["type"], "requires_creation": not matches})
    types = {_ioc_entity_type(row) for row in rows if row["type"] not in ("path", "user", "other")}
    connectors = [c for c in _connectors(client) if c.get("active") and not c.get("auto")
                  and any(_scope_matches(c, kind) for kind in types)]
    if any(e["requires_creation"] for e in entities):
        warnings.append("Unknown IOCs require creating marked observables before the selected connectors can run.")
    return {"entities": entities, "connectors": connectors, "warnings": warnings}


def _ioc_entity_type(row):
    return {"ip": "IPv6-Addr" if ":" in row["value"] else "IPv4-Addr", "hash": "StixFile",
            "domain": "Domain-Name", "url": "Url", "email": "Email-Addr"}.get(row["type"], "")


def _scope_matches(connector, entity_type):
    scope = {str(value).lower() for value in connector.get("scope", [])}
    return bool(entity_type) and entity_type.lower() != "artifact" and (
        entity_type.lower() in scope or "stix-cyber-observable" in scope)


def _poll_enrichment(client, case_dir, entry, ctx):
    status = entry.get("state", "pending")
    for _ in range(POLL_LIMIT):
        if ctx.cancelled():
            break
        work = client.work(entry["work_id"])
        error = "Connector reported an error." if work.get("errors") else ""
        status = "failed" if error else work.get("status", "pending")
        conn = db.connect(case_dir)
        try:
            conn.execute("UPDATE opencti_enrichments SET state=?,updated=?,error=? WHERE id=?",
                         (status, db.now(), error, entry["id"]))
            conn.commit()
        finally:
            conn.close()
        if status in ("complete", "completed", "error", "failed"):
            break
        ctx.cancel_event.wait(POLL_SECONDS)
    return status


def _refresh_lookup(client, case_dir, row, config):
    entities = client.lookup(row["type"], row["value"])
    payload = {"ioc_id": row["id"], "checked_at": db.now(), "stale": False,
               "entities": [_entity(e) for e in entities],
               "status": "own" if _only_own(entities, _mapped_ids(case_dir, config)) else ("known" if entities else "unknown"), "error": ""}
    _store_lookup(case_dir, row, payload, _destination(config))


def refresh_enrichment(root, case_dir):
    """Explicitly refresh saved work IDs; never ask a connector to run again."""
    config = _config(root)
    conn = db.connect(case_dir)
    try:
        entries = db.rows(conn, "SELECT * FROM opencti_enrichments WHERE destination=? "
                         "AND state NOT IN ('complete','completed','error','failed') ORDER BY updated",
                         (_destination(config),))
    finally:
        conn.close()
    current = {row["id"]: row for row in _iocs(case_dir)}
    entries = [entry for entry in entries if entry["ioc_id"] in current
               and _identity(current[entry["ioc_id"]]) == entry["identity"]]
    def run(ctx):
        client = OpenCTIClient(config)
        checked, errors = 0, 0
        for entry in entries:
            if ctx.cancelled():
                break
            try:
                status = _poll_enrichment(client, case_dir, entry, ctx)
                checked += 1
                if status in ("complete", "completed"):
                    _refresh_lookup(client, case_dir, current[entry["ioc_id"]], config)
            except Exception as exc:
                errors += 1
                conn = db.connect(case_dir)
                try:
                    # Keep it pending so a later explicit status check can
                    # recover a transient connection failure without rerunning.
                    conn.execute("UPDATE opencti_enrichments SET updated=?,error=? WHERE id=?",
                                 (db.now(), _error(exc), entry["id"]))
                    conn.commit()
                finally:
                    conn.close()
        return {"checked": checked, "errors": errors}
    return {"job_id": manager.submit(case_dir, "opencti-enrichment-status", run)}


def enrich(root, case_dir, ioc_ids, connector_ids, create_missing=False):
    config = _config(root)
    rows = _iocs(case_dir, ioc_ids)
    if not connector_ids:
        raise ValueError("Select at least one matching enrichment connector.")
    def run(ctx):
        client = OpenCTIClient(config)
        connectors = {c["id"]: c for c in _connectors(client) if c.get("active") and not c.get("auto")}
        if set(connector_ids) - set(connectors):
            raise ValueError("A selected enrichment connector is unavailable.")
        count = 0
        for row in rows:
            if ctx.cancelled():
                break
            if row["type"] in ("path", "user", "other"):
                continue
            if not any(_scope_matches(connectors[key], _ioc_entity_type(row)) for key in connector_ids):
                continue
            matches = client.lookup(row["type"], row["value"])
            if not matches:
                if not create_missing:
                    raise ValueError("An unknown IOC requires explicit permission to create an observable. Review enrichment again.")
                _manual_only(client)
                marking = graph.MARKINGS[workspace.case_info(case_dir)["profile"]["marking"]]
                matches = [client.create_observable(row["type"], row["value"], marking)]
            for entity in matches:
                entity_type = entity.get("entity_type", entity.get("type", ""))
                if entity_type == "Artifact":
                    continue
                for connector_id in connector_ids:
                    connector = connectors[connector_id]
                    if not _scope_matches(connector, entity_type):
                        continue
                    result = client.enrich(entity["id"], connector_id)
                    work_id = result.get("id")
                    if not work_id:
                        raise ValueError("The enrichment connector returned no trackable work ID.")
                    entry_id = str(uuid.uuid4())
                    conn = db.connect(case_dir)
                    try:
                        conn.execute("INSERT INTO opencti_enrichments VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (entry_id, row["id"], _identity(row), entity["id"], connector_id, work_id,
                             "pending", db.now(), "", _destination(config)))
                        conn.commit()
                    finally:
                        conn.close()
                    count += 1
                    _poll_enrichment(client, case_dir, {"id": entry_id, "work_id": work_id}, ctx)
                    _refresh_lookup(client, case_dir, row, config)
        if not count:
            raise ValueError("None of the selected connectors supports these IOCs.")
        return {"requested": count}
    return {"job_id": manager.submit(case_dir, "opencti-enrichment", run)}
