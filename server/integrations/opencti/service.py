"""Explicit OpenCTI operations with durable receipts and local, offline reads.

A preview is an immutable, destination-bound authorization snapshot. Queue
acceptance is recorded separately from completed imports. Workers resume the
same receipt instead of inventing a new case or repeating completed imports.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import hashlib
import json
import threading
import time
import uuid
from datetime import datetime, timezone

from server import db
from server.ioc import model as ioc_model
from server.integrations.opencti import graph
from server import settings, workspace
from server.jobs import manager
from server.integrations.opencti.client import OpenCTIClient

_LOCK = threading.RLock()
_ACTIVE = set()
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
    conn = db.connect(case_dir)
    try:
        rows = ioc_model.enrich_rows(conn, db.rows(conn, "SELECT * FROM iocs ORDER BY id"))
    finally:
        conn.close()
    profile = workspace.case_info(case_dir)
    return {"profile": _digest([profile.get("reference"), profile.get("profile")]),
            **{str(row["id"]): _digest(row) for row in rows if row["type"] in graph.IOC_TYPES}}


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
    _manual_only(client)
    return {**result, "ok": True}


def state(root, case_dir):
    """Read transfer receipts locally, without lookups or enrichment."""
    destination = _mapping_destination(settings.opencti_config(root))
    current = {row["id"]: row for row in _iocs(case_dir) if row["type"] in graph.IOC_TYPES}
    revisions = _revisions(case_dir)
    conn = db.connect(case_dir)
    try:
        exports = db.rows(conn, "SELECT * FROM opencti_exports ORDER BY created DESC")
        jobs = db.rows(conn, "SELECT * FROM jobs WHERE kind='opencti-export' ORDER BY id DESC LIMIT 50")
    finally:
        conn.close()
    sync = {key: {"ioc_id": key, "status": "new"} for key in current}
    receipts = []
    for receipt in reversed(exports):
        payload = json.loads(receipt["payload"])
        receipts.append({key: receipt[key] for key in ("id", "state", "created", "updated", "error")})
        receipts[-1]["stats"] = {"objects": len(payload.get("objects", [])), "batches": payload.get("batches", [])}
        if payload.get("mapping_destination", receipt["destination"]) != destination:
            continue
        for row in payload.get("iocs", []):
            key = row["id"]
            if key not in current or not row.get("selected") or row.get("source_uid") != current[key].get("source_uid"):
                continue
            changed = payload.get("revisions", {}).get(str(key)) != revisions.get(str(key))
            status = "changed" if changed else "exported" if receipt["state"] == "complete" else "error" if receipt["state"] in ("partial", "failed") else "new"
            sync[key] = {"ioc_id": key, "status": status, "error": receipt["error"]}
    for job in jobs:
        job["stats"] = json.loads(job.get("stats") or "{}")
    return {"exports": list(reversed(receipts)), "sync": list(sync.values()), "jobs": jobs}


def _error(exc):
    # Adapter errors are sanitized. Unexpected exception text can contain
    # workstation paths or HTTP bodies, so expose only its class.
    if isinstance(exc, ValueError) or exc.__class__.__name__ in ("OpenCTIError", "OpenCTIClientError"):
        return str(exc)
    return "OpenCTI operation failed (" + type(exc).__name__ + ")."


@workspace._serialized
def preview(root, case_dir, options=None):
    conn = db.connect(case_dir)
    conn.close()
    options = options or {}
    result = graph.build_preview(case_dir, options)
    result["graph_fingerprint"] = result["fingerprint"]
    config = settings.opencti_config(root)
    conn = db.connect(case_dir)
    try:
        previous = db.rows(conn, "SELECT object_json FROM opencti_mappings WHERE destination=?", (_mapping_destination(config),))
        result["mapping_revision"] = _digest(sorted([graph._stable(json.loads(row["object_json"])) for row in previous], key=lambda obj: obj["id"]))
        result["mapping_destination"] = _mapping_destination(config)
        result["preview_id"] = str(uuid.uuid4())
        stored = {**result, "revisions": _revisions(case_dir)}
        conn.execute("INSERT INTO opencti_previews VALUES (?,?,?,?,?,?)",
                     (result["preview_id"], db.now(), result["graph_fingerprint"], _json(options), _json(stored), _destination(config)))
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


def _mapping(case_dir, obj, remote, destination, *, reused=False, conn=None):
    if conn is None:
        owned = db.connect(case_dir)
        try:
            _mapping(case_dir, obj, remote, destination, reused=reused, conn=owned)
            owned.commit()
        finally:
            owned.close()
        return
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


def _prepare_shared(client, case_dir, receipt, payload, *, lookup=None, ctx=None):
    """Reuse exact shared entities without resubmitting their mutable fields.

    Keep the reviewed graph in the receipt. The wire graph only rewrites
    references and omits matched shared objects; it never imports our author,
    timestamps or marking onto somebody else's observable/CVE/identity.
    """
    if payload.get("preflight_complete"):
        return
    case_types = {"incident", "x-opencti-case-incident", "relationship"}
    reused = {}
    candidates = [obj for obj in payload["objects"]
                  if not (obj["type"] in case_types and obj.get("x_shellhound_case_reference") == payload["case_reference"])]
    # Only independent reads run concurrently; bounded chunks avoid queuing an
    # entire export after cancellation. Each worker owns its HTTP client.
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="opencti-preflight") as pool:
        for offset in range(0, len(candidates), 4):
            if ctx and ctx.cancelled():
                return
            chunk = candidates[offset:offset + 4]
            for obj, existing in zip(chunk, pool.map(lookup or client.find_existing_shared, chunk)):
                if existing:
                    if not existing.get("id") or not existing.get("standard_id"):
                        raise ValueError("A shared OpenCTI match has no stable identity; transfer was not started.")
                    reused[obj["id"]] = {"id": existing["id"], "standard_id": existing["standard_id"]}
                    _mapping(case_dir, obj, existing, payload["mapping_destination"], reused=True)
            if ctx:
                ctx.progress((offset + len(chunk)) / max(1, len(candidates)), "Checking existing objects")
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
            if payload.get("model_version", 0) != 4 or payload.get("samples"):
                raise ValueError("This saved transfer uses retired OpenCTI features. Create a fresh preview before transferring.")
            client = OpenCTIClient(config)
            if _destination(settings.opencti_config(root)) != receipt["destination"]:
                raise ValueError("OpenCTI connection changed; create a new preview.")
            if payload.get("revisions") != {str(k): v for k, v in _revisions(case_dir).items()}:
                raise ValueError("Case data changed while transfer was queued; create a fresh preview.")
            _manual_only(client)
            _save_export(case_dir, receipt, payload, "running")
            worker_clients = threading.local()
            def lookup(obj):
                if not hasattr(worker_clients, "client"):
                    worker_clients.client = OpenCTIClient(config)
                return worker_clients.client.find_existing_shared(obj)
            phase_started = time.monotonic()
            _prepare_shared(client, case_dir, receipt, payload, lookup=lookup, ctx=ctx)
            payload.setdefault("timings", {})["preflight_seconds"] = round(time.monotonic() - phase_started, 3)
            if ctx.cancelled():
                _save_export(case_dir, receipt, payload, "paused")
                return {"export_id": receipt["id"], "state": "paused"}
            phase_started = time.monotonic()
            reviewed_objects = {o["id"]: o for o in payload["objects"]}
            objects = {o["id"]: o for o in payload["wire_objects"]}
            for index, batch in enumerate(payload["batches"]):
                if ctx.cancelled():
                    _save_export(case_dir, receipt, payload, "paused", "Transfer paused; completed work is retained.")
                    return {"export_id": receipt["id"], "state": "paused"}
                if batch["state"] == "complete":
                    continue
                ctx.progress(index / (len(payload["batches"]) + 1), "Importing reviewed objects")
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
                ctx.progress(index / (len(payload["batches"]) + 1), "Verifying imported objects")
                verify_ids = batch.get("verify_ids", batch["ids"])
                verified = client.resolve_many(verify_ids)
                mapping_conn = db.connect(case_dir)
                try:
                    for source_id in verify_ids:
                        obj = objects[source_id]
                        remote = verified.get(source_id)
                        if not remote:
                            batch["state"] = "unverified"
                            raise ValueError("Import finished but an object is not visible to the integration account. Check markings and access rights.")
                        _mapping(case_dir, reviewed_objects[obj["id"]], remote, payload["mapping_destination"], conn=mapping_conn)
                    mapping_conn.commit()
                finally:
                    mapping_conn.close()
                batch["state"] = "complete"
                _save_export(case_dir, receipt, payload)
                ctx.progress((index + 1) / (len(payload["batches"]) + 1), "Importing reviewed objects")
            conn = db.connect(case_dir)
            try:
                mapped = {row['source_id']: row['remote_id'] for row in db.rows(conn,
                    'SELECT source_id,remote_id FROM opencti_mappings WHERE destination=?', (payload['mapping_destination'],))}
            finally:
                conn.close()
            for obj in payload['objects']:
                if obj['type'] in ('ipv4-addr', 'ipv6-addr') and obj.get('labels'):
                    if ctx.cancelled():
                        _save_export(case_dir, receipt, payload, 'paused')
                        return {'export_id': receipt['id'], 'state': 'paused'}
                    client.add_ip_labels(mapped[obj['id']], obj['labels'])
            payload["timings"]["import_verify_seconds"] = round(time.monotonic() - phase_started, 3)
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
        if payload.get("model_version") != 4:
            raise ValueError("Create a fresh export preview before transferring.")
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
    if payload.get("model_version") != 4:
        raise ValueError("Create a fresh preview instead of retrying a legacy transfer.")
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
