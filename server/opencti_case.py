"""Case-local state and evidence preparation for the OpenCTI adapter."""
from __future__ import annotations

import hashlib
import json
import mimetypes
import os
from pathlib import Path

from server import db
from server import opencti


class CaseOpenCtiError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def json_load(value, fallback):
    try:
        result = json.loads(value or "")
    except (TypeError, ValueError):
        return fallback
    return result if isinstance(result, type(fallback)) else fallback


def safe_file(conn, raw_path: str) -> Path:
    """Resolve one regular file inside the registered Evidence fence."""
    value = str(raw_path or "").strip()
    if not value:
        raise CaseOpenCtiError("file_missing", "No evidence file was selected")
    candidate = Path(value)
    if not candidate.is_absolute():
        absolute = db.absolute_from_evidence(db.evidence_roots(conn), value)
        if not absolute:
            raise CaseOpenCtiError("file_missing", "Evidence file no longer exists")
        candidate = Path(absolute)
    try:
        target = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise CaseOpenCtiError("file_missing", "Evidence file no longer exists") from exc
    if not target.is_file():
        raise CaseOpenCtiError("not_regular", "Selected evidence is not a regular file")
    for root in db.evidence_roots(conn):
        try:
            root_path = Path(root).resolve(strict=True)
            target.relative_to(root_path)
            return target
        except (OSError, RuntimeError, ValueError):
            continue
    raise CaseOpenCtiError("outside_evidence", "File is outside registered evidence")


def file_hashes(path: Path) -> dict:
    digests = {"MD5": hashlib.md5(usedforsecurity=False), "SHA-1": hashlib.sha1(),
               "SHA-256": hashlib.sha256()}
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def file_snapshot(conn, raw_path: str, local_ref: str, indicator=False) -> dict:
    path = safe_file(conn, raw_path)
    before = path.stat()
    hashes = file_hashes(path)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise CaseOpenCtiError("file_changed", "Evidence file changed while it was hashed")
    created = before.st_ctime if os.name == "nt" else getattr(before, "st_birthtime", None)
    def stamp(value):
        if value is None:
            return None
        from datetime import datetime, timezone
        return datetime.fromtimestamp(value, timezone.utc).isoformat(
            timespec="seconds").replace("+00:00", "Z")
    return {
        "kind": "file", "local_ref": local_ref, "path": str(path),
        "relative_path": db.case_relative_path(conn, str(path)), "name": path.name,
        "size": before.st_size, "hashes": hashes,
        "mime_type": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
        "created_at": stamp(created), "modified_at": stamp(before.st_mtime),
        "accessed_at": stamp(before.st_atime), "indicator": bool(indicator),
        "device": str(before.st_dev), "inode": str(before.st_ino),
        "mtime_ns": str(before.st_mtime_ns),
    }


def get_draft(conn) -> dict:
    row = conn.execute("SELECT updated_at, payload FROM opencti_draft WHERE id=1").fetchone()
    if not row:
        return {"items": [], "summary": "", "marking_id": "", "updated_at": ""}
    result = json_load(row[1], {})
    result["updated_at"] = row[0]
    return result


def save_draft(conn, draft: dict) -> dict:
    clean_items = []
    seen = set()
    for raw in list(draft.get("items") or [])[:1000]:
        if not isinstance(raw, dict):
            continue
        kind = str(raw.get("kind") or "")
        if kind not in {"ioc", "actor", "file", "finding"}:
            continue
        value = raw.get("id") if kind in {"ioc", "finding"} else raw.get("value") or raw.get("path")
        key = (kind, str(value))
        if not value or key in seen:
            continue
        seen.add(key)
        item = {"kind": kind, "indicator": bool(raw.get("indicator"))}
        if kind in {"ioc", "finding"}:
            item["id"] = int(value)
        elif kind == "actor":
            item["value"] = str(value).strip()
        else:
            item["path"] = str(value)
        clean_items.append(item)
    clean = {"items": clean_items,
             "summary": str(draft.get("summary") or "")[:20000],
             "marking_id": str(draft.get("marking_id") or "")[:200]}
    at = db.now()
    conn.execute(
        "INSERT INTO opencti_draft(id,updated_at,payload) VALUES(1,?,?) "
        "ON CONFLICT(id) DO UPDATE SET updated_at=excluded.updated_at,payload=excluded.payload",
        (at, json.dumps(clean, ensure_ascii=False)))
    conn.commit()
    return {**clean, "updated_at": at}


def delete_draft(conn):
    conn.execute("DELETE FROM opencti_draft WHERE id=1")
    conn.commit()


def _catalog_entry(config: dict, group: str, selected_id: str) -> dict:
    return next((row for row in config.get(group, [])
                 if str(row.get("id")) == str(selected_id)), {})


def redact_evidence_roots(text: str, roots) -> str:
    """Remove registered absolute roots from analyst-visible STIX prose."""
    clean = str(text or "")
    for root in sorted((str(value) for value in roots), key=len, reverse=True):
        variants = {root, root.replace("\\", "/"), root.replace("/", "\\")}
        for value in variants:
            if value:
                clean = clean.replace(value, "<evidence-root>")
    return clean


def materialize(case_dir, config: dict, draft: dict, publication_id: str) -> dict:
    """Resolve IDs and paths at preview time; the browser supplies no facts."""
    conn = db.connect(case_dir)
    try:
        items = []
        roots = db.evidence_roots(conn)
        for selected in draft.get("items") or []:
            kind = selected["kind"]
            local_ref = f"{kind}:{selected.get('id', selected.get('value', selected.get('path', '')))}"
            if kind == "ioc":
                row = conn.execute("SELECT * FROM iocs WHERE id=?", (selected["id"],)).fetchone()
                if not row:
                    raise CaseOpenCtiError("item_missing", "Selected IOC no longer exists")
                items.append({"kind": "observable", "local_ref": local_ref,
                              "type": row["type"], "value": row["value"],
                              "label": row["value"], "indicator": selected.get("indicator", False)})
            elif kind == "actor":
                value = opencti.normalize_value("ip", selected["value"])
                items.append({"kind": "observable", "local_ref": local_ref,
                              "type": "ip", "value": value, "label": value,
                              "indicator": selected.get("indicator", False)})
            elif kind == "file":
                items.append(file_snapshot(conn, selected["path"], local_ref,
                                           selected.get("indicator", False)))
            elif kind == "finding":
                row = conn.execute("SELECT * FROM findings WHERE id=? AND triage='confirmed'",
                                   (selected["id"],)).fetchone()
                if not row:
                    raise CaseOpenCtiError(
                        "finding_not_confirmed", "Only confirmed findings can be published")
                target_ref = f"finding-artifact:{row['id']}"
                artifact_kind = str(row["artifact_kind"] or "").lower()
                artifact = str(row["artifact"] or "")
                target = None
                if artifact_kind in {"client", "ip"}:
                    try:
                        target = {"kind": "observable", "local_ref": target_ref,
                                  "type": "ip",
                                  "value": opencti.normalize_value("ip", artifact),
                                  "label": artifact, "indicator": False}
                    except ValueError:
                        pass
                elif artifact_kind == "file":
                    relative = db.case_relative_path(conn, artifact)
                    if not Path(relative).is_absolute():
                        target = {"kind": "observable", "local_ref": target_ref,
                                  "type": "path", "value": relative,
                                  "label": relative, "indicator": False}
                elif artifact_kind in {"account", "user"}:
                    target = {"kind": "observable", "local_ref": target_ref,
                              "type": "user", "value": artifact,
                              "label": artifact, "indicator": False}
                if target:
                    items.append(target)
                note = row["triage_note"] or (
                    f"Confirmed Shellhound finding: {row['rule']}")
                items.append({"kind": "finding", "local_ref": local_ref,
                              "id": row["id"], "rule": row["rule"],
                              "content": redact_evidence_roots(note, roots),
                              "object_refs": [target_ref] if target else [],
                              "severity": row["severity"]})
        if not items:
            raise CaseOpenCtiError("empty_draft", "Select at least one object")
        marking_id = draft.get("marking_id") or config.get("default_marking_id")
        marking = _catalog_entry(config, "markings", marking_id)
        if not marking or not marking.get("standard_id"):
            raise CaseOpenCtiError("marking_missing", "Select a verified OpenCTI marking")
        author = _catalog_entry(config, "authors", config.get("author_id"))
        if not author or not author.get("standard_id"):
            raise CaseOpenCtiError("author_missing", "Select a verified OpenCTI author")
        # Case identity already lives in the case database. Reading it here
        # avoids trusting a browser-supplied case label and works for every
        # current Shellhound case (whose human-readable sidecar is JSON).
        meta = {row[0]: row[1] for row in conn.execute(
            "SELECT key,value FROM meta WHERE key IN ('name','reference')")}
        case = {"slug": Path(case_dir).name, "name": meta.get("name") or Path(case_dir).name,
                "reference": meta.get("reference") or ""}
        summary = redact_evidence_roots(draft.get("summary", ""), roots)
        built = opencti.build_bundle(
            case, publication_id, summary, marking["standard_id"],
            author["standard_id"], items)
        return {**built, "items": items, "case": case,
                "marking": marking, "author": author,
                "summary": summary}
    finally:
        conn.close()


def publication_rows(conn) -> list[dict]:
    rows = db.rows(conn, "SELECT * FROM opencti_publications ORDER BY created_at DESC")
    files = db.rows(conn, "SELECT * FROM opencti_publication_files ORDER BY id")
    by_publication = {}
    for row in files:
        by_publication.setdefault(row["publication_id"], []).append(row)
    for row in rows:
        row["files"] = by_publication.get(row["id"], [])
        row["snapshot"] = json_load(row.get("snapshot"), {})
        row["taxii_result"] = json_load(row.get("taxii_result"), {})
    return rows


def context_rows(conn, kind="", key="") -> list[dict]:
    sql = "SELECT * FROM opencti_lookup_snapshots"
    params = []
    clauses = []
    if kind:
        clauses.append("target_kind=?")
        params.append(kind)
    if key:
        clauses.append("target_key=?")
        params.append(key)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY fetched_at DESC"
    rows = db.rows(conn, sql, params)
    for row in rows:
        row["result"] = json_load(row.pop("payload"), {})
    return rows
