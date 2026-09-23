"""Source inventory and a rebuildable non-HTTP event index.

Source configuration and selected evidence live in case.db. Each source's
events and generation are replaced in one SQLite transaction; a failed source
keeps its old generation, explicitly stale, without retiring other sources.
"""
import hashlib
import json
import os
import sqlite3
import uuid
from collections import Counter
from pathlib import Path

from server import db, log_parsers as parsers, ruleswitch
from server.engines import errorlog
from server.artifacts import ART_SQL
from server.engines.fsutil import canonical_file, path_within_any
from server.paths import display_path, io_path

INDEX_NAME = "logevents.db"
MAX_FILES = 10000
MAX_SELECTION = 200
_INDEX_SCHEMA = """
CREATE TABLE IF NOT EXISTS generations (source_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (
 id TEXT NOT NULL, source_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
 family TEXT NOT NULL, epoch INTEGER, ip TEXT NOT NULL, account TEXT NOT NULL,
 path TEXT NOT NULL, operation TEXT NOT NULL, outcome TEXT NOT NULL,
 artifact TEXT NOT NULL, line INTEGER NOT NULL, raw TEXT NOT NULL, payload TEXT NOT NULL,
 PRIMARY KEY(id,fingerprint)
);
CREATE INDEX IF NOT EXISTS events_source ON events(source_id, line);
CREATE INDEX IF NOT EXISTS events_time ON events(epoch, id);
CREATE INDEX IF NOT EXISTS events_ip ON events(ip, epoch);
CREATE INDEX IF NOT EXISTS events_artifact ON events(artifact, epoch);
"""


class LogEvidenceError(ValueError):
    pass


def _hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def marker(path):
    try:
        st = os.stat(io_path(path))
        return f"{st.st_size}:{st.st_mtime_ns}:{st.st_ctime_ns}"
    except OSError:
        return "missing"


def fingerprint(path, options, ctx=None):
    digest = hashlib.sha256((parsers.VERSION + json.dumps(options, sort_keys=True)).encode())
    with open(io_path(path), "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            if ctx and ctx.cancelled():
                raise LogEvidenceError("Cancelled before this source finished")
            digest.update(block)
    return digest.hexdigest()


def files(paths, ctx=None):
    seen = set()
    for target in paths:
        if os.path.isfile(io_path(target)):
            candidates = [target]
        elif os.path.isdir(io_path(target)):
            def walk(root):
                found = False
                for directory, dirs, names in os.walk(io_path(root), followlinks=False):
                    dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(directory, d)))
                    for name in sorted(names):
                        found = True
                        yield os.path.join(directory, name)
                if not found:
                    yield root  # An empty/unreadable folder needs a source warning too.
            candidates = walk(target)
        else:
            candidates = [target]  # Missing evidence must produce an actionable source result.
        for path in candidates:
            if ctx and ctx.cancelled():
                return
            identity = canonical_file(path)
            if identity in seen:
                continue
            if not path_within_any(path, [target]):
                continue
            seen.add(identity)
            if len(seen) > MAX_FILES:
                raise LogEvidenceError("More than 10,000 log files. Register smaller folders to finish discovery")
            if ctx:
                ctx.phase_progress(0, f"Discovering logs: {len(seen):,} files", "discovering", len(seen), None)
            yield display_path(path), identity


def _detect(path):
    try:
        return {**parsers.detect(list(parsers.text_lines(path, preview=True))), "error": ""}
    except (OSError, ValueError, EOFError, lzma_error()) as exc:
        return {"format": "text", "ambiguous": False, "candidates": [], "recognized": False,
                "error": "Cannot read this text source" if isinstance(exc, OSError) else str(exc)}


def lzma_error():
    import lzma
    return lzma.LZMAError


def preview(path, timezone='auto'):
    from server import source_time
    from server.engines.accesslog import AccessLogParser, fast_epoch
    rows = []
    for filename, identity in files([path]):
        detected = _detect(filename)
        examples = []
        try:
            access = AccessLogParser()
            for _, line in parsers.text_lines(filename, preview=True):
                parsed = parsers.parse_line(detected['format'], line)
                if parsed and parsed['raw_time']:
                    examples.append(source_time.example(parsed['raw_time'], timezone))
                elif detected['format'] == 'access':
                    record = access.parse(line)
                    if record:
                        stamp = record.get('time', '')
                        absolute = fast_epoch(stamp)
                        if absolute:
                            examples.append(source_time.example(stamp, timezone, absolute[0]))
                if len(examples) == 2:
                    break
        except (OSError, ValueError, EOFError, lzma_error()):
            pass
        rows.append({"id": _hash(identity)[:24], "path": filename, "name": Path(filename).name,
                     **detected, "family": parsers.FAMILIES[detected["format"]], 'time_examples': examples})
    return {"sources": rows, "formats": parsers.FORMATS}


def validate_settings(options):
    result = {key: str(options.get(key) or "").strip() for key in
              ("format", "timezone", "label", "server_root", "webroot")}
    result["format"] = result["format"] or "auto"
    if result["format"] not in parsers.FORMATS:
        raise LogEvidenceError("Choose a supported log format")
    parsers.zone(result["timezone"])
    if len(result["label"]) > 120 or any(len(value) > 4096 for value in result.values()):
        raise LogEvidenceError("Source settings are too long")
    if bool(result["server_root"]) != bool(result["webroot"]):
        raise LogEvidenceError("Path mapping needs both the original server root and a registered webroot")
    return result


def inventory(case_dir, *, persist=False, ctx=None):
    conn = db.connect(case_dir)
    try:
        evidence = db.rows(conn, "SELECT * FROM evidence WHERE kind IN ('logs','access_logs') ORDER BY id")
        known = {row["identity"]: row for row in db.rows(conn, "SELECT * FROM log_sources")}
        rows = []
        for path, identity in files([e["path"] for e in evidence], ctx):
            old = known.get(identity)
            options = json.loads(old["settings"]) if old else {}
            detected = _detect(path)
            fmt = options.get("format", "auto")
            fmt = detected["format"] if fmt == "auto" else fmt
            item = {**(old or {}), "id": old["id"] if old else _hash(identity)[:24],
                    "path": path, "identity": identity, "settings": options,
                    "format": fmt, "family": parsers.FAMILIES[fmt],
                    "detected": detected, "current_marker": marker(path),
                    "evidence_ids": [e["id"] for e in evidence if path_within_any(path, [e["path"]])]}
            item["fresh"] = bool(old and old["state"] == "ready" and old["marker"] == item["current_marker"]
                                 and json.loads(old["stats"]).get("parser_version") == parsers.VERSION)
            item["stats"] = json.loads(old["stats"]) if old else {}
            item.setdefault("state", "new")
            item.setdefault("warning", "")
            item.setdefault("fingerprint", "")
            item.setdefault("accepted_fingerprint", "")
            if persist:
                conn.execute("INSERT OR IGNORE INTO log_sources(id,path,identity,format) VALUES (?,?,?,?)",
                             (item["id"], path, identity, fmt))
            rows.append(item)
        if persist:
            conn.commit()
        return rows
    finally:
        conn.close()


def configure(case_dir, source_id, options, source=None):
    source = source or next((s for s in inventory(case_dir, persist=True) if s["id"] == source_id), None)
    if source is None:
        raise LogEvidenceError("This log source is no longer registered")
    options = validate_settings(options)
    conn = db.connect(case_dir)
    try:
        if options["webroot"] and not any(canonical_file(options["webroot"]) == canonical_file(r["path"])
                                        for r in db.rows(conn, "SELECT path FROM evidence WHERE kind='webroot'")):
            raise LogEvidenceError("Choose a webroot registered in this case")
        if options != source["settings"]:
            conn.execute("UPDATE log_sources SET settings=?,state='new',accepted_fingerprint='' WHERE id=?",
                         (json.dumps(options), source_id))
            for eid in source["evidence_ids"]:
                conn.execute("UPDATE evidence SET scanned_at='' WHERE id=?", (eid,))
            conn.commit()
    finally:
        conn.close()


def access_targets(case_dir):
    """Keep legacy registrations byte-for-byte compatible until explicitly migrated."""
    conn = db.connect(case_dir)
    try:
        legacy = [r["path"] for r in db.rows(conn, "SELECT path FROM evidence WHERE kind='access_logs'")]
        has_new = db.one(conn, "SELECT id FROM evidence WHERE kind='logs' LIMIT 1")
    finally:
        conn.close()
    if not has_new:
        return legacy
    return [s["path"] for s in inventory(case_dir) if s["format"] == "access"]


def _open_index(case_dir, write=False):
    path = Path(case_dir) / INDEX_NAME
    if not write and not path.exists():
        return None
    conn = sqlite3.connect(str(path) if write else path.resolve().as_uri() + "?mode=ro", uri=not write, timeout=15)
    conn.row_factory = sqlite3.Row
    if write:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(_INDEX_SCHEMA)
    return conn


def _resolve(conn, logged, options, roots=None):
    if not logged:
        return ""
    if roots is None:
        roots = [r["path"] for r in db.rows(conn, "SELECT path FROM evidence WHERE kind='webroot'")]
    normalized = logged.replace("\\", "/")
    candidates = []
    prefix = options.get("server_root", "").replace("\\", "/").rstrip("/")
    target = options.get("webroot", "")
    if prefix and target and any(canonical_file(target) == canonical_file(root) for root in roots):
        if normalized.startswith(prefix + "/"):
            candidates.append(str(Path(target) / normalized[len(prefix) + 1:]))
    elif os.path.isabs(logged):
        candidates.append(logged)
    else:
        candidates.extend(str(Path(root) / normalized) for root in roots)
    found = {canonical_file(p): str(Path(p).resolve()) for p in candidates
             if os.path.isfile(io_path(p)) and path_within_any(p, roots)}
    return next(iter(found.values())) if len(found) == 1 else ""


def _save_finding(conn, event, *, manual=False, note=""):
    artifact = event["artifact"] or "log-observation:" + event["id"]
    kind = "file" if event["artifact"] else "log_observation"
    rule = ("Selected log observation" if manual else "ClamAV reported malware detection" if event["detection"]
            else "FTP activity involving a flagged file")
    source = "log_observation"
    # The record ID in the rule gives stable identity without misusing a log line as a file line.
    rule_id = "log.manual" if manual else "log.malware" if event["detection"] else "log.ftp"
    previous = db.one(conn, "SELECT f.artifact,f.artifact_kind FROM log_observations o JOIN findings f "
                           "ON f.fingerprint=o.finding_fingerprint WHERE o.event_id=? AND f.rule_id=? LIMIT 1",
                           (event["id"], rule_id))
    # A later path mapping adds context; it cannot move an analyst's decision
    # to a different file or manufacture a second review item for this event.
    if previous:
        artifact, kind = previous["artifact"], previous["artifact_kind"]
    before = db.one(conn, f"WITH art AS ({ART_SQL}) SELECT * FROM art WHERE artifact=?", (artifact,))
    fingerprint_value = db.upsert_finding(conn, source, db.SEV_MEDIUM if event["detection"] else db.SEV_LOW,
        rule + " · " + event["id"][:10], kind, artifact, evidence=parsers.redact(
            f"{event['source_name']}:{event['line']} · {note or event['raw']}" )[:1000], rule_id=rule_id,
        engine="" if manual else "log_source:" + event["source_id"], run=event.get("run", 0))
    if before:
        conn.execute("UPDATE findings SET triage=?,triage_note=?,triaged_at=? WHERE fingerprint=?",
                     (before["triage"], before["triage_note"], before["triaged_at"], fingerprint_value))
    safe = {**event, "raw": parsers.redact(event["raw"]), "mapped_artifact": event["artifact"],
            "artifact": artifact, "artifact_kind": kind}
    conn.execute("INSERT INTO log_observations VALUES (?,?,?,?) ON CONFLICT(event_id,finding_fingerprint) "
                 "DO UPDATE SET snapshot=excluded.snapshot",
                 (event["id"], fingerprint_value, event["source_id"], json.dumps(safe)))
    return fingerprint_value


def _save_error_finding(conn, event, disabled):
    if not event["path"] or not errorlog._INTERESTING.search(event["raw"]):
        return
    hard = bool(errorlog._HARD.search(event["raw"]))
    rule_id = "errorlog.hard" if hard else "errorlog.soft"
    if rule_id in disabled:
        return
    artifact = event["artifact"] or "log-observation:" + event["id"]
    kind = "file" if event["artifact"] else "log_observation"
    previous = db.one(conn, "SELECT f.artifact,f.artifact_kind FROM log_observations o JOIN findings f "
                           "ON f.fingerprint=o.finding_fingerprint WHERE o.event_id=? AND f.rule_id=? LIMIT 1",
                           (event["id"], rule_id))
    if previous:
        artifact, kind = previous["artifact"], previous["artifact_kind"]
    before = db.one(conn, f"WITH art AS ({ART_SQL}) SELECT * FROM art WHERE artifact=?", (artifact,))
    fp = db.upsert_finding(conn, "errorlog", db.SEV_MEDIUM if hard else db.SEV_LOW,
        ("PHP error names this file (fatal/parse)" if hard else "PHP error names this file") + " · " + event["source_id"][:10], kind, artifact,
        line=event.get("file_line") if kind == "file" else None, evidence=parsers.redact(f"{event['source_name']}:{event['line']} · {event['raw']}")[:400],
        rule_id=rule_id, engine="log_source:" + event["source_id"], run=event["run"])
    if before:
        conn.execute("UPDATE findings SET triage=?,triage_note=?,triaged_at=? WHERE fingerprint=?",
                     (before["triage"], before["triage_note"], before["triaged_at"], fp))
    conn.execute("INSERT OR REPLACE INTO log_observations VALUES (?,?,?,?)", (event["id"], fp, event["source_id"],
        json.dumps({**event, "raw": parsers.redact(event["raw"]), "mapped_artifact": event["artifact"],
                    "artifact": artifact, "artifact_kind": kind})))


def build(case_dir, ctx=None, source_ids=None):
    sources = inventory(case_dir, persist=True, ctx=ctx)
    if source_ids is not None:
        wanted = set(source_ids)
        if wanted - {s["id"] for s in sources}:
            raise LogEvidenceError("A selected source is no longer registered")
        sources = [s for s in sources if s["id"] in wanted]
    stats = {"files": 0, "events": 0, "log_warnings": 0, "failed_sources": 0}
    conn = db.connect(case_dir)
    index = _open_index(case_dir, write=True)
    disabled = ruleswitch.disabled_ids(Path(case_dir).parent)
    roots = [r["path"] for r in db.rows(conn, "SELECT path FROM evidence WHERE kind='webroot'")]
    try:
        for n, source in enumerate(sources):
            if ctx and ctx.cancelled():
                break
            sid, options, fmt = source["id"], source["settings"], source["format"]
            if fmt == "access":
                conn.execute("UPDATE log_sources SET format='access',state='ready',marker=?,warning='',stats=? WHERE id=?",
                             (marker(source["path"]), json.dumps({"parser_version": parsers.VERSION}), sid))
                conn.commit()
                continue  # HTTP records belong exclusively to the existing index.
            run = db.begin_run(conn, "log_source:" + sid)
            before = marker(source["path"])
            warning = ""
            current_fp = ""
            try:
                conn.execute("UPDATE log_sources SET state='indexing' WHERE id=?", (sid,))
                conn.commit()
                current_fp = fingerprint(source["path"], options, ctx)
                if ctx:
                    ctx.phase_progress(n / max(len(sources), 1), "Reading log source", "indexing", n, len(sources))
                index.execute("BEGIN")
                index.execute("DELETE FROM events WHERE source_id=? AND fingerprint=?", (sid, current_fp))
                counts = Counter()
                index.execute("CREATE TEMP TABLE IF NOT EXISTS repeats (hash TEXT PRIMARY KEY, n INTEGER)")
                index.execute("DELETE FROM repeats")
                resolved = {}
                for event in parsers.records(source["path"], fmt, options.get("timezone", "")):
                    if ctx and ctx.cancelled():
                        raise LogEvidenceError("Cancelled before this source finished")
                    key = _hash(event["raw"])
                    index.execute("INSERT INTO repeats VALUES (?,1) ON CONFLICT(hash) DO UPDATE SET n=n+1", (key,))
                    occurrence = index.execute("SELECT n FROM repeats WHERE hash=?", (key,)).fetchone()[0]
                    event_id = _hash(f"{sid}:{key}:{occurrence}")
                    if event["path"] not in resolved:
                        if len(resolved) > 10000:
                            resolved.clear()
                        resolved[event["path"]] = _resolve(conn, event["path"], options, roots)
                    event.update(id=event_id, source_id=sid, source_name=options.get("label") or Path(source["path"]).name,
                                 family=source["family"], format=fmt, fingerprint=current_fp,
                                 artifact=resolved[event["path"]], run=run)
                    index.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                        event_id, sid, current_fp, source["family"], event["epoch"], event["ip"], event["account"],
                        event["path"], event["operation"], event["outcome"], event["artifact"], event["line"],
                        event["raw"], json.dumps(event)))
                    counts["events"] += 1
                    counts["unparsed"] += not event["parsed"]
                    counts["undated"] += event["epoch"] is None
                    if ctx and counts["events"] % 1000 == 0:
                        ctx.phase_progress(n / max(len(sources), 1), f"Reading log source: {counts['events']:,} entries",
                                           "indexing", n, len(sources))
                if marker(source["path"]) != before or fingerprint(source["path"], options, ctx) != current_fp:
                    raise LogEvidenceError("Source changed while it was being read; retry this source")
                if fmt == "text":
                    warning = "Not automatically analyzed. Search this text and select relevant entries for review."
                elif counts["unparsed"]:
                    warning = f"{counts['unparsed']:,} entries could not be interpreted; their original text is available."
                index.commit()
                # Findings are published only after the whole source was read successfully.
                flagged_artifacts = {r["artifact"] for r in db.rows(conn, f"WITH art AS ({ART_SQL}) SELECT artifact FROM art WHERE findings>0 AND triage!='dismissed'")}
                for row in index.execute("SELECT payload FROM events WHERE source_id=? AND fingerprint=?", (sid, current_fp)):
                    if ctx and ctx.cancelled():
                        raise LogEvidenceError("Cancelled before this source finished")
                    event = json.loads(row[0])
                    flagged = event["artifact"] in flagged_artifacts
                    if event["detection"] or (event["family"] == "ftp" and flagged):
                        _save_finding(conn, event)
                    elif event["family"] == "error":
                        _save_error_finding(conn, event, disabled)
                conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES (?,?)", ("engine_done:log_source:" + sid, str(run)))
                conn.execute("UPDATE log_sources SET state='ready',fingerprint=?,marker=?,format=?,warning=?,stats=? WHERE id=?",
                             (current_fp, before, fmt, warning, json.dumps({**counts, "parser_version": parsers.VERSION}), sid))
                conn.commit()
                index.execute("INSERT OR REPLACE INTO generations VALUES (?,?)", (sid, current_fp))
                index.execute("DELETE FROM events WHERE source_id=? AND fingerprint!=?", (sid, current_fp))
                index.commit()
                stats["files"] += 1
                stats["events"] += counts["events"]
            except (OSError, ValueError, EOFError, sqlite3.Error, lzma_error()) as exc:
                index.rollback()
                conn.rollback()
                warning = str(exc) if isinstance(exc, (LogEvidenceError, parsers.LogReadError)) else "Unable to read or index this source. Check access and file integrity, then retry."
                state = "cancelled" if ctx and ctx.cancelled() else "failed"
                conn.execute("UPDATE log_sources SET state=?,warning=?,accepted_fingerprint='' WHERE id=?", (state, warning, sid))
                conn.commit()
                stats["failed_sources"] += 1
                if ctx and ctx.cancelled():
                    break
            if warning:
                stats["log_warnings"] += 1
                if ctx:
                    ctx.detailed_skip(source["path"], warning, "log_source", source["path"])
        # A completed migration replaces the old case-wide error engine.
        # A failed or scoped pass cannot retire support from another source.
        if source_ids is None and not stats["failed_sources"] and not (ctx and ctx.cancelled()) and db.one(
                conn, "SELECT id FROM evidence WHERE kind='logs' LIMIT 1"):
            legacy_run = db.begin_run(conn, "errorlog")
            db.complete_run(conn, "errorlog", legacy_run)
        if ctx:
            ctx.phase_progress(1, "Log sources processed", "indexing", stats["files"], len(sources))
    finally:
        index.close()
        conn.close()
    return stats


def source_status(case_dir):
    sources = inventory(case_dir)
    http_fresh = None
    if any(s["format"] == "access" for s in sources):
        from server.engines import logindex
        http_fresh = bool(logindex.status(case_dir, access_targets(case_dir)).get("fresh"))
    index = _open_index(case_dir)
    try:
        generations = dict(index.execute("SELECT source_id,fingerprint FROM generations")) if index else {}
    finally:
        if index:
            index.close()
    for s in sources:
        if s["format"] != "access":
            s["fresh"] = s["fresh"] and generations.get(s["id"]) == s["fingerprint"]
        else:
            s["fresh"] = bool(http_fresh)
            s["state"] = "ready" if http_fresh else "new"
            s["warning"] = ""
        if s["state"] == "indexing":
            from server.jobs import manager
            conn = db.connect(case_dir)
            try:
                running = db.rows(conn, "SELECT id FROM jobs WHERE kind='log_events' AND state IN ('queued','running')")
                if not any(manager.progress_snapshot(case_dir, row["id"]) for row in running):
                    s["state"] = "failed"
                    s["warning"] = "Interrupted before completion. Analyze this source again."
            finally:
                conn.close()
        if s["warning"]:
            try:
                s["warning_fingerprint"] = fingerprint(s["path"], s["settings"])
            except OSError:
                s["warning_fingerprint"] = "unreadable"
        s["accepted"] = bool(s["warning"] and s["accepted_fingerprint"] == _warning_key(s))
    return sources


def _warning_key(source):
    return _hash(source["id"] + source["current_marker"] + source.get("warning_fingerprint", "") + json.dumps(source["settings"], sort_keys=True) + source["warning"])


def accept_warning(case_dir, sid):
    source = next((s for s in source_status(case_dir) if s["id"] == sid), None)
    if not source or not source["warning"]:
        raise LogEvidenceError("No current warning for this source")
    conn = db.connect(case_dir)
    try:
        conn.execute("UPDATE log_sources SET accepted_fingerprint=? WHERE id=?", (_warning_key(source), sid))
        conn.execute("INSERT INTO meta(key,value) VALUES (?,?)", ("log_warning_review:" + sid + ":" + uuid.uuid4().hex,
            json.dumps({"source_id": sid, "warning": source["warning"], "fingerprint": _warning_key(source), "accepted_at": db.now()})))
        skipped = db.one(conn, "SELECT s.job_id,s.ordinal FROM job_skips s JOIN jobs j ON j.id=s.job_id "
                              "WHERE j.kind='log_events' AND s.path=? ORDER BY s.job_id DESC LIMIT 1", (source["path"],))
        if skipped:
            conn.execute("INSERT INTO skip_reviews(job_id,ordinal,accepted_at) VALUES (?,?,?)",
                         (skipped["job_id"], skipped["ordinal"], db.now()))
        conn.commit()
    finally:
        conn.close()


def warning_counts(case_dir):
    rows = [s for s in source_status(case_dir) if s["warning"] and s["format"] != "access"]
    return sum(not s["accepted"] for s in rows), sum(s["accepted"] for s in rows)


def reconcile_receipts(conn):
    """Derive the non-HTTP receipt from all sources, including scoped retries.

    A retry can repair its own sources, but cannot certify an unprocessed sibling
    or replace an access-index/Sigma result in a mixed registration.
    """
    evidence = db.rows(conn, "SELECT * FROM evidence WHERE kind='logs'")
    if not evidence:
        return
    known = {s["identity"]: s for s in db.rows(conn, "SELECT * FROM log_sources")}
    job = db.one(conn, "SELECT * FROM jobs WHERE kind='log_events' ORDER BY id DESC LIMIT 1")
    http_fresh = None
    for item in evidence:
        stats = json.loads(item["stats"] or "{}")
        attempt = stats.get("last_attempt", {})
        engines = dict(attempt.get("engines", {}))
        sources = [known.get(identity) for _, identity in files([item["path"]])]
        has_access = any(s and s["format"] == "access" for s in sources)
        others = [s for s in sources if not s or s["format"] != "access"]
        ready = bool(sources) and all(s and s["state"] in ("ready", "failed")
            and (s["state"] == "failed" or (s["marker"] == marker(s["path"])
                and json.loads(s["stats"]).get("parser_version") == parsers.VERSION)) for s in others)
        state = "complete" if ready and job and job["state"] == "done" else "partial"
        if job and job["state"] in ("queued", "running", "cancelled", "failed"):
            state = "running" if job["state"] == "queued" else job["state"]
        warnings = sum(bool(s and s["warning"]) for s in others)
        if state == "complete" and warnings:
            state = "complete_with_warnings"
        engines["log_events"] = {"state": state, "stats": {"log_warnings": warnings,
            "events": sum(json.loads(s["stats"]).get("events", 0) for s in others if s)}}
        if has_access and not {"index_logs", "sigma"}.issubset(engines):
            engines.setdefault("index_logs", {"state": "partial"})
            engines.setdefault("sigma", {"state": "partial"})
        if has_access:
            if http_fresh is None:
                from server.engines import logindex
                case_dir = Path(conn.execute("PRAGMA database_list").fetchone()["file"]).parent
                http_fresh = bool(logindex.status(case_dir, access_targets(case_dir)).get("fresh"))
            if not http_fresh:
                engines["index_logs"] = {**engines["index_logs"], "state": "partial"}
        states = {outcome["state"] for outcome in engines.values()}
        status = next((s for s in ("running", "failed", "cancelled", "partial", "complete_with_warnings") if s in states), "complete")
        updated = {**attempt, "run_id": attempt.get("run_id") or (job or {}).get("run_id", ""),
                   "engines": engines, "status": status, "warnings": warnings}
        scanned = (item["scanned_at"] or (job or {}).get("finished") or db.now()) if status in ("complete", "complete_with_warnings") else ""
        if updated != attempt or scanned != item["scanned_at"]:
            stats["last_attempt"] = updated
            conn.execute("UPDATE evidence SET stats=?,scanned_at=? WHERE id=?", (json.dumps(stats), scanned, item["id"]))


def search(case_dir, filters=None):
    filters = filters or {}
    limit = min(max(int(filters.get("limit", 100)), 1), 200)
    offset = max(int(filters.get("offset", 0)), 0)
    active = {s["id"]: s for s in source_status(case_dir) if s["format"] != "access"}
    if not active:
        return {"rows": [], "total": 0, "next_offset": None}
    from server.chain import clock_offsets
    case_conn = db.connect(case_dir)
    try:
        correction = clock_offsets(case_conn)["logs"]
    finally:
        case_conn.close()
    where, values = ["source_id IN (" + ",".join("?" for _ in active) + ")",
                     "fingerprint=(SELECT g.fingerprint FROM generations g WHERE g.source_id=events.source_id)"], list(active)
    for key in ("family", "source_id", "ip", "account", "operation", "outcome", "id"):
        if filters.get(key):
            where.append(key + "=?")
            values.append(str(filters[key]))
    for key, column in (("search", "raw"), ("path", "path")):
        if filters.get(key):
            where.append(f"instr(lower({column}),lower(?))>0")
            values.append(str(filters[key])[:2000])
    for key, op in (("from_epoch", ">="), ("to_epoch", "<=")):
        if filters.get(key) is not None:
            where.append("epoch" + op + "?")
            values.append(int(filters[key]) - correction)
    index = _open_index(case_dir)
    if not index:
        return {"rows": [], "total": 0, "next_offset": None}
    try:
        clause = " AND ".join(where)
        total = index.execute("SELECT count(*) FROM events WHERE " + clause, values).fetchone()[0]
        rows = []
        for row in index.execute("SELECT payload FROM events WHERE " + clause + " ORDER BY epoch IS NULL,epoch,source_id,line,id LIMIT ? OFFSET ?", values + [limit, offset]):
            event = json.loads(row[0])
            source = active[event["source_id"]]
            event.update(raw=parsers.redact(event["raw"]), fresh=bool(source["fresh"] and event["fingerprint"] == source["fingerprint"]))
            event["recorded_epoch"] = event["epoch"]
            event["clock_correction"] = correction
            if event["epoch"] is not None:
                event["epoch"] += correction
            rows.append(event)
        if rows:
            conn = db.connect(case_dir)
            try:
                decisions = {r["artifact"]: r["triage"] for r in db.rows(conn,
                    f"WITH art AS ({ART_SQL}) SELECT artifact,triage FROM art WHERE artifact IN (" +
                    ",".join("?" for _ in rows) + ")", tuple(e["artifact"] or "log-observation:" + e["id"] for e in rows))}
                for event in rows:
                    artifact = event["artifact"] or "log-observation:" + event["id"]
                    event["triage"] = decisions.get(artifact, "new")
                    if event["triage"] == "confirmed" and event["epoch"] is not None:
                        from server.chain import _event_id
                        event["timeline_id"] = _event_id("log", "log-observation", artifact, event["raw_time"], event["id"])
            finally:
                conn.close()
        return {"rows": rows, "total": total, "next_offset": offset + limit if offset + limit < total else None}
    finally:
        index.close()


def _current_event(case_dir, event_id, *, expected=""):
    result = search(case_dir, {"id": event_id, "limit": 1})
    if not result["rows"]:
        raise LogEvidenceError("This event is no longer in the registered evidence. Reanalyze its source")
    event = result["rows"][0]
    source = next(s for s in source_status(case_dir) if s["id"] == event["source_id"])
    try:
        current_fp = fingerprint(source["path"], source["settings"])
    except OSError:
        current_fp = ""
    if not event["fresh"] or current_fp != event["fingerprint"] or (expected and expected != current_fp):
        raise LogEvidenceError("This source or its settings changed. Reanalyze before opening or selecting its evidence")
    return event, source


def context(case_dir, event_id, expected=""):
    event, source = _current_event(case_dir, event_id, expected=expected)
    conn = db.connect(case_dir)
    try:
        event["artifact_available"] = bool(event["artifact"] and _resolve(conn, event["path"], source["settings"]) == event["artifact"])
    finally:
        conn.close()
    lines = []
    for number, text in parsers.text_lines(source["path"]):
        if number > event["line_end"] + 5:
            break
        if number >= max(1, event["line"] - 5):
            lines.append({"line": number, "text": parsers.redact(text), "selected": event["line"] <= number <= event["line_end"]})
    if fingerprint(source["path"], source["settings"]) != event["fingerprint"]:
        raise LogEvidenceError("Source changed while reading its context. Reanalyze this source")
    return {"event": event, "lines": lines, "source_name": event["source_name"], "source_path": source["path"]}


def apply(case_dir, selections, note=""):
    if not selections or len(selections) > MAX_SELECTION:
        raise LogEvidenceError("Select between 1 and 200 visible entries")
    sources = {s["id"]: s for s in source_status(case_dir)}
    index = _open_index(case_dir)
    if index is None:
        raise LogEvidenceError("Analyze these sources first")
    ids = list(dict.fromkeys(s["id"] for s in selections))
    expected = {s["id"]: s.get("fingerprint", "") for s in selections}
    try:
        events = [json.loads(r[0]) for r in index.execute("SELECT payload FROM events WHERE id IN (" +
            ",".join("?" for _ in ids) + ") AND fingerprint=(SELECT g.fingerprint FROM generations g WHERE g.source_id=events.source_id)", ids)]
    finally:
        index.close()
    if len(events) != len(ids):
        raise LogEvidenceError("A selected event is no longer available. Refresh the results")
    checked = {}
    for event in events:
        sid = event["source_id"]
        source = sources.get(sid)
        if not source or not source["fresh"]:
            raise LogEvidenceError("A selected source changed. Reanalyze it before selecting evidence")
        if sid not in checked:
            try:
                checked[sid] = fingerprint(source["path"], source["settings"])
            except OSError:
                checked[sid] = ""
        if checked[sid] != event["fingerprint"] or (expected[event["id"]] and expected[event["id"]] != checked[sid]):
            raise LogEvidenceError("A selected source changed. Reanalyze it before selecting evidence")
    conn = db.connect(case_dir)
    try:
        fingerprints = [_save_finding(conn, event, manual=True, note=note[:2000]) for event in events]
        conn.commit()
        return {"added": len(set(fingerprints)), "artifacts": list(dict.fromkeys(e["artifact"] or "log-observation:" + e["id"] for e in events))}
    finally:
        conn.close()


def saved_for_artifact(conn, artifact):
    events = {}
    for row in db.rows(conn, "SELECT o.snapshot FROM log_observations o JOIN findings f "
                       "ON f.fingerprint=o.finding_fingerprint WHERE f.artifact=? ORDER BY o.rowid DESC", (artifact,)):
        event = json.loads(row["snapshot"])
        events.setdefault(event["id"], event)
    return list(events.values())


def artifact_label(conn, artifact):
    events = saved_for_artifact(conn, artifact)
    return f"{events[0]['source_name']}:{events[0]['line']}" if events else "Log observation"


def retire_removed(case_dir):
    active = {s["id"] for s in inventory(case_dir)}
    conn = db.connect(case_dir)
    try:
        for source in db.rows(conn, "SELECT id FROM log_sources"):
            if source["id"] not in active:
                engine = "log_source:" + source["id"]
                run = db.begin_run(conn, engine)
                db.complete_run(conn, engine, run)
    finally:
        conn.close()


def timeline_events(case_dir, *, artifacts=None):
    conn = db.connect(case_dir)
    try:
        confirmed = (set(artifacts) if artifacts is not None else
                     {r["artifact"] for r in db.rows(conn, f"WITH art AS ({ART_SQL}) SELECT artifact FROM art WHERE triage='confirmed'")})
        saved = [e for artifact in confirmed for e in saved_for_artifact(conn, artifact)]
    finally:
        conn.close()
    sources = {s["id"]: s for s in source_status(case_dir)}
    for source in sources.values():
        try:
            source["fresh"] = source["fresh"] and fingerprint(source["path"], source["settings"]) == source["fingerprint"]
        except OSError:
            source["fresh"] = False
    selected = {e["id"]: e for e in saved}
    index = _open_index(case_dir)
    try:
        if index:
            items = sorted(confirmed)
            for start in range(0, len(items), 100):
                chunk = items[start:start + 100]
                for row in index.execute("SELECT payload FROM (SELECT payload, ROW_NUMBER() OVER "
                    "(PARTITION BY artifact,source_id,operation ORDER BY epoch IS NULL,epoch,id) position FROM events "
                    "WHERE fingerprint=(SELECT g.fingerprint FROM generations g WHERE g.source_id=events.source_id) AND artifact IN (" + ",".join("?" for _ in chunk) + ") AND "
                    "((operation='upload' AND outcome='success') OR operation IN ('web_error','malware_detection'))) WHERE position=1", chunk):
                    event = json.loads(row[0])
                    selected[event["id"]] = event
    finally:
        if index:
            index.close()
    for event in selected.values():
        source = sources.get(event["source_id"], {})
        event["fresh"] = bool(source.get("fresh") and event["fingerprint"] == source.get("fingerprint"))
        event["raw"] = parsers.redact(event["raw"])
    return list(selected.values())
