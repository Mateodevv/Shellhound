# server/app.py
"""The FastAPI application: every endpoint of the five views, the analyze
pipeline, and the WebSocket that keeps the UI live.

Security model (inherited from the legacy panel, surface reduced):
  * bound to 127.0.0.1 by default;
  * every /api call and the WebSocket require the startup token (header
    X-Token or ?token=); on a loopback bind it is injected into the page;
  * case slugs from the client resolve through workspace.resolve_case
    (never a free path); evidence paths are registered by the analyst.
Evidence file CONTENT is never served -- findings carry text excerpts only,
which the React frontend renders as text. That removes the hostile-HTML
attack surface the legacy file manager had to sandbox.
"""
import asyncio
import csv
import io
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from server import db, iocs as ioclib, workspace
from server.config import Config
from server.engines import cmsinventory, detect, logindex, sqldump, webshell
from server.events import hub
from server.jobs import manager

WEB_DIST = Path(__file__).resolve().parent.parent / "web" / "dist"

EVIDENCE_KINDS = ("webroot", "access_logs", "sql_dump")


def create_app(config: Config) -> FastAPI:
    app = FastAPI(title="SHELLHOUND", docs_url=None, redoc_url=None,
                  openapi_url=None)
    app.state.config = config
    config.ensure_workspace()

    # --- auth ---------------------------------------------------------------

    def require_token(request: Request):
        token = request.headers.get("x-token") or request.query_params.get("token")
        if token != config.token:
            raise HTTPException(401, "invalid or missing token")

    auth = Depends(require_token)

    def case_dir_or_404(slug: str) -> Path:
        case_dir = workspace.resolve_case(config.workspace, slug)
        if case_dir is None:
            raise HTTPException(404, f"unknown case: {slug}")
        return case_dir

    @app.on_event("startup")
    async def _attach_loop():
        hub.attach_loop(asyncio.get_running_loop())

    # --- workspace / cases --------------------------------------------------

    @app.get("/api/state", dependencies=[auth])
    def state():
        return {"workspace": str(config.workspace),
                "cases": workspace.list_cases(config.workspace)}

    class NewCase(BaseModel):
        name: str
        reference: str = ""
        notes: str = ""

    @app.post("/api/cases", dependencies=[auth])
    def create_case(body: NewCase):
        if not body.name.strip():
            raise HTTPException(400, "case name must not be empty")
        case_dir = workspace.create_case(config.workspace, body.name,
                                         body.reference, body.notes)
        return workspace.case_info(case_dir)

    # How long a "how much evidence is this?" scan may take. A webroot can
    # hold six figures of files and a log directory gigabytes; the answer is
    # for ORIENTATION ("57 MB, 1.744 Dateien"), so a partial count that
    # SAYS it is partial beats blocking the page.
    _META_BUDGET_SECONDS = 2.5
    _META_FILE_CAP = 300_000

    def _evidence_meta(path):
        """(files, bytes, partial) for a file or directory, time-boxed."""
        p = Path(path)
        try:
            if p.is_file():
                return 1, p.stat().st_size, False
        except OSError:
            return 0, 0, False
        deadline = time.monotonic() + _META_BUDGET_SECONDS
        files = total = 0
        partial = False
        stack = [str(p)]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(entry.path)
                            elif entry.is_file(follow_symlinks=False):
                                files += 1
                                total += entry.stat().st_size
                        except OSError:
                            continue
                        if files >= _META_FILE_CAP:
                            return files, total, True
            except OSError:
                continue
            if time.monotonic() > deadline:
                partial = True
                break
        return files, total, partial

    def _refresh_meta(conn, row):
        """Fill in size/file count for one evidence row if it is missing."""
        if row.get("meta_at"):
            return row
        files, total, partial = _evidence_meta(row["path"])
        conn.execute(
            "UPDATE evidence SET files = ?, bytes = ?, meta_at = ?, "
            "meta_partial = ? WHERE id = ?",
            (files, total, db.now(), int(partial), row["id"]))
        conn.commit()
        row.update(files=files, bytes=total, meta_at=db.now(),
                   meta_partial=int(partial))
        return row

    @app.get("/api/cases/{slug}", dependencies=[auth])
    def case_detail(slug: str):
        case_dir = case_dir_or_404(slug)
        info = workspace.case_info(case_dir)
        conn = db.connect(case_dir)
        try:
            evidence = db.rows(conn, "SELECT * FROM evidence ORDER BY kind, path")
            for e in evidence:
                e["stats"] = json.loads(e.get("stats") or "{}")
                e["exists"] = os.path.exists(e["path"])
                if e["exists"]:
                    _refresh_meta(conn, e)
        finally:
            conn.close()
        log_targets = [e["path"] for e in evidence if e["kind"] == "access_logs"]
        info["evidence_items"] = evidence
        info["log_index"] = logindex.status(case_dir,
                                            log_targets if log_targets else None)
        return info

    @app.get("/api/cases/{slug}/summary", dependencies=[auth])
    def case_close_preview(slug: str):
        """What closing this case would pack away -- shown before it happens."""
        case_dir = case_dir_or_404(slug)
        return workspace.case_summary(case_dir)

    @app.post("/api/cases/{slug}/archive", dependencies=[auth])
    def archive(slug: str):
        """Close the case: everything into one zip, working copy removed.
        Running jobs are cancelled first -- an engine still writing into a
        database that is being packed would archive a half-written case."""
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            live = [r["id"] for r in db.rows(
                conn, "SELECT id FROM jobs WHERE state IN ('queued','running')")]
        finally:
            conn.close()
        for job_id in live:
            manager.cancel(job_id)
        if live:
            manager.wait_for(live, timeout=20)
        zip_path, summary = workspace.archive_case(config.workspace, case_dir)
        hub.publish({"type": "invalidate", "scope": "workspace"})
        return {"archive": str(zip_path), "file": zip_path.name,
                "summary": summary, "cancelled_jobs": len(live)}

    @app.get("/api/archives", dependencies=[auth])
    def archives():
        return {"archive_dir": str(config.workspace / workspace.ARCHIVE_DIR),
                "archives": workspace.list_archives(config.workspace)}

    class ImportBody(BaseModel):
        file: str | None = None      # a name inside the workspace's archive/
        path: str | None = None      # or an arbitrary zip somewhere on disk

    @app.post("/api/import", dependencies=[auth])
    def import_case(body: ImportBody):
        """Bring a closed case back. `file` names an archive in the
        workspace's own archive/ folder; `path` accepts a zip from anywhere
        (a hand-over from another machine)."""
        if body.file:
            base = (config.workspace / workspace.ARCHIVE_DIR).resolve()
            candidate = (base / body.file).resolve()
            if candidate.parent != base:
                raise HTTPException(400, "invalid archive name")
            zip_path = candidate
        elif body.path:
            zip_path = Path(body.path).expanduser()
        else:
            raise HTTPException(400, "either file or path must be given")
        try:
            result = workspace.import_archive(config.workspace, zip_path)
        except workspace.ImportError_ as e:
            raise HTTPException(400, str(e)) from e
        hub.publish({"type": "invalidate", "scope": "workspace"})
        return result

    # --- evidence -----------------------------------------------------------

    class NewEvidence(BaseModel):
        kind: str
        path: str

    @app.post("/api/cases/{slug}/evidence", dependencies=[auth])
    def add_evidence(slug: str, body: NewEvidence):
        case_dir = case_dir_or_404(slug)
        if body.kind not in EVIDENCE_KINDS:
            raise HTTPException(400, f"kind must be one of {EVIDENCE_KINDS}")
        path = str(Path(body.path).expanduser())
        if not os.path.exists(path):
            raise HTTPException(400, f"path does not exist: {path}")
        conn = db.connect(case_dir)
        try:
            conn.execute(
                "INSERT OR IGNORE INTO evidence (kind, path, added) VALUES (?,?,?)",
                (body.kind, path, db.now()))
            conn.commit()
            return db.rows(conn, "SELECT * FROM evidence ORDER BY kind, path")
        finally:
            conn.close()

    class PatchEvidence(BaseModel):
        label: str

    @app.patch("/api/cases/{slug}/evidence/{evidence_id}", dependencies=[auth])
    def rename_evidence(slug: str, evidence_id: int, body: PatchEvidence):
        """Give this piece of evidence a name a human recognises."""
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            conn.execute("UPDATE evidence SET label = ? WHERE id = ?",
                         (body.label.strip()[:120], evidence_id))
            conn.commit()
            return {"ok": True}
        finally:
            conn.close()

    @app.delete("/api/cases/{slug}/evidence/{evidence_id}", dependencies=[auth])
    def remove_evidence(slug: str, evidence_id: int):
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            conn.execute("DELETE FROM evidence WHERE id = ?", (evidence_id,))
            conn.commit()
            return {"ok": True}
        finally:
            conn.close()

    class DetectBody(BaseModel):
        folder: str

    @app.post("/api/detect", dependencies=[auth])
    def detect_evidence(body: DetectBody):
        return detect.scan(body.folder)

    @app.get("/api/pickpath", dependencies=[auth])
    def pickpath(path: str = ""):
        """Server-side folder browser: directories only, plus drives on
        Windows when no path is given."""
        if not path.strip():
            if os.name == "nt":
                drives = []
                try:
                    drives = os.listdrives()
                except (OSError, AttributeError):
                    drives = [f"{c}:\\" for c in "CDEF" if os.path.exists(f"{c}:\\")]
                return {"path": "", "parent": None,
                        "dirs": [{"name": d, "path": d} for d in drives]}
            path = "/"
        p = Path(path).expanduser()
        if not p.is_dir():
            raise HTTPException(400, f"not a directory: {p}")
        dirs = []
        try:
            for entry in sorted(p.iterdir(), key=lambda e: e.name.lower()):
                try:
                    if entry.is_dir():
                        dirs.append({"name": entry.name, "path": str(entry)})
                except OSError:
                    continue
        except OSError as e:
            raise HTTPException(400, f"cannot list {p}: {e}")
        parent = str(p.parent) if p.parent != p else None
        return {"path": str(p), "parent": parent, "dirs": dirs}

    # --- analyze pipeline ---------------------------------------------------

    def _evidence_by_kind(case_dir):
        conn = db.connect(case_dir)
        try:
            rows = db.rows(conn, "SELECT * FROM evidence")
        finally:
            conn.close()
        out = {}
        for r in rows:
            out.setdefault(r["kind"], []).append(r)
        return out

    def _mark_scanned(case_dir, ids, stats):
        conn = db.connect(case_dir)
        try:
            for eid in ids:
                conn.execute(
                    "UPDATE evidence SET scanned_at = ?, stats = ? WHERE id = ?",
                    (db.now(), json.dumps(stats), eid))
            conn.commit()
        finally:
            conn.close()

    @app.post("/api/cases/{slug}/analyze", dependencies=[auth])
    def analyze(slug: str):
        """One button: index the logs, scan the webroot, inventory the CMS,
        analyze the dumps -- whatever evidence is registered."""
        case_dir = case_dir_or_404(slug)
        by_kind = _evidence_by_kind(case_dir)
        started = []

        logs = by_kind.get("access_logs", [])
        if logs:
            paths = [e["path"] for e in logs]
            ids = [e["id"] for e in logs]

            def run_logs(ctx, paths=paths, ids=ids, case_dir=case_dir):
                stats = logindex.build(case_dir, paths, ctx)
                _mark_scanned(case_dir, ids, stats)
                return stats

            started.append({"kind": "index_logs",
                            "job": manager.submit(case_dir, "index_logs", run_logs)})

        webroots = by_kind.get("webroot", [])
        if webroots:
            paths = [e["path"] for e in webroots]
            ids = [e["id"] for e in webroots]

            def run_shell(ctx, paths=paths, ids=ids, case_dir=case_dir):
                stats = webshell.scan(case_dir, paths, ctx)
                _mark_scanned(case_dir, ids, stats)
                return stats

            def run_cms(ctx, paths=paths, case_dir=case_dir):
                return cmsinventory.scan(case_dir, paths, ctx)

            started.append({"kind": "webshell",
                            "job": manager.submit(case_dir, "webshell", run_shell)})
            started.append({"kind": "cms",
                            "job": manager.submit(case_dir, "cms", run_cms)})

        dumps = by_kind.get("sql_dump", [])
        if dumps:
            paths = [e["path"] for e in dumps]
            ids = [e["id"] for e in dumps]

            def run_sql(ctx, paths=paths, ids=ids, case_dir=case_dir):
                stats = sqldump.scan(case_dir, paths, ctx)
                _mark_scanned(case_dir, ids, stats)
                return stats

            started.append({"kind": "sqldb",
                            "job": manager.submit(case_dir, "sqldb", run_sql)})

        if not started:
            raise HTTPException(400, "no evidence registered — add paths first")
        return {"started": started}

    @app.get("/api/cases/{slug}/jobs", dependencies=[auth])
    def jobs_list(slug: str):
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            rows = db.rows(conn,
                           "SELECT * FROM jobs ORDER BY id DESC LIMIT 50")
            for r in rows:
                r["stats"] = json.loads(r.get("stats") or "{}")
            return rows
        finally:
            conn.close()

    @app.post("/api/cases/{slug}/jobs/{job_id}/cancel", dependencies=[auth])
    def cancel_job(slug: str, job_id: int):
        case_dir_or_404(slug)
        return {"cancelled": manager.cancel(job_id)}

    # --- dashboard ----------------------------------------------------------

    @app.get("/api/cases/{slug}/dashboard", dependencies=[auth])
    def dashboard(slug: str):
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            severity = {r["severity"]: r["n"] for r in db.rows(
                conn, "SELECT severity, count(*) n FROM findings "
                      "WHERE triage != 'dismissed' GROUP BY severity")}
            triage = {r["triage"]: r["n"] for r in db.rows(
                conn, "SELECT triage, count(*) n FROM findings GROUP BY triage")}
            ioc_count = conn.execute("SELECT count(*) FROM iocs").fetchone()[0]
            admins = conn.execute(
                "SELECT count(*) FROM db_accounts WHERE admin = 1").fetchone()[0]
            accounts = conn.execute("SELECT count(*) FROM db_accounts").fetchone()[0]
            installs = db.rows(conn, "SELECT * FROM cms_installs ORDER BY root")
            evidence = db.rows(conn, "SELECT * FROM evidence ORDER BY kind")
            running = db.rows(conn,
                              "SELECT * FROM jobs WHERE state IN ('queued','running') "
                              "ORDER BY id DESC")
            for r in running:
                r["stats"] = json.loads(r.get("stats") or "{}")
        finally:
            conn.close()
        return {
            "severity": severity, "triage": triage, "iocs": ioc_count,
            "accounts": accounts, "admins": admins,
            "cms_installs": installs, "evidence": evidence,
            "jobs_running": running,
            "logs": logindex.overview(case_dir),
            "timeline": logindex.timeline(case_dir),
        }

    # --- findings -----------------------------------------------------------

    @app.get("/api/cases/{slug}/findings", dependencies=[auth])
    def findings_list(slug: str, severity: str = "", triage: str = "",
                      source: str = "", kind: str = "", search: str = "",
                      hide_confirmed: bool = False, hide_info: bool = False,
                      limit: int = 500, offset: int = 0):
        """The findings list. `hide_confirmed` / `hide_info` are what makes the
        default view the REMAINING WORK: decided findings and pure context
        (scanner noise) drop out until they are asked for. Nothing is deleted
        -- the counts below always describe the whole set."""
        case_dir = case_dir_or_404(slug)
        where, params = [], []
        if severity != "":
            where.append("severity = ?")
            params.append(int(severity))
        elif hide_info:
            where.append("severity < ?")
            params.append(db.SEV_INFO)
        if triage:
            where.append("triage = ?")
            params.append(triage)
        elif hide_confirmed:
            where.append("triage != 'confirmed'")
        if source:
            where.append("source = ?")
            params.append(source)
        if kind:
            where.append("artifact_kind = ?")
            params.append(kind)
        if search:
            where.append("(rule LIKE ? OR artifact LIKE ? OR evidence LIKE ?)")
            like = f"%{search}%"
            params += [like, like, like]
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        conn = db.connect(case_dir)
        try:
            total = conn.execute(
                f"SELECT count(*) FROM findings {clause}", params).fetchone()[0]
            rows = db.rows(conn,
                           f"SELECT * FROM findings {clause} "
                           f"ORDER BY severity, artifact, line "
                           f"LIMIT ? OFFSET ?", params + [min(limit, 2000), offset])
            counts = {
                "severity": {r["severity"]: r["n"] for r in db.rows(
                    conn, "SELECT severity, count(*) n FROM findings GROUP BY severity")},
                "triage": {r["triage"]: r["n"] for r in db.rows(
                    conn, "SELECT triage, count(*) n FROM findings GROUP BY triage")},
                "source": {r["source"]: r["n"] for r in db.rows(
                    conn, "SELECT source, count(*) n FROM findings GROUP BY source")},
            }
            # The evidence roots travel with the findings so the UI can show a
            # path the way an analyst thinks about it -- `images/shell.php`
            # under a named webroot, not 90 characters of absolute path.
            roots = db.rows(conn, "SELECT kind, path, label FROM evidence")
            return {"total": total, "findings": rows, "counts": counts,
                    "roots": roots}
        finally:
            conn.close()

    class TriageBody(BaseModel):
        fingerprints: list[str]
        state: str
        note: str = ""
        # CONFIRMING SPREADS ALONG THE ARTIFACT, dismissing does not. The
        # asymmetry is the point: deciding a file IS a webshell makes every
        # rule that fired on it a true observation about a malicious file.
        # Deciding that ONE rule was a false positive says nothing about the
        # others -- so that decision stays where the analyst put it.
        cascade: bool = True

    @app.post("/api/cases/{slug}/triage", dependencies=[auth])
    def set_triage(slug: str, body: TriageBody):
        case_dir = case_dir_or_404(slug)
        if body.state not in db.TRIAGE_STATES:
            raise HTTPException(400, f"state must be one of {db.TRIAGE_STATES}")
        conn = db.connect(case_dir)
        collected = []
        try:
            fingerprints = list(body.fingerprints)
            if body.state == "confirmed" and body.cascade and fingerprints:
                marks = ",".join("?" * len(fingerprints))
                artifacts = [r["artifact"] for r in db.rows(
                    conn, f"SELECT DISTINCT artifact FROM findings "
                          f"WHERE fingerprint IN ({marks})", fingerprints)]
                if artifacts:
                    amarks = ",".join("?" * len(artifacts))
                    fingerprints = [r["fingerprint"] for r in db.rows(
                        conn, f"SELECT fingerprint FROM findings "
                              f"WHERE artifact IN ({amarks})", artifacts)]
            body = body.model_copy(update={"fingerprints": fingerprints})
            marks = ",".join("?" * len(body.fingerprints))
            rows = db.rows(conn,
                           f"SELECT * FROM findings WHERE fingerprint IN ({marks})",
                           body.fingerprints)
            conn.execute(
                f"UPDATE findings SET triage = ?, triage_note = ?, triaged_at = ? "
                f"WHERE fingerprint IN ({marks})",
                [body.state, body.note, db.now()] + body.fingerprints)
            # Confirming collects the artifact into the IOC box -- provenance
            # is written at the moment of collection.
            if body.state == "confirmed":
                hashes = {}
                meta = db.one(conn, "SELECT value FROM meta WHERE key = 'webshell_hashes'")
                if meta:
                    hashes = json.loads(meta["value"] or "{}")
                for f in rows:
                    collected += _collect_confirmed(conn, case_dir, f, hashes)
            conn.commit()
        finally:
            conn.close()
        hub.publish({"type": "invalidate", "scope": "findings"})
        return {"updated": len(body.fingerprints), "collected": collected}

    def _collect_confirmed(conn, case_dir, finding, hashes):
        """The confirm chain: artifact into the box, plus the instant hunts
        that used to be follow-up jobs."""
        out = []
        kind = finding["artifact_kind"]
        artifact = finding["artifact"]
        rule = finding["rule"].lower()
        if kind == "file":
            tags = [ioclib.TAG_FINDING, ioclib.TAG_CONFIRMED]
            if finding["source"] == "webshell":
                tags.append(ioclib.TAG_WEBSHELL)
            db.add_ioc(conn, artifact, "path", tags,
                       origin=f"confirmed: {finding['rule']}")
            out.append({"value": artifact, "type": "path"})
            digest = hashes.get(artifact)
            if digest:
                db.add_ioc(conn, digest, "hash",
                           [ioclib.TAG_DERIVED, ioclib.TAG_CONFIRMED],
                           origin=f"sha-256 of {os.path.basename(artifact)}")
                out.append({"value": digest, "type": "hash"})
            # instant hunt: who requested this file name?
            name = os.path.basename(artifact.replace("\\", "/"))
            for hit in logindex.who_requested(case_dir, [name], limit=25):
                db.add_ioc(conn, hit["ip"], "ip", [ioclib.TAG_HUNT],
                           origin=f"requested {hit['name']} ({hit['hits']}×)")
                out.append({"value": hit["ip"], "type": "ip",
                            "hits": hit["hits"], "ok_hits": hit["ok_hits"]})
        elif kind == "client":
            tags = [ioclib.TAG_FINDING, ioclib.TAG_CONFIRMED]
            if "scanner" in rule:
                tags.append(ioclib.TAG_SCANNER)
            if "flood" in rule or "brute" in rule:
                tags.append(ioclib.TAG_BRUTE)
            if "successful" in rule:
                tags.append(ioclib.TAG_SUCCESS)
            db.add_ioc(conn, artifact, "ip", tags,
                       origin=f"confirmed: {finding['rule']}")
            out.append({"value": artifact, "type": "ip"})
        elif kind == "table":
            db.add_ioc(conn, artifact, "other",
                       [ioclib.TAG_FINDING, ioclib.TAG_CONFIRMED, ioclib.TAG_INJECTED],
                       origin=f"confirmed: {finding['rule']}")
            out.append({"value": artifact, "type": "other"})
            hosts = list(dict.fromkeys(
                ioclib.HOST_RE.findall(finding["evidence"] or "")))[:5]
            for host in hosts:
                db.add_ioc(conn, host, "domain",
                           [ioclib.TAG_DERIVED, ioclib.TAG_INJECTED],
                           origin=f"host in evidence of: {finding['rule']}")
                out.append({"value": host, "type": "domain"})
        return out

    _PREVIEW_MAX_BYTES = 2 * 1024 * 1024
    _PREVIEW_RADIUS = 14
    _PREVIEW_LINE_CAP = 400

    def _file_preview(path, line):
        """A bounded excerpt around the finding line. Evidence is hostile
        content, but it travels as TEXT in JSON and React renders it escaped
        -- same rule as the evidence excerpts."""
        try:
            with open(path, "rb") as fh:
                raw = fh.read(_PREVIEW_MAX_BYTES + 1)
        except OSError as e:
            return {"error": str(e)}
        truncated = len(raw) > _PREVIEW_MAX_BYTES
        if b"\x00" in raw[:8192]:
            return {"binary": True}
        text = raw[:_PREVIEW_MAX_BYTES].decode("utf-8", errors="replace")
        lines = text.splitlines()
        if line and 1 <= line <= len(lines):
            lo = max(0, line - 1 - _PREVIEW_RADIUS)
            hi = min(len(lines), line + _PREVIEW_RADIUS)
        else:
            lo, hi = 0, min(len(lines), 30)
        return {"from_line": lo + 1, "focus": line,
                "lines": [l[:_PREVIEW_LINE_CAP] for l in lines[lo:hi]],
                "total_lines": len(lines), "truncated": truncated}

    @app.get("/api/cases/{slug}/findings/{fingerprint}/context",
             dependencies=[auth])
    def finding_context(slug: str, fingerprint: str):
        """Everything needed to judge ONE finding in place: file metadata +
        code preview, the actor's profile for client findings, table facts
        for dump findings -- plus every sibling finding on the same artifact."""
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            f = db.one(conn, "SELECT * FROM findings WHERE fingerprint = ?",
                       (fingerprint,))
            if f is None:
                raise HTTPException(404, "unknown finding")
            siblings = db.rows(conn,
                               "SELECT fingerprint, severity, rule, line, triage "
                               "FROM findings WHERE artifact = ? AND fingerprint != ? "
                               "ORDER BY severity, line", (f["artifact"], fingerprint))
            out = {"siblings": siblings}
            kind = f["artifact_kind"]
            if kind == "file":
                path = f["artifact"]
                info = {"exists": os.path.isfile(path)}
                if info["exists"]:
                    try:
                        st = os.stat(path)
                        info["size"] = st.st_size
                        info["mtime"] = datetime.fromtimestamp(
                            st.st_mtime).isoformat(timespec="seconds")
                    except OSError:
                        pass
                    meta = db.one(conn, "SELECT value FROM meta "
                                        "WHERE key = 'webshell_hashes'")
                    hashes = json.loads(meta["value"] or "{}") if meta else {}
                    digest = hashes.get(path)
                    if not digest and info.get("size", 0) <= 32 * 1024 * 1024:
                        from server.engines.fsutil import sha256_of
                        digest = sha256_of(path)
                    info["sha256"] = digest or ""
                    info["in_upload_dir"] = webshell.in_upload_dir(path)
                    try:
                        with open(path, "rb") as fh:
                            head = fh.read(webshell.GUARD_SNIFF_BYTES)
                        info["cms_guard"] = bool(webshell.CMS_GUARD_RE.search(head))
                    except OSError:
                        info["cms_guard"] = None
                    info["preview"] = _file_preview(path, f["line"])
                out["file"] = info
                name = os.path.basename(path.replace("\\", "/"))
                out["hunt"] = logindex.who_requested(case_dir, [name], limit=15)
            elif kind == "client":
                out["actor"] = logindex.actor_profile(case_dir, f["artifact"])
            elif kind == "table":
                out["table"] = db.one(conn,
                                      "SELECT t.*, d.path AS dump_path, d.cms "
                                      "FROM db_tables t JOIN db_dumps d ON d.id = t.dump_id "
                                      "WHERE t.name = ?", (f["artifact"],))
            return out
        finally:
            conn.close()

    # --- looking at an evidence file ---------------------------------------
    # THE GUARD: a path from the client is only ever read when it resolves
    # INSIDE a registered evidence root of this case. Nothing else on the
    # machine is reachable through this endpoint, and the check runs on the
    # RESOLVED path, so `..` and symlinks cannot walk out of the tree.
    #
    # The content is returned as JSON DATA and rendered as text by React --
    # never served as a document. A malicious .html in a compromised webroot
    # therefore has nothing to execute in: it is a string in a <pre>, not a
    # page the browser parses.

    def _evidence_roots(case_dir):
        conn = db.connect(case_dir)
        try:
            return [r["path"] for r in db.rows(conn, "SELECT path FROM evidence")]
        finally:
            conn.close()

    def _within_evidence(case_dir, path):
        try:
            target = Path(path).resolve(strict=True)
        except (OSError, RuntimeError):
            raise HTTPException(404, "Datei nicht gefunden")
        for root in _evidence_roots(case_dir):
            try:
                root_resolved = Path(root).resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if target == root_resolved:
                return target
            try:
                target.relative_to(root_resolved)
                return target
            except ValueError:
                continue
        raise HTTPException(
            403, "Diese Datei liegt außerhalb der registrierten Evidence "
                 "dieses Falls und wird nicht gelesen.")

    _RAW_WINDOW = 256 * 1024          # bytes decoded per raw page
    _HEX_WINDOW = 16 * 1024           # bytes per hex page (1024 rows of 16)

    @app.get("/api/cases/{slug}/file", dependencies=[auth])
    def file_content(slug: str, path: str, mode: str = "raw", offset: int = 0):
        """One page of an evidence file, as raw text or as a hex dump."""
        case_dir = case_dir_or_404(slug)
        target = _within_evidence(case_dir, path)
        if not target.is_file():
            raise HTTPException(400, "Kein reguläres File")
        try:
            size = target.stat().st_size
            window = _HEX_WINDOW if mode == "hex" else _RAW_WINDOW
            offset = max(0, min(int(offset), size))
            with open(target, "rb") as fh:
                fh.seek(offset)
                chunk = fh.read(window)
        except OSError as e:
            raise HTTPException(400, f"Datei nicht lesbar: {e}")

        out = {"path": str(target), "size": size, "offset": offset,
               "length": len(chunk), "eof": offset + len(chunk) >= size,
               "mode": mode, "window": window,
               "binary": b"\x00" in chunk[:8192]}

        if mode == "hex":
            rows = []
            for i in range(0, len(chunk), 16):
                part = chunk[i:i + 16]
                rows.append({
                    "offset": offset + i,
                    "hex": " ".join(f"{b:02x}" for b in part),
                    # Printable ASCII only; everything else is a dot. Decoding
                    # bytes here would show mojibake as if it were content.
                    "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in part),
                })
            out["rows"] = rows
            return out

        text = chunk.decode("utf-8", errors="replace")
        # Line numbers are only honest from the start of the file; a page that
        # begins mid-file says so instead of inventing a first line number.
        out["from_line"] = 1 if offset == 0 else None
        out["lines"] = text.split("\n")
        return out

    class HuntBody(BaseModel):
        names: list[str]

    @app.post("/api/cases/{slug}/hunt", dependencies=[auth])
    def hunt(slug: str, body: HuntBody):
        """Who requested these file names -- instant, from the index."""
        case_dir = case_dir_or_404(slug)
        return {"hits": logindex.who_requested(case_dir, body.names)}

    # --- actors -------------------------------------------------------------

    @app.get("/api/cases/{slug}/actors", dependencies=[auth])
    def actors(slug: str, search: str = "", sort: str = "requests",
               flag: str = "", limit: int = 100, offset: int = 0):
        case_dir = case_dir_or_404(slug)
        result = logindex.actors_list(case_dir, search, sort, flag, limit, offset)
        ids = [a["ip_id"] for a in result["actors"]]
        sparks = logindex.actor_sparklines(case_dir, ids)
        conn = db.connect(case_dir)
        try:
            box_ips = {r["value"] for r in db.rows(
                conn, "SELECT value FROM iocs WHERE type = 'ip'")}
        finally:
            conn.close()
        for a in result["actors"]:
            a["sparkline"] = sparks["series"].get(a["ip_id"], [])
            a["in_box"] = a["ip"] in box_ips
        result["span"] = sparks["span"]
        return result

    class TraceBody(BaseModel):
        ips: list[str]
        from_epoch: int | None = None
        to_epoch: int | None = None
        limit: int = 2000
        offset: int = 0

    @app.post("/api/cases/{slug}/trace", dependencies=[auth])
    def trace(slug: str, body: TraceBody):
        case_dir = case_dir_or_404(slug)
        if not body.ips:
            raise HTTPException(400, "no client addresses given")
        return logindex.trace(case_dir, body.ips, body.from_epoch,
                              body.to_epoch, min(body.limit, 10000), body.offset)

    @app.get("/api/cases/{slug}/trace.csv", dependencies=[auth])
    def trace_csv(slug: str, ips: str):
        case_dir = case_dir_or_404(slug)
        wanted = [p.strip() for p in ips.split(",") if p.strip()]
        result = logindex.trace(case_dir, wanted, limit=200000)
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["Client", "Time", "Method", "URI", "Status", "Size",
                    "Referrer", "User-Agent", "Source"])
        for r in result["rows"]:
            stamp = ""
            if r["epoch"]:
                stamp = datetime.fromtimestamp(
                    r["epoch"] + (r["tz"] or 0), tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S")
            uri = r["uri"] or ""
            if uri and uri[0] in ("=", "+", "-", "@"):
                uri = "'" + uri
            w.writerow([r["client"], stamp, r["method"], uri, r["status"],
                        r["size"], r["referrer"], r["agent"], r["source"]])
        return Response(
            buf.getvalue(), media_type="text/csv",
            headers={"Content-Disposition":
                     f"attachment; filename=trace_{len(wanted)}_clients.csv"})

    class CollectBody(BaseModel):
        ips: list[str]

    @app.post("/api/cases/{slug}/actors/collect", dependencies=[auth])
    def collect_actors(slug: str, body: CollectBody):
        """Actors into the IOC box, tagged with what the logs saw them do."""
        case_dir = case_dir_or_404(slug)
        listed = logindex.actors_list(case_dir, limit=100000)
        by_ip = {a["ip"]: a for a in listed["actors"]}
        conn = db.connect(case_dir)
        added = 0
        try:
            for ip in body.ips:
                a = by_ip.get(ip)
                tags = [ioclib.TAG_ACTOR]
                origin = "actor: collected from the actors list"
                if a:
                    if a["scanner_uas"] != "[]":
                        tags.append(ioclib.TAG_SCANNER)
                    if a["login_posts"] >= logindex.BF_THRESHOLD:
                        tags.append(ioclib.TAG_BRUTE)
                    if a["login_redirects"] > 0 and a["login_posts"] >= logindex.BF_THRESHOLD:
                        tags.append(ioclib.TAG_SUCCESS)
                    origin = f"actor: {a['requests']} request(s)"
                db.add_ioc(conn, ip, "ip", tags, origin=origin)
                added += 1
            conn.commit()
        finally:
            conn.close()
        hub.publish({"type": "invalidate", "scope": "iocs"})
        return {"added": added}

    # --- IOC box ------------------------------------------------------------

    @app.get("/api/cases/{slug}/iocs", dependencies=[auth])
    def iocs_list(slug: str):
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            rows = db.rows(conn, "SELECT * FROM iocs ORDER BY added DESC, id DESC")
            for r in rows:
                r["tags"] = json.loads(r["tags"] or "[]")
            return rows
        finally:
            conn.close()

    class NewIoc(BaseModel):
        value: str
        type: str = ""
        note: str = ""

    @app.post("/api/cases/{slug}/iocs", dependencies=[auth])
    def add_ioc(slug: str, body: NewIoc):
        case_dir = case_dir_or_404(slug)
        value = body.value.strip()
        if not value:
            raise HTTPException(400, "empty value")
        ioc_type = body.type if body.type in ioclib.IOC_TYPES else ioclib.classify(value)
        conn = db.connect(case_dir)
        try:
            db.add_ioc(conn, value, ioc_type, [ioclib.TAG_ANALYST],
                       note=body.note, origin="added by the analyst")
            conn.commit()
        finally:
            conn.close()
        return {"ok": True, "type": ioc_type}

    class PatchIoc(BaseModel):
        type: str | None = None
        note: str | None = None

    @app.patch("/api/cases/{slug}/iocs/{ioc_id}", dependencies=[auth])
    def patch_ioc(slug: str, ioc_id: int, body: PatchIoc):
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            if body.type is not None:
                if body.type not in ioclib.IOC_TYPES:
                    raise HTTPException(400, f"type must be one of {ioclib.IOC_TYPES}")
                conn.execute("UPDATE iocs SET type = ? WHERE id = ?",
                             (body.type, ioc_id))
            if body.note is not None:
                conn.execute("UPDATE iocs SET note = ? WHERE id = ?",
                             (body.note, ioc_id))
            conn.commit()
            return {"ok": True}
        finally:
            conn.close()

    @app.delete("/api/cases/{slug}/iocs/{ioc_id}", dependencies=[auth])
    def delete_ioc(slug: str, ioc_id: int):
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            conn.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))
            conn.commit()
            return {"ok": True}
        finally:
            conn.close()

    @app.get("/api/cases/{slug}/iocs/export", dependencies=[auth])
    def export_iocs(slug: str, format: str = "csv"):
        case_dir = case_dir_or_404(slug)
        info = workspace.case_info(case_dir)
        conn = db.connect(case_dir)
        try:
            rows = db.rows(conn, "SELECT * FROM iocs ORDER BY type, value")
        finally:
            conn.close()
        stem = f"iocs_{info['slug']}"
        if format == "json":
            return Response(ioclib.to_json(rows, info["name"]),
                            media_type="application/json",
                            headers={"Content-Disposition":
                                     f"attachment; filename={stem}.json"})
        if format == "stix":
            return Response(ioclib.to_stix(rows, info["name"]),
                            media_type="application/json",
                            headers={"Content-Disposition":
                                     f"attachment; filename={stem}_stix.json"})
        return Response(ioclib.to_csv(rows), media_type="text/csv",
                        headers={"Content-Disposition":
                                 f"attachment; filename={stem}.csv"})

    # --- CMS inventory ------------------------------------------------------

    @app.get("/api/cases/{slug}/cms", dependencies=[auth])
    def cms_view(slug: str):
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            installs = db.rows(conn, "SELECT * FROM cms_installs ORDER BY root")
            items = db.rows(conn, "SELECT * FROM cms_items ORDER BY type, name")
        finally:
            conn.close()
        by_install = {}
        for item in items:
            by_install.setdefault(item["install_id"], []).append(item)
        for inst in installs:
            inst["items"] = by_install.get(inst["id"], [])
        return {"installs": installs}

    # --- database view ------------------------------------------------------

    @app.get("/api/cases/{slug}/database", dependencies=[auth])
    def database_view(slug: str):
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            dumps = db.rows(conn, "SELECT * FROM db_dumps ORDER BY path")
            for d in dumps:
                d["meta"] = json.loads(d["meta"] or "{}")
            tables = db.rows(conn,
                             "SELECT * FROM db_tables ORDER BY rows DESC, name")
            accounts = db.rows(conn,
                               "SELECT * FROM db_accounts "
                               "ORDER BY admin DESC, cms, login")
            findings = db.rows(conn,
                               "SELECT * FROM findings WHERE source = 'sqldb' "
                               "ORDER BY severity, artifact LIMIT 500")
        finally:
            conn.close()
        return {"dumps": dumps, "tables": tables, "accounts": accounts,
                "findings": findings}

    # --- websocket ----------------------------------------------------------

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket):
        if ws.query_params.get("token") != config.token:
            await ws.close(code=4401)
            return
        await ws.accept()
        queue = hub.subscribe()
        try:
            while True:
                event = await queue.get()
                await ws.send_json(event)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            hub.unsubscribe(queue)

    # --- SPA ----------------------------------------------------------------

    if (WEB_DIST / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=WEB_DIST / "assets"),
                  name="assets")

    def _index_html():
        index = WEB_DIST / "index.html"
        if not index.is_file():
            return ("<h1>SHELLHOUND</h1><p>Frontend build missing — run "
                    "<code>cd web && npm run build</code>.</p>")
        html = index.read_text(encoding="utf-8")
        if config.loopback:
            inject = f'<script>window.__SHELLHOUND_TOKEN__="{config.token}"</script>'
            html = html.replace("</head>", inject + "</head>")
        return html

    @app.get("/", response_class=HTMLResponse)
    def spa_root():
        return _index_html()

    @app.get("/favicon.svg")
    def favicon():
        icon = WEB_DIST / "favicon.svg"
        if icon.is_file():
            return Response(icon.read_bytes(), media_type="image/svg+xml")
        return PlainTextResponse("", status_code=404)

    return app
