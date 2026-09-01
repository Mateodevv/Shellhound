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
import hashlib
import io
import json
import os
import time
import uuid
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from server import case_report, correlation, coverage, db, enrich, geoip, huntrules
from server import iocs as ioclib
from server import opencti as openctilib
from server import opencti_case
from server import rules as rulelib, ruleswitch
from server import patterns as patternlib
from server import settings as settingslib, workspace
from server.artifacts import (ART_SQL, MUTED_CLAUSE, art_sql,
                              counts as artifact_counts, uri_path,
                              uri_targets, web_path)
from server.chain import case_chain
from server.i18n import lang_of
from server.i18n import t as _t
from server.config import Config
from server.engines import (cmsinventory, detect, errorlog, logindex,
                            sigmascan, sqldump, yarascan,
                            webrootdiff, webshell)
from server.events import hub
from server.jobs import manager

def _csv_safe(value):
    """One CSV cell that a spreadsheet will not execute.

    Excel and LibreOffice read a cell beginning with `=`, `+`, `-` or `@` as a
    formula, and `=cmd|'/c calc'!A1` in a user agent is a working command as
    soon as somebody opens the export. Every field in a log line comes off the
    wire, so every field is prefixed -- guarding only the URI, which is what
    this did, left the two most obvious ones open.

    A leading apostrophe is the conventional escape: spreadsheets drop it and
    show the text, and a reader that is not a spreadsheet sees the value with
    one visible marker rather than a silently changed one.
    """
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text


def _fs_time(value):
    """One filesystem timestamp in explicit UTC, or None when unavailable."""
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat(
            timespec="seconds").replace("+00:00", "Z")
    except (OSError, OverflowError, TypeError, ValueError):
        return None


def _file_metadata(st):
    """Portable filesystem facts without inventing a creation timestamp.

    POSIX ctime is metadata-change time, while Windows ctime is creation
    time. Keep those meanings in separate fields so the UI never labels the
    same number differently merely because the case moved platforms.
    """
    if st is None:
        return {"created_at": None, "modified_at": None,
                "accessed_at": None, "changed_at": None}
    birth = getattr(st, "st_birthtime", None)
    created = birth if birth is not None else (st.st_ctime if os.name == "nt" else None)
    changed = None if os.name == "nt" else st.st_ctime
    return {
        "created_at": _fs_time(created),
        "modified_at": _fs_time(st.st_mtime),
        "accessed_at": _fs_time(st.st_atime),
        "changed_at": _fs_time(changed),
    }


def _filesystem_key(value):
    """Match filesystem paths without collapsing distinct POSIX names."""
    normalized = str(value).replace("\\", "/")
    return normalized.casefold() if os.name == "nt" else normalized


def _find_web_dist():
    """The built interface -- under web/dist in the repository, under
    server/static in an installed package. Both routes, so that `pip install`
    works without a Node toolchain on the forensic machine and development in
    the repository stays unchanged."""
    here = Path(__file__).resolve().parent
    # A source checkout can also contain a staged server/static left behind by
    # a package build.  Prefer the live web build there; an installed package
    # has no sibling web/dist and naturally falls through to server/static.
    for candidate in (here.parent / "web" / "dist", here / "static"):
        if (candidate / "index.html").is_file():
            return candidate
    # Nothing built: the server runs anyway (the API is complete), and the
    # start page says what is missing.
    return here.parent / "web" / "dist"


WEB_DIST = _find_web_dist()

EVIDENCE_KINDS = ("webroot", "access_logs", "sql_dump", "reference")


def create_app(config: Config) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_app):
        # The event hub is shared by the HTTP routes and the WebSocket.  It
        # needs the loop uvicorn actually runs, not whichever loop happened to
        # exist while create_app assembled the routes.
        hub.attach_loop(asyncio.get_running_loop())
        yield

    app = FastAPI(title="SHELLHOUND", docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    app.state.config = config
    config.ensure_workspace()

    # --- auth ---------------------------------------------------------------

    def require_token(request: Request):
        token = request.headers.get("x-token") or request.query_params.get("token")
        if token != config.token:
            raise HTTPException(401, "invalid or missing token")

    auth = Depends(require_token)

    # --- language -----------------------------------------------------------

    def request_lang(request: Request) -> str:
        """The language the prose assembled HERE is written in.

        The browser sends it as a header on every API call; a download link
        cannot set headers and sends `?lang=` instead. Anything the server
        STORES stays English regardless -- see server/i18n.py."""
        return lang_of(request.headers.get("x-lang")
                       or request.query_params.get("lang"))

    lang_dep = Depends(request_lang)

    def request_tz(request: Request) -> str:
        """Which reading of the timestamps the prose assembled HERE uses.

        Travels exactly like the language, and for the same reason: parts of
        the chronology are sentences with times rendered into them, and a
        sentence cannot be re-rendered in the browser. What is STORED is
        untouched -- an epoch in UTC plus the offset from the log line."""
        raw = (request.headers.get("x-tz")
               or request.query_params.get("tz") or "utc").lower()
        return "utc" if raw == "utc" else "log"

    tz_dep = Depends(request_tz)

    def _pattern_error(exc, lang):
        """A validation message in the language of the request.

        The exception carries its own English text; the key only turns it
        into another language when the catalogue knows one."""
        return _t(lang, exc.key) if exc.key else str(exc)

    def case_dir_or_404(slug: str) -> Path:
        case_dir = workspace.resolve_case(config.workspace, slug)
        if case_dir is None:
            raise HTTPException(404, f"unknown case: {slug}")
        return case_dir

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
    def case_detail(slug: str, lang: str = lang_dep):
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
        info["log_index"] = logindex.status(
            case_dir, log_targets if log_targets else None, lang)
        return info

    class PatchCase(BaseModel):
        name: str | None = None
        reference: str | None = None
        notes: str | None = None

    @app.patch("/api/cases/{slug}", dependencies=[auth])
    def patch_case(slug: str, body: PatchCase):
        case_dir = case_dir_or_404(slug)
        return workspace.update_case(
            case_dir, name=body.name, reference=body.reference,
            notes=body.notes)

    @app.get("/api/cases/{slug}/summary", dependencies=[auth])
    def case_close_preview(slug: str):
        """What closing this case would pack away -- shown before it happens."""
        case_dir = case_dir_or_404(slug)
        return workspace.case_summary(case_dir)

    def _drain_jobs(case_dir, lang):
        """Cancel running jobs and wait for them out. An engine that is
        still running holds an open handle on case.db -- on Windows the
        removal of the working copy would fail with WinError 32, so both
        ways out of a case (archive and delete) refuse cleanly instead."""
        conn = db.connect(case_dir)
        try:
            live = [r["id"] for r in db.rows(
                conn, "SELECT id FROM jobs WHERE state IN ('queued','running')")]
        finally:
            conn.close()
        for job_id in live:
            manager.cancel(case_dir, job_id)
        if live:
            still_running = manager.wait_for(case_dir, live, timeout=20)
            if still_running:
                raise HTTPException(409, _t(lang, "err.jobsRunning"))
        return len(live)

    @app.post("/api/cases/{slug}/archive", dependencies=[auth])
    def archive(slug: str, lang: str = lang_dep):
        """Close the case: everything into one zip, working copy removed.
        Running jobs are cancelled first -- an engine still writing into a
        database that is being packed would archive a half-written case."""
        case_dir = case_dir_or_404(slug)
        cancelled = _drain_jobs(case_dir, lang)
        zip_path, summary = workspace.archive_case(config.workspace, case_dir)
        hub.publish({"type": "invalidate", "scope": "workspace"})
        return {"archive": str(zip_path), "file": zip_path.name,
                "summary": summary, "cancelled_jobs": cancelled}

    @app.delete("/api/cases/{slug}", dependencies=[auth])
    def delete_case(slug: str, lang: str = lang_dep):
        """Remove the case for good -- no archive, no way back.

        Deliberately NOT the default way out of a case (that is /archive):
        this exists for the test case, the duplicate, the wrong start.
        Working copy only -- registered evidence on disk is somebody's
        original data and is never touched."""
        case_dir = case_dir_or_404(slug)
        _drain_jobs(case_dir, lang)
        name = workspace.delete_case(case_dir)
        hub.publish({"type": "invalidate", "scope": "workspace"})
        return {"ok": True, "name": name}

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
    def add_evidence(slug: str, body: NewEvidence, lang: str = lang_dep):
        case_dir = case_dir_or_404(slug)
        if body.kind not in EVIDENCE_KINDS:
            raise HTTPException(400, f"kind must be one of {EVIDENCE_KINDS}")
        path = str(Path(body.path).expanduser())
        if not os.path.exists(path):
            raise HTTPException(400, _t(lang, "err.evidenceMissing", path=path))
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

    class GeoBody(BaseModel):
        ips: list[str]

    @app.post("/api/geo", dependencies=[auth])
    def geo(body: GeoBody, lang: str = lang_dep):
        """Countries for IPs, in one batch -- OFFLINE from the workspace MMDB.

        Independent of the case: the attribution of an address does not
        depend on it. Special ranges (private, loopback, documentation) come
        even WITHOUT a database -- the standard library knows those for
        certain, and in a log "the source IP is private" is often the more
        important statement than any country."""
        out = {}
        for ip in list(dict.fromkeys(body.ips))[:500]:
            info = geoip.lookup(config.workspace, ip, lang)
            if info is not None:
                out[ip] = info
        return {**geoip.status(config.workspace, lang), "results": out}

    @app.post("/api/geo/download", dependencies=[auth])
    def geo_download():
        """Fetch the DB-IP Country Lite into the workspace -- the ONLY place
        where this tool speaks outward, and only on an explicit click. No
        case data goes out: the request is a single file download from
        download.db-ip.com."""
        result = geoip.download(config.workspace)
        if not result.get("ok"):
            raise HTTPException(502, result.get("error", "download failed"))
        return result

    # --- settings and enrichment --------------------------------------------
    #
    # The GeoIP download used to be the ONLY thing this tool sent outward.
    # Enrichment adds a second door, and it is built like the first one: shut
    # by default, opened by the analyst, and never wider than one indicator
    # per click. What comes back is a foreign OPINION -- it is stored apart
    # from the findings and never moves a severity or a triage state.

    @app.get("/api/settings", dependencies=[auth])
    def settings_get():
        """The operator configuration. API KEYS NEVER COME BACK IN FULL --
        only whether one is set and its last four characters."""
        return settingslib.public(config.workspace)

    class KeyBody(BaseModel):
        service: str
        key: str = ""          # empty clears it: that is how a service is
                               # switched off, not a separate verb

    @app.post("/api/settings/key", dependencies=[auth])
    def settings_key(body: KeyBody):
        try:
            return settingslib.set_key(config.workspace, body.service, body.key)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e

    class AckBody(BaseModel):
        accepted: bool

    @app.post("/api/settings/enrichment-ack", dependencies=[auth])
    def settings_ack(body: AckBody):
        """The analyst has read what a lookup sends out. Until this is set,
        `enrich` refuses -- the same gate as the GeoIP confirmation."""
        return settingslib.set_ack(config.workspace, body.accepted)

    def _opencti_http_error(exc):
        if isinstance(exc, openctilib.OpenCtiError):
            raise HTTPException(exc.status, {"code": exc.code, "message": str(exc)}) from exc
        if isinstance(exc, opencti_case.CaseOpenCtiError):
            raise HTTPException(400, {"code": exc.code, "message": str(exc)}) from exc
        raise exc

    class OpenCtiSettingsBody(BaseModel):
        url: str | None = None
        token: str | None = None
        taxii_collection_url: str | None = None
        author_id: str | None = None
        author_name: str | None = None
        default_marking_id: str | None = None
        default_marking_name: str | None = None

    @app.get("/api/settings/opencti", dependencies=[auth])
    def opencti_settings_get():
        return settingslib.public(config.workspace)["opencti"]

    @app.put("/api/settings/opencti", dependencies=[auth])
    def opencti_settings_put(body: OpenCtiSettingsBody):
        values = body.model_dump(exclude_unset=True)
        # Reject malformed external URLs before persisting them. Empty values
        # intentionally clear the integration and therefore need no parsing.
        try:
            if values.get("url"):
                openctilib.validate_https_url(values["url"])
            if values.get("taxii_collection_url"):
                openctilib.validate_https_url(
                    values["taxii_collection_url"], "TAXII collection URL")
        except openctilib.OpenCtiError as exc:
            _opencti_http_error(exc)
        return settingslib.set_opencti(config.workspace, values)

    @app.post("/api/settings/opencti/test", dependencies=[auth])
    def opencti_settings_test():
        private = settingslib.opencti(config.workspace)
        try:
            with openctilib.OpenCtiClient(private) as client:
                result = client.test_connection()
        except openctilib.OpenCtiError as exc:
            _opencti_http_error(exc)
        public = settingslib.verify_opencti(config.workspace, result)
        return {"ok": True, "user": result.get("user", {}), "opencti": public}

    class EnrichBody(BaseModel):
        service: str           # virustotal | abuseipdb
        value: str             # THE one indicator; nothing else is sent
        refresh: bool = False

    @app.post("/api/cases/{slug}/enrich", dependencies=[auth])
    def enrich_one(slug: str, body: EnrichBody):
        """Ask one service about one indicator. Explicit, one at a time --
        there is no sweep and no background refresh."""
        case_dir = case_dir_or_404(slug)
        try:
            return enrich.lookup(config.workspace, case_dir, body.service,
                                 body.value, body.refresh)
        except enrich.EnrichError as e:
            raise HTTPException(502, str(e)) from e

    @app.get("/api/cases/{slug}/enrichment", dependencies=[auth])
    def enrichment_list(slug: str):
        """Everything already looked up in this case -- so a list can show
        its badges without one request per row."""
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            rows = db.rows(conn, "SELECT service, value, kind, fetched, payload "
                                 "FROM enrichment ORDER BY fetched DESC")
        finally:
            conn.close()
        for r in rows:
            try:
                r["result"] = json.loads(r.pop("payload") or "{}")
            except ValueError:
                r["result"] = {}
        return {"entries": rows}

    # --- OpenCTI -----------------------------------------------------------
    # Every operation is an analyst click. Reads become timestamped foreign
    # context; writes become immutable publication receipts. Neither path
    # calls a finding/triage function.

    def _opencti_config():
        try:
            return openctilib.validate_config(
                settingslib.opencti(config.workspace), require_verified=True)
        except openctilib.OpenCtiError as exc:
            _opencti_http_error(exc)

    class OpenCtiLookupTarget(BaseModel):
        kind: str
        value: str

    class OpenCtiLookupBody(BaseModel):
        targets: list[OpenCtiLookupTarget] = Field(default_factory=list)

    def _case_lookup_targets(case_dir, supplied):
        if supplied:
            raw = [(row.kind, row.value) for row in supplied]
        else:
            conn = db.connect(case_dir)
            try:
                raw = [(row["type"], row["value"]) for row in db.rows(
                    conn, "SELECT type,value FROM iocs ORDER BY id")]
                confirmed_files = [row["artifact"] for row in db.rows(
                    conn, "SELECT DISTINCT artifact FROM findings "
                          "WHERE artifact_kind='file' AND triage='confirmed' "
                          "ORDER BY artifact LIMIT 100")]
                for index, path in enumerate(confirmed_files):
                    try:
                        snap = opencti_case.file_snapshot(
                            conn, path, f"lookup-file:{index}")
                        raw.append(("hash", snap["hashes"]["SHA-256"]))
                    except opencti_case.CaseOpenCtiError:
                        continue
            finally:
                conn.close()
            actor_result = logindex.actors_list(
                case_dir, sort="evidence", limit=500, offset=0)
            raw.extend(("ip", row["ip"]) for row in actor_result["actors"])
        allowed = {"ip", "hash", "url", "domain", "email", "user", "path"}
        result, seen = [], set()
        for kind, value in raw:
            kind = str(kind).lower()
            if kind not in allowed:
                continue
            try:
                normalized = openctilib.normalize_value(kind, value)
            except ValueError:
                continue
            key = (kind, normalized)
            if key in seen:
                continue
            seen.add(key)
            result.append(key)
        # The bound is stated in the response, never a silent partial sweep.
        return result[:1000], max(0, len(result) - 1000)

    @app.post("/api/cases/{slug}/opencti/lookups", dependencies=[auth])
    def opencti_lookups(slug: str, body: OpenCtiLookupBody):
        case_dir = case_dir_or_404(slug)
        private = _opencti_config()
        targets, omitted = _case_lookup_targets(case_dir, body.targets)
        fetched = openctilib.utc_now()
        entries = []
        try:
            with openctilib.OpenCtiClient(private) as client:
                for kind, value in targets:
                    result = client.lookup(kind, value)
                    entries.append({"target_kind": kind, "target_key": value,
                                    "fetched_at": fetched, "result": result})
        except openctilib.OpenCtiError as exc:
            _opencti_http_error(exc)
        conn = db.connect(case_dir)
        try:
            for entry in entries:
                conn.execute(
                    "INSERT INTO opencti_lookup_snapshots"
                    "(target_kind,target_key,fetched_at,payload) VALUES(?,?,?,?) "
                    "ON CONFLICT(target_kind,target_key) DO UPDATE SET "
                    "fetched_at=excluded.fetched_at,payload=excluded.payload",
                    (entry["target_kind"], entry["target_key"], fetched,
                     json.dumps(entry["result"], ensure_ascii=False)))
            conn.commit()
        finally:
            conn.close()
        return {"entries": entries, "checked": len(entries), "omitted": omitted,
                "fetched_at": fetched}

    @app.get("/api/cases/{slug}/opencti/context", dependencies=[auth])
    def opencti_context(slug: str, kind: str = "", key: str = ""):
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            return {"entries": opencti_case.context_rows(conn, kind, key)}
        finally:
            conn.close()

    class OpenCtiPromoteBody(BaseModel):
        snapshot_id: int
        external_id: str
        value: str
        type: str
        note: str = ""

    @app.post("/api/cases/{slug}/opencti/context/promote", dependencies=[auth])
    def opencti_promote(slug: str, body: OpenCtiPromoteBody):
        case_dir = case_dir_or_404(slug)
        if body.type not in ioclib.IOC_TYPES or body.type == "other":
            raise HTTPException(400, "unsupported IOC type")
        try:
            normalized = openctilib.normalize_value(body.type, body.value)
        except ValueError as exc:
            raise HTTPException(400, "invalid IOC value") from exc
        conn = db.connect(case_dir)
        try:
            row = conn.execute(
                "SELECT payload FROM opencti_lookup_snapshots WHERE id=?",
                (body.snapshot_id,)).fetchone()
            if not row:
                raise HTTPException(404, "OpenCTI snapshot not found")
            payload = opencti_case.json_load(row[0], {})
            candidates = []
            candidates.extend(payload.get("matches") or [])
            candidates.extend(payload.get("related") or [])
            candidate = next((item for item in candidates
                              if str(item.get("id")) == body.external_id), None)
            if (not candidate or str(candidate.get("value") or "") != body.value
                    or candidate.get("ioc_type") != body.type
                    or not candidate.get("promotable")):
                raise HTTPException(409, "IOC is not a promotable value in this snapshot")
            ioc_id = db.add_ioc(
                conn, normalized, body.type, ["opencti", ioclib.TAG_ANALYST],
                note=body.note[:4000], origin="selected from OpenCTI context")
            conn.execute(
                "INSERT OR IGNORE INTO ioc_external_sources"
                "(ioc_id,provider,external_id,source_url,snapshot_id,added) "
                "VALUES(?,?,?,?,?,?)",
                (ioc_id, "opencti", body.external_id,
                 settingslib.opencti(config.workspace).get("url", ""),
                 body.snapshot_id, db.now()))
            conn.commit()
        finally:
            conn.close()
        hub.publish({"type": "invalidate", "scope": "iocs"})
        return {"ok": True, "ioc_id": ioc_id}

    class OpenCtiDraftItem(BaseModel):
        kind: str
        id: int | None = None
        value: str | None = None
        path: str | None = None
        indicator: bool = False

    class OpenCtiDraftBody(BaseModel):
        items: list[OpenCtiDraftItem] = Field(default_factory=list)
        summary: str = Field(default="", max_length=20000)
        marking_id: str = ""

    @app.get("/api/cases/{slug}/opencti/draft", dependencies=[auth])
    def opencti_draft_get(slug: str):
        conn = db.connect(case_dir_or_404(slug))
        try:
            return opencti_case.get_draft(conn)
        finally:
            conn.close()

    @app.put("/api/cases/{slug}/opencti/draft", dependencies=[auth])
    def opencti_draft_put(slug: str, body: OpenCtiDraftBody):
        conn = db.connect(case_dir_or_404(slug))
        try:
            return opencti_case.save_draft(conn, body.model_dump())
        finally:
            conn.close()

    @app.delete("/api/cases/{slug}/opencti/draft", dependencies=[auth])
    def opencti_draft_delete(slug: str):
        conn = db.connect(case_dir_or_404(slug))
        try:
            opencti_case.delete_draft(conn)
            return {"ok": True}
        finally:
            conn.close()

    class OpenCtiPreviewBody(BaseModel):
        publication_id: str | None = None

    def _uuid_or_new(value):
        try:
            return str(uuid.UUID(str(value))) if value else str(uuid.uuid4())
        except ValueError as exc:
            raise HTTPException(400, "invalid publication id") from exc

    def _preview_response(built, publication_id):
        files = [{key: row.get(key) for key in
                  ("relative_path", "name", "size", "hashes", "mime_type",
                   "artifact_stix_id")}
                 for row in built["uploads"]]
        return {"publication_id": publication_id,
                "fingerprint": built["fingerprint"],
                "report_id": built["report_id"], "case": built["case"],
                "summary": built["summary"], "marking": built["marking"],
                "author": built["author"], "files": files,
                "objects": built["bundle"]["objects"],
                "object_count": len(built["bundle"]["objects"])}

    @app.post("/api/cases/{slug}/opencti/preview", dependencies=[auth])
    def opencti_preview(slug: str, body: OpenCtiPreviewBody):
        case_dir = case_dir_or_404(slug)
        private = _opencti_config()
        publication_id = _uuid_or_new(body.publication_id)
        conn = db.connect(case_dir)
        try:
            draft = opencti_case.get_draft(conn)
        finally:
            conn.close()
        try:
            built = opencti_case.materialize(
                case_dir, private, draft, publication_id)
        except (opencti_case.CaseOpenCtiError, openctilib.OpenCtiError) as exc:
            _opencti_http_error(exc)
        conn = db.connect(case_dir)
        try:
            existing = conn.execute(
                "SELECT status FROM opencti_publications WHERE id=?",
                (publication_id,)).fetchone()
            if existing and existing["status"] != "previewed":
                raise HTTPException(409, {"code": "publication_exists",
                                          "message": "Publication id is no longer a preview"})
            _record_publication(conn, publication_id, built, "previewed")
        finally:
            conn.close()
        return _preview_response(built, publication_id)

    class OpenCtiPublishBody(BaseModel):
        publication_id: str
        expected_fingerprint: str
        confirm_duplicate: bool = False

    def _safe_snapshot(built):
        uploads = []
        for row in built["uploads"]:
            uploads.append({key: row.get(key) for key in
                            ("local_ref", "relative_path", "name", "size", "hashes",
                             "artifact_stix_id", "mime_type")})
        return {"bundle": built["bundle"], "uploads": uploads,
                "case": built["case"], "summary": built["summary"],
                "marking": built["marking"], "author": built["author"]}

    def _record_publication(conn, publication_id, built, status="publishing"):
        snapshot = _safe_snapshot(built)
        conn.execute("DELETE FROM opencti_publication_files WHERE publication_id=?",
                     (publication_id,))
        conn.execute(
            "INSERT INTO opencti_publications"
            "(id,report_stix_id,fingerprint,status,created_at,marking_id,"
            "marking_name,author_id,author_name,snapshot) VALUES(?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET report_stix_id=excluded.report_stix_id,"
            "fingerprint=excluded.fingerprint,status=excluded.status,"
            "marking_id=excluded.marking_id,marking_name=excluded.marking_name,"
            "author_id=excluded.author_id,author_name=excluded.author_name,"
            "snapshot=excluded.snapshot,error_code='',error_message='',taxii_result='{}'",
            (publication_id, built["report_id"], built["fingerprint"], status,
             db.now(), built["marking"].get("id", ""),
             built["marking"].get("name", ""), built["author"].get("id", ""),
             built["author"].get("name", ""), json.dumps(snapshot, ensure_ascii=False)))
        for upload in built["uploads"]:
            conn.execute(
                "INSERT INTO opencti_publication_files"
                "(publication_id,relative_path,sha256,size,device,inode,mtime_ns,"
                "artifact_stix_id,status) VALUES(?,?,?,?,?,?,?,?,'pending')",
                (publication_id, upload["relative_path"],
                 (upload.get("hashes") or {}).get("SHA-256", ""), upload["size"],
                 upload.get("device", ""), upload.get("inode", ""),
                 upload.get("mtime_ns", ""),
                 upload["artifact_stix_id"]))
        conn.commit()

    def _update_publication(conn, publication_id, status, error=None,
                            taxii_result=None):
        code = error.code if isinstance(error, openctilib.OpenCtiError) else ""
        message = str(error) if error else ""
        conn.execute(
            "UPDATE opencti_publications SET status=?,completed_at=?,error_code=?,"
            "error_message=?,taxii_result=COALESCE(?,taxii_result) WHERE id=?",
            (status, db.now() if status in ("published", "partial", "failed") else "",
             code, message, json.dumps(taxii_result, ensure_ascii=False)
             if taxii_result is not None else None, publication_id))
        conn.commit()

    def _upload_publication_files(case_dir, private, publication_id, client):
        conn = db.connect(case_dir)
        failures = 0
        try:
            publication = conn.execute(
                "SELECT marking_id FROM opencti_publications WHERE id=?",
                (publication_id,)).fetchone()
            pending = db.rows(
                conn, "SELECT * FROM opencti_publication_files "
                      "WHERE publication_id=? AND status!='uploaded' ORDER BY id",
                (publication_id,))
            for row in pending:
                try:
                    target = opencti_case.safe_file(conn, row["relative_path"])
                    before = target.stat()
                    expected_identity = (row.get("device") or "",
                                         row.get("inode") or "",
                                         row.get("mtime_ns") or "")
                    actual_identity = (str(before.st_dev), str(before.st_ino),
                                       str(before.st_mtime_ns))
                    if any(expected_identity) and expected_identity != actual_identity:
                        raise openctilib.OpenCtiError(
                            "file_changed", "Evidence file identity changed after preview", 409)
                    hashes = opencti_case.file_hashes(target)
                    if hashes.get("SHA-256") != row["sha256"] or before.st_size != row["size"]:
                        raise openctilib.OpenCtiError(
                            "file_changed", "Evidence file changed after preview", 409)
                    remote_id = client.find_observable_id(row["artifact_stix_id"])
                    client.upload_file(remote_id, str(target), publication["marking_id"])
                    after = target.stat()
                    after_hash = opencti_case.file_hashes(target).get("SHA-256")
                    if ((before.st_dev, before.st_ino, before.st_size,
                         before.st_mtime_ns) !=
                            (after.st_dev, after.st_ino, after.st_size,
                             after.st_mtime_ns) or after_hash != row["sha256"]):
                        raise openctilib.OpenCtiError(
                            "file_changed", "Evidence file changed during upload", 409)
                    conn.execute(
                        "UPDATE opencti_publication_files SET status='uploaded',"
                        "remote_id=?,error_code='',error_message='' WHERE id=?",
                        (remote_id, row["id"]))
                except (openctilib.OpenCtiError, opencti_case.CaseOpenCtiError,
                        OSError) as exc:
                    failures += 1
                    code = getattr(exc, "code", "file_error")
                    message = str(exc) if not isinstance(exc, OSError) else "Evidence file is not readable"
                    conn.execute(
                        "UPDATE opencti_publication_files SET status='failed',"
                        "error_code=?,error_message=? WHERE id=?",
                        (code, message, row["id"]))
                conn.commit()
            return failures
        finally:
            conn.close()

    @app.post("/api/cases/{slug}/opencti/publish", dependencies=[auth])
    def opencti_publish(slug: str, body: OpenCtiPublishBody):
        case_dir = case_dir_or_404(slug)
        private = _opencti_config()
        publication_id = _uuid_or_new(body.publication_id)
        conn = db.connect(case_dir)
        try:
            draft = opencti_case.get_draft(conn)
        finally:
            conn.close()
        try:
            built = opencti_case.materialize(case_dir, private, draft, publication_id)
        except (opencti_case.CaseOpenCtiError, openctilib.OpenCtiError) as exc:
            _opencti_http_error(exc)
        if built["fingerprint"] != body.expected_fingerprint:
            raise HTTPException(409, {"code": "preview_stale",
                                      "message": "Package changed; review the preview again"})
        conn = db.connect(case_dir)
        try:
            existing = conn.execute(
                "SELECT status,fingerprint,snapshot FROM opencti_publications WHERE id=?",
                (publication_id,)).fetchone()
            if (not existing or existing["status"] != "previewed"
                    or existing["fingerprint"] != built["fingerprint"]):
                raise HTTPException(409, {"code": "preview_missing",
                    "message": "Preview is missing or no longer current"})
            duplicate = conn.execute(
                "SELECT id,report_stix_id,created_at FROM opencti_publications "
                "WHERE fingerprint=? AND id<>? AND status IN ('published','partial') "
                "ORDER BY created_at DESC LIMIT 1",
                (built["fingerprint"], publication_id)).fetchone()
            if duplicate and not body.confirm_duplicate:
                raise HTTPException(409, {"code": "duplicate",
                    "message": "An identical package was already published",
                    "publication": dict(duplicate)})
            preview_snapshot = opencti_case.json_load(existing["snapshot"], {})
            preview_bundle = preview_snapshot.get("bundle")
            if not isinstance(preview_bundle, dict):
                raise HTTPException(409, {"code": "preview_invalid",
                    "message": "Stored preview is invalid; review it again"})
            _update_publication(conn, publication_id, "publishing")
        finally:
            conn.close()
        taxii_result = None
        try:
            with openctilib.OpenCtiClient(private) as client:
                # Publish the immutable bundle the analyst actually reviewed,
                # not a freshly rebuilt variant with new timestamps.
                taxii_result = client.taxii_push(preview_bundle)
                conn = db.connect(case_dir)
                try:
                    conn.execute(
                        "UPDATE opencti_publications SET taxii_result=? WHERE id=?",
                        (json.dumps(taxii_result, ensure_ascii=False), publication_id))
                    conn.commit()
                finally:
                    conn.close()
                failures = _upload_publication_files(
                    case_dir, private, publication_id, client)
        except openctilib.OpenCtiError as exc:
            conn = db.connect(case_dir)
            try:
                _update_publication(conn, publication_id, "failed", exc, taxii_result)
            finally:
                conn.close()
            _opencti_http_error(exc)
        conn = db.connect(case_dir)
        try:
            status = "partial" if failures else "published"
            _update_publication(conn, publication_id, status)
            if status == "published":
                opencti_case.delete_draft(conn)
            result = next(row for row in opencti_case.publication_rows(conn)
                          if row["id"] == publication_id)
        finally:
            conn.close()
        return result

    @app.get("/api/cases/{slug}/opencti/publications", dependencies=[auth])
    def opencti_publications(slug: str):
        conn = db.connect(case_dir_or_404(slug))
        try:
            return {"entries": opencti_case.publication_rows(conn)}
        finally:
            conn.close()

    @app.post("/api/cases/{slug}/opencti/publications/{publication_id}/retry",
              dependencies=[auth])
    def opencti_retry(slug: str, publication_id: str):
        case_dir = case_dir_or_404(slug)
        private = _opencti_config()
        publication_id = _uuid_or_new(publication_id)
        conn = db.connect(case_dir)
        try:
            row = conn.execute("SELECT * FROM opencti_publications WHERE id=?",
                               (publication_id,)).fetchone()
            if not row:
                raise HTTPException(404, "publication not found")
            snapshot = opencti_case.json_load(row["snapshot"], {})
            _update_publication(conn, publication_id, "publishing")
        finally:
            conn.close()
        taxii_result = None
        try:
            with openctilib.OpenCtiClient(private) as client:
                if row["status"] == "failed" or not opencti_case.json_load(
                        row["taxii_result"], {}):
                    taxii_result = client.taxii_push(snapshot.get("bundle") or {})
                failures = _upload_publication_files(
                    case_dir, private, publication_id, client)
        except openctilib.OpenCtiError as exc:
            conn = db.connect(case_dir)
            try:
                _update_publication(conn, publication_id, "failed", exc, taxii_result)
            finally:
                conn.close()
            _opencti_http_error(exc)
        conn = db.connect(case_dir)
        try:
            _update_publication(conn, publication_id,
                                "partial" if failures else "published",
                                taxii_result=taxii_result)
            result = next(row for row in opencti_case.publication_rows(conn)
                          if row["id"] == publication_id)
        finally:
            conn.close()
        return result

    @app.get("/api/cases/{slug}/coverage", dependencies=[auth])
    def log_coverage(slug: str, lang: str = lang_dep, tz: str = tz_dep):
        """Where the logs are SILENT, and whether the shape of the hole looks
        deliberate. No findings and no severities: a removed window and a
        quiet night look identical from here, so this points at the question
        rather than answering it."""
        return coverage.report(case_dir_or_404(slug), lang, tz)

    @app.get("/api/yara", dependencies=[auth])
    def yara_status():
        """Whether the analyst's own rules can run, and out of what.

        Distinguishes the two silences that look alike: no YARA installed
        versus no rules placed. "No YARA findings" must never be ambiguous
        between "the rules found nothing" and "there were no rules"."""
        return yarascan.status(config.workspace)

    @app.get("/api/rules", dependencies=[auth])
    def rules_list():
        """Every built-in rule and whether this workspace runs it."""
        return rulelib.public(config.workspace)

    class RuleSwitch(BaseModel):
        enabled: bool = True

    @app.post("/api/rules/{rule_id}/enabled", dependencies=[auth])
    def rules_toggle(rule_id: str, body: RuleSwitch, lang: str = lang_dep):
        """Switch a rule off for this workspace.

        It stops running; findings it already wrote stay where they are with
        their triage. A switch is not a retraction -- an artifact somebody
        confirmed does not stop being confirmed because the rule that pointed
        at it was later muted."""
        if rule_id not in rulelib.known_ids():
            raise HTTPException(404, _t(lang, "err.ruleUnknown"))
        return ruleswitch.set_enabled(config.workspace, rule_id, body.enabled)

    # --- the rule files, as things the analyst edits ----------------------
    # They live in the WORKSPACE, like the pattern library and for the same
    # reason: a rule set grows across cases. Editing them here rather than in
    # a text editor is only convenience -- the files stay plain `.yar` and can
    # still be dropped in by hand or pulled from a vendor feed.

    def _yara_error(exc, lang):
        if not exc.key:
            return str(exc)
        label = _t(lang, exc.key)
        detail = str(exc).strip()
        # The catalogue explains the class of error; the compiler says where
        # it is. Both are needed to repair a rule in the editor.
        return f"{label}: {detail}" if detail and detail != label else label

    @app.get("/api/yara/rules", dependencies=[auth])
    def yara_rules():
        return {"rules": yarascan.list_rules(config.workspace),
                "dir": yarascan.rules_dir(config.workspace),
                "available": yarascan.yara is not None}

    @app.get("/api/yara/rules/{name}", dependencies=[auth])
    def yara_rule_source(name: str, lang: str = lang_dep):
        try:
            return {"name": name,
                    "source": yarascan.read_rule(config.workspace, name)}
        except yarascan.RuleError as e:
            raise HTTPException(404, _yara_error(e, lang)) from e

    class RuleBody(BaseModel):
        source: str = ""

    @app.put("/api/yara/rules/{name}", dependencies=[auth])
    def yara_rule_write(name: str, body: RuleBody, lang: str = lang_dep):
        """Create or replace. Compiles first -- a rule that does not compile
        is one the next scan reports as skipped, and hearing that at save
        time is cheaper than hearing it in the middle of a case."""
        try:
            return yarascan.write_rule(config.workspace, name, body.source)
        except yarascan.RuleError as e:
            raise HTTPException(400, _yara_error(e, lang)) from e

    @app.delete("/api/yara/rules/{name}", dependencies=[auth])
    def yara_rule_delete(name: str, lang: str = lang_dep):
        try:
            return yarascan.delete_rule(config.workspace, name)
        except yarascan.RuleError as e:
            raise HTTPException(404, _yara_error(e, lang)) from e

    class RuleToggle(BaseModel):
        enabled: bool = True

    @app.post("/api/yara/rules/{name}/enabled", dependencies=[auth])
    def yara_rule_toggle(name: str, body: RuleToggle, lang: str = lang_dep):
        """Switched off, not deleted: a rule file may have come from a vendor
        feed, and parking it must not edit somebody else's text."""
        try:
            return yarascan.set_rule_enabled(config.workspace, name,
                                             body.enabled)
        except yarascan.RuleError as e:
            raise HTTPException(404, _yara_error(e, lang)) from e

    class DetectBody(BaseModel):
        folder: str

    @app.post("/api/detect", dependencies=[auth])
    def detect_evidence(body: DetectBody, lang: str = lang_dep):
        return detect.scan(body.folder, lang)

    # How many entries a directory yields at most. An upload folder with
    # 40,000 files should not bring the dialog to a halt; the response says
    # along that it was truncated.
    _LISTING_CAP = 2000

    @app.get("/api/pickpath", dependencies=[auth])
    def pickpath(path: str = ""):
        """Server-side folder browser -- directories AND files, plus the
        drives on Windows when no path is given.

        Files belong in it because not every piece of evidence is a folder: a
        SQL dump is a single file, and whoever cannot see it cannot select
        it either."""
        if not path.strip():
            if os.name == "nt":
                drives = []
                try:
                    drives = os.listdrives()
                except (OSError, AttributeError):
                    drives = [f"{c}:\\" for c in "CDEF" if os.path.exists(f"{c}:\\")]
                return {"path": "", "parent": None, "files": [],
                        "dirs": [{"name": d, "path": d} for d in drives],
                        "truncated": False}
            path = "/"
        p = Path(path).expanduser()
        if not p.is_dir():
            raise HTTPException(400, f"not a directory: {p}")
        dirs, files, truncated = _list_dir(p)
        parent = str(p.parent) if p.parent != p else None
        return {"path": str(p), "parent": parent, "dirs": dirs,
                "files": files, "truncated": truncated}

    def _list_dir(p):
        """(dirs, files, truncated) of one directory, alphabetically."""
        dirs, files, seen = [], [], 0
        try:
            with os.scandir(p) as it:
                for entry in it:
                    seen += 1
                    if seen > _LISTING_CAP:
                        return (sorted(dirs, key=lambda d: d["name"].lower()),
                                sorted(files, key=lambda f: f["name"].lower()),
                                True)
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            dirs.append({"name": entry.name, "path": entry.path})
                        elif entry.is_file(follow_symlinks=False):
                            try:
                                stat = entry.stat(follow_symlinks=False)
                                size = stat.st_size
                                metadata = _file_metadata(stat)
                            except OSError:
                                size = 0
                                metadata = _file_metadata(None)
                            files.append({"name": entry.name, "path": entry.path,
                                          "size": size, **metadata})
                    except OSError:
                        continue
        except OSError as e:
            raise HTTPException(400, f"cannot list {p}: {e}")
        return (sorted(dirs, key=lambda d: d["name"].lower()),
                sorted(files, key=lambda f: f["name"].lower()), False)

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
        run_id = uuid.uuid4().hex[:12]

        logs = by_kind.get("access_logs", [])
        if logs:
            paths = [e["path"] for e in logs]
            ids = [e["id"] for e in logs]

            def run_logs(ctx, paths=paths, ids=ids, case_dir=case_dir):
                stats = logindex.build(case_dir, paths, ctx, config.workspace)
                _mark_scanned(case_dir, ids, stats)
                return stats

            started.append({"kind": "index_logs",
                            "job": manager.submit(case_dir, "index_logs", run_logs,
                                                  run_id=run_id)})

            # The error logs sit in the same directory and were skipped by
            # the index -- they name files the access log structurally
            # cannot see. Own job: it reads the same directory but answers a
            # different question.
            def run_errors(ctx, paths=paths, case_dir=case_dir):
                return errorlog.scan(case_dir, paths, ctx, config.workspace)

            started.append({"kind": "errorlog",
                            "job": manager.submit(case_dir, "errorlog", run_errors,
                                                  run_id=run_id)})

            # The analyst's own SIGMA rules over the finished index. Its own
            # job because it is the log-side counterpart to the YARA one:
            # somebody else's rules, running after the thing they read has
            # been built. Nothing here if the sigma/ folder is empty.
            def run_sigma(ctx, case_dir=case_dir):
                return sigmascan.scan(case_dir, config.workspace, ctx)

            started.append({"kind": "sigma",
                            "job": manager.submit(case_dir, "sigma", run_sigma,
                                                  run_id=run_id)})

        webroots = by_kind.get("webroot", [])
        if webroots:
            paths = [e["path"] for e in webroots]
            ids = [e["id"] for e in webroots]

            def run_shell(ctx, paths=paths, ids=ids, case_dir=case_dir):
                stats = webshell.scan(case_dir, paths, ctx, config.workspace)
                _mark_scanned(case_dir, ids, stats)
                return stats

            def run_cms(ctx, paths=paths, case_dir=case_dir):
                return cmsinventory.scan(case_dir, paths, ctx)

            started.append({"kind": "webshell",
                            "job": manager.submit(case_dir, "webshell", run_shell,
                                                  run_id=run_id)})
            started.append({"kind": "cms",
                            "job": manager.submit(case_dir, "cms", run_cms,
                                                  run_id=run_id)})

            # The analyst's OWN rules, if there are any. Queued as its own
            # job so a slow rule set never holds up the shipped scan.
            if yarascan.status(config.workspace).get("rules"):
                def run_yara(ctx, paths=paths, case_dir=case_dir):
                    return yarascan.scan(case_dir, paths,
                                         workspace=config.workspace, ctx=ctx)

                started.append({"kind": "yara",
                                "job": manager.submit(case_dir, "yara", run_yara,
                                                      run_id=run_id)})

        dumps = by_kind.get("sql_dump", [])
        if dumps:
            paths = [e["path"] for e in dumps]
            ids = [e["id"] for e in dumps]

            def run_sql(ctx, paths=paths, ids=ids, case_dir=case_dir):
                stats = sqldump.scan(case_dir, paths, ctx, config.workspace)
                _mark_scanned(case_dir, ids, stats)
                return stats

            started.append({"kind": "sqldb",
                            "job": manager.submit(case_dir, "sqldb", run_sql,
                                                  run_id=run_id)})

        if not started:
            raise HTTPException(400, "no evidence registered — add paths first")
        return {"run_id": run_id, "started": started}

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
        case_dir = case_dir_or_404(slug)
        return {"cancelled": manager.cancel(case_dir, job_id)}

    # --- dashboard ----------------------------------------------------------

    @app.get("/api/cases/{slug}/dashboard", dependencies=[auth])
    def dashboard(slug: str, lang: str = lang_dep, tz: str = tz_dep):
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            # Counted in ARTIFACTS -- the same unit the findings view works
            # in. "14 Dateien" is the size of the job; the 119 rules that
            # fired on them are the evidence, not the workload.
            severity = {r["worst"]: r["n"] for r in db.rows(
                conn, f"WITH art AS ({ART_SQL}) SELECT worst, count(*) n "
                      f"FROM art WHERE triage != 'dismissed' GROUP BY worst")}
            triage = artifact_counts(conn)["triage"]
            confirmed_kinds = {r["artifact_kind"]: r["n"] for r in db.rows(
                conn, f"WITH art AS ({ART_SQL}) SELECT artifact_kind, count(*) n "
                      f"FROM art WHERE triage = 'confirmed' GROUP BY artifact_kind")}
            confirmed_severity = {r["worst"]: r["n"] for r in db.rows(
                conn, f"WITH art AS ({ART_SQL}) SELECT worst, count(*) n "
                      f"FROM art WHERE triage = 'confirmed' GROUP BY worst")}
            # A dashboard count without any names forces the analyst to leave
            # the overview before it answers the basic question "what was
            # confirmed?".  Keep the preview short, but balance it by entity
            # type so a case with many client artifacts does not hide every
            # confirmed file (or vice versa).
            confirmed_artifacts = db.rows(conn, f"""
                WITH art AS ({ART_SQL}), ranked AS (
                    SELECT artifact, artifact_kind, worst,
                           ROW_NUMBER() OVER (
                               PARTITION BY artifact_kind
                               ORDER BY worst, lower(artifact)
                           ) AS kind_rank
                    FROM art WHERE triage = 'confirmed'
                )
                SELECT artifact, artifact_kind, worst FROM ranked
                ORDER BY kind_rank,
                         CASE artifact_kind
                           WHEN 'file' THEN 0 WHEN 'table' THEN 1
                           WHEN 'dump' THEN 2 ELSE 3 END,
                         worst, lower(artifact)
                LIMIT 6
            """)
            findings_total = conn.execute(
                "SELECT count(*) FROM findings").fetchone()[0]
            ioc_count = conn.execute("SELECT count(*) FROM iocs").fetchone()[0]
            admins = conn.execute(
                "SELECT count(*) FROM db_accounts WHERE admin = 1").fetchone()[0]
            accounts = conn.execute("SELECT count(*) FROM db_accounts").fetchone()[0]
            installs = db.rows(conn, "SELECT * FROM cms_installs ORDER BY root")
            evidence = db.rows(conn, "SELECT * FROM evidence ORDER BY kind")
            # DECODED, like everywhere else this row is sent. It left here as
            # the raw JSON text from the column, so the same declared type
            # arrived as an object from the case detail and as a string from
            # here -- and reading a field off a string is `undefined` in the
            # browser rather than an error, so the component simply showed
            # nothing depending on which view had opened it.
            for e in evidence:
                e["stats"] = json.loads(e.get("stats") or "{}")
            running = db.rows(conn,
                              "SELECT * FROM jobs WHERE state IN ('queued','running') "
                              "ORDER BY id DESC")
            for r in running:
                r["stats"] = json.loads(r.get("stats") or "{}")
        finally:
            conn.close()

        # The dashboard names a handful of measured milestones, not an
        # inferred attack story.  Build them from the same chronology as the
        # dedicated view so timestamps, clock alignment and source labels
        # cannot drift between the two surfaces.
        chain = case_chain(case_dir, lang, tz, event_cap=None)
        events = chain["events"]
        observations = []
        seen = set()

        def observe(role, event):
            if event is None:
                return
            identity = (event["at"], event["kind"], event["title"],
                        event["artifact"])
            if identity in seen:
                return
            seen.add(identity)
            observations.append({
                key: event[key] for key in (
                    "at", "kind", "title", "detail", "source", "artifact",
                    "artifact_kind", "ip", "severity")
            } | {"role": role})

        observe("first", events[0] if events else None)
        first_success = next(
            (event for event in events if event["kind"] == "erfolg"), None)
        observe("first_success", first_success)
        observe("account", next(
            (event for event in events if event["kind"] == "konto"), None))
        observe("first_alert", next(
            (event for event in events if event["kind"] == "alarm"), None))
        observe("last", events[-1] if events else None)
        observations.sort(key=lambda event: event["at"])

        return {
            "severity": severity, "triage": triage, "iocs": ioc_count,
            "confirmed_kinds": confirmed_kinds,
            "confirmed_severity": confirmed_severity,
            "confirmed_artifacts": confirmed_artifacts,
            "findings_total": findings_total,
            "accounts": accounts, "admins": admins,
            "cms_installs": installs, "evidence": evidence,
            "jobs_running": running,
            "logs": logindex.overview(case_dir),
            "timeline": logindex.timeline(case_dir),
            "chronology": {
                "total_events": chain["total_events"],
                "event_span": chain["event_span"],
                "first_success_at": (first_success["at"]
                                     if first_success else None),
                "observations": observations,
                "gaps": chain["gaps"],
                "undated": len(chain["undated"]),
                "zone": chain["zone"],
                "tz_offsets": chain["tz_offsets"],
                "tz_mixed": chain["tz_mixed"],
            },
        }

    # --- the chronology of the case -----------------------------------------
    # Assembled in server/chain.py -- it is the one piece of narrative the
    # server writes, shared by this route and the JSON export.

    @app.get("/api/cases/{slug}/chain", dependencies=[auth])
    def chain(slug: str, lang: str = lang_dep, tz: str = tz_dep,
              limit: int = 80, offset: int = 0, order: str = "asc"):
        """One page of the evidential chronology.

        Pagination is a presentation concern, not an evidence gap: the
        response therefore carries an exact total and never files events
        beyond the current page as undated evidence.
        """
        if not 1 <= limit <= 200:
            raise HTTPException(422, "limit must be between 1 and 200")
        if offset < 0:
            raise HTTPException(422, "offset must not be negative")
        if order not in ("asc", "desc"):
            raise HTTPException(422, "order must be asc or desc")

        result = case_chain(case_dir_or_404(slug), lang, tz, event_cap=None)
        complete = result["events"]
        if order == "desc":
            complete = list(reversed(complete))
        result["events"] = complete[offset:offset + limit]
        result["offset"] = offset
        result["limit"] = limit
        result["order"] = order
        result["truncated"] = offset + len(result["events"]) < len(complete)
        return result

    @app.get("/api/cases/{slug}/activity", dependencies=[auth])
    def activity(slug: str):
        """Analyst decisions and analysis runs, newest first.

        The evidential chronology remains `/chain`; this is the audit trail
        of work performed on the case and deliberately does not pretend to be
        incident time.
        """
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            decisions = db.rows(
                conn, "SELECT * FROM triage_events ORDER BY id DESC LIMIT 100")
            jobs = db.rows(
                conn, "SELECT id, run_id, kind, state, created, started, "
                      "finished, stats FROM jobs ORDER BY id DESC LIMIT 100")
            for job in jobs:
                job["stats"] = json.loads(job.get("stats") or "{}")
            hunts = db.rows(
                conn, "SELECT id, pattern, label, ran_at, hits, clients "
                      "FROM hunt_runs ORDER BY id DESC LIMIT 50")
            return {"decisions": decisions, "jobs": jobs, "hunts": hunts}
        finally:
            conn.close()

    @app.get("/api/cases/{slug}/report.html", dependencies=[auth])
    def report_download(slug: str, sections: str = "", preview: bool = False,
                        lang: str = lang_dep, tz: str = tz_dep):
        """One offline, printable file containing the case's stated facts."""
        case_dir = case_dir_or_404(slug)
        cross_case = correlation.compare(config.workspace, slug)
        body, digest = case_report.render_bytes(
            case_dir, lang, tz, cross_case=cross_case,
            sections=(sections.split(",") if sections else None))
        return Response(
            body, media_type="text/html",
            headers={
                "Content-Disposition":
                    f"{'inline' if preview else 'attachment'}; "
                    f"filename=report_{case_dir.name}_{tz}.html",
                "X-Content-SHA256": digest,
                "X-Content-Type-Options": "nosniff",
            })

    class ClockBody(BaseModel):
        # Seconds, per source. 0 = the clocks hold as they stand.
        logs: int = 0
        dump: int = 0

    @app.post("/api/cases/{slug}/clock", dependencies=[auth])
    def set_clock(slug: str, body: ClockBody):
        """Set the clock offset. Limited to ±26h: more than one time-zone
        span plus drift is no longer an alignment but a typo."""
        case_dir = case_dir_or_404(slug)
        limit = 26 * 3600
        if abs(body.logs) > limit or abs(body.dump) > limit:
            raise HTTPException(400, "offset beyond ±26h")
        conn = db.connect(case_dir)
        try:
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('clock_offsets', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (json.dumps({"logs": body.logs, "dump": body.dump}),))
            conn.commit()
        finally:
            conn.close()
        return {"ok": True, "logs": body.logs, "dump": body.dump}

    # --- the global search ---------------------------------------------------

    _SEARCH_CAP = 8

    @app.get("/api/cases/{slug}/search", dependencies=[auth])
    def global_search(slug: str, q: str = ""):
        """ONE field across the whole case: artifacts, indicators, actors,
        accounts. With nine views, "where was that again…" otherwise turns
        into real friction -- and the answer always sits in exactly one of
        them.

        Every group is hard-capped: the palette is a springboard, not a
        result list. Whoever needs more than eight hits is better served by
        the respective view with its filters."""
        case_dir = case_dir_or_404(slug)
        term = q.strip()
        if len(term) < 2:
            return {"artifacts": [], "iocs": [], "actors": [], "accounts": []}
        like = "%" + (term.replace("\\", "\\\\").replace("%", "\\%")
                      .replace("_", "\\_")) + "%"
        conn = db.connect(case_dir)
        try:
            artifacts = db.rows(
                conn, f"WITH art AS ({ART_SQL}) "
                      f"SELECT artifact, artifact_kind, worst, triage, findings "
                      f"FROM art WHERE artifact LIKE ? ESCAPE '\\' "
                      f"ORDER BY worst LIMIT ?", (like, _SEARCH_CAP))
            iocs = db.rows(
                conn, "SELECT id, value, type, note FROM iocs "
                      "WHERE value LIKE ? ESCAPE '\\' OR note LIKE ? ESCAPE '\\' "
                      "ORDER BY added DESC LIMIT ?", (like, like, _SEARCH_CAP))
            accounts = db.rows(
                conn, "SELECT id, login, email, admin, tbl FROM db_accounts "
                      "WHERE login LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\' "
                      "LIMIT ?", (like, like, _SEARCH_CAP))
        finally:
            conn.close()
        # Actors from the log index -- the total population, including
        # clients without any finding. Whoever searches for an IP is usually
        # searching for exactly those.
        listed = logindex.actors_list(case_dir, search=term, limit=_SEARCH_CAP)
        actors = [{"ip": a["ip"], "requests": a["requests"],
                   "first_epoch": a["first_epoch"], "last_epoch": a["last_epoch"],
                   "tz": a["tz"], "alerts": len(a["alerts"])}
                  for a in listed["actors"]]
        return {"artifacts": artifacts, "iocs": iocs, "actors": actors,
                "accounts": accounts}

    # --- findings -----------------------------------------------------------
    #
    # THE UNIT OF WORK IS THE ARTIFACT, NOT THE SINGLE FINDING.
    #
    # Eight rules firing on one dropped shell are eight observations about ONE
    # file, and the analyst decides about the file: is this thing part of the
    # incident or not? Asking the same question eight times produced eight
    # answers that could contradict each other and a count that overstated the
    # case ("119 Findings" reads like 119 problems; it was 14 files).
    #
    # So severity, triage state and every filter below are computed PER
    # ARTIFACT: its worst severity, its decision. The individual findings
    # travel along as the evidence FOR that decision.

    # The artifact aggregate lives in server/artifacts.py: every query that
    # counts or lists artifacts has to fold the rows of one artifact the same
    # way, or the dashboard and the findings list count different things.

    @app.get("/api/cases/{slug}/findings", dependencies=[auth])
    def findings_list(slug: str, hide_severity: str = "", hide_triage: str = "",
                      hide_source: str = "", source: str = "", kind: str = "",
                      search: str = "",
                      show_retired: bool = False,
                      limit: int = 500, offset: int = 0):
        """The artifact list with the findings of every artifact attached.

        Legacy hide filters remove a class. `source` is the inclusive source
        facet used by the current UI: every chip directly says what remains
        visible, and a mixed-source artifact matches every source it carries.
        Every chip in the UI is a toggle
        that removes its class from view (`hide_severity=3,2` etc.) and
        brings it back on the next click. Several can stack. Nothing is
        deleted -- the counts always describe the whole set, and an artifact
        that IS shown always arrives COMPLETE: filtering must never hide part
        of what a decision is based on.

        `severity` is the artifact's worst finding, `triage` its decision.

        A SWITCHED-OFF RULE ALSO HIDES. An artifact whose findings ALL came
        from muted rules leaves the work list -- that is what switching a
        rule off is for. But only while it is still UNDECIDED: a confirmed or
        reviewed artifact stays, because the decision is the analyst's and a
        muted rule is not a retraction. Nothing is deleted either way, and
        the response says how many went, because a list that quietly shrinks
        is a list nobody can trust."""
        case_dir = case_dir_or_404(slug)
        muted = ruleswitch.disabled_ids(config.workspace)
        art = art_sql(muted)

        def csv_values(raw, allowed):
            return [v for v in (p.strip() for p in raw.split(",")) if v in allowed]

        where, params = [], []
        sevs = csv_values(hide_severity, {"0", "1", "2", "3"})
        if sevs:
            where.append(f"worst NOT IN ({','.join('?' * len(sevs))})")
            params += [int(s) for s in sevs]
        triages = csv_values(hide_triage, set(db.TRIAGE_STATES))
        if triages:
            where.append(f"triage NOT IN ({','.join('?' * len(triages))})")
            params += triages
        allowed_sources = {"webshell", "sqldb", "logs", "yara", "errorlog",
                           "analyst"}
        sources = csv_values(hide_source, allowed_sources)
        if sources:
            where.append(f"source NOT IN ({','.join('?' * len(sources))})")
            params += sources
        # New clients use an inclusive source facet. An artifact may have
        # findings from more than one engine (a custom YARA rule and the
        # shipped webshell rules on the same file), so filtering the single
        # representative `art.source` loses exactly those mixed artifacts.
        # Select through the underlying findings instead.
        selected_sources = csv_values(source, allowed_sources)
        if source:
            if selected_sources:
                where.append(
                    "artifact IN (SELECT DISTINCT artifact FROM findings "
                    f"WHERE source IN ({','.join('?' * len(selected_sources))}))")
                params += selected_sources
            else:
                where.append("0 = 1")
        if kind:
            where.append("artifact_kind = ?")
            params.append(kind)
        if search:
            # An artifact matches when ANY of its findings matches -- and then
            # shows all of them. A hit on one rule is a reason to look at the
            # file, not a reason to see only that rule.
            # ESCAPED, like every other list endpoint. Unescaped, `_` is a
            # single-character wildcard and `%` matches anything, so an analyst
            # searching for the table `wp_options` also got `wpXoptions` --
            # and a work list answering with rows nobody asked about is a work
            # list that has to be checked by hand. Table and column names are
            # full of underscores, which is what makes this bite here.
            where.append("artifact IN (SELECT artifact FROM findings "
                         "WHERE rule LIKE ? ESCAPE '\\' "
                         "OR artifact LIKE ? ESCAPE '\\' "
                         "OR evidence LIKE ? ESCAPE '\\')")
            like = "%" + (search.replace("\\", "\\\\").replace("%", "\\%")
                          .replace("_", "\\_")) + "%"
            params += [like, like, like]
        # The muted-rule filter, applied on top of the chip filters. Defined
        # in artifacts.py, brackets included -- see the note there on what
        # SQL's AND/OR precedence does to it without them.
        # `show_retired` widens it: the banner's toggle lets the analyst SEE
        # the undecided artifacts the last completed scan did not reproduce,
        # instead of only being told their number.
        muted_clause = MUTED_CLAUSE
        if show_retired:
            muted_clause = (f"({MUTED_CLAUSE} "
                            f"OR (findings = 0 AND retired > 0))")
        where.append(muted_clause)
        clause = "WHERE " + " AND ".join(where)
        conn = db.connect(case_dir)
        try:
            total = conn.execute(
                f"WITH art AS ({art}) SELECT count(*) FROM art {clause}",
                params).fetchone()[0]
            # How many left the list without the analyst hiding them, split
            # by WHY -- "the switches cost me N" and "M were not seen again"
            # are different sentences, and charging a retirement to the
            # switches would send somebody hunting through rule toggles for
            # a file that is simply gone. Same chip filters otherwise.
            without = [w for w in where if w is not muted_clause]
            silent_clause = ("WHERE " + " AND ".join(without)) if without else ""
            hidden = conn.execute(
                f"WITH art AS ({art}) SELECT count(*) FROM art "
                f"{silent_clause}", params).fetchone()[0] - total
            # Counted against the UNWIDENED clause on purpose: with the
            # toggle on, the retired ones sit in the list and `hidden` no
            # longer contains them -- but the banner they are toggled from
            # still has to say how many they are.
            retired_where = " AND ".join(
                without + [f"NOT {MUTED_CLAUSE}", "findings = 0",
                           "retired > 0"])
            retired_hidden = conn.execute(
                f"WITH art AS ({art}) SELECT count(*) FROM art "
                f"WHERE {retired_where}", params).fetchone()[0]
            muted_hidden = hidden - (0 if show_retired else retired_hidden)
            artifacts = db.rows(
                conn,
                f"WITH art AS ({art}) SELECT * FROM art {clause} "
                f"ORDER BY worst, artifact LIMIT ? OFFSET ?",
                params + [min(limit, 2000), offset])
            rows = []
            if artifacts:
                names = [a["artifact"] for a in artifacts]
                marks = ",".join("?" * len(names))
                # Retired rows travel too, marked: the interface shows them
                # greyed with the date they were last seen, because a row
                # that silently vanished from under a decision is exactly
                # what this column exists to prevent.
                rows = db.rows(conn,
                               f"SELECT f.*, CASE WHEN {db.LIVE_PREDICATE} "
                               f"THEN 0 ELSE 1 END AS retired "
                               f"FROM findings f {db.RETIRE_JOIN} "
                               f"WHERE f.artifact IN ({marks}) "
                               f"ORDER BY retired, f.severity, f.artifact, "
                               f"f.line", names)
            counts = artifact_counts(conn)
            # The evidence roots travel with the findings so the UI can show a
            # path the way an analyst thinks about it -- `images/shell.php`
            # under a named webroot, not 90 characters of absolute path.
            roots = db.rows(conn, "SELECT kind, path, label FROM evidence")
            return {"total": total, "artifacts": artifacts, "findings": rows,
                    "findings_total": conn.execute(
                        "SELECT count(*) FROM findings").fetchone()[0],
                    # Artifacts a switched-off rule took out of this list.
                    # Stated, not silent: a list that shrinks without saying
                    # so is a list nobody can trust.
                    "muted_hidden": muted_hidden,
                    # Undecided artifacts none of whose findings the last
                    # completed scans reproduced. Stated for the same reason.
                    "retired_hidden": retired_hidden,
                    "muted_rules": len(muted),
                    "counts": counts, "roots": roots}
        finally:
            conn.close()

    def _artifacts_of(conn, artifacts, fingerprints):
        """Resolve a triage request to the set of artifacts it touches. A
        fingerprint is accepted as a POINTER TO ITS ARTIFACT -- the decision
        belongs to the file, whichever of its rules the analyst clicked."""
        names = {str(a) for a in artifacts if str(a).strip()}
        fps = [str(f) for f in fingerprints if str(f).strip()]
        if fps:
            marks = ",".join("?" * len(fps))
            names |= {r["artifact"] for r in db.rows(
                conn, f"SELECT DISTINCT artifact FROM findings "
                      f"WHERE fingerprint IN ({marks})", fps)}
        return sorted(names)

    class TriageBody(BaseModel):
        # THE DECISION BELONGS TO THE ARTIFACT. Either name the artifacts
        # directly, or send fingerprints -- they are read as pointers to their
        # artifact, so an older client keeps working and gets the new
        # semantics: the whole file is decided, not one of its rules.
        artifacts: list[str] = []
        fingerprints: list[str] = []
        state: str
        # NOT "" BY DEFAULT. An empty string is a note the analyst wrote and
        # then cleared; no field at all is a caller that has no note to send.
        # The five bare confirm buttons and the bulk decision are the second
        # kind, and treating them as the first erased the sentence somebody
        # had typed while looking at the file.
        note: str | None = None
        # Whether a confirmation may travel along proven links (see
        # _propagate). Off for undo and for applying a suggestion -- those
        # must not start a second wave.
        propagate: bool = True

    @app.post("/api/cases/{slug}/triage", dependencies=[auth])
    def set_triage(slug: str, body: TriageBody):
        """Decide about artifacts. Every finding of an artifact carries the
        decision -- they are the evidence for it, not separate questions."""
        case_dir = case_dir_or_404(slug)
        if body.state not in db.TRIAGE_STATES:
            raise HTTPException(400, f"state must be one of {db.TRIAGE_STATES}")
        conn = db.connect(case_dir)
        collected = []
        retained_iocs = []
        try:
            artifacts = _artifacts_of(conn, body.artifacts, body.fingerprints)
            if not artifacts:
                return {"updated": 0, "artifacts": 0, "collected": [],
                        "linked": [], "suggested": [], "retained_iocs": []}
            marks = ",".join("?" * len(artifacts))
            previous = {row["artifact"]: row for row in db.rows(
                conn, f"WITH art AS ({ART_SQL}) SELECT artifact, artifact_kind, "
                      f"triage FROM art WHERE artifact IN ({marks})", artifacts)}
            rows = db.rows(conn,
                           f"SELECT * FROM findings WHERE artifact IN ({marks}) "
                           f"ORDER BY severity, line", artifacts)
            if body.note is None:
                # Deciding again is not retracting what was written.
                conn.execute(
                    f"UPDATE findings SET triage = ?, triaged_at = ? "
                    f"WHERE artifact IN ({marks})",
                    [body.state, db.now()] + artifacts)
            else:
                conn.execute(
                    f"UPDATE findings SET triage = ?, triage_note = ?, "
                    f"triaged_at = ? WHERE artifact IN ({marks})",
                    [body.state, body.note, db.now()] + artifacts)
            for artifact in artifacts:
                before = previous.get(artifact)
                if before and before["triage"] != body.state:
                    conn.execute(
                        "INSERT INTO triage_events (artifact, artifact_kind, "
                        "from_state, to_state, note, propagated, at) "
                        "VALUES (?,?,?,?,?,0,?)",
                        (artifact, before["artifact_kind"], before["triage"],
                         body.state, body.note or "", db.now()))
            # Confirming collects the artifact into the IOC box -- provenance
            # is written at the moment of collection -- and travels one step
            # along the links the log index can PROVE.
            linked, suggested = [], []
            if body.state == "confirmed":
                hashes = {}
                meta = db.one(conn, "SELECT value FROM meta WHERE key = 'webshell_hashes'")
                if meta:
                    hashes = json.loads(meta["value"] or "{}")
                by_artifact = {}
                for f in rows:
                    by_artifact.setdefault(f["artifact"], []).append(f)
                touches = _touches(conn, case_dir, by_artifact)
                for artifact, findings in by_artifact.items():
                    collected += _collect_confirmed(conn, case_dir, artifact,
                                                    findings, hashes,
                                                    touches.get(artifact, []))
                if body.propagate:
                    linked, suggested = _propagate(conn, case_dir,
                                                   set(artifacts), touches)
            else:
                # Removing a confirmation does not silently delete evidence
                # from the IOC box. It marks the structured provenance stale
                # and returns an explicit keep/review/remove decision.
                formerly_confirmed = [artifact for artifact in artifacts
                                      if artifact in previous and
                                      previous[artifact]["triage"] == "confirmed"]
                if formerly_confirmed:
                    retained_iocs = _retire_collected_iocs(
                        conn, formerly_confirmed)
            conn.commit()
        finally:
            conn.close()
        hub.publish({"type": "invalidate", "scope": "findings"})
        return {"updated": len(rows), "artifacts": len(artifacts),
                "collected": _dedupe_collected(collected),
                "linked": linked, "suggested": suggested,
                "retained_iocs": retained_iocs}

    class RemoveGeneratedIocsBody(BaseModel):
        ioc_ids: list[int] = []
        artifacts: list[str] = []

    @app.post("/api/cases/{slug}/triage/iocs/remove", dependencies=[auth])
    def remove_generated_iocs(slug: str, body: RemoveGeneratedIocsBody):
        """Remove only stale indicators created solely by withdrawn triage.

        A manually added IOC or one still backed by another confirmed
        artifact is never eligible, even if a client tampers with the ids in
        the request. The server rechecks the provenance instead of trusting
        the button state.
        """
        case_dir = case_dir_or_404(slug)
        ids = sorted({int(value) for value in body.ioc_ids if int(value) > 0})
        artifacts = sorted({str(value) for value in body.artifacts
                            if str(value).strip()})
        if not ids or not artifacts:
            return {"removed": [], "kept": ids}
        id_marks = ",".join("?" * len(ids))
        art_marks = ",".join("?" * len(artifacts))
        conn = db.connect(case_dir)
        removed = []
        try:
            candidates = db.rows(
                conn, "SELECT DISTINCT i.* FROM iocs i JOIN ioc_sources s "
                      "ON s.ioc_id = i.id "
                      f"WHERE i.id IN ({id_marks}) AND s.artifact IN "
                      f"({art_marks}) AND s.active = 0", ids + artifacts)
            for ioc in candidates:
                active = conn.execute(
                    "SELECT 1 FROM ioc_sources WHERE ioc_id = ? AND active = 1",
                    (ioc["id"],)).fetchone()
                try:
                    tags = set(json.loads(ioc.get("tags") or "[]"))
                except (TypeError, ValueError):
                    tags = set()
                if active or ioclib.TAG_ANALYST in tags:
                    continue
                conn.execute("DELETE FROM ioc_links WHERE src = ? OR dst = ?",
                             (ioc["id"], ioc["id"]))
                conn.execute("DELETE FROM ioc_sources WHERE ioc_id = ?",
                             (ioc["id"],))
                conn.execute("DELETE FROM ioc_external_sources WHERE ioc_id = ?",
                             (ioc["id"],))
                conn.execute("DELETE FROM iocs WHERE id = ?", (ioc["id"],))
                removed.append(ioc["id"])
            conn.commit()
        finally:
            conn.close()
        if removed:
            hub.publish({"type": "invalidate", "scope": "iocs"})
        return {"removed": removed, "kept": [value for value in ids
                                               if value not in removed]}

    # Nobody computes more than this in passing: a hash over a 2 GB file
    # leaves the request hanging. The same limit as in the detail view.
    _HASH_MAX_BYTES = 32 * 1024 * 1024

    _file_hash_cache = {}

    def _hashes_of(path):
        """Forensic comparison hashes in one bounded read of the file.

        MD5 and SHA-1 are compatibility identifiers, not security claims.
        The cache key includes size and nanosecond modification/metadata time,
        so an ordinarily changed file cannot keep the previous digest merely
        because its path stayed put.
        """
        try:
            if not os.path.isfile(path):
                return {}
            stat = os.stat(path)
            if stat.st_size > _HASH_MAX_BYTES:
                return {}
            key = (str(path), stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
            cached = _file_hash_cache.get(key)
            if cached is not None:
                return dict(cached)

            hashers = {}
            for name in ("md5", "sha1", "sha256"):
                try:
                    try:
                        hasher = hashlib.new(name, usedforsecurity=False)
                    except TypeError:  # Python/OpenSSL without the keyword
                        hasher = hashlib.new(name)
                except ValueError:  # Algorithm disabled by the local provider
                    continue
                hashers[name] = hasher
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    for hasher in hashers.values():
                        hasher.update(chunk)
            answer = {name: hasher.hexdigest()
                      for name, hasher in hashers.items()}
            if len(_file_hash_cache) >= 256:
                _file_hash_cache.clear()
            _file_hash_cache[key] = answer
            return dict(answer)
        except (OSError, ValueError):
            return {}

    def _sha256_of(path):
        """SHA-256 of an evidence file, or '' when too large/unreadable."""
        return _hashes_of(path).get("sha256", "")

    # --- what hangs on an artifact ---------------------------------------
    #
    # A DECISION SHOULD NOT BE MADE TWICE. Whoever decides a file to be a
    # true positive has thereby also decided about the clients that
    # demonstrably loaded it -- and the other way round. What was missing
    # was the proof of WHICH clients those are.
    #
    # The proof sits in the log index: the full URI plus status. Two tiers
    # follow from it, and only the first decides along:
    #   strong -- the client loaded EXACTLY this file and got a 2xx. It used
    #             the file; that is the same incident.
    #   medium -- same path, but never successful. A probe into the void is
    #             something other than an access, so it is suggested and not
    #             decided.
    # A bare name comparison ("some index.php") is NO proof and no longer
    # appears here at all.

    def _touches(conn, case_dir, by_artifact):
        """artifact -> [{ip, hits, ok_hits, uri}] for the file artifacts in
        it. One query for all names, the path comparison afterwards."""
        files = {a: web_path(conn, a) for a, findings in by_artifact.items()
                 if findings and findings[0]["artifact_kind"] == "file"}
        if not files:
            return {}
        names = [os.path.basename(p) for p in files.values()]
        rows = logindex.requests_for_names(case_dir, names)
        out = {}
        for artifact, rel in files.items():
            hits = {}
            for r in rows:
                if not uri_targets(r["uri"], rel):
                    continue
                agg = hits.setdefault(r["ip"], {"ip": r["ip"], "hits": 0,
                                                "ok_hits": 0, "uri": r["uri"]})
                agg["hits"] += r["hits"]
                agg["ok_hits"] += r["ok_hits"]
            out[artifact] = sorted(hits.values(),
                                   key=lambda h: (-h["ok_hits"], -h["hits"]))
        return out

    def _propagate(conn, case_dir, decided, touches):
        """A decision travels EXACTLY ONE STEP.

        What comes back is (linked, suggested): what was decided along --
        with the state from before, so the interface can take it back -- and
        what is only suggested. One step, no more: otherwise a confirmed file
        pulls clients along, which pull further files along, and in the end a
        whole case rests on one decision."""
        # Which artifacts exist at all, and where do they stand? A client
        # without a finding of its own is not an artifact -- it only lands in
        # the IOC box, as before.
        known = {r["artifact"]: r for r in db.rows(
            conn, f"WITH art AS ({ART_SQL}) "
                  f"SELECT artifact, artifact_kind, triage, triage_note FROM art")}
        # A propagation only touches what is NOT yet decided. A false
        # positive assigned by hand must never be overwritten by automation
        # -- and an already confirmed artifact needs neither a new note nor a
        # new timestamp.
        open_states = ("new", "reviewed")
        linked, suggested, seen = [], [], set(decided)

        def entry(artifact, why, hits=None, ok_hits=None):
            row = known[artifact]
            return {"artifact": artifact, "kind": row["artifact_kind"],
                    "why": why, "hits": hits, "ok_hits": ok_hits,
                    "previous": {"state": row["triage"],
                                 "note": row["triage_note"] or ""}}

        # --- file confirmed -> the clients that loaded it ------------------
        for artifact, hits in touches.items():
            label = os.path.basename(str(artifact).replace("\\", "/"))
            for h in hits:
                if h["ip"] in seen or h["ip"] not in known:
                    continue
                if known[h["ip"]]["artifact_kind"] != "client":
                    continue
                if known[h["ip"]]["triage"] not in open_states:
                    continue
                if h["ok_hits"] > 0:
                    seen.add(h["ip"])
                    linked.append(entry(
                        h["ip"], f"loaded {label} ({h['ok_hits']}× 2xx)",
                        h["hits"], h["ok_hits"]))
                else:
                    suggested.append(entry(
                        h["ip"], f"requested {label}, never successful "
                                 f"({h['hits']}×)", h["hits"], h["ok_hits"]))

        # --- client confirmed -> the files it loaded -----------------------
        clients = [a for a in decided
                   if known.get(a, {}).get("artifact_kind") == "client"]
        if clients:
            file_paths = {a: web_path(conn, a) for a, r in known.items()
                          if r["artifact_kind"] == "file"
                          and r["triage"] in open_states}
            if file_paths:
                rows = logindex.requests_for_names(
                    case_dir, [os.path.basename(p) for p in file_paths.values()])
                by_ip = {}
                for r in rows:
                    by_ip.setdefault(r["ip"], []).append(r)
                for ip in clients:
                    for artifact, rel in file_paths.items():
                        if artifact in seen:
                            continue
                        tail = "/" + rel
                        hit = [r for r in by_ip.get(ip, [])
                               if uri_path(r["uri"]).endswith(tail)]
                        if not hit:
                            continue
                        ok = sum(r["ok_hits"] for r in hit)
                        n = sum(r["hits"] for r in hit)
                        label = os.path.basename(str(artifact).replace("\\", "/"))
                        if ok > 0:
                            seen.add(artifact)
                            linked.append(entry(
                                artifact, f"loaded by {ip} ({ok}× 2xx)",
                                n, ok))
                        else:
                            suggested.append(entry(
                                artifact,
                                f"requested by {ip}, never successful ({n}×)",
                                n, ok))

        # The propagation itself: its own note, so the case records WHAT the
        # decision follows from and that it was not made by hand.
        for item in linked:
            note = f"propagated: {item['why']}"
            conn.execute(
                "UPDATE findings SET triage = 'confirmed', triage_note = ?, "
                "triaged_at = ? WHERE artifact = ?",
                (note, db.now(), item["artifact"]))
            conn.execute(
                "INSERT INTO triage_events (artifact, artifact_kind, "
                "from_state, to_state, note, propagated, at) "
                "VALUES (?,?,?,?,?,1,?)",
                (item["artifact"], item["kind"], item["previous"]["state"],
                 "confirmed", note, db.now()))
        return linked, suggested

    def _dedupe_collected(items):
        """One line per indicator in the confirmation receipt -- an artifact
        with six rules must not report the same IP six times."""
        seen, out = set(), []
        for item in items:
            key = (item["type"], item["value"])
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
        return out

    def _track_ioc(conn, ioc_id, artifact, role="direct"):
        """Record machine-readable provenance for a generated indicator."""
        conn.execute(
            "INSERT INTO ioc_sources (ioc_id, artifact, role, active, added) "
            "VALUES (?,?,?,?,?) ON CONFLICT(ioc_id, artifact, role) DO UPDATE "
            "SET active = 1, added = excluded.added",
            (ioc_id, artifact, role, 1, db.now()))

    def _retire_collected_iocs(conn, artifacts):
        marks = ",".join("?" * len(artifacts))
        conn.execute(f"UPDATE ioc_sources SET active = 0 WHERE artifact IN "
                     f"({marks})", artifacts)
        rows = db.rows(
            conn, "SELECT DISTINCT i.* FROM iocs i JOIN ioc_sources s "
                  f"ON s.ioc_id = i.id WHERE s.artifact IN ({marks}) "
                  "ORDER BY i.type, i.value", artifacts)
        out = []
        for ioc in rows:
            active = conn.execute(
                "SELECT 1 FROM ioc_sources WHERE ioc_id = ? AND active = 1",
                (ioc["id"],)).fetchone()
            try:
                tags = set(json.loads(ioc.get("tags") or "[]"))
            except (TypeError, ValueError):
                tags = set()
            sources = db.rows(
                conn, "SELECT artifact, role, active FROM ioc_sources "
                      "WHERE ioc_id = ? ORDER BY artifact", (ioc["id"],))
            out.append({
                "id": ioc["id"], "value": ioc["value"], "type": ioc["type"],
                "origin": ioc.get("origin") or "", "sources": sources,
                "removable": not active and ioclib.TAG_ANALYST not in tags,
            })
        return out

    def _collect_confirmed(conn, case_dir, artifact, findings, hashes,
                           touches=()):
        """The confirm chain for ONE artifact: the artifact into the box, plus
        the instant hunts that used to be follow-up jobs. Tags come from every
        rule that fired on it -- the decision was about all of them.

        `touches` are the clients that requested THIS PATH (see _touches).
        Earlier this matched the file NAME, which put every visitor of any
        `index.php` into the case file as soon as a shell happened to be
        called that."""
        out = []
        kind = findings[0]["artifact_kind"]
        rules = ", ".join(dict.fromkeys(f["rule"] for f in findings))[:200]
        rule_text = " ".join(f["rule"].lower() for f in findings)
        sources = {f["source"] for f in findings}
        origin = f"confirmed: {rules}"
        if kind == "file":
            tags = [ioclib.TAG_FINDING, ioclib.TAG_CONFIRMED]
            manual_webshell = any(
                f.get("rule_id") == "analyst.file_review" for f in findings)
            if "webshell" in sources or manual_webshell:
                tags.append(ioclib.TAG_WEBSHELL)
            # The path IN THE WEBROOT, never the absolute one. Where the
            # copy sits on the forensic machine is nobody's business outside
            # that machine -- and an export would otherwise carry it out.
            value = db.case_relative_path(conn, artifact)
            path_id = db.add_ioc(conn, value, "path", tags, origin=origin)
            _track_ioc(conn, path_id, artifact, "direct")
            out.append({"value": value, "type": "path"})
            # The hash from the scan, otherwise computed now: the detail
            # view shows it anyway, and a confirmed artifact without its
            # SHA-256 in the box would be a gap in the report.
            digest = hashes.get(artifact) or _sha256_of(artifact)
            if digest:
                hash_id = db.add_ioc(conn, digest, "hash",
                                     [ioclib.TAG_DERIVED, ioclib.TAG_CONFIRMED],
                                     origin=f"sha-256 of {os.path.basename(artifact)}")
                _track_ioc(conn, hash_id, artifact, "hash")
                # Path and hash describe THE SAME file. Only here is that
                # still known: afterwards the box holds two rows one cannot
                # tell it from.
                db.link_iocs(conn, hash_id, path_id, ioclib.LINK_HASH_OF)
                out.append({"value": digest, "type": "hash"})
            # instant hunt: who requested exactly this path?
            name = os.path.basename(artifact.replace("\\", "/"))
            for hit in list(touches)[:25]:
                tags = [ioclib.TAG_HUNT]
                if hit["ok_hits"] > 0:
                    tags.append(ioclib.TAG_SUCCESS)
                ip_id = db.add_ioc(conn, hit["ip"], "ip", tags,
                                   origin=f"requested {name} ({hit['hits']}×, "
                                          f"{hit['ok_hits']}× 2xx)")
                _track_ioc(conn, ip_id, artifact, "requester")
                db.link_iocs(conn, ip_id, path_id, ioclib.LINK_REQUESTED,
                             f"{hit['hits']}× requested, {hit['ok_hits']}× 2xx")
                out.append({"value": hit["ip"], "type": "ip",
                            "hits": hit["hits"], "ok_hits": hit["ok_hits"]})
        elif kind == "client":
            tags = [ioclib.TAG_FINDING, ioclib.TAG_CONFIRMED]
            if "scanner" in rule_text:
                tags.append(ioclib.TAG_SCANNER)
            if "flood" in rule_text or "brute" in rule_text:
                tags.append(ioclib.TAG_BRUTE)
            if "successful" in rule_text:
                tags.append(ioclib.TAG_SUCCESS)
            client_id = db.add_ioc(conn, artifact, "ip", tags, origin=origin)
            _track_ioc(conn, client_id, artifact, "direct")
            out.append({"value": artifact, "type": "ip"})
        elif kind == "table":
            table_id = db.add_ioc(
                conn, artifact, "other",
                [ioclib.TAG_FINDING, ioclib.TAG_CONFIRMED, ioclib.TAG_INJECTED],
                origin=origin)
            _track_ioc(conn, table_id, artifact, "direct")
            out.append({"value": artifact, "type": "other"})
            hosts = []
            for f in findings:
                hosts += ioclib.HOST_RE.findall(f["evidence"] or "")
            for host in list(dict.fromkeys(hosts))[:5]:
                host_id = db.add_ioc(conn, host, "domain",
                                     [ioclib.TAG_DERIVED, ioclib.TAG_INJECTED],
                                     origin=f"host in evidence of: {rules}")
                _track_ioc(conn, host_id, artifact, "derived-host")
                # WHERE the domain stood is half the statement: a domain
                # without a place of finding is a mere claim in a report.
                db.link_iocs(conn, host_id, table_id, ioclib.LINK_HOST_IN,
                             rules[:120])
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

    @app.get("/api/cases/{slug}/artifact", dependencies=[auth])
    def artifact_context(slug: str, artifact: str,
                         lang: str = lang_dep):
        """EVERYTHING about one artifact, in one answer -- this is the view an
        analyst decides from.

        Whatever the artifact is, the reply carries: every finding on it with
        its rule and evidence, the decision and its note, and the context that
        fits its kind (file metadata + code preview around the strongest hit,
        the actor profile of a client, the table behind a dump finding).

        `related_ips` is the pivot back into the logs: every address this
        artifact touches -- who requested the file, the client itself, any
        address left in the evidence -- with the note whether it is already in
        the IOC box. The UI turns each of them into a trace."""
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            findings = db.rows(conn,
                               "SELECT * FROM findings WHERE artifact = ? "
                               "ORDER BY severity, line", (artifact,))
            if not findings:
                raise HTTPException(404, "unknown artifact")
            kind = findings[0]["artifact_kind"]
            states = {f["triage"] for f in findings}
            state = ("confirmed" if "confirmed" in states
                     else "dismissed" if states == {"dismissed"}
                     else "reviewed" if "reviewed" in states else "new")
            notes = [f["triage_note"] for f in findings if f["triage_note"]]
            out = {
                "artifact": artifact, "kind": kind, "findings": findings,
                "triage": state, "triage_note": notes[0] if notes else "",
                "triaged_at": max((f["triaged_at"] or "" for f in findings),
                                  default=""),
                "worst": min(f["severity"] for f in findings),
                "sources": sorted({f["source"] for f in findings}),
            }
            # The preview focuses the line of the STRONGEST finding that named
            # one -- that is the line the analyst came here to read.
            focus = next((f["line"] for f in findings if f["line"]), None)
            hunt = []
            if kind == "file":
                path = artifact
                info = {"exists": os.path.isfile(path)}
                if info["exists"]:
                    try:
                        st = os.stat(path)
                        info["size"] = st.st_size
                        info["mtime"] = datetime.fromtimestamp(
                            st.st_mtime).isoformat(timespec="seconds")
                        info.update(_file_metadata(st))
                    except OSError:
                        pass
                    meta = db.one(conn, "SELECT value FROM meta "
                                        "WHERE key = 'webshell_hashes'")
                    hashes = json.loads(meta["value"] or "{}") if meta else {}
                    file_hashes = _hashes_of(path)
                    stored_sha256 = hashes.get(path)
                    if stored_sha256:
                        file_hashes["sha256"] = stored_sha256
                    info["hashes"] = file_hashes
                    info["hashes_limited"] = info.get("size", 0) > _HASH_MAX_BYTES
                    # Kept for archives and clients from before the grouped
                    # hash response existed.
                    info["sha256"] = file_hashes.get("sha256", "")
                    info["in_upload_dir"] = webshell.in_upload_dir(path)
                    try:
                        with open(path, "rb") as fh:
                            head = fh.read(webshell.GUARD_SNIFF_BYTES)
                        info["cms_guard"] = bool(webshell.CMS_GUARD_RE.search(head))
                    except OSError:
                        info["cms_guard"] = None
                    info["preview"] = _file_preview(path, focus)
                out["file"] = info
                # Who requested EXACTLY this file -- path, not name.
                name = os.path.basename(path.replace("\\", "/"))
                hunt = [dict(h, name=name) for h in
                        _touches(conn, case_dir, {artifact: findings}).get(
                            artifact, [])[:15]]
                out["hunt"] = hunt
            elif kind == "client":
                out["actor"] = logindex.actor_profile(case_dir, artifact)
            elif kind == "table":
                out["table"] = db.one(conn,
                                      "SELECT t.*, d.path AS dump_path, d.cms "
                                      "FROM db_tables t JOIN db_dumps d ON d.id = t.dump_id "
                                      "WHERE t.name = ?", (artifact,))
            elif kind == "dump":
                out["dump"] = db.one(conn, "SELECT * FROM db_dumps WHERE path = ?",
                                     (artifact,))
                if out["dump"]:
                    out["dump"]["meta"] = json.loads(out["dump"]["meta"] or "{}")
            out["related_ips"] = _related_ips(conn, kind, artifact,
                                              findings, hunt, lang)
            return out
        finally:
            conn.close()

    def _related_ips(conn, kind, artifact, findings, hunt, lang="en"):
        """Every client address this artifact points at, with WHY it is here.
        Ordered by how much it says: the client itself first, then whoever
        requested the file most often, then addresses left in the evidence."""
        box = {r["value"] for r in db.rows(
            conn, "SELECT value FROM iocs WHERE type = 'ip'")}
        out, seen = [], set()

        def add(ip, why, hits=None, ok_hits=None):
            ip = str(ip).strip()
            if not ip or ip in seen:
                return
            seen.add(ip)
            out.append({"ip": ip, "why": why, "hits": hits, "ok_hits": ok_hits,
                        "in_box": ip in box})

        if kind == "client":
            add(artifact, "this client")
        for hit in hunt:
            add(hit["ip"],
                (f"loaded {hit['name']} ({hit['ok_hits']}× 2xx)"
                 if hit["ok_hits"] else f"requested {hit['name']}, "
                                        f"never successful"),
                hit["hits"], hit["ok_hits"])
        for f in findings:
            for ip in ioclib.IP_RE.findall(f["evidence"] or "")[:10]:
                add(ip, _t(lang, "related.fromEvidence", rule=f["rule"]))
        return out[:40]

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

    def _within_evidence(case_dir, path, lang="en"):
        try:
            target = Path(path).resolve(strict=True)
        except (OSError, RuntimeError):
            raise HTTPException(404, _t(lang, "err.fileNotFound"))
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
        raise HTTPException(403, _t(lang, "err.outsideEvidence"))

    _RAW_WINDOW = 256 * 1024          # bytes decoded per raw page
    _HEX_WINDOW = 16 * 1024           # bytes per hex page (1024 rows of 16)

    @app.get("/api/cases/{slug}/file", dependencies=[auth])
    def file_content(slug: str, path: str, mode: str = "raw", offset: int = 0,
                     lang: str = lang_dep):
        """One page of an evidence file, as raw text or as a hex dump."""
        case_dir = case_dir_or_404(slug)
        target = _within_evidence(case_dir, path, lang)
        if not target.is_file():
            raise HTTPException(400, _t(lang, "err.notRegularFile"))
        try:
            stat = target.stat()
            size = stat.st_size
            window = _HEX_WINDOW if mode == "hex" else _RAW_WINDOW
            offset = max(0, min(int(offset), size))
            with open(target, "rb") as fh:
                fh.seek(offset)
                chunk = fh.read(window)
        except OSError as e:
            raise HTTPException(400, f"file not readable: {e}")

        out = {"path": str(target), "size": size, "offset": offset,
               "length": len(chunk), "eof": offset + len(chunk) >= size,
               "mode": mode, "window": window,
               "binary": b"\x00" in chunk[:8192], **_file_metadata(stat),
               "hashes": _hashes_of(str(target)),
               "hashes_limited": size > _HASH_MAX_BYTES}

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

    # --- pattern hunt -------------------------------------------------------
    # The library belongs to the WORKSPACE: created once, a pattern is ready
    # in every further case. The case only records what was searched for in
    # it -- including the runs without hits.

    @app.get("/api/patterns", dependencies=[auth])
    def patterns_list():
        """Both halves, switched-off entries included so the interface can
        offer them back. Each row says which half it came from."""
        rows = patternlib.library(config.workspace, include_disabled=True,
                                  include_archived=True)
        return {"patterns": rows,
                "path": str(patternlib.library_path(config.workspace)),
                "bundled": sum(1 for p in rows if p["source"] == "bundled"),
                "disabled": sum(1 for p in rows if not p["enabled"])}

    class NewPattern(BaseModel):
        # One or more paths. `pattern` is the older single-path form and is
        # still accepted so an import written by an earlier version lands.
        patterns: list[str] = []
        pattern: str = ""
        match: str = "any"      # how several paths combine, OVER CLIENTS
        name: str = ""
        cve: str = ""
        description: str = ""
        text: str = ""          # several at once (lines or JSON)
        rule: dict | None = None
        dsl: str = ""
        technology: str = ""

    class ValidatePattern(BaseModel):
        rule: dict | None = None
        dsl: str = ""

    def parsed_hunt_rule(rule=None, dsl=""):
        try:
            return (huntrules.parse_dsl(dsl) if str(dsl or "").strip()
                    else huntrules.normalise_rule(rule))
        except huntrules.RuleError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/api/patterns/validate", dependencies=[auth])
    def patterns_validate(body: ValidatePattern):
        rule = parsed_hunt_rule(body.rule, body.dsl)
        legacy = huntrules.legacy_projection(rule)
        return {"rule": rule, "rule_hash": huntrules.rule_hash(rule),
                "dsl": huntrules.to_dsl(rule), **legacy,
                "technology": huntrules.suggest_technology(
                    huntrules.to_dsl(rule))}

    @app.post("/api/patterns", dependencies=[auth])
    def patterns_add(body: NewPattern, lang: str = lang_dep):
        try:
            if body.text.strip():
                return patternlib.import_text(config.workspace, body.text)
            return {"added": 1, "skipped": 0, "invalid": 0,
                    "entry": patternlib.add(
                        config.workspace,
                        body.patterns or [body.pattern],
                        body.name, body.cve, body.description, body.match,
                        rule=(parsed_hunt_rule(body.rule, body.dsl)
                              if body.rule is not None or body.dsl.strip()
                              else None),
                        technology=body.technology)}
        except patternlib.PatternError as e:
            raise HTTPException(400, _pattern_error(e, lang)) from e

    class PatchPattern(BaseModel):
        patterns: list[str] | None = None
        match: str | None = None
        name: str | None = None
        cve: str | None = None
        description: str | None = None
        rule: dict | None = None
        dsl: str = ""
        technology: str | None = None
        expected_version: int | None = None
        archived: bool | None = None

    @app.patch("/api/patterns/{pattern_id}", dependencies=[auth])
    def patterns_patch(pattern_id: str, body: PatchPattern,
                       lang: str = lang_dep):
        try:
            canonical = (parsed_hunt_rule(body.rule, body.dsl)
                         if body.rule is not None or body.dsl.strip() else None)
            return patternlib.update(
                config.workspace, pattern_id, body.patterns, body.name,
                body.cve, body.description, body.match, rule=canonical,
                technology=body.technology,
                expected_version=body.expected_version,
                archived=body.archived)
        except patternlib.PatternError as e:
            status = 409 if e.key == "err.patternVersionConflict" else 400
            raise HTTPException(status, _pattern_error(e, lang)) from e

    class ClonePattern(BaseModel):
        disable_original: bool = False
        rule: dict | None = None
        dsl: str = ""
        name: str | None = None
        cve: str | None = None
        description: str | None = None
        technology: str | None = None

    @app.post("/api/patterns/{pattern_id}/clone", dependencies=[auth])
    def patterns_clone(pattern_id: str, body: ClonePattern,
                       lang: str = lang_dep):
        try:
            canonical = (parsed_hunt_rule(body.rule, body.dsl)
                         if body.rule is not None or body.dsl.strip() else None)
            return patternlib.clone(config.workspace, pattern_id,
                                    disable_original=body.disable_original,
                                    rule=canonical, name=body.name, cve=body.cve,
                                    description=body.description,
                                    technology=body.technology)
        except patternlib.PatternError as e:
            raise HTTPException(400, _pattern_error(e, lang)) from e

    @app.get("/api/patterns/{pattern_id}/versions", dependencies=[auth])
    def patterns_versions(pattern_id: str, lang: str = lang_dep):
        try:
            return {"versions": patternlib.versions(config.workspace,
                                                     pattern_id)}
        except patternlib.PatternError as e:
            raise HTTPException(404, _pattern_error(e, lang)) from e

    class RestorePattern(BaseModel):
        expected_version: int | None = None

    @app.post("/api/patterns/{pattern_id}/versions/{version}/restore",
              dependencies=[auth])
    def patterns_restore(pattern_id: str, version: int, body: RestorePattern,
                         lang: str = lang_dep):
        try:
            return patternlib.restore(config.workspace, pattern_id, version,
                                      body.expected_version)
        except patternlib.PatternError as e:
            status = 409 if e.key == "err.patternVersionConflict" else 400
            raise HTTPException(status, _pattern_error(e, lang)) from e

    @app.delete("/api/patterns/{pattern_id}", dependencies=[auth])
    def patterns_delete(pattern_id: str):
        """Deletes an own pattern, switches off a bundled one -- a bundled
        pattern lives in the package and would come back on the next start."""
        return patternlib.remove(config.workspace, pattern_id)

    class TogglePattern(BaseModel):
        enabled: bool = True

    @app.post("/api/patterns/{pattern_id}/enabled", dependencies=[auth])
    def patterns_toggle(pattern_id: str, body: TogglePattern,
                        lang: str = lang_dep):
        try:
            return patternlib.set_enabled(config.workspace, pattern_id,
                                          body.enabled)
        except patternlib.PatternError as e:
            raise HTTPException(400, _pattern_error(e, lang)) from e

    @app.get("/api/patterns/export", dependencies=[auth])
    def patterns_export():
        return Response(patternlib.export_text(config.workspace),
                        media_type="application/json",
                        headers={"Content-Disposition":
                                 "attachment; filename=hunt_patterns.json"})

    class RunHunt(BaseModel):
        # Empty = the whole library. The normal case is "run everything": a
        # library one has to trigger entry by entry is not used by anyone
        # after the third case.
        ids: list[str] = []

    class PreviewHunt(BaseModel):
        patterns: list[str] = []
        match: str = "any"

    def enrich_hunt_match(conn, match):
        """Attach only case-owned correlations to the clients on screen.

        Reputation is deliberately absent: this answers whether the same
        address is already a finding, a decision or an indicator in THIS
        case.  Those are measured relationships the analyst can act on.
        """
        clients = match.get("clients") or []
        ips = [client["ip"] for client in clients]
        states = {}
        boxed = set()
        if ips:
            # A multi-path ANY hunt can merge up to 200 clients per path.
            # Stay below SQLite builds that still cap parameters at 999.
            for start in range(0, len(ips), 800):
                chunk = ips[start:start + 800]
                marks = ",".join("?" * len(chunk))
                states.update({row["artifact"]: row for row in db.rows(
                    conn, f"WITH art AS ({ART_SQL}) "
                          f"SELECT artifact, triage, findings FROM art "
                          f"WHERE artifact_kind = 'client' "
                          f"AND artifact IN ({marks})", chunk)})
                boxed.update(row["value"] for row in db.rows(
                    conn, f"SELECT value FROM iocs WHERE type = 'ip' "
                          f"AND value IN ({marks})", chunk))
        for client in clients:
            state = states.get(client["ip"], {})
            client["triage"] = state.get("triage", "")
            client["finding_count"] = state.get("findings", 0)
            client["in_box"] = client["ip"] in boxed
        return match

    class HuntTestBody(BaseModel):
        pattern_id: str = ""
        rule: dict | None = None
        dsl: str = ""
        batch_id: str = ""

    def test_rule_from_body(body: HuntTestBody):
        entry = patternlib.find(config.workspace, body.pattern_id) \
            if body.pattern_id else None
        if body.rule is None and not body.dsl.strip():
            if not entry:
                raise HTTPException(400, "a hunt test needs a rule")
            return entry["rule"], entry
        return parsed_hunt_rule(body.rule, body.dsl), entry

    def store_hunt_test(case_dir, rule, entry=None, batch_id=""):
        match = logindex.match_rule(case_dir, rule)
        stamp = db.now()
        fingerprint = logindex.index_fingerprint(case_dir)
        encoded = json.dumps(match["rule"], ensure_ascii=False,
                             sort_keys=True, separators=(",", ":"))
        conn = db.connect(case_dir)
        try:
            enrich_hunt_match(conn, match)
            cur = conn.execute(
                "INSERT INTO hunt_tests(pattern_id,pattern_version,rule_hash,"
                "rule_json,dsl,tested_at,index_fingerprint,hits,ok_hits,clients,"
                "ok_clients,uris,first_epoch,last_epoch,tz,truncated,coverage_json,"
                "batch_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ((entry or {}).get("id", ""), int((entry or {}).get("version", 0)),
                 match["rule_hash"], encoded, huntrules.to_dsl(match["rule"]),
                 stamp, fingerprint, match["hits"], match["ok_hits"],
                 match["clients_total"], match["ok_clients"], match["uri_total"],
                 match["first_epoch"], match["last_epoch"], match["tz"],
                 int(bool(match.get("truncated") or match.get("clients_truncated")
                          or match.get("uris_truncated"))),
                 json.dumps(match["coverage"], separators=(",", ":")),
                 str(batch_id or "")))
            test_id = cur.lastrowid
            conn.commit()
        finally:
            conn.close()
        test = {"id": test_id, "pattern_id": (entry or {}).get("id", ""),
                "pattern_version": int((entry or {}).get("version", 0)),
                "rule_hash": match["rule_hash"], "rule": match["rule"],
                "dsl": huntrules.to_dsl(match["rule"]), "tested_at": stamp,
                "index_fingerprint": fingerprint, "coverage": match["coverage"],
                "hits": match["hits"], "ok_hits": match["ok_hits"],
                "clients": match["clients_total"],
                "ok_clients": match["ok_clients"],
                "uris": match["uri_total"],
                "first_epoch": match["first_epoch"],
                "last_epoch": match["last_epoch"], "tz": match["tz"],
                "truncated": bool(match.get("truncated")
                                  or match.get("clients_truncated")
                                  or match.get("uris_truncated")),
                "batch_id": str(batch_id or "")}
        return {"test": test, "result": match}

    @app.post("/api/cases/{slug}/hunt/tests", dependencies=[auth])
    def hunt_test_create(slug: str, body: HuntTestBody):
        case_dir = case_dir_or_404(slug)
        rule, entry = test_rule_from_body(body)
        return store_hunt_test(case_dir, rule, entry, body.batch_id)

    def public_hunt_test(row):
        item = dict(row)
        try:
            item["rule"] = json.loads(item.pop("rule_json"))
        except (ValueError, TypeError):
            item["rule"] = {}
            item.pop("rule_json", None)
        try:
            item["coverage"] = json.loads(item.pop("coverage_json"))
        except (ValueError, TypeError):
            item["coverage"] = {}
            item.pop("coverage_json", None)
        for key in ("truncated", "legacy"):
            item[key] = bool(item.get(key))
        return item

    @app.get("/api/cases/{slug}/hunt/tests", dependencies=[auth])
    def hunt_test_list(slug: str, pattern_id: str = "", limit: int = 100):
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            where = "WHERE pattern_id = ?" if pattern_id else ""
            params = [pattern_id] if pattern_id else []
            rows = db.rows(
                conn, "SELECT * FROM hunt_tests " + where +
                " ORDER BY id DESC LIMIT ?", params + [max(1, min(limit, 500))])
            return {"tests": [public_hunt_test(row) for row in rows]}
        finally:
            conn.close()

    class HuntClusterBody(BaseModel):
        cursor: str = ""
        limit: int = 200
        sort: str = "requests"
        direction: str = "desc"

    def hunt_test_or_404(case_dir, test_id):
        conn = db.connect(case_dir)
        try:
            row = db.one(conn, "SELECT * FROM hunt_tests WHERE id = ?", (test_id,))
        finally:
            conn.close()
        if not row:
            raise HTTPException(404, "hunt test not found")
        return public_hunt_test(row)

    def require_fresh_hunt_test(case_dir, test):
        current = logindex.index_fingerprint(case_dir)
        if not current or current != test.get("index_fingerprint"):
            raise HTTPException(409, "the access-log index changed; test again")

    @app.post("/api/cases/{slug}/hunt/tests/{test_id}/clusters",
              dependencies=[auth])
    def hunt_test_clusters(slug: str, test_id: int, body: HuntClusterBody):
        case_dir = case_dir_or_404(slug)
        test = hunt_test_or_404(case_dir, test_id)
        require_fresh_hunt_test(case_dir, test)
        try:
            return logindex.rule_clusters(case_dir, test["rule"], body.cursor,
                                          body.limit, body.sort, body.direction)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    class HuntApplyBody(BaseModel):
        cluster_keys: list[str] = Field(default_factory=list)
        pattern_id: str = ""
        expected_version: int | None = None
        pattern: dict = Field(default_factory=dict)
        disable_original: bool = True
        idempotency_key: str = ""

    def selected_hunt_clusters(case_dir, rule, wanted):
        wanted = set(wanted)
        found, cursor = {}, ""
        for _page in range(50):
            page = logindex.rule_clusters(case_dir, rule, cursor, 200)
            for cluster in page["clusters"]:
                if cluster["cluster_key"] in wanted:
                    found[cluster["cluster_key"]] = cluster
            if len(found) == len(wanted) or not page["next_cursor"]:
                break
            cursor = page["next_cursor"]
        if set(found) != wanted:
            raise HTTPException(409, "the selected request clusters changed; test again")
        return [found[key] for key in wanted]

    @app.post("/api/cases/{slug}/hunt/tests/{test_id}/apply",
              dependencies=[auth])
    def hunt_test_apply(slug: str, test_id: int, body: HuntApplyBody,
                        lang: str = lang_dep):
        if not body.cluster_keys or len(body.cluster_keys) > 200:
            raise HTTPException(400, "select between one and 200 request clusters")
        if len(set(body.cluster_keys)) != len(body.cluster_keys):
            raise HTTPException(400, "duplicate request cluster")
        case_dir = case_dir_or_404(slug)
        test = hunt_test_or_404(case_dir, test_id)
        require_fresh_hunt_test(case_dir, test)
        rule = huntrules.normalise_rule(test["rule"])
        metadata = body.pattern if isinstance(body.pattern, dict) else {}
        submitted = metadata.get("rule")
        if submitted is not None and huntrules.rule_hash(submitted) != test["rule_hash"]:
            raise HTTPException(409, "the pattern changed after this test")
        raw_key = body.idempotency_key.strip() or hashlib.sha256(
            json.dumps({"test": test_id, "source": body.pattern_id,
                        "version": body.expected_version,
                        "disable": body.disable_original,
                        "clusters": sorted(body.cluster_keys),
                        "pattern": metadata}, ensure_ascii=False,
                       sort_keys=True, separators=(",", ":"))
            .encode("utf-8")).hexdigest()
        conn = db.connect(case_dir)
        try:
            existing = db.one(
                conn, "SELECT id,pattern_id FROM hunt_applications "
                      "WHERE idempotency_key = ?", (raw_key,))
        finally:
            conn.close()
        if existing:
            saved = patternlib.find(config.workspace, existing["pattern_id"])
            if not saved:
                raise HTTPException(409, "the applied pattern no longer exists")
            return {"application_id": existing["id"], "pattern": saved,
                    "findings": 0, "already_applied": True}
        source = patternlib.find(config.workspace, body.pattern_id) \
            if body.pattern_id else None
        if source and body.expected_version is not None \
                and int(body.expected_version) != int(source["version"]):
            raise HTTPException(409, "the pattern version changed; reload it")
        try:
            if source and not metadata:
                if test["rule_hash"] != source["rule_hash"]:
                    raise HTTPException(409, "the saved pattern differs from this test")
                saved = source
            elif source and source["source"] == "own":
                saved = patternlib.update(
                    config.workspace, source["id"],
                    name=metadata.get("name", source["name"]),
                    cve=metadata.get("cve", source["cve"]),
                    description=metadata.get("description", source["description"]),
                    rule=rule,
                    technology=metadata.get("technology", source["technology"]),
                    expected_version=body.expected_version)
            elif source:
                changed = (
                    test["rule_hash"] != source["rule_hash"]
                    or metadata.get("name", source["name"]) != source["name"]
                    or metadata.get("cve", source["cve"]) != source["cve"]
                    or metadata.get("description", source["description"])
                    != source["description"]
                    or metadata.get("technology", source["technology"])
                    != source["technology"])
                if changed:
                    saved = patternlib.clone(
                        config.workspace, source["id"], rule=rule,
                        name=metadata.get("name", source["name"]),
                        cve=metadata.get("cve", source["cve"]),
                        description=metadata.get("description",
                                                 source["description"]),
                        technology=metadata.get("technology",
                                                source["technology"]),
                        disable_original=body.disable_original)
                else:
                    saved = source
            else:
                saved = patternlib.add(
                    config.workspace, [], metadata.get("name") or
                    ((source or {}).get("name") or "Hunt pattern"),
                    metadata.get("cve", (source or {}).get("cve", "")),
                    metadata.get("description",
                                 (source or {}).get("description", "")),
                    rule=rule,
                    technology=metadata.get("technology",
                                            (source or {}).get("technology", "")),
                    derived_from=None)
        except patternlib.PatternError as exc:
            status = 409 if exc.key == "err.patternVersionConflict" else 400
            raise HTTPException(status, _pattern_error(exc, lang)) from exc
        clusters = selected_hunt_clusters(case_dir, rule, body.cluster_keys)
        conn = db.connect(case_dir)
        try:
            cur = conn.execute(
                "INSERT INTO hunt_applications(test_id,pattern_id,pattern_version,"
                "rule_hash,applied_at,idempotency_key) VALUES (?,?,?,?,?,?)",
                (test_id, saved["id"], saved["version"], test["rule_hash"],
                 db.now(), raw_key))
            application_id = cur.lastrowid
            by_client = {}
            for cluster in clusters:
                evidence = [{"request_id": cluster["request_id"],
                             "uri": cluster["example_uri"]}]
                conn.execute(
                    "INSERT INTO hunt_application_clusters(application_id,"
                    "cluster_key,client,method,uri_pattern,status_class,requests,"
                    "ok_hits,first_epoch,last_epoch,evidence_json) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (application_id, cluster["cluster_key"], cluster["client"],
                     cluster["method"], cluster["uri_pattern"],
                     cluster["status_class"], cluster["requests"],
                     cluster["ok_hits"], cluster["first_epoch"],
                     cluster["last_epoch"], json.dumps(evidence,
                                                        separators=(",", ":"))))
                by_client.setdefault(cluster["client"], []).append(cluster)
            for client, selected in by_client.items():
                requests = sum(row["requests"] for row in selected)
                ok_hits = sum(row["ok_hits"] for row in selected)
                examples = ", ".join(row["example_uri"] for row in selected[:3])
                label = saved["name"] or saved["dsl"].splitlines()[0]
                db.upsert_finding(
                    conn, "logs", db.SEV_HIGH if ok_hits else db.SEV_LOW,
                    f"Selected Pattern Hunt evidence ({label}, v{saved['version']})",
                    "client", client,
                    evidence=(f"{requests} selected requests, {ok_hits} answered 2xx; "
                              f"test #{test_id}; examples: {examples}")[:400],
                    rule_id=f"hunt.{saved['id']}.v{saved['version']}")
            conn.commit()
        finally:
            conn.close()
        hub.publish({"type": "invalidate", "scope": "findings"})
        return {"application_id": application_id, "pattern": saved,
                "findings": len(by_client), "already_applied": False}

    class HuntBatchBody(BaseModel):
        ids: list[str] = Field(default_factory=list)

    @app.post("/api/cases/{slug}/hunt/batch-tests", dependencies=[auth])
    def hunt_batch_tests(slug: str, body: HuntBatchBody):
        case_dir = case_dir_or_404(slug)
        available = patternlib.library(config.workspace)
        wanted = ([entry for entry in available if entry["id"] in set(body.ids)]
                  if body.ids else available)
        if not wanted:
            raise HTTPException(400, "no active patterns selected")
        batch_id = uuid.uuid4().hex[:12]

        def work(ctx):
            hits = tests = 0
            for index, entry in enumerate(wanted):
                if ctx.cancelled():
                    break
                ctx.progress(index / len(wanted),
                             f"Testing {entry['name'] or entry['id']}")
                result = store_hunt_test(case_dir, entry["rule"], entry, batch_id)
                tests += 1
                hits += result["result"]["hits"]
            return {"tests": tests, "hits": hits, "batch_id": batch_id}

        job_id = manager.submit(case_dir, "hunt", work, run_id=batch_id)
        return {"job_id": job_id, "batch_id": batch_id,
                "patterns": len(wanted)}

    @app.post("/api/cases/{slug}/hunt/preview", dependencies=[auth])
    def hunt_preview(slug: str, body: PreviewHunt, lang: str = lang_dep):
        """Test an unsaved hypothesis without writing findings or history."""
        try:
            paths, mode = patternlib.validate_hypothesis(
                body.patterns, body.match)
        except patternlib.PatternError as e:
            raise HTTPException(400, _pattern_error(e, lang)) from e
        case_dir = case_dir_or_404(slug)
        match = logindex.match_patterns(case_dir, paths, mode)
        conn = db.connect(case_dir)
        try:
            return enrich_hunt_match(conn, match)
        finally:
            conn.close()

    @app.post("/api/cases/{slug}/hunt/run", dependencies=[auth])
    def hunt_run(slug: str, body: RunHunt):
        """Every pattern against the log index. Hits become findings on the
        CLIENT artifact -- so everything further runs through the existing
        triage instead of opening a second work list next to the first.

        Outcome-gated like the other log rules: answered with 2xx a hit is
        HIGH, a bare attempt stays LOW. That raises its review priority; the
        HTTP status alone does not prove that exploitation succeeded."""
        case_dir = case_dir_or_404(slug)
        # Enabled patterns only, both halves. A switched-off bundled pattern
        # is not run even when its id is asked for by name.
        available = patternlib.library(config.workspace)
        wanted = ([p for p in available if p["id"] in set(body.ids)]
                  if body.ids else available)
        if not wanted:
            return {"results": [], "findings": 0, "ran": 0}

        results, new_findings = [], 0
        conn = db.connect(case_dir)
        try:
            for entry in wanted:
                match = logindex.match_patterns(case_dir, entry["patterns"],
                                                entry["match"],
                                                request=entry.get("request"))
                name = entry["name"] or match["pattern"]
                request = entry.get("request") or {}
                conditions = []
                if request.get("methods"):
                    conditions.append("method=" + "/".join(
                        request["methods"]))
                if request.get("user_agents"):
                    conditions.append("user-agent=" + "/".join(
                        request["user_agents"]))
                condition_text = (" · " + ", ".join(conditions)
                                  if conditions else "")
                for client in match["clients"]:
                    ok = client["ok_hits"] > 0
                    rule = (f"Request matching a stored pattern ({name}) "
                            f"— {'answered 2xx' if ok else 'attempts only'}")
                    example = match["uris"][0]["uri"] if match["uris"] else ""
                    # Where the pattern came from travels into the case: a
                    # pattern this version ships is checkable by whoever
                    # reads the report, one the analyst wrote is not.
                    origin = ("shipped with SHELLHOUND"
                              if entry.get("source") == "bundled"
                              else "analyst's own pattern")
                    db.upsert_finding(
                        conn, "logs", db.SEV_HIGH if ok else db.SEV_LOW, rule,
                        "client", client["ip"],
                        evidence=(f"{client['hits']}× requested, of those "
                                  f"{client['ok_hits']}× 2xx · pattern: "
                                  f"{match['pattern']}{condition_text} "
                                  f"({origin}) · "
                                  f"e.g. {example}")[:400])
                    new_findings += 1
                enrich_hunt_match(conn, match)
                conn.execute(
                    "INSERT INTO hunt_runs (pattern, label, ran_at, hits,"
                    " ok_hits, clients, ok_clients, uris, first_epoch,"
                    " last_epoch, tz) VALUES (?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(pattern) DO UPDATE SET label=excluded.label,"
                    " ran_at=excluded.ran_at, hits=excluded.hits,"
                    " ok_hits=excluded.ok_hits, clients=excluded.clients,"
                    " ok_clients=excluded.ok_clients, uris=excluded.uris,"
                    " first_epoch=excluded.first_epoch,"
                    " last_epoch=excluded.last_epoch, tz=excluded.tz",
                    (match["pattern"], entry["name"], db.now(), match["hits"],
                     match["ok_hits"], match["clients_total"],
                     match["ok_clients"], match["uri_total"],
                     match["first_epoch"], match["last_epoch"], match["tz"]))
                results.append({**match, "id": entry["id"],
                                "name": entry["name"], "cve": entry["cve"]})
            conn.commit()
        finally:
            conn.close()
        if new_findings:
            hub.publish({"type": "invalidate", "scope": "findings"})
        return {"results": results, "findings": new_findings,
                "ran": len(wanted)}

    @app.get("/api/cases/{slug}/hunt/runs", dependencies=[auth])
    def hunt_runs(slug: str):
        """The record of this case: what was searched for, unsuccessfully
        included."""
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            return {"runs": db.rows(conn, "SELECT * FROM hunt_runs "
                                          "ORDER BY ok_hits DESC, hits DESC")}
        finally:
            conn.close()

    # --- clicking through the evidence -------------------------------------

    @app.get("/api/cases/{slug}/browse", dependencies=[auth])
    def browse(slug: str, path: str = "", lang: str = lang_dep):
        """Browse the registered evidence.

        Without `path` the roots themselves are the list -- one starts at
        what belongs to the case, not at the file system. Every deeper path
        runs through the same fence as the file viewer (_within_evidence, on
        the RESOLVED path), so that one cannot click one's way out of the
        evidence here.

        Every entry says right away whether it is already in the IOC box and
        whether findings sit on it -- otherwise one flags by hand what has
        long been recorded."""
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            roots = db.rows(conn, "SELECT kind, path, label FROM evidence "
                                  "ORDER BY kind, path")
            # The box carries CASE-RELATIVE paths -- the comparison
            # therefore runs on the same form, otherwise the browser would
            # never report "already recorded". The roots come out here; the
            # conversion itself is pure string work afterwards, without a
            # database.
            box = {str(r["value"]).replace("\\", "/").rstrip("/").lower()
                   for r in db.rows(conn, "SELECT value FROM iocs WHERE type = 'path'")}
            roots_abs = db.evidence_roots(conn)
            flagged = {str(r["artifact"]).replace("\\", "/").lower(): r
                       for r in db.rows(
                           conn, f"WITH art AS ({ART_SQL}) SELECT artifact, worst,"
                                 f" triage, findings FROM art "
                                 f"WHERE artifact_kind = 'file'")}
            reviewed = {_filesystem_key(r["artifact"]): r
                        for r in db.rows(
                            conn, "SELECT artifact, triage AS state, "
                                  "triage_note AS note, triaged_at AS at "
                                  "FROM findings WHERE artifact_kind = 'file' "
                                  "AND source = 'analyst' "
                                  "AND rule_id = 'analyst.file_review'")}
        finally:
            conn.close()

        if not path.strip():
            return {"path": "", "parent": None, "roots": roots, "dirs": [],
                    "files": [], "truncated": False}
        target = _within_evidence(case_dir, path, lang)
        if not target.is_dir():
            raise HTTPException(400, "not a directory")
        dirs, files, truncated = _list_dir(target)

        def relative(p):
            # ONE implementation, not a second one that drifts: this used to
            # be a hand-copied twin of the rule in db.py, and the day that
            # rule changed the browser went on marking `in_box` against the
            # old spelling -- every flagged file silently unflagged.
            return db.relative_to_evidence(roots_abs, p)

        def annotate(entry):
            key = entry["path"].replace("\\", "/").lower()
            hit = flagged.get(key)
            entry["in_box"] = relative(entry["path"]).lower() in box
            entry["relative"] = relative(entry["path"])
            entry["flagged"] = hit["findings"] if hit else 0
            entry["worst"] = hit["worst"] if hit else None
            entry["triage"] = hit["triage"] if hit else None
            entry["review"] = reviewed.get(_filesystem_key(entry["path"]))
            return entry

        # Within a root you may go up -- but only as far as the root.
        parent = str(target.parent)
        try:
            _within_evidence(case_dir, parent, lang)
        except HTTPException:
            parent = None
        return {"path": str(target), "parent": parent, "roots": roots,
                "dirs": dirs, "files": [annotate(f) for f in files],
                "truncated": truncated}

    class FlagBody(BaseModel):
        paths: list[str]
        note: str = ""

    class FileReviewBody(BaseModel):
        path: str = Field(min_length=1)
        state: str
        note: str = Field(default="", max_length=4000)

    @app.post("/api/cases/{slug}/files/review", dependencies=[auth])
    def review_file(slug: str, body: FileReviewBody, lang: str = lang_dep):
        """Record a manual file decision through the ordinary audit chain.

        The analyst observation is its own unmanaged finding: a later scanner
        run can neither claim nor retire it. Triage remains the decision axis,
        so a confirmed manual webshell appears in reports and produces the
        same path/hash provenance as a scanner-backed confirmation.
        """
        if body.state not in ("reviewed", "confirmed", "dismissed"):
            raise HTTPException(400, "state must be reviewed, confirmed or dismissed")
        note = body.note.strip()
        if body.state in ("confirmed", "dismissed") and not note:
            raise HTTPException(400, "a reason is required for a final file decision")

        case_dir = case_dir_or_404(slug)
        target = _within_evidence(case_dir, body.path, lang)
        if not target.is_file():
            raise HTTPException(400, _t(lang, "err.notRegularFile"))
        artifact = str(target)
        statements = {
            "reviewed": "Analyst reviewed the file; the decision remains open.",
            "confirmed": "Analyst classified the file as a webshell.",
            "dismissed": "Analyst reviewed the file and found no webshell evidence.",
        }
        conn = db.connect(case_dir)
        try:
            db.upsert_finding(
                conn, "analyst",
                db.SEV_HIGH if body.state == "confirmed" else db.SEV_INFO,
                "Manual file review", "file", artifact,
                evidence=statements[body.state], rule_id="analyst.file_review")
            conn.commit()
        finally:
            conn.close()

        result = set_triage(slug, TriageBody(
            artifacts=[artifact], state=body.state, note=note,
            # The file-review panel has no propagation receipt. Keep the
            # decision scoped to the file instead of silently deciding linked
            # artifacts the analyst cannot see in that workflow.
            propagate=False))
        return {**result, "review": {
            "state": body.state, "note": note,
            "at": db.now(),
        }}

    @app.post("/api/cases/{slug}/files/flag", dependencies=[auth])
    def flag_files(slug: str, body: FlagBody, lang: str = lang_dep):
        """Take files in as indicators by hand -- path AND SHA-256.

        The hash is the point: a path describes where something sat on THIS
        server, the hash recognises the same file anywhere. The origin says
        explicitly that a human decided this and not a rule."""
        case_dir = case_dir_or_404(slug)
        # CHECK FIRST, WRITE SECOND: _within_evidence opens the case
        # database itself, and doing that in the middle of an open write
        # transaction does not work -- the second connection runs into
        # "database is locked". Besides, it is the right order anyway: a
        # rejected path should have written nothing at all.
        targets = []
        for raw in body.paths:
            target = _within_evidence(case_dir, raw, lang)
            if target.is_file():
                targets.append(str(target))

        conn = db.connect(case_dir)
        added = []
        try:
            for path in targets:
                value = db.case_relative_path(conn, path)
                path_id = db.add_ioc(
                    conn, value, "path",
                    [ioclib.TAG_ANALYST, ioclib.TAG_MODIFIED],
                    note=body.note,
                    # Stored, therefore in the project language.
                    origin="marked by the analyst in the file browser")
                added.append({"value": value, "type": "path"})
                digest = _sha256_of(path)
                if digest:
                    hash_id = db.add_ioc(
                        conn, digest, "hash",
                        [ioclib.TAG_ANALYST, ioclib.TAG_DERIVED],
                        # Stored, and therefore English: it travels into every export.
                        origin=f"sha-256 of {os.path.basename(path)}")
                    db.link_iocs(conn, hash_id, path_id, ioclib.LINK_HASH_OF)
                    added.append({"value": digest, "type": "hash"})
            conn.commit()
        finally:
            conn.close()
        hub.publish({"type": "invalidate", "scope": "iocs"})
        return {"added": added}

    # --- Webroot-Diff --------------------------------------------------------

    class DiffBody(BaseModel):
        webroot_id: int
        reference_id: int

    @app.post("/api/cases/{slug}/diff/run", dependencies=[auth])
    def diff_run(slug: str, body: DiffBody, lang: str = lang_dep):
        """Webroot against reference copy, as a job -- two CMS trees are tens
        of thousands of files, and that does not belong in a request."""
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            rows = {r["id"]: r for r in db.rows(conn, "SELECT * FROM evidence")}
        finally:
            conn.close()
        webroot = rows.get(body.webroot_id)
        reference = rows.get(body.reference_id)
        if webroot is None or reference is None:
            raise HTTPException(404, "evidence not found")
        if body.webroot_id == body.reference_id:
            raise HTTPException(400, _t(lang, "err.sameTree"))
        for e in (webroot, reference):
            if not os.path.isdir(e["path"]):
                raise HTTPException(400, f"not a directory: {e['path']}")

        wid, wpath = webroot["id"], webroot["path"]
        rid, rpath = reference["id"], reference["path"]

        def run(ctx):
            return webrootdiff.run(ctx, wid, wpath, rid, rpath)

        return {"job": manager.submit(case_dir, "webroot_diff", run)}

    @app.get("/api/cases/{slug}/diff", dependencies=[auth])
    def diff_list(slug: str, hide_status: str = "", search: str = "",
                  limit: int = 500, offset: int = 0):
        """The result of the last comparison. Filters are hide switches as
        everywhere (`hide_status=extra,missing`)."""
        case_dir = case_dir_or_404(slug)
        hidden = [h.strip() for h in hide_status.split(",") if h.strip()]
        conn = db.connect(case_dir)
        try:
            where, params = [], []
            if hidden:
                marks = ",".join("?" * len(hidden))
                where.append(f"status NOT IN ({marks})")
                params += hidden
            if search.strip():
                where.append("path LIKE ? ESCAPE '\\'")
                params.append("%" + (search.strip().replace("\\", "\\\\")
                                     .replace("%", "\\%").replace("_", "\\_")) + "%")
            clause = ("WHERE " + " AND ".join(where)) if where else ""
            total = conn.execute(
                f"SELECT count(*) FROM webroot_diff {clause}", params).fetchone()[0]
            counts = {r["status"]: r["n"] for r in db.rows(
                conn, "SELECT status, count(*) n FROM webroot_diff GROUP BY status")}
            rows = db.rows(
                conn,
                f"SELECT * FROM webroot_diff {clause} "
                f"ORDER BY CASE status WHEN 'modified' THEN 0 WHEN 'extra' THEN 1 "
                f"WHEN 'too_big' THEN 2 ELSE 3 END, path "
                f"LIMIT ? OFFSET ?", params + [min(limit, 2000), offset])
            roots = {r["id"]: r for r in db.rows(
                conn, "SELECT id, path, label, kind FROM evidence")}
            ran_at = rows[0]["ran_at"] if rows else (db.one(
                conn, "SELECT ran_at FROM webroot_diff LIMIT 1") or {}).get("ran_at", "")
            # Which IOC paths are already in the box -- the button should not
            # offer what is done. Compared via the case-relative path.
            flagged = {r["value"] for r in db.rows(
                conn, "SELECT value FROM iocs WHERE type = 'path'")}
            webroot_row = next((roots.get(r["webroot_id"]) for r in rows), None)
            for r in rows:
                root = roots.get(r["webroot_id"])
                if root and r["status"] != "missing":
                    absolute = os.path.join(root["path"], r["path"].replace("/", os.sep))
                    r["absolute"] = absolute
                    r["in_box"] = db.case_relative_path(conn, absolute) in flagged
                else:
                    r["absolute"] = ""
                    r["in_box"] = False
            return {"total": total, "counts": counts, "rows": rows,
                    "ran_at": ran_at,
                    "webroot": dict(webroot_row) if webroot_row else None}
        finally:
            conn.close()

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
               flag: str = "", hide: str = "", triage_states: str = "",
               limit: int = 100, offset: int = 0):
        case_dir = case_dir_or_404(slug)
        hidden = [h.strip() for h in hide.split(",") if h.strip()]
        conn = db.connect(case_dir)
        try:
            box_ips = {r["value"] for r in db.rows(
                conn, "SELECT value FROM iocs WHERE type = 'ip'")}
            # The decision of the client artifact, if there is one: what has
            # long been decided in Findings has to be visible in Actors --
            # otherwise one re-assesses it here in one's head.
            triage_map = {r["artifact"]: r["triage"] for r in db.rows(
                conn, f"WITH art AS ({ART_SQL}) SELECT artifact, triage "
                      f"FROM art WHERE artifact_kind = 'client'")}
        finally:
            conn.close()
        indexed_triage_ips = set(logindex.actors_by_ip(
            case_dir, triage_map.keys()))
        allowed_states = set(db.TRIAGE_STATES)
        wanted_states = [state for state in (
            part.strip() for part in triage_states.split(",")
        ) if state in allowed_states]
        selected_ips = ({ip for ip, state in triage_map.items()
                         if state in wanted_states}
                        if wanted_states else None)
        result = logindex.actors_list(
            case_dir, search, sort, flag, hidden,
            max(1, min(limit, 200)), max(0, offset), selected_ips,
        )
        ids = [a["ip_id"] for a in result["actors"]]
        sparks = logindex.actor_sparklines(case_dir, ids)
        for a in result["actors"]:
            a["sparkline"] = sparks["series"].get(a["ip_id"], [])
            a["in_box"] = a["ip"] in box_ips
            a["triage"] = triage_map.get(a["ip"])
        result["span"] = sparks["span"]
        counts = logindex.actor_counts(case_dir)
        counts["triage"] = {
            state: sum(1 for ip, value in triage_map.items()
                       if ip in indexed_triage_ips and value == state)
            for state in db.TRIAGE_STATES
        }
        counts["ioc"] = len(box_ips)
        result["facets"] = counts
        # The threshold travels with the data instead of being repeated in
        # the frontend. The badges of a row and the "inconspicuous" filter
        # are the same statement, and the filter is evaluated in SQL against
        # BF_THRESHOLD -- a second copy in TypeScript would drift silently
        # the day this number changes, and the list would then contradict
        # itself.
        result["bf_threshold"] = logindex.BF_THRESHOLD
        return result

    @app.get("/api/cases/{slug}/actor", dependencies=[auth])
    def actor_detail(slug: str, ip: str):
        """One client as an investigation record, whether or not a finding
        exists for it. The artifact endpoint intentionally requires a finding;
        this profile also serves quiet clients selected from the full log
        population and keeps telemetry separate from the analyst decision."""
        case_dir = case_dir_or_404(slug)
        profile = logindex.actor_profile(case_dir, ip)
        if profile is None:
            raise HTTPException(404, "unknown client")
        relations = logindex.actor_relations(case_dir, ip)
        conn = db.connect(case_dir)
        try:
            aggregate = db.one(
                conn, f"WITH art AS ({ART_SQL}) SELECT * FROM art "
                      "WHERE artifact_kind = 'client' AND artifact = ?",
                (ip,),
            )
            findings = db.rows(
                conn, "SELECT * FROM findings WHERE artifact_kind = 'client' "
                      "AND artifact = ? ORDER BY severity, line", (ip,),
            )
            in_box = bool(db.one(
                conn, "SELECT id FROM iocs WHERE type = 'ip' AND value = ?",
                (ip,),
            ))
            if relations:
                peer_ips = [peer["ip"] for peer in relations]
                marks = ",".join("?" * len(peer_ips))
                peer_triage = {r["artifact"]: r["triage"] for r in db.rows(
                    conn, f"WITH art AS ({ART_SQL}) SELECT artifact, triage "
                          f"FROM art WHERE artifact_kind = 'client' "
                          f"AND artifact IN ({marks})", peer_ips)}
                peer_iocs = {r["value"] for r in db.rows(
                    conn, f"SELECT value FROM iocs WHERE type = 'ip' "
                          f"AND value IN ({marks})", peer_ips)}
                for peer in relations:
                    peer["triage"] = peer_triage.get(peer["ip"])
                    peer["in_box"] = peer["ip"] in peer_iocs
        finally:
            conn.close()
        return {
            **profile,
            "triage": aggregate["triage"] if aggregate else None,
            "triage_note": aggregate["triage_note"] if aggregate else "",
            "triaged_at": aggregate["triaged_at"] if aggregate else "",
            "worst": aggregate["worst"] if aggregate else None,
            "findings": findings,
            "in_box": in_box,
            "relations": relations,
        }

    class CompareActorsBody(BaseModel):
        ips: list[str]

    @app.post("/api/cases/{slug}/actors/compare", dependencies=[auth])
    def compare_actors(slug: str, body: CompareActorsBody):
        """Exact overlaps for a small, analyst-selected set of clients."""
        case_dir = case_dir_or_404(slug)
        try:
            result = logindex.compare_actors(case_dir, body.ips)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        conn = db.connect(case_dir)
        try:
            triage_map = {r["artifact"]: r["triage"] for r in db.rows(
                conn, f"WITH art AS ({ART_SQL}) SELECT artifact, triage "
                      f"FROM art WHERE artifact_kind = 'client'")}
            box_ips = {r["value"] for r in db.rows(
                conn, "SELECT value FROM iocs WHERE type = 'ip'")}
        finally:
            conn.close()
        for actor in result["actors"]:
            actor["triage"] = triage_map.get(actor["ip"])
            actor["in_box"] = actor["ip"] in box_ips
        return result

    class TraceBody(BaseModel):
        ips: list[str]
        from_epoch: int | None = None
        to_epoch: int | None = None
        limit: int = 2000
        offset: int = 0
        search: str = ""
        status: str = ""          # 2xx | 3xx | 4xx | 5xx | err
        method: str = ""
        sort: str = "time"
        mark_exact: list[str] = Field(default_factory=list)
        mark_contains: list[str] = Field(default_factory=list)
        evidence_only: bool = False

    @app.post("/api/cases/{slug}/trace", dependencies=[auth])
    def trace(slug: str, body: TraceBody):
        case_dir = case_dir_or_404(slug)
        if not body.ips:
            raise HTTPException(400, "no client addresses given")
        return logindex.trace(case_dir, body.ips, body.from_epoch,
                              body.to_epoch, min(body.limit, 10000),
                              body.offset, body.search, body.status,
                              body.method, body.sort, body.mark_exact,
                              body.mark_contains, body.evidence_only)

    class TraceTimelineBody(BaseModel):
        ips: list[str]

    @app.post("/api/cases/{slug}/trace/timeline", dependencies=[auth])
    def trace_timeline(slug: str, body: TraceTimelineBody):
        """The timeline of THESE clients -- the same curve as in the
        dashboard, only restricted to the selection. Deliberately separate
        from the trace itself: the curve describes the WHOLE period, not the
        page currently displayed, and must not change when paging."""
        case_dir = case_dir_or_404(slug)
        return {"timeline": logindex.timeline_for_ips(case_dir, body.ips)}

    @app.get("/api/cases/{slug}/trace.csv", dependencies=[auth])
    def trace_csv(slug: str, ips: str, search: str = "", status: str = "",
                  method: str = "", sort: str = "time"):
        """The trace as evidence: a ZIP of the CSV and a manifest.

        A trace export travels into reports and handovers as an exhibit. It
        only becomes citable with three things: WHAT was queried (clients and
        filters -- the same export with a different filter is a different
        exhibit), HOW MUCH came out, and a checksum by which every recipient
        can check its integrity. None of that belongs in the CSV itself:
        comment lines break every import, and a checksum INSIDE the file
        cannot vouch for the file.

        The export takes the same filters as the view: what one has filtered
        in front of one is what one wants to export."""
        case_dir = case_dir_or_404(slug)
        info = workspace.case_info(case_dir)
        wanted = [p.strip() for p in ips.split(",") if p.strip()]
        result = logindex.trace(case_dir, wanted, limit=200000,
                                search=search, status=status,
                                method=method, sort=sort)
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
            # EVERY FIELD THE CLIENT CONTROLS, not just the URI. Referrer,
            # user agent and the request method come straight off the wire,
            # and this file exists to be opened in a spreadsheet: a user agent
            # of `=cmd|'/c calc'!A1` executed when the analyst double-clicked
            # the export. Only the URI was guarded.
            # AN EMPTY CELL, NOT A ZERO. The log wrote "-" and the index
            # keeps that as NULL; a 0 here would be a measured number
            # asserting that nothing came back, which is the opposite of
            # what a dash means.
            w.writerow([_csv_safe(r["client"]), stamp, _csv_safe(r["method"]),
                        _csv_safe(r["uri"]), r["status"],
                        "" if r["size"] is None else r["size"],
                        _csv_safe(r["referrer"]), _csv_safe(r["agent"]),
                        _csv_safe(r["source"])])
        csv_bytes = buf.getvalue().encode("utf-8")
        digest = hashlib.sha256(csv_bytes).hexdigest()

        filters = [f"Clients: {', '.join(wanted)}"]
        if search.strip():
            filters.append(f"Search: {search.strip()}")
        if status.strip():
            filters.append(f"Status: {status.strip()}")
        if method.strip():
            filters.append(f"Method: {method.strip()}")
        filters.append(f"Sort: {sort}")
        truncated = result["total"] > len(result["rows"])
        manifest = "\n".join([
            "SHELLHOUND trace export",
            f"Case: {info['name']} ({info['slug']})",
            f"Exported: {db.now()}",
            "",
            "Query:",
            *(f"  {line}" for line in filters),
            "",
            f"Rows: {len(result['rows'])} of {result['total']}"
            + (" — TRUNCATED at the export limit" if truncated else ""),
            "Times in the time zone of the respective log line.",
            "",
            f"SHA-256 (trace.csv): {digest}",
            "",
            "Verify:  certutil -hashfile trace.csv SHA256",
            "     or:  sha256sum trace.csv",
        ]) + "\n"

        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("trace.csv", csv_bytes)
            zf.writestr("MANIFEST.txt", manifest)
        stem = f"trace_{info['slug']}_{len(wanted)}_clients"
        return Response(
            zbuf.getvalue(), media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename={stem}.zip",
                     "X-Content-SHA256": digest})

    # --- full-case access-log explorer ------------------------------------

    class AccessQueryBody(BaseModel):
        search: str = ""
        from_epoch: int | None = None
        to_epoch: int | None = None
        clients: list[str] = Field(default_factory=list)
        exclude_clients: list[str] = Field(default_factory=list)
        paths: list[str] = Field(default_factory=list)
        exclude_paths: list[str] = Field(default_factory=list)
        agents: list[str] = Field(default_factory=list)
        exclude_agents: list[str] = Field(default_factory=list)
        source_ids: list[int] = Field(default_factory=list)
        exclude_source_ids: list[int] = Field(default_factory=list)
        status: str = ""
        method: str = ""
        min_size: int | None = None
        max_size: int | None = None
        signals_only: bool = False
        sort: str = "time_desc"
        cursor: str = ""
        limit: int = 200

    def access_filters(body: AccessQueryBody, *, keep_page=False):
        data = body.model_dump()
        if body.sort not in ("time", "time_desc"):
            raise HTTPException(400, "unsupported access-log sort")
        for key in ("clients", "exclude_clients", "paths", "exclude_paths",
                    "agents", "exclude_agents", "source_ids",
                    "exclude_source_ids"):
            if len(data[key]) > 100:
                raise HTTPException(400, f"too many values in {key}")
        if body.from_epoch is not None and body.to_epoch is not None \
                and body.from_epoch > body.to_epoch:
            raise HTTPException(400, "from_epoch is after to_epoch")
        if not keep_page:
            data.pop("cursor", None)
            data.pop("limit", None)
        return data

    @app.post("/api/cases/{slug}/access/search", dependencies=[auth])
    def access_search(slug: str, body: AccessQueryBody):
        case_dir = case_dir_or_404(slug)
        filters = access_filters(body, keep_page=True)
        try:
            return logindex.access_search(
                case_dir, filters, limit=max(25, min(body.limit, 500)))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/api/cases/{slug}/access/overview", dependencies=[auth])
    def access_overview(slug: str, body: AccessQueryBody):
        case_dir = case_dir_or_404(slug)
        return logindex.access_overview(case_dir, access_filters(body))

    @app.post("/api/cases/{slug}/access/patterns", dependencies=[auth])
    def access_patterns(slug: str, body: AccessQueryBody):
        case_dir = case_dir_or_404(slug)
        return logindex.access_patterns(case_dir, access_filters(body))

    @app.post("/api/cases/{slug}/access/segments", dependencies=[auth])
    def access_segments(slug: str, body: AccessQueryBody):
        case_dir = case_dir_or_404(slug)
        try:
            return logindex.access_segments(case_dir, access_filters(body))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/api/cases/{slug}/access/request/{request_id}", dependencies=[auth])
    def access_request(slug: str, request_id: int, before: int = 12,
                       after: int = 12):
        case_dir = case_dir_or_404(slug)
        try:
            return logindex.access_request_context(
                case_dir, request_id, before=before, after=after)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc

    def parsed_access_export_filters(raw: str):
        try:
            payload = json.loads(raw or "{}")
            if not isinstance(payload, dict):
                raise ValueError
            body = AccessQueryBody(**payload)
        except (ValueError, TypeError) as exc:
            raise HTTPException(400, "invalid access-log export filters") from exc
        return access_filters(body)

    @app.get("/api/cases/{slug}/access/export", dependencies=[auth])
    def access_export(slug: str, filters: str = "{}"):
        """The visible access-log scope as a citable ZIP exhibit."""
        case_dir = case_dir_or_404(slug)
        active = parsed_access_export_filters(filters)
        result = logindex.access_search(case_dir, active, limit=200000)
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow([
            "Request key", "Client", "Time", "Method", "URI", "Status",
            "Size", "Referrer", "User-Agent", "Source", "Source line",
            "Signals",
        ])
        for row in result["rows"]:
            stamp = ""
            if row["epoch"]:
                stamp = datetime.fromtimestamp(
                    row["epoch"] + (row["tz"] or 0), tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S")
            writer.writerow([
                _csv_safe(row["request_key"]), _csv_safe(row["client"]), stamp,
                _csv_safe(row["method"]), _csv_safe(row["uri"]), row["status"],
                "" if row["size"] is None else row["size"],
                _csv_safe(row["referrer"]), _csv_safe(row["agent"]),
                _csv_safe(row["source"]), row["line_no"],
                _csv_safe(", ".join(row.get("signals") or ())),
            ])
        csv_bytes = buf.getvalue().encode("utf-8")
        digest = hashlib.sha256(csv_bytes).hexdigest()
        info = workspace.case_info(case_dir)
        manifest = "\n".join([
            "SHELLHOUND access-log export",
            f"Case: {info['name']} ({info['slug']})",
            f"Exported: {db.now()}",
            "",
            "Structured filters:",
            json.dumps(active, ensure_ascii=False, sort_keys=True, indent=2),
            "",
            f"Rows: {len(result['rows'])} of {result['total']}"
            + (" — TRUNCATED at 200000" if result["total"] > len(result["rows"]) else ""),
            "Times use the UTC offset recorded on each source line.",
            f"SHA-256 (access-log.csv): {digest}",
        ]) + "\n"
        archive_buf = io.BytesIO()
        with zipfile.ZipFile(archive_buf, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("access-log.csv", csv_bytes)
            archive.writestr("MANIFEST.txt", manifest.encode("utf-8"))
        return Response(
            archive_buf.getvalue(), media_type="application/zip",
            headers={"Content-Disposition":
                     f"attachment; filename=access_{info['slug']}.zip",
                     "X-Content-SHA256": digest})

    class AccessSavedBody(BaseModel):
        name: str = Field(min_length=1, max_length=120)
        query: dict = Field(default_factory=dict)

    @app.get("/api/cases/{slug}/access/saved", dependencies=[auth])
    def access_saved_list(slug: str):
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            return [{**dict(row), "query": json.loads(row["query"] or "{}")}
                    for row in db.rows(conn,
                        "SELECT id, name, query, created, updated "
                        "FROM access_saved_queries ORDER BY updated DESC, id DESC")]
        finally:
            conn.close()

    @app.post("/api/cases/{slug}/access/saved", dependencies=[auth])
    def access_saved_add(slug: str, body: AccessSavedBody):
        case_dir = case_dir_or_404(slug)
        # Validate the stored object with the same model the search uses and
        # discard cursors: reopening a query always starts at its first page.
        validated = access_filters(AccessQueryBody(**body.query))
        encoded = json.dumps(validated, ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 65536:
            raise HTTPException(400, "saved access query is too large")
        stamp = db.now()
        conn = db.connect(case_dir)
        try:
            cur = conn.execute(
                "INSERT INTO access_saved_queries(name, query, created, updated) "
                "VALUES (?,?,?,?)", (body.name.strip(), encoded, stamp, stamp))
            conn.commit()
            return {"id": cur.lastrowid, "name": body.name.strip(),
                    "query": validated, "created": stamp, "updated": stamp}
        finally:
            conn.close()

    @app.delete("/api/cases/{slug}/access/saved/{saved_id}", dependencies=[auth])
    def access_saved_delete(slug: str, saved_id: int):
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            cur = conn.execute("DELETE FROM access_saved_queries WHERE id = ?",
                               (saved_id,))
            conn.commit()
            if not cur.rowcount:
                raise HTTPException(404, "saved access query not found")
            return {"ok": True}
        finally:
            conn.close()

    class AccessClipBody(BaseModel):
        request_id: int
        note: str = Field(default="", max_length=2000)

    @app.get("/api/cases/{slug}/access/clips", dependencies=[auth])
    def access_clip_list(slug: str):
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            return [{**dict(row), "snapshot": json.loads(row["snapshot"] or "{}")}
                    for row in db.rows(conn,
                        "SELECT id, request_key, snapshot, note, added "
                        "FROM access_clips ORDER BY id DESC")]
        finally:
            conn.close()

    @app.get("/api/cases/{slug}/access/clips/export", dependencies=[auth])
    def access_clip_export(slug: str):
        """Analyst-selected request lines as a citable handover archive."""
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            clips = [{**dict(row),
                      "snapshot": json.loads(row["snapshot"] or "{}")}
                     for row in db.rows(
                         conn, "SELECT id, request_key, snapshot, note, added "
                               "FROM access_clips ORDER BY id")]
        finally:
            conn.close()
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow([
            "Clip", "Request key", "Client", "Time", "Method", "URI",
            "Status", "Size", "Referrer", "User-Agent", "Source",
            "Source line", "Signals", "Analyst note", "Raw source line",
            "Added",
        ])
        for clip in clips:
            row = clip["snapshot"]
            stamp = ""
            if row.get("epoch"):
                stamp = datetime.fromtimestamp(
                    row["epoch"] + (row.get("tz") or 0), tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S")
            writer.writerow([
                clip["id"], _csv_safe(clip["request_key"]),
                _csv_safe(row.get("client", "")), stamp,
                _csv_safe(row.get("method", "")),
                _csv_safe(row.get("uri", "")), row.get("status", ""),
                "" if row.get("size") is None else row.get("size"),
                _csv_safe(row.get("referrer", "")),
                _csv_safe(row.get("agent", "")),
                _csv_safe(row.get("source", "")), row.get("line_no", ""),
                _csv_safe(", ".join(row.get("signals") or ())),
                _csv_safe(clip.get("note", "")),
                _csv_safe(row.get("raw_line", "")), clip.get("added", ""),
            ])
        csv_bytes = buf.getvalue().encode("utf-8")
        digest = hashlib.sha256(csv_bytes).hexdigest()
        info = workspace.case_info(case_dir)
        manifest = "\n".join([
            "SHELLHOUND access-log evidence basket",
            f"Case: {info['name']} ({info['slug']})",
            f"Exported: {db.now()}",
            f"Analyst-selected requests: {len(clips)}",
            "Rows are snapshots retained when the analyst pinned them.",
            f"SHA-256 (evidence-basket.csv): {digest}",
        ]) + "\n"
        archive_buf = io.BytesIO()
        with zipfile.ZipFile(archive_buf, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("evidence-basket.csv", csv_bytes)
            archive.writestr("MANIFEST.txt", manifest.encode("utf-8"))
        return Response(
            archive_buf.getvalue(), media_type="application/zip",
            headers={"Content-Disposition":
                     f"attachment; filename=access_basket_{info['slug']}.zip",
                     "X-Content-SHA256": digest})

    @app.post("/api/cases/{slug}/access/clips", dependencies=[auth])
    def access_clip_add(slug: str, body: AccessClipBody):
        case_dir = case_dir_or_404(slug)
        try:
            context = logindex.access_request_context(case_dir, body.request_id)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        snapshot = dict(context["request"])
        snapshot["raw_line"] = context.get("raw_line", "")
        snapshot["raw_truncated"] = context.get("raw_truncated", False)
        encoded = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"))
        stamp = db.now()
        conn = db.connect(case_dir)
        try:
            conn.execute(
                "INSERT INTO access_clips(request_key, snapshot, note, added) "
                "VALUES (?,?,?,?) ON CONFLICT(request_key) DO UPDATE SET "
                "snapshot=excluded.snapshot, note=excluded.note",
                (snapshot["request_key"], encoded, body.note.strip(), stamp))
            conn.commit()
            row = conn.execute(
                "SELECT id, request_key, snapshot, note, added FROM access_clips "
                "WHERE request_key = ?", (snapshot["request_key"],)).fetchone()
            return {**dict(row), "snapshot": json.loads(row["snapshot"])}
        finally:
            conn.close()

    @app.delete("/api/cases/{slug}/access/clips/{clip_id}", dependencies=[auth])
    def access_clip_delete(slug: str, clip_id: int):
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            cur = conn.execute("DELETE FROM access_clips WHERE id = ?", (clip_id,))
            conn.commit()
            if not cur.rowcount:
                raise HTTPException(404, "access clip not found")
            return {"ok": True}
        finally:
            conn.close()

    class CollectBody(BaseModel):
        ips: list[str]
        # Where the selection comes from. On a pattern hit that is the
        # actual statement -- "this address requested the exploit path" says
        # more than "collected from the actors list".
        origin: str = ""

    @app.post("/api/cases/{slug}/actors/collect", dependencies=[auth])
    def collect_actors(slug: str, body: CollectBody):
        """Actors into the IOC box, tagged with what the logs saw them do."""
        case_dir = case_dir_or_404(slug)
        # Look up precisely instead of fetching the whole actor table: the
        # caller wants to take in a handful of addresses, not read tens of
        # thousands -- and that is exactly what ran into "too many SQL
        # variables" on a real case.
        by_ip = logindex.actors_by_ip(case_dir, body.ips)
        conn = db.connect(case_dir)
        added = 0
        try:
            for ip in body.ips:
                a = by_ip.get(ip)
                tags = [ioclib.TAG_ACTOR]
                origin = "actor: collected from the actors list"
                if a:
                    tags = ioclib.actor_tags(a, logindex.BF_THRESHOLD)
                    origin = f"actor: {a['requests']} request(s)"
                # A supplied origin replaces the generic one: it says WHY
                # this address was taken in, and that is the fact that counts
                # in the report.
                if body.origin.strip():
                    origin = body.origin.strip()[:200]
                    tags.append(ioclib.TAG_HUNT)
                db.add_ioc(conn, ip, "ip", tags, origin=origin)
                added += 1
            conn.commit()
        finally:
            conn.close()
        hub.publish({"type": "invalidate", "scope": "iocs"})
        return {"added": added}

    # --- IOC box ------------------------------------------------------------

    def _ioc_spans(case_dir, rows):
        """Attach first_seen/last_seen (log-local dates) to address IOCs.

        Always both keys, null when the index has nothing: a field that
        appears and disappears per row is a contract nobody can type."""
        spans = logindex.actor_spans(
            case_dir, [r["value"] for r in rows if r["type"] == "ip"])
        for r in rows:
            span = spans.get(r["value"]) if r["type"] == "ip" else None
            r["first_seen"] = span[0] if span else None
            r["last_seen"] = span[1] if span else None
        return rows

    @app.get("/api/cases/{slug}/iocs", dependencies=[auth])
    def iocs_list(slug: str):
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            rows = db.rows(conn, "SELECT * FROM iocs ORDER BY added DESC, id DESC")
            _ioc_spans(case_dir, rows)
            # Path indicators are stored webroot-relative (what the other
            # side can look for), but the file viewer wants the file where
            # it LIES. Resolved here, once per listing, so the interface
            # offers "view" exactly on the entries the evidence can answer.
            roots_abs = db.evidence_roots(conn)
            for r in rows:
                r["tags"] = json.loads(r["tags"] or "[]")
                r["links"] = []
                if r["type"] == "path":
                    r["resolved"] = db.absolute_from_evidence(
                        roots_abs, r["value"])
            # Every edge hangs on BOTH ends, each in its own reading
            # direction. Otherwise the analyst would have to know at which of
            # the two indicators the relationship is "stored" -- a question
            # that is none of their business.
            by_id = {r["id"]: r for r in rows}
            for row in rows:
                row["external_sources"] = []
            for source in db.rows(
                    conn, "SELECT ioc_id,provider,external_id,source_url,snapshot_id,added "
                          "FROM ioc_external_sources ORDER BY added"):
                target = by_id.get(source["ioc_id"])
                if target is not None:
                    target["external_sources"].append(source)
            for link in db.ioc_links(conn):
                out, back = ioclib.LINK_LABELS.get(
                    link["kind"], (link["kind"], link["kind"]))
                src, dst = by_id.get(link["src_id"]), by_id.get(link["dst_id"])
                if src is not None:
                    src["links"].append({
                        "kind": link["kind"], "label": out, "note": link["note"],
                        "value": link["dst_value"], "type": link["dst_type"],
                        "id": link["dst_id"]})
                if dst is not None:
                    dst["links"].append({
                        "kind": link["kind"], "label": back, "note": link["note"],
                        "value": link["src_value"], "type": link["src_type"],
                        "id": link["src_id"]})
            return rows
        finally:
            conn.close()

    @app.get("/api/cases/{slug}/iocs/cross-case", dependencies=[auth])
    def iocs_cross_case(slug: str):
        # Resolve first for the same 404 contract as every case endpoint;
        # correlation opens all databases read-only after that.
        case_dir_or_404(slug)
        return correlation.compare(config.workspace, slug)

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
        # Hex has no case. The collectors write hexdigest() and are already
        # lower-case; only the analyst pastes `4323…C`, and without this the
        # same digest lives twice and the cross-case comparison -- exact by
        # design -- walks past itself. Paths stay untouched: their case is
        # part of the value.
        if ioc_type == "hash":
            value = value.lower()
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
            # The edges along with it: SQLite only enforces foreign keys
            # with the PRAGMA switched on, and setting that globally would
            # affect every other delete path of this database. One line is
            # enough here.
            conn.execute("DELETE FROM ioc_links WHERE src = ? OR dst = ?",
                         (ioc_id, ioc_id))
            conn.execute("DELETE FROM ioc_external_sources WHERE ioc_id = ?",
                         (ioc_id,))
            conn.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))
            conn.commit()
            return {"ok": True}
        finally:
            conn.close()

    @app.get("/api/cases/{slug}/iocs/export", dependencies=[auth])
    def export_iocs(slug: str, format: str = "csv", lang: str = lang_dep,
                    tz: str = tz_dep, hide_types: str = "",
                    hide_tags: str = "", search: str = ""):
        """Export the box -- or exactly what the analyst is looking at.

        The filter parameters carry the SAME semantics as the view: a type
        chip hides its type, a tag chip hides entries whose tags are ALL
        hidden, the search matches value, note or origin. Handing the
        hoster 'the twelve addresses' must not require editing a CSV by
        hand -- and must not silently ship the rest either."""
        case_dir = case_dir_or_404(slug)
        info = workspace.case_info(case_dir)
        conn = db.connect(case_dir)
        try:
            rows = db.rows(conn, "SELECT * FROM iocs ORDER BY type, value")
            links = db.ioc_links(conn)
        finally:
            conn.close()
        _ioc_spans(case_dir, rows)
        hidden_types = {t for t in hide_types.split(",") if t}
        hidden_tags = {t for t in hide_tags.split(",") if t}
        needle = search.strip().lower()
        if hidden_types or hidden_tags or needle:
            def visible(r):
                if r["type"] in hidden_types:
                    return False
                tags = json.loads(r["tags"] or "[]")
                if tags and all(t in hidden_tags for t in tags):
                    return False
                if needle and not any(
                        needle in str(r[k] or "").lower()
                        for k in ("value", "note", "origin")):
                    return False
                return True
            rows = [r for r in rows if visible(r)]
            kept = {r["id"] for r in rows}
            # An edge whose far end was filtered away would name an
            # indicator the file does not carry.
            links = [l for l in links
                     if l["src_id"] in kept and l["dst_id"] in kept]
        stem = f"iocs_{info['slug']}"
        if format == "json":
            return Response(ioclib.to_json(rows, info["name"], links,
                                           chain=case_chain(case_dir, lang, tz)),
                            media_type="application/json",
                            headers={"Content-Disposition":
                                     f"attachment; filename={stem}.json"})
        if format == "stix":
            return Response(ioclib.to_stix(rows, info["name"], links),
                            media_type="application/json",
                            headers={"Content-Disposition":
                                     f"attachment; filename={stem}_stix.json"})
        return Response(ioclib.to_csv(rows, links), media_type="text/csv",
                        headers={"Content-Disposition":
                                 f"attachment; filename={stem}.csv"})

    # --- CMS inventory ------------------------------------------------------

    def _ext_scope(item):
        """What an extension spans in the file system.

        The stored path points sometimes at the directory, sometimes at the
        manifest inside it, sometimes at a single-file extension (WP's
        hello.php). The slug decides: if the directory in the path is named
        like the slug, the whole tree belongs to it -- otherwise only the
        file itself. A single file must never inherit its container,
        otherwise hello.php "contains" every shell in the plugins folder."""
        s = str(item["path"]).replace("\\", "/").rstrip("/").lower()
        parts = s.split("/")
        slug = str(item["slug"]).strip().lower()
        if parts and parts[-1] == slug:
            return "dir", s
        if len(parts) >= 2 and parts[-2] == slug:
            return "dir", "/".join(parts[:-1])
        if "." in parts[-1]:
            return "file", s
        return "dir", s

    @app.get("/api/cases/{slug}/cms", dependencies=[auth])
    def cms_view(slug: str):
        """The inventory, tied to the case: every extension knows whether
        flagged artifacts lie under its path. That is the question one opens
        this page for during an incident -- which extension is it?"""
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            installs = db.rows(conn, "SELECT * FROM cms_installs ORDER BY root")
            items = db.rows(conn, "SELECT * FROM cms_items ORDER BY type, name")
            flagged = db.rows(conn,
                              f"WITH art AS ({ART_SQL}) "
                              f"SELECT artifact, worst, triage, findings "
                              f"FROM art WHERE artifact_kind = 'file'")
            overrides = {(r["scope"], r["key"]): r for r in db.rows(
                conn, "SELECT * FROM cms_version_overrides")}
        finally:
            conn.close()
        root_by_id = {i["id"]: i["root"] for i in installs}

        def overlay(row, scope, key):
            """Lay the analyst's correction over the measured value --
            without losing it: `version_parsed` stays next to it, otherwise
            a report could no longer tell what was measured and what was
            decided."""
            row["version_parsed"] = row["version"]
            o = overrides.get((scope, key))
            row["version_set"] = o["version"] if o else ""
            row["version_note"] = o["note"] if o else ""
            row["version_set_at"] = o["set_at"] if o else ""
            if o:
                row["version"] = o["version"]
            return row
        arts = [(str(a["artifact"]).replace("\\", "/").lower(), a)
                for a in flagged]
        by_install = {}
        for item in items:
            kind, scope = _ext_scope(item)
            hits = []
            for norm, a in arts:
                if (norm == scope if kind == "file"
                        else norm == scope or norm.startswith(scope + "/")):
                    hits.append({"artifact": a["artifact"], "worst": a["worst"],
                                 "triage": a["triage"],
                                 "findings": a["findings"]})
            hits.sort(key=lambda h: h["worst"])
            item["artifacts"] = hits[:8]
            item["flagged"] = len(hits)
            overlay(item, "item", _item_key(root_by_id.get(item["install_id"], ""),
                                            item))
            by_install.setdefault(item["install_id"], []).append(item)
        for inst in installs:
            overlay(inst, "install", inst["root"])
            inst["items"] = by_install.get(inst["id"], [])
        return {"installs": installs}

    def _item_key(root, item):
        """The identity of an extension ACROSS RE-ANALYSES. The id changes on
        every run (the table is emptied), root + type + slug stay -- and the
        analyst's correction hangs on that."""
        return f"{root}|{item['type']}|{item['slug']}"

    class VersionBody(BaseModel):
        # Empty string = take the correction back, return to the measured
        # value.
        version: str = ""
        note: str = ""

    def _set_version(case_dir, scope, key, body):
        conn = db.connect(case_dir)
        try:
            value = body.version.strip()[:60]
            if value:
                conn.execute(
                    "INSERT INTO cms_version_overrides (scope, key, version,"
                    " note, set_at) VALUES (?,?,?,?,?) "
                    "ON CONFLICT(scope, key) DO UPDATE SET "
                    "version=excluded.version, note=excluded.note, "
                    "set_at=excluded.set_at",
                    (scope, key, value, body.note.strip()[:300], db.now()))
            else:
                conn.execute("DELETE FROM cms_version_overrides "
                             "WHERE scope = ? AND key = ?", (scope, key))
            conn.commit()
        finally:
            conn.close()
        return {"ok": True, "version": body.version.strip()[:60]}

    @app.patch("/api/cases/{slug}/cms/items/{item_id}", dependencies=[auth])
    def set_item_version(slug: str, item_id: int, body: VersionBody):
        """Set a version by hand -- when the manifest is missing, forged, or
        the analyst has established it some other way."""
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            row = db.one(conn, "SELECT i.*, s.root AS root FROM cms_items i "
                               "JOIN cms_installs s ON s.id = i.install_id "
                               "WHERE i.id = ?", (item_id,))
        finally:
            conn.close()
        if row is None:
            raise HTTPException(404, "unknown extension")
        return _set_version(case_dir, "item", _item_key(row["root"], row), body)

    @app.patch("/api/cases/{slug}/cms/installs/{install_id}", dependencies=[auth])
    def set_install_version(slug: str, install_id: int, body: VersionBody):
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            row = db.one(conn, "SELECT * FROM cms_installs WHERE id = ?",
                         (install_id,))
        finally:
            conn.close()
        if row is None:
            raise HTTPException(404, "unknown install")
        return _set_version(case_dir, "install", row["root"], body)

    # --- database view ------------------------------------------------------

    # How long before the export an account must have been created to stand
    # out as "young". Not a judgement -- a sorting aid: in an incident a
    # two-day-old administrator is the first row one looks at, and among 400
    # accounts one would not otherwise find it.
    _YOUNG_DAYS = 30

    # phpMyAdmin writes "Generation Time: Jan 06, 2026 at 08:00 AM" (and
    # "06. Jan 2026 um 08:00" in German). None of the ISO or dotted forms
    # parse that, so the export reference date was missing for the most
    # common export on shared hosting -- and the "young account" aid, which
    # measures against it, had nothing to measure against.
    _STAMP_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d",
                      "%d.%m.%Y %H:%M:%S", "%d.%m.%Y",
                      "%b %d, %Y at %I:%M %p", "%b %d, %Y at %H:%M",
                      "%d. %b %Y um %H:%M", "%d %b %Y at %I:%M %p")

    def _parse_stamp(text):
        raw = str(text or "").strip()
        if not raw:
            return None
        for fmt in _STAMP_FORMATS:
            try:
                return datetime.strptime(raw[:len(fmt) + 6].strip(), fmt)
            except ValueError:
                continue
        return None

    def _account_signals(acc, reference, lang="en"):
        """What STANDS OUT about this account -- as named observations, not
        as a score. A dump cannot say that an admin is malicious; it can say
        that one was created yesterday and has never signed in. The
        assessment stays with the analyst, the ordering only makes it
        findable."""
        out = []
        registered = _parse_stamp(acc["registered"])
        if acc["admin"]:
            out.append({"id": "admin", "label": _t(lang, "signal.admin"),
                        "why": _t(lang, "account.admin")})
        if registered and reference and 0 <= (reference - registered).days <= _YOUNG_DAYS:
            days = (reference - registered).days
            out.append({"id": "young",
                        "label": (_t(lang, "account.young.sameDay") if days == 0
                                  else _t(lang, "signal.young.days", n=days)),
                        "why": _t(lang, "account.young.why")})
        if "weak" in (acc["hash_type"] or ""):
            out.append({"id": "weak_hash", "label": _t(lang, "signal.weakHash"),
                        "why": _t(lang, "account.weakHash.why")})
        if acc["admin"] and not acc["last_login"] and acc["cms"] == "Joomla":
            out.append({"id": "never", "label": _t(lang, "signal.never"),
                        "why": _t(lang, "account.neverLoggedIn.why")})
        if acc["sessions"]:
            out.append({"id": "session", "label": _t(lang, "signal.session"),
                        "why": _t(lang, "account.session.why")})
        if acc["blocked"]:
            out.append({"id": "blocked", "label": _t(lang, "signal.blocked"),
                        "why": _t(lang, "account.blocked.why")})
        return out

    # Order of conspicuousness -- for sorting only.
    _SIGNAL_WEIGHT = {"admin": 4, "young": 3, "never": 2, "session": 2,
                      "weak_hash": 1, "blocked": 0}

    def _database_intelligence(dumps, accounts, installs, items, file_artifacts):
        """Join dump semantics with the independently measured webroot.

        A row in ``wp_options`` or ``#__extensions`` says what the CMS was
        configured to load.  The CMS inventory says what was actually present
        in the supplied file evidence.  Keeping both measurements separate and
        joining them here makes disagreements visible without turning a
        missing backup directory into a finding.
        """
        categories = ("configuration", "extensions", "access",
                      "persistence", "content")
        out = {name: [] for name in categories}
        cms_seen = set()
        truncated = {name: False for name in categories}

        account_by_user = {}
        for account in accounts:
            key = (account["dump_id"], account["cms"], str(account["user_id"] or ""))
            account_by_user[key] = account

        for dump in dumps:
            raw = dump.pop("intelligence", "{}")
            try:
                snapshot = json.loads(raw or "{}") if isinstance(raw, str) else (raw or {})
            except (TypeError, ValueError, json.JSONDecodeError):
                snapshot = {}
            if not isinstance(snapshot, dict):
                snapshot = {}
            cms_seen.update(snapshot.get("cms") or [])
            for category in categories:
                rows = snapshot.get(category) or []
                if not isinstance(rows, list):
                    continue
                for value in rows:
                    if not isinstance(value, dict):
                        continue
                    row = dict(value)
                    row["dump_id"] = dump["id"]
                    row["dump_name"] = os.path.basename(dump["path"])
                    if category == "access" and row.get("user_id"):
                        account = account_by_user.get((
                            dump["id"], row.get("cms", ""), str(row["user_id"])))
                        if account:
                            row["account_login"] = account["login"]
                            row["account_email"] = account["email"]
                            row["account_admin"] = bool(account["admin"])
                            row["account_signals"] = [
                                signal["id"] for signal in account.get("signals", [])]
                    out[category].append(row)
                truncated[category] = bool(
                    truncated[category] or (snapshot.get("truncated") or {}).get(category))

        # WordPress stores the parent template and active stylesheet as two
        # options.  For a non-child theme both values are identical; showing
        # that as two active themes would inflate the summary and create a
        # fake discrepancy.  A child theme remains two distinct rows because
        # the slugs differ.
        merged_extensions = []
        wp_themes = {}
        for extension in out["extensions"]:
            if (extension.get("cms") == "WordPress" and
                    extension.get("type") == "theme"):
                identity = (extension.get("dump_id"), extension.get("key"))
                existing = wp_themes.get(identity)
                if existing:
                    if extension.get("scope") == "active":
                        existing.update(extension)
                    continue
                wp_themes[identity] = extension
            merged_extensions.append(extension)
        out["extensions"] = merged_extensions

        install_by_id = {row["id"]: row for row in installs}
        installs_by_cms = {}
        for install in installs:
            installs_by_cms.setdefault(install["cms"], []).append(install)

        def norm_slug(value):
            slug = str(value or "").strip().lower().replace("\\", "/")
            slug = slug.rsplit("/", 1)[-1].rsplit(".", 1)[0]
            for prefix in ("com_", "mod_", "plg_", "tpl_"):
                if slug.startswith(prefix):
                    slug = slug[len(prefix):]
            return slug.replace("-", "_")

        def item_matches(extension, item):
            install = install_by_id.get(item["install_id"])
            if not install or install["cms"] != extension.get("cms"):
                return False
            ext_type = str(extension.get("type") or "").lower()
            item_type = str(item["type"] or "").lower()
            if extension.get("cms") == "WordPress":
                if ext_type == "plugin" and "plugin" not in item_type:
                    return False
                if ext_type == "theme" and "theme" not in item_type:
                    return False
            elif ext_type and ext_type not in item_type and item_type not in ext_type:
                # Joomla labels carry detail such as ``Plugin (system)`` and
                # ``Component (Site)``; comparing their base class prevents a
                # module and component with the same suffix from colliding.
                base = item_type.split(" ", 1)[0].split("(", 1)[0]
                if ext_type != base:
                    return False
            candidates = {
                norm_slug(extension.get("name")),
                norm_slug(extension.get("element")),
                norm_slug(str(extension.get("key") or "").split(":")[-1]),
            }
            candidates.discard("")
            return norm_slug(item["slug"]) in candidates

        artifact_rows = []
        for artifact in file_artifacts:
            artifact_rows.append((
                str(artifact["artifact"] or "").replace("\\", "/").lower(),
                artifact))

        def item_findings(item):
            kind, scope = _ext_scope(item)
            hits = []
            for path, artifact in artifact_rows:
                belongs = (path == scope) if kind == "file" else (
                    path == scope or path.startswith(scope + "/"))
                if belongs:
                    hits.append({"artifact": artifact["artifact"],
                                 "worst": artifact["worst"],
                                 "triage": artifact["triage"],
                                 "findings": artifact["findings"]})
            return hits[:8]

        matched_item_ids = set()
        for extension in out["extensions"]:
            matches = [item for item in items if item_matches(extension, item)]
            matches.sort(key=lambda item: (
                0 if norm_slug(item["slug"]) == norm_slug(
                    extension.get("element") or extension.get("name")) else 1,
                item["id"]))
            match = matches[0] if matches else None
            signals = []
            if match:
                matched_item_ids.add(match["id"])
                fs_version = str(match["version"] or "")
                db_version = str(extension.get("version") or "")
                findings = item_findings(match)
                extension["filesystem"] = {
                    "status": "present", "path": match["path"],
                    "version": fs_version, "type": match["type"],
                    "findings": findings,
                }
                if (db_version and fs_version and
                        "unknown" not in db_version.lower() and
                        "unknown" not in fs_version.lower() and
                        db_version != fs_version):
                    signals.append("version_mismatch")
                if findings:
                    signals.append("flagged_files")
            else:
                cms_installs = installs_by_cms.get(extension.get("cms"), [])
                extension["filesystem"] = {
                    "status": "missing" if len(cms_installs) == 1 else "unknown",
                    "path": "", "version": "", "type": "", "findings": [],
                }
                if extension.get("enabled") and len(cms_installs) == 1:
                    signals.append("active_missing_files")
            extension["signals"] = signals
            extension["review"] = bool(signals)

        # Also show what exists only in the file evidence.  WordPress
        # must-use plugins and drop-ins are executable even though no DB row
        # can exist for them; ordinary plugins/themes are explicitly shown as
        # inactive.  Joomla filesystem-only entries remain "unknown" because
        # one extension can legitimately have several client-side parts.
        for item in items:
            install = install_by_id.get(item["install_id"])
            if not install or item["id"] in matched_item_ids:
                continue
            cms = install["cms"]
            if cms not in cms_seen:
                continue
            low_type = str(item["type"] or "").lower()
            always_on = cms == "WordPress" and (
                low_type == "must-use plugin" or low_type == "drop-in")
            findings = item_findings(item)
            out["extensions"].append({
                "cms": cms, "key": f"filesystem:{item['id']}",
                "name": item["name"], "element": item["slug"],
                "type": item["type"], "scope": "filesystem",
                "enabled": True if always_on else False if cms == "WordPress" else None,
                "version": "", "folder": "", "source_table": "",
                "source_row": 0, "dump_id": None, "dump_name": "",
                "filesystem_only": True,
                "filesystem": {"status": "present", "path": item["path"],
                               "version": item["version"], "type": item["type"],
                               "findings": findings},
                "signals": (["flagged_files"] if findings else []),
                "review": bool(findings),
            })

        for row in out["configuration"]:
            signals = []
            if row.get("key") == "users_can_register" and str(row.get("value")) == "1":
                signals.append("open_registration")
            if row.get("key") == "default_role" and str(row.get("value")).lower() in (
                    "administrator", "editor"):
                signals.append("privileged_default_role")
            row["signals"] = signals
            row["review"] = bool(signals)

        privileged_groups = ("administrator", "super user", "super users")
        for row in out["access"]:
            signals = []
            label = str(row.get("label") or "").lower()
            roles = [str(role).lower() for role in row.get("roles") or []]
            if row.get("account_admin") or any(
                    role in privileged_groups for role in [label, *roles]):
                signals.append("privileged_access")
            if row.get("kind") == "application_password":
                signals.append("application_password")
            elif row.get("kind") == "session":
                signals.append("active_session")
            recent_privileged = (row.get("account_admin") and
                                 "young" in row.get("account_signals", []))
            if recent_privileged:
                signals.append("recent_privileged_account")
            row["signals"] = signals
            # Ordinary administrator roles and existing sessions belong in
            # the access lens, not automatically in the top review queue.
            # Otherwise a healthy site with many editors would bury actual
            # contradictions.  New privileged accounts and application
            # passwords remain explicit review work.
            row["review"] = bool(
                recent_privileged or row.get("kind") == "application_password")

        for row in out["persistence"]:
            signals = ["external_target"] if row.get("domains") else []
            row["signals"] = signals
            row["review"] = bool(signals)

        for row in out["content"]:
            row["signals"] = list(dict.fromkeys(row.get("signals") or []))
            row["review"] = bool(row["signals"])

        review_queue = []
        access_review_seen = set()
        for category in categories:
            for row in out[category]:
                if row.get("review"):
                    if category == "access":
                        # One recent privileged account can have a role row,
                        # several sessions and an application-password row.
                        # It is one account review, not four queue items.  An
                        # application password remains its own review because
                        # the analyst may revoke it independently.
                        if row.get("kind") == "application_password":
                            identity = (row.get("dump_id"), row.get("user_id"),
                                        "application_password", row.get("key"))
                        else:
                            identity = (row.get("dump_id"), row.get("user_id"),
                                        "recent_privileged_account")
                        if identity in access_review_seen:
                            continue
                        access_review_seen.add(identity)
                    review_queue.append({"category": category, **row})
        review_queue.sort(key=lambda row: (
            0 if "active_missing_files" in row.get("signals", []) else
            1 if "flagged_files" in row.get("signals", []) else
            2 if row.get("category") == "content" else 3,
            str(row.get("name") or row.get("label") or row.get("title") or "")))

        summary = {
            "needs_review": len(review_queue),
            "active_extensions": sum(
                1 for row in out["extensions"] if row.get("enabled") is True),
            "access_records": len(out["access"]),
            "persistence_records": len(out["persistence"]),
            "content_signals": sum(1 for row in out["content"] if row.get("signals")),
        }
        return {**out, "cms": sorted(cms_seen), "truncated": truncated,
                "review_queue": review_queue, "summary": summary}

    def _database_data(case_dir, lang="en"):
        conn = db.connect(case_dir)
        try:
            all_dumps = db.rows(conn, "SELECT * FROM db_dumps ORDER BY path")
            for d in all_dumps:
                d["meta"] = json.loads(d["meta"] or "{}")
            tables = db.rows(conn,
                             "SELECT t.*, d.kind AS dump_kind FROM db_tables t "
                             "JOIN db_dumps d ON d.id = t.dump_id "
                             "ORDER BY t.rows DESC, t.name")
            accounts = db.rows(conn, "SELECT * FROM db_accounts")
            # Which accounts are already in the box -- so the button does
            # not offer what has long been done.
            in_box = {r["value"] for r in db.rows(
                conn, "SELECT value FROM iocs WHERE type IN ('user','email')")}
            findings = db.rows(conn,
                               "SELECT * FROM findings WHERE source = 'sqldb' "
                               "ORDER BY severity, artifact LIMIT 500")
            flagged = db.rows(conn,
                              f"WITH art AS ({ART_SQL}) "
                              f"SELECT artifact, worst, triage, findings FROM art "
                              f"WHERE artifact_kind = 'table'")
            installs = db.rows(conn, "SELECT * FROM cms_installs ORDER BY root")
            cms_items = db.rows(conn, "SELECT * FROM cms_items ORDER BY type, name")
            file_artifacts = db.rows(
                conn, f"WITH art AS ({ART_SQL}) SELECT artifact, worst, triage, findings "
                      f"FROM art WHERE artifact_kind = 'file'")
        finally:
            conn.close()

        # Shipped schema files (install/uninstall/updates of an extension)
        # are not evidence about the database -- they stand separately so
        # that they do not bury the one real export.
        dumps = [d for d in all_dumps if d["kind"] != "schema"]
        schema_files = [d for d in all_dumps if d["kind"] == "schema"]

        # Reference point for "young": when was the export taken? The head
        # of the dump usually says so; otherwise the youngest account in it.
        # Without a reference nothing is marked as young -- better no signal
        # than an invented one.
        reference = None
        for d in dumps:
            reference = reference or _parse_stamp(d["meta"].get("created"))
        if reference is None:
            stamps = [s for s in (_parse_stamp(a["registered"]) for a in accounts) if s]
            reference = max(stamps) if stamps else None

        for a in accounts:
            a["signals"] = _account_signals(a, reference, lang)
            a["rank"] = sum(_SIGNAL_WEIGHT.get(s["id"], 0) for s in a["signals"])
            a["in_box"] = (a["login"] or "").strip() in in_box
        accounts.sort(key=lambda a: (-a["rank"], a["cms"], a["login"].lower()))

        by_table = {}
        for f in flagged:
            by_table[f["artifact"]] = f
        for t in tables:
            hit = by_table.get(t["name"])
            t["flagged"] = hit["findings"] if hit else 0
            t["worst"] = hit["worst"] if hit else None
            t["triage"] = hit["triage"] if hit else None
        # Findings per schema file: a manipulated install.sql is the reason
        # these files are still scanned at all.
        by_dump = {}
        for t in tables:
            if t["flagged"]:
                by_dump[t["dump_id"]] = by_dump.get(t["dump_id"], 0) + t["flagged"]
        for d in schema_files:
            d["flagged"] = by_dump.get(d["id"], 0)
            d.pop("intelligence", None)
        intelligence = _database_intelligence(
            dumps, accounts, installs, cms_items, file_artifacts)
        return {"dumps": dumps, "schema_files": schema_files,
                "tables": [t for t in tables if t["dump_kind"] != "schema"],
                "schema_tables": sum(1 for t in tables if t["dump_kind"] == "schema"),
                "accounts": accounts, "findings": findings,
                "reference": reference.isoformat(sep=" ") if reference else "",
                "intelligence": intelligence}

    @app.get("/api/cases/{slug}/database", dependencies=[auth])
    def database_view(slug: str, lang: str = lang_dep):
        """What the dump yields -- tied to the case: tables know whether
        findings sit on them, accounts carry their conspicuous traits and are
        sorted by them."""
        return _database_data(case_dir_or_404(slug), lang)

    @app.get("/api/cases/{slug}/database/accounts.csv", dependencies=[auth])
    def accounts_csv(slug: str, only: str = "", lang: str = lang_dep):
        """The accounts as a table -- for the password reset list that
        follows every incident. `only=admins` narrows it to those with full
        privileges. Password hashes are NOT in it: this tool documents an
        incident, it does not prepare an attack."""
        case_dir = case_dir_or_404(slug)
        data = _database_data(case_dir, lang)
        rows = [a for a in data["accounts"]
                if only != "admins" or a["admin"]]
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow([_t(lang, "csv.login"), _t(lang, "csv.email"),
                    _t(lang, "csv.role"), "CMS", _t(lang, "csv.table"),
                    _t(lang, "csv.registered"), _t(lang, "csv.lastLogin"),
                    _t(lang, "csv.hashScheme"), _t(lang, "csv.blocked"),
                    _t(lang, "account.conspicuous")])
        for a in rows:
            value = a["login"] or ""
            if value[:1] in ("=", "+", "-", "@"):
                value = "'" + value
            w.writerow([
                value, a["email"],
                _t(lang, "csv.administrator") if a["admin"] else _t(lang, "csv.user"),
                a["cms"], a["tbl"], a["registered"], a["last_login"] or "",
                a["hash_type"],
                _t(lang, "csv.yes") if a["blocked"] else _t(lang, "csv.no"),
                ", ".join(s["label"] for s in a["signals"]),
            ])
        stem = "admins" if only == "admins" else "accounts"
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition":
                                 f"attachment; filename={stem}_{slug}.csv"})

    class FlagAccount(BaseModel):
        # The id from db_accounts. Not the login: the same name can appear
        # in two tables, and only the row knows which of the two was meant.
        account_id: int
        note: str = ""

    @app.post("/api/cases/{slug}/database/accounts/flag", dependencies=[auth])
    def flag_account(slug: str, body: FlagAccount):
        """Take a planted account in as an indicator.

        The LOGIN is the indicator, not the row: under this name someone
        signs in again, and that is what one searches for in other systems.
        The e-mail comes along as its own entry when there is one -- it is
        the second value by which the same account can be found elsewhere --
        and both stay linked so that the report states they belong to ONE
        account.

        The assessment itself is made by the analyst: a dump cannot say that
        an admin is malicious. Hence a button and not a rule."""
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            acc = db.one(conn, "SELECT * FROM db_accounts WHERE id = ?",
                         (body.account_id,))
            if acc is None:
                raise HTTPException(404, "account not found")
            login = (acc["login"] or "").strip()
            if not login:
                raise HTTPException(400, "account has no login name")
            tags = [ioclib.TAG_ANALYST, ioclib.TAG_ACCOUNT]
            # The origin travels into the archive and therefore stays in
            # the project language.
            where = (f"{acc['cms'] or 'CMS'} account from "
                     f"{acc['tbl'] or 'the export'}")
            if acc["admin"]:
                where += " (administrator)"
            login_id = db.add_ioc(conn, login, "user", tags, note=body.note,
                                  origin=f"marked by the analyst — {where}")
            added = [{"value": login, "type": "user"}]
            email = (acc["email"] or "").strip()
            if email:
                mail_id = db.add_ioc(
                    conn, email, "email", [ioclib.TAG_ANALYST, ioclib.TAG_DERIVED],
                    origin=f"e-mail of account {login}")
                db.link_iocs(conn, mail_id, login_id, ioclib.LINK_ACCOUNT_OF)
                added.append({"value": email, "type": "email"})
            conn.commit()
        finally:
            conn.close()
        hub.publish({"type": "invalidate", "scope": "iocs"})
        return {"added": added}

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
