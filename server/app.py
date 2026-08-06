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
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from server import coverage, db, enrich, geoip, iocs as ioclib
from server import patterns as patternlib
from server import settings as settingslib, workspace
from server.artifacts import ART_SQL, counts as artifact_counts, uri_path, web_path
from server.chain import case_chain
from server.i18n import lang_of
from server.i18n import t as _t
from server.config import Config
from server.engines import (cmsinventory, detect, errorlog, logindex, sqldump,
                            yarascan,
                            webrootdiff, webshell)
from server.events import hub
from server.jobs import manager

def _find_web_dist():
    """The built interface -- under web/dist in the repository, under
    server/static in an installed package. Both routes, so that `pip install`
    works without a Node toolchain on the forensic machine and development in
    the repository stays unchanged."""
    here = Path(__file__).resolve().parent
    for candidate in (here / "static", here.parent / "web" / "dist"):
        if (candidate / "index.html").is_file():
            return candidate
    # Nothing built: the server runs anyway (the API is complete), and the
    # start page says what is missing.
    return here.parent / "web" / "dist"


WEB_DIST = _find_web_dist()

EVIDENCE_KINDS = ("webroot", "access_logs", "sql_dump", "reference")


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

    # --- language -----------------------------------------------------------

    def request_lang(request: Request) -> str:
        """The language the prose assembled HERE is written in.

        The browser sends it as a header on every API call; a download link
        cannot set headers and sends `?lang=` instead. Anything the server
        STORES stays English regardless -- see server/i18n.py."""
        return lang_of(request.headers.get("x-lang")
                       or request.query_params.get("lang"))

    lang_dep = Depends(request_lang)

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

    @app.get("/api/cases/{slug}/summary", dependencies=[auth])
    def case_close_preview(slug: str):
        """What closing this case would pack away -- shown before it happens."""
        case_dir = case_dir_or_404(slug)
        return workspace.case_summary(case_dir)

    @app.post("/api/cases/{slug}/archive", dependencies=[auth])
    def archive(slug: str, lang: str = lang_dep):
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
            manager.cancel(case_dir, job_id)
        if live:
            still_running = manager.wait_for(case_dir, live, timeout=20)
            if still_running:
                # An engine that is still running holds an open handle on
                # case.db -- on Windows the delete of the working copy would
                # fail with WinError 32. Refuse cleanly instead.
                raise HTTPException(409, _t(lang, "err.jobsRunning"))
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

    @app.get("/api/cases/{slug}/coverage", dependencies=[auth])
    def log_coverage(slug: str, lang: str = lang_dep):
        """Where the logs are SILENT, and whether the shape of the hole looks
        deliberate. No findings and no severities: a removed window and a
        quiet night look identical from here, so this points at the question
        rather than answering it."""
        return coverage.report(case_dir_or_404(slug), lang)

    @app.get("/api/yara", dependencies=[auth])
    def yara_status():
        """Whether the analyst's own rules can run, and out of what.

        Distinguishes the two silences that look alike: no YARA installed
        versus no rules placed. "No YARA findings" must never be ambiguous
        between "the rules found nothing" and "there were no rules"."""
        return yarascan.status(config.workspace)

    # --- the rule files, as things the analyst edits ----------------------
    # They live in the WORKSPACE, like the pattern library and for the same
    # reason: a rule set grows across cases. Editing them here rather than in
    # a text editor is only convenience -- the files stay plain `.yar` and can
    # still be dropped in by hand or pulled from a vendor feed.

    def _yara_error(exc, lang):
        return _t(lang, exc.key) if exc.key else str(exc)

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
                                size = entry.stat().st_size
                            except OSError:
                                size = 0
                            files.append({"name": entry.name, "path": entry.path,
                                          "size": size})
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

            # The error logs sit in the same directory and were skipped by
            # the index -- they name files the access log structurally
            # cannot see. Own job: it reads the same directory but answers a
            # different question.
            def run_errors(ctx, paths=paths, case_dir=case_dir):
                return errorlog.scan(case_dir, paths, ctx)

            started.append({"kind": "errorlog",
                            "job": manager.submit(case_dir, "errorlog", run_errors)})

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

            # The analyst's OWN rules, if there are any. Queued as its own
            # job so a slow rule set never holds up the shipped scan.
            if yarascan.status(config.workspace).get("rules"):
                def run_yara(ctx, paths=paths, case_dir=case_dir):
                    return yarascan.scan(case_dir, paths,
                                         workspace=config.workspace, ctx=ctx)

                started.append({"kind": "yara",
                                "job": manager.submit(case_dir, "yara", run_yara)})

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
        case_dir = case_dir_or_404(slug)
        return {"cancelled": manager.cancel(case_dir, job_id)}

    # --- dashboard ----------------------------------------------------------

    @app.get("/api/cases/{slug}/dashboard", dependencies=[auth])
    def dashboard(slug: str):
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
            findings_total = conn.execute(
                "SELECT count(*) FROM findings").fetchone()[0]
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
            "findings_total": findings_total,
            "accounts": accounts, "admins": admins,
            "cms_installs": installs, "evidence": evidence,
            "jobs_running": running,
            "logs": logindex.overview(case_dir),
            "timeline": logindex.timeline(case_dir),
        }

    # --- the chronology of the case -----------------------------------------
    # Assembled in server/chain.py -- it is the one piece of narrative the
    # server writes, shared by this route and the JSON export.

    @app.get("/api/cases/{slug}/chain", dependencies=[auth])
    def chain(slug: str, lang: str = lang_dep):
        return case_chain(case_dir_or_404(slug), lang)

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
                      hide_source: str = "", kind: str = "", search: str = "",
                      limit: int = 500, offset: int = 0):
        """The artifact list with the findings of every artifact attached.

        FILTERS HIDE, THEY DO NOT SELECT: every chip in the UI is a toggle
        that removes its class from view (`hide_severity=3,2` etc.) and
        brings it back on the next click. Several can stack. Nothing is
        deleted -- the counts always describe the whole set, and an artifact
        that IS shown always arrives COMPLETE: filtering must never hide part
        of what a decision is based on.

        `severity` is the artifact's worst finding, `triage` its decision."""
        case_dir = case_dir_or_404(slug)

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
        sources = csv_values(hide_source, {"webshell", "sqldb", "logs"})
        if sources:
            where.append(f"source NOT IN ({','.join('?' * len(sources))})")
            params += sources
        if kind:
            where.append("artifact_kind = ?")
            params.append(kind)
        if search:
            # An artifact matches when ANY of its findings matches -- and then
            # shows all of them. A hit on one rule is a reason to look at the
            # file, not a reason to see only that rule.
            where.append("artifact IN (SELECT artifact FROM findings "
                         "WHERE rule LIKE ? OR artifact LIKE ? OR evidence LIKE ?)")
            like = f"%{search}%"
            params += [like, like, like]
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        conn = db.connect(case_dir)
        try:
            total = conn.execute(
                f"WITH art AS ({ART_SQL}) SELECT count(*) FROM art {clause}",
                params).fetchone()[0]
            artifacts = db.rows(
                conn,
                f"WITH art AS ({ART_SQL}) SELECT * FROM art {clause} "
                f"ORDER BY worst, artifact LIMIT ? OFFSET ?",
                params + [min(limit, 2000), offset])
            rows = []
            if artifacts:
                names = [a["artifact"] for a in artifacts]
                marks = ",".join("?" * len(names))
                rows = db.rows(conn,
                               f"SELECT * FROM findings WHERE artifact IN ({marks}) "
                               f"ORDER BY severity, artifact, line", names)
            counts = artifact_counts(conn)
            # The evidence roots travel with the findings so the UI can show a
            # path the way an analyst thinks about it -- `images/shell.php`
            # under a named webroot, not 90 characters of absolute path.
            roots = db.rows(conn, "SELECT kind, path, label FROM evidence")
            return {"total": total, "artifacts": artifacts, "findings": rows,
                    "findings_total": conn.execute(
                        "SELECT count(*) FROM findings").fetchone()[0],
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
        note: str = ""
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
        try:
            artifacts = _artifacts_of(conn, body.artifacts, body.fingerprints)
            if not artifacts:
                return {"updated": 0, "artifacts": 0, "collected": []}
            marks = ",".join("?" * len(artifacts))
            rows = db.rows(conn,
                           f"SELECT * FROM findings WHERE artifact IN ({marks}) "
                           f"ORDER BY severity, line", artifacts)
            conn.execute(
                f"UPDATE findings SET triage = ?, triage_note = ?, triaged_at = ? "
                f"WHERE artifact IN ({marks})",
                [body.state, body.note, db.now()] + artifacts)
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
            conn.commit()
        finally:
            conn.close()
        hub.publish({"type": "invalidate", "scope": "findings"})
        return {"updated": len(rows), "artifacts": len(artifacts),
                "collected": _dedupe_collected(collected),
                "linked": linked, "suggested": suggested}

    # Nobody computes more than this in passing: a hash over a 2 GB file
    # leaves the request hanging. The same limit as in the detail view.
    _HASH_MAX_BYTES = 32 * 1024 * 1024

    def _sha256_of(path):
        """SHA-256 of an evidence file, or '' when too large/unreadable."""
        try:
            if not os.path.isfile(path) or os.path.getsize(path) > _HASH_MAX_BYTES:
                return ""
            from server.engines.fsutil import sha256_of
            return sha256_of(path) or ""
        except OSError:
            return ""

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
            tail = "/" + rel
            hits = {}
            for r in rows:
                if not uri_path(r["uri"]).endswith(tail):
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
            conn.execute(
                "UPDATE findings SET triage = 'confirmed', triage_note = ?, "
                "triaged_at = ? WHERE artifact = ?",
                (f"propagated: {item['why']}", db.now(), item["artifact"]))
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
            if "webshell" in sources:
                tags.append(ioclib.TAG_WEBSHELL)
            # The path IN THE WEBROOT, never the absolute one. Where the
            # copy sits on the forensic machine is nobody's business outside
            # that machine -- and an export would otherwise carry it out.
            value = db.case_relative_path(conn, artifact)
            path_id = db.add_ioc(conn, value, "path", tags, origin=origin)
            out.append({"value": value, "type": "path"})
            # The hash from the scan, otherwise computed now: the detail
            # view shows it anyway, and a confirmed artifact without its
            # SHA-256 in the box would be a gap in the report.
            digest = hashes.get(artifact) or _sha256_of(artifact)
            if digest:
                hash_id = db.add_ioc(conn, digest, "hash",
                                     [ioclib.TAG_DERIVED, ioclib.TAG_CONFIRMED],
                                     origin=f"sha-256 of {os.path.basename(artifact)}")
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
            db.add_ioc(conn, artifact, "ip", tags, origin=origin)
            out.append({"value": artifact, "type": "ip"})
        elif kind == "table":
            table_id = db.add_ioc(
                conn, artifact, "other",
                [ioclib.TAG_FINDING, ioclib.TAG_CONFIRMED, ioclib.TAG_INJECTED],
                origin=origin)
            out.append({"value": artifact, "type": "other"})
            hosts = []
            for f in findings:
                hosts += ioclib.HOST_RE.findall(f["evidence"] or "")
            for host in list(dict.fromkeys(hosts))[:5]:
                host_id = db.add_ioc(conn, host, "domain",
                                     [ioclib.TAG_DERIVED, ioclib.TAG_INJECTED],
                                     origin=f"host in evidence of: {rules}")
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
    def artifact_context(slug: str, artifact: str):
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
                    except OSError:
                        pass
                    meta = db.one(conn, "SELECT value FROM meta "
                                        "WHERE key = 'webshell_hashes'")
                    hashes = json.loads(meta["value"] or "{}") if meta else {}
                    info["sha256"] = hashes.get(path) or _sha256_of(path)
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
            out["related_ips"] = _related_ips(conn, kind, artifact, findings, hunt)
            return out
        finally:
            conn.close()

    def _related_ips(conn, kind, artifact, findings, hunt):
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
                add(ip, f"steht in der Evidence von: {f['rule']}")
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
            size = target.stat().st_size
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

    # --- pattern hunt -------------------------------------------------------
    # The library belongs to the WORKSPACE: created once, a pattern is ready
    # in every further case. The case only records what was searched for in
    # it -- including the runs without hits.

    @app.get("/api/patterns", dependencies=[auth])
    def patterns_list():
        """Both halves, switched-off entries included so the interface can
        offer them back. Each row says which half it came from."""
        rows = patternlib.library(config.workspace, include_disabled=True)
        return {"patterns": rows,
                "path": str(patternlib.library_path(config.workspace)),
                "bundled": sum(1 for p in rows if p["source"] == "bundled"),
                "disabled": sum(1 for p in rows if not p["enabled"])}

    class NewPattern(BaseModel):
        pattern: str = ""
        label: str = ""
        note: str = ""          # a tag beside the name, kept short
        about: str = ""         # what a hit here proves -- the long form
        text: str = ""          # several at once (lines or JSON)

    @app.post("/api/patterns", dependencies=[auth])
    def patterns_add(body: NewPattern, lang: str = lang_dep):
        try:
            if body.text.strip():
                return patternlib.import_text(config.workspace, body.text)
            return {"added": 1, "skipped": 0, "invalid": 0,
                    "entry": patternlib.add(config.workspace, body.pattern,
                                            body.label, body.note,
                                            body.about)}
        except patternlib.PatternError as e:
            raise HTTPException(400, _pattern_error(e, lang)) from e

    class PatchPattern(BaseModel):
        pattern: str | None = None
        label: str | None = None
        note: str | None = None
        about: str | None = None

    @app.patch("/api/patterns/{pattern_id}", dependencies=[auth])
    def patterns_patch(pattern_id: str, body: PatchPattern,
                       lang: str = lang_dep):
        try:
            return patternlib.update(config.workspace, pattern_id,
                                     body.pattern, body.label, body.note,
                                     body.about)
        except patternlib.PatternError as e:
            raise HTTPException(400, _pattern_error(e, lang)) from e

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

    @app.post("/api/cases/{slug}/hunt/run", dependencies=[auth])
    def hunt_run(slug: str, body: RunHunt):
        """Every pattern against the log index. Hits become findings on the
        CLIENT artifact -- so everything further runs through the existing
        triage instead of opening a second work list next to the first.

        Outcome-gated like the other log rules: answered with 2xx a hit is
        HIGH, a bare attempt stays LOW. With the pattern the analyst has said
        that the path belongs to an exploit -- whether the server played
        along is something only the status code says."""
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
                match = logindex.match_pattern(case_dir, entry["pattern"])
                name = entry["label"] or entry["pattern"]
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
                                  f"{entry['pattern']} ({origin}) · "
                                  f"e.g. {example}")[:400])
                    new_findings += 1
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
                    (entry["pattern"], entry["label"], db.now(), match["hits"],
                     match["ok_hits"], match["clients_total"],
                     match["ok_clients"], match["uri_total"],
                     match["first_epoch"], match["last_epoch"], match["tz"]))
                results.append({**match, "id": entry["id"],
                                "label": entry["label"], "note": entry["note"]})
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
            bases = db.evidence_bases(conn)
            flagged = {str(r["artifact"]).replace("\\", "/").lower(): r
                       for r in db.rows(
                           conn, f"WITH art AS ({ART_SQL}) SELECT artifact, worst,"
                                 f" triage, findings FROM art "
                                 f"WHERE artifact_kind = 'file'")}
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
            norm = p.replace("\\", "/").rstrip("/")
            low = norm.lower()
            for root, base in bases:
                if low == root.lower() or low.startswith(root.lower() + "/"):
                    return (norm[len(base) + 1:] if base else norm)
            return norm

        def annotate(entry):
            key = entry["path"].replace("\\", "/").lower()
            hit = flagged.get(key)
            entry["in_box"] = relative(entry["path"]).lower() in box
            entry["relative"] = relative(entry["path"])
            entry["flagged"] = hit["findings"] if hit else 0
            entry["worst"] = hit["worst"] if hit else None
            entry["triage"] = hit["triage"] if hit else None
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
                        origin=f"sha-256 von {os.path.basename(path)}")
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
               flag: str = "", hide: str = "", limit: int = 100,
               offset: int = 0):
        case_dir = case_dir_or_404(slug)
        hidden = [h.strip() for h in hide.split(",") if h.strip()]
        result = logindex.actors_list(case_dir, search, sort, flag, hidden,
                                      limit, offset)
        ids = [a["ip_id"] for a in result["actors"]]
        sparks = logindex.actor_sparklines(case_dir, ids)
        conn = db.connect(case_dir)
        try:
            box_ips = {r["value"] for r in db.rows(
                conn, "SELECT value FROM iocs WHERE type = 'ip'")}
            # The decision of the client artifact, if there is one: what has
            # long been decided in Findings has to be visible in Actors --
            # otherwise one re-assesses it here in one's head.
            triage = {r["artifact"]: r["triage"] for r in db.rows(
                conn, f"WITH art AS ({ART_SQL}) SELECT artifact, triage "
                      f"FROM art WHERE artifact_kind = 'client'")}
        finally:
            conn.close()
        for a in result["actors"]:
            a["sparkline"] = sparks["series"].get(a["ip_id"], [])
            a["in_box"] = a["ip"] in box_ips
            a["triage"] = triage.get(a["ip"])
        result["span"] = sparks["span"]
        # The threshold travels with the data instead of being repeated in
        # the frontend. The badges of a row and the "inconspicuous" filter
        # are the same statement, and the filter is evaluated in SQL against
        # BF_THRESHOLD -- a second copy in TypeScript would drift silently
        # the day this number changes, and the list would then contradict
        # itself.
        result["bf_threshold"] = logindex.BF_THRESHOLD
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

    @app.post("/api/cases/{slug}/trace", dependencies=[auth])
    def trace(slug: str, body: TraceBody):
        case_dir = case_dir_or_404(slug)
        if not body.ips:
            raise HTTPException(400, "no client addresses given")
        return logindex.trace(case_dir, body.ips, body.from_epoch,
                              body.to_epoch, min(body.limit, 10000),
                              body.offset, body.search, body.status,
                              body.method, body.sort)

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
            uri = r["uri"] or ""
            if uri and uri[0] in ("=", "+", "-", "@"):
                uri = "'" + uri
            w.writerow([r["client"], stamp, r["method"], uri, r["status"],
                        r["size"], r["referrer"], r["agent"], r["source"]])
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
                    if a["scanner_uas"] != "[]":
                        tags.append(ioclib.TAG_SCANNER)
                    if a["login_posts"] >= logindex.BF_THRESHOLD:
                        tags.append(ioclib.TAG_BRUTE)
                    if a["login_redirects"] > 0 and a["login_posts"] >= logindex.BF_THRESHOLD:
                        tags.append(ioclib.TAG_SUCCESS)
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

    @app.get("/api/cases/{slug}/iocs", dependencies=[auth])
    def iocs_list(slug: str):
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            rows = db.rows(conn, "SELECT * FROM iocs ORDER BY added DESC, id DESC")
            for r in rows:
                r["tags"] = json.loads(r["tags"] or "[]")
                r["links"] = []
            # Every edge hangs on BOTH ends, each in its own reading
            # direction. Otherwise the analyst would have to know at which of
            # the two indicators the relationship is "stored" -- a question
            # that is none of their business.
            by_id = {r["id"]: r for r in rows}
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
            # The edges along with it: SQLite only enforces foreign keys
            # with the PRAGMA switched on, and setting that globally would
            # affect every other delete path of this database. One line is
            # enough here.
            conn.execute("DELETE FROM ioc_links WHERE src = ? OR dst = ?",
                         (ioc_id, ioc_id))
            conn.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))
            conn.commit()
            return {"ok": True}
        finally:
            conn.close()

    @app.get("/api/cases/{slug}/iocs/export", dependencies=[auth])
    def export_iocs(slug: str, format: str = "csv", lang: str = lang_dep):
        case_dir = case_dir_or_404(slug)
        info = workspace.case_info(case_dir)
        conn = db.connect(case_dir)
        try:
            rows = db.rows(conn, "SELECT * FROM iocs ORDER BY type, value")
            links = db.ioc_links(conn)
        finally:
            conn.close()
        stem = f"iocs_{info['slug']}"
        if format == "json":
            return Response(ioclib.to_json(rows, info["name"], links,
                                           chain=case_chain(case_dir, lang)),
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

    _STAMP_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d",
                      "%d.%m.%Y %H:%M:%S", "%d.%m.%Y")

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
        return {"dumps": dumps, "schema_files": schema_files,
                "tables": [t for t in tables if t["dump_kind"] != "schema"],
                "schema_tables": sum(1 for t in tables if t["dump_kind"] == "schema"),
                "accounts": accounts, "findings": findings,
                "reference": reference.isoformat(sep=" ") if reference else ""}

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
