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
            still_running = manager.wait_for(live, timeout=20)
            if still_running:
                # An engine that is still running holds an open handle on
                # case.db -- on Windows the delete of the working copy would
                # fail with WinError 32. Refuse cleanly instead.
                raise HTTPException(
                    409, "Es laufen noch Jobs, die nicht rechtzeitig beendet "
                         "werden konnten. Bitte kurz warten und den Fall "
                         "erneut schließen.")
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
            # Counted in ARTIFACTS -- the same unit the findings view works
            # in. "14 Dateien" is the size of the job; the 119 rules that
            # fired on them are the evidence, not the workload.
            severity = {r["worst"]: r["n"] for r in db.rows(
                conn, f"WITH art AS ({_ART_SQL}) SELECT worst, count(*) n "
                      f"FROM art WHERE triage != 'dismissed' GROUP BY worst")}
            triage = _artifact_counts(conn)["triage"]
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

    # The aggregate every artifact query starts from. `state` folds the rows
    # of one artifact into one decision -- confirmed wins (one real hit makes
    # the artifact real), dismissed only counts when it is unanimous. Legacy
    # cases triaged per finding therefore stay readable instead of showing a
    # state their rows do not agree on.
    _ART_SQL = """
        SELECT artifact,
               MIN(artifact_kind) AS artifact_kind,
               MIN(severity)      AS worst,
               MIN(source)        AS source,
               COUNT(*)           AS findings,
               MAX(triaged_at)    AS triaged_at,
               MAX(triage_note)   AS triage_note,
               MAX(last_seen)     AS last_seen,
               CASE
                 WHEN SUM(triage = 'confirmed') > 0 THEN 'confirmed'
                 WHEN SUM(triage = 'dismissed') = COUNT(*) THEN 'dismissed'
                 WHEN SUM(triage = 'reviewed') > 0 THEN 'reviewed'
                 ELSE 'new'
               END AS triage
        FROM findings GROUP BY artifact
    """

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
                f"WITH art AS ({_ART_SQL}) SELECT count(*) FROM art {clause}",
                params).fetchone()[0]
            artifacts = db.rows(
                conn,
                f"WITH art AS ({_ART_SQL}) SELECT * FROM art {clause} "
                f"ORDER BY worst, artifact LIMIT ? OFFSET ?",
                params + [min(limit, 2000), offset])
            rows = []
            if artifacts:
                names = [a["artifact"] for a in artifacts]
                marks = ",".join("?" * len(names))
                rows = db.rows(conn,
                               f"SELECT * FROM findings WHERE artifact IN ({marks}) "
                               f"ORDER BY severity, artifact, line", names)
            counts = _artifact_counts(conn)
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

    def _artifact_counts(conn):
        """The chip counts -- artifacts, not findings, in every dimension."""
        def group(column):
            return {r[column]: r["n"] for r in db.rows(
                conn, f"WITH art AS ({_ART_SQL}) "
                      f"SELECT {column}, count(*) n FROM art GROUP BY {column}")}
        sev = group("worst")
        return {"severity": sev, "triage": group("triage"),
                "source": group("source"),
                "total": sum(sev.values())}

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

    # Groesser als das rechnet niemand nebenbei durch: ein Hash ueber eine
    # 2-GB-Datei laesst den Request haengen. Dieselbe Grenze wie im Detail.
    _HASH_MAX_BYTES = 32 * 1024 * 1024

    def _sha256_of(path):
        """SHA-256 einer Evidence-Datei, oder '' wenn zu gross/unlesbar."""
        try:
            if not os.path.isfile(path) or os.path.getsize(path) > _HASH_MAX_BYTES:
                return ""
            from server.engines.fsutil import sha256_of
            return sha256_of(path) or ""
        except OSError:
            return ""

    # --- was an einem Artefakt hängt -------------------------------------
    #
    # EINE ENTSCHEIDUNG SOLL NICHT ZWEIMAL GETROFFEN WERDEN. Wer eine Datei
    # als True Positive entscheidet, hat damit auch über die Clients
    # entschieden, die sie nachweislich geladen haben -- und umgekehrt. Was
    # fehlte, war der Beleg dafür, WELCHE Clients das sind.
    #
    # Der Beleg steht im Log-Index: die vollständige URI plus Status. Daraus
    # ergeben sich zwei Stufen, und nur die erste entscheidet mit:
    #   stark  -- der Client hat GENAU diese Datei geladen und 2xx bekommen.
    #             Er hat sie benutzt; das ist derselbe Vorfall.
    #   mittel -- gleicher Pfad, aber nie erfolgreich. Eine Sondierung ins
    #             Leere ist etwas anderes als ein Zugriff, also wird sie
    #             vorgeschlagen und nicht entschieden.
    # Der reine Namensvergleich („irgendein index.php") ist KEIN Beleg und
    # taucht hier gar nicht mehr auf.

    def _uri_path(uri):
        """Der Pfadteil einer URI, klein geschrieben, ohne Query."""
        return str(uri or "").split("?", 1)[0].split("#", 1)[0].strip().lower()

    def _web_path(conn, artifact):
        """Die Datei so, wie sie in einer URL stünde: der Pfad unterhalb der
        Evidence-Wurzel, unter der sie liegt. Fällt auf den Dateinamen
        zurück, wenn keine Wurzel passt."""
        target = str(artifact).replace("\\", "/")
        best = ""
        for row in db.rows(conn, "SELECT path FROM evidence"):
            root = str(row["path"]).replace("\\", "/").rstrip("/")
            if root and target.lower().startswith(root.lower() + "/") \
                    and len(root) > len(best):
                best = root
        rel = target[len(best) + 1:] if best else os.path.basename(target)
        return rel.strip("/").lower()

    def _touches(conn, case_dir, by_artifact):
        """artifact -> [{ip, hits, ok_hits, uri}] für die Datei-Artefakte
        darin. Eine Abfrage für alle Namen, der Pfadvergleich danach."""
        files = {a: _web_path(conn, a) for a, findings in by_artifact.items()
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
                if not _uri_path(r["uri"]).endswith(tail):
                    continue
                agg = hits.setdefault(r["ip"], {"ip": r["ip"], "hits": 0,
                                                "ok_hits": 0, "uri": r["uri"]})
                agg["hits"] += r["hits"]
                agg["ok_hits"] += r["ok_hits"]
            out[artifact] = sorted(hits.values(),
                                   key=lambda h: (-h["ok_hits"], -h["hits"]))
        return out

    def _propagate(conn, case_dir, decided, touches):
        """Eine Entscheidung wandert GENAU EINEN SCHRITT weit.

        Zurück kommt (linked, suggested): was mitentschieden wurde -- mit dem
        Zustand davor, damit die Oberfläche es zurücknehmen kann -- und was
        nur vorgeschlagen wird. Ein Schritt, nicht mehr: sonst zieht eine
        bestätigte Datei Clients nach, die weitere Dateien nachziehen, und am
        Ende steht ein Fall auf einer Entscheidung."""
        # Welche Artefakte gibt es überhaupt, und wie stehen sie? Ein Client
        # ohne eigenes Finding ist kein Artefakt -- er landet wie bisher nur
        # in der IOC Box.
        known = {r["artifact"]: r for r in db.rows(
            conn, f"WITH art AS ({_ART_SQL}) "
                  f"SELECT artifact, artifact_kind, triage, triage_note FROM art")}
        # Eine Übernahme fasst nur an, was noch NICHT entschieden ist. Ein
        # von Hand vergebenes False Positive darf eine Automatik niemals
        # überschreiben -- und ein bereits bestätigtes Artefakt braucht
        # weder neue Notiz noch neuen Zeitstempel.
        open_states = ("new", "reviewed")
        linked, suggested, seen = [], [], set(decided)

        def entry(artifact, why, hits=None, ok_hits=None):
            row = known[artifact]
            return {"artifact": artifact, "kind": row["artifact_kind"],
                    "why": why, "hits": hits, "ok_hits": ok_hits,
                    "previous": {"state": row["triage"],
                                 "note": row["triage_note"] or ""}}

        # --- Datei bestätigt -> die Clients, die sie geladen haben ---------
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
                        h["ip"], f"hat {label} geladen ({h['ok_hits']}× 2xx)",
                        h["hits"], h["ok_hits"]))
                else:
                    suggested.append(entry(
                        h["ip"], f"hat {label} angefragt, nie erfolgreich "
                                 f"({h['hits']}×)", h["hits"], h["ok_hits"]))

        # --- Client bestätigt -> die Dateien, die er geladen hat -----------
        clients = [a for a in decided
                   if known.get(a, {}).get("artifact_kind") == "client"]
        if clients:
            file_paths = {a: _web_path(conn, a) for a, r in known.items()
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
                               if _uri_path(r["uri"]).endswith(tail)]
                        if not hit:
                            continue
                        ok = sum(r["ok_hits"] for r in hit)
                        n = sum(r["hits"] for r in hit)
                        label = os.path.basename(str(artifact).replace("\\", "/"))
                        if ok > 0:
                            seen.add(artifact)
                            linked.append(entry(
                                artifact, f"wurde von {ip} geladen ({ok}× 2xx)",
                                n, ok))
                        else:
                            suggested.append(entry(
                                artifact,
                                f"wurde von {ip} angefragt, nie erfolgreich ({n}×)",
                                n, ok))

        # Die Übernahme selbst: eigener Vermerk, damit im Fall steht, WORAUS
        # die Entscheidung folgt und dass sie nicht von Hand getroffen wurde.
        for item in linked:
            conn.execute(
                "UPDATE findings SET triage = 'confirmed', triage_note = ?, "
                "triaged_at = ? WHERE artifact = ?",
                (f"übernommen: {item['why']}", db.now(), item["artifact"]))
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
            db.add_ioc(conn, artifact, "path", tags, origin=origin)
            out.append({"value": artifact, "type": "path"})
            # Der Hash aus dem Scan, sonst jetzt berechnet: das Detail zeigt
            # ihn ohnehin an, und ein bestaetigtes Artefakt ohne seinen
            # SHA-256 in der Box waere im Bericht eine Luecke.
            digest = hashes.get(artifact) or _sha256_of(artifact)
            if digest:
                db.add_ioc(conn, digest, "hash",
                           [ioclib.TAG_DERIVED, ioclib.TAG_CONFIRMED],
                           origin=f"sha-256 of {os.path.basename(artifact)}")
                out.append({"value": digest, "type": "hash"})
            # instant hunt: who requested exactly this path?
            name = os.path.basename(artifact.replace("\\", "/"))
            for hit in list(touches)[:25]:
                tags = [ioclib.TAG_HUNT]
                if hit["ok_hits"] > 0:
                    tags.append(ioclib.TAG_SUCCESS)
                db.add_ioc(conn, hit["ip"], "ip", tags,
                           origin=f"requested {name} ({hit['hits']}×, "
                                  f"{hit['ok_hits']}× 2xx)")
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
            db.add_ioc(conn, artifact, "other",
                       [ioclib.TAG_FINDING, ioclib.TAG_CONFIRMED, ioclib.TAG_INJECTED],
                       origin=origin)
            out.append({"value": artifact, "type": "other"})
            hosts = []
            for f in findings:
                hosts += ioclib.HOST_RE.findall(f["evidence"] or "")
            for host in list(dict.fromkeys(hosts))[:5]:
                db.add_ioc(conn, host, "domain",
                           [ioclib.TAG_DERIVED, ioclib.TAG_INJECTED],
                           origin=f"host in evidence of: {rules}")
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
                # Wer hat GENAU diese Datei angefragt -- Pfad, nicht Name.
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
            add(artifact, "Dieser Client")
        for hit in hunt:
            add(hit["ip"],
                (f"hat {hit['name']} geladen ({hit['ok_hits']}× 2xx)"
                 if hit["ok_hits"] else f"hat {hit['name']} angefragt, "
                                        f"nie erfolgreich"),
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
            # Die Entscheidung des Client-Artefakts, falls es eines gibt: in
            # Actors muss sichtbar sein, was in Findings längst entschieden
            # wurde — sonst bewertet man hier gedanklich neu.
            triage = {r["artifact"]: r["triage"] for r in db.rows(
                conn, f"WITH art AS ({_ART_SQL}) SELECT artifact, triage "
                      f"FROM art WHERE artifact_kind = 'client'")}
        finally:
            conn.close()
        for a in result["actors"]:
            a["sparkline"] = sparks["series"].get(a["ip_id"], [])
            a["in_box"] = a["ip"] in box_ips
            a["triage"] = triage.get(a["ip"])
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

    def _ext_scope(item):
        """Worauf sich eine Extension im Dateisystem erstreckt.

        Der gespeicherte Pfad zeigt mal auf das Verzeichnis, mal auf das
        Manifest darin, mal auf eine Einzeldatei-Extension (WPs hello.php).
        Der Slug entscheidet: heißt das Verzeichnis im Pfad wie der Slug,
        gehört der ganze Baum dazu — sonst nur die Datei selbst. Eine
        Einzeldatei darf nie ihren Container erben, sonst „enthält" hello.php
        jede Shell im plugins-Ordner."""
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
        """Das Inventar, verknüpft mit dem Fall: jede Extension weiß, ob
        unter ihrem Pfad geflaggte Artefakte liegen. Das ist die Frage, wegen
        der man die Seite im Vorfall öffnet — welche Erweiterung ist es?"""
        case_dir = case_dir_or_404(slug)
        conn = db.connect(case_dir)
        try:
            installs = db.rows(conn, "SELECT * FROM cms_installs ORDER BY root")
            items = db.rows(conn, "SELECT * FROM cms_items ORDER BY type, name")
            flagged = db.rows(conn,
                              f"WITH art AS ({_ART_SQL}) "
                              f"SELECT artifact, worst, triage, findings "
                              f"FROM art WHERE artifact_kind = 'file'")
            overrides = {(r["scope"], r["key"]): r for r in db.rows(
                conn, "SELECT * FROM cms_version_overrides")}
        finally:
            conn.close()
        root_by_id = {i["id"]: i["root"] for i in installs}

        def overlay(row, scope, key):
            """Die Korrektur des Analysten über den Messwert legen -- ohne
            ihn zu verlieren: `version_parsed` bleibt daneben stehen, sonst
            wäre im Bericht nicht mehr erkennbar, was gemessen und was
            entschieden wurde."""
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
        """Die Identität einer Extension ÜBER RE-ANALYSEN HINWEG. Die id
        wechselt bei jedem Lauf (die Tabelle wird geleert), Wurzel + Typ +
        Slug bleiben -- daran hängt die Korrektur des Analysten."""
        return f"{root}|{item['type']}|{item['slug']}"

    class VersionBody(BaseModel):
        # Leerer String = Korrektur zurücknehmen, zurück auf den Messwert.
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
        """Eine Version von Hand setzen -- wenn das Manifest fehlt, gefälscht
        ist oder der Analyst sie anders belegt hat."""
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

    # Wie lange vor dem Export ein Konto angelegt worden sein muss, damit es
    # als "jung" auffällt. Kein Urteil -- eine Sortierhilfe: bei einem
    # Vorfall ist ein zwei Tage alter Administrator die erste Zeile, die man
    # ansieht, und in 400 Konten findet man sie sonst nicht.
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

    def _account_signals(acc, reference):
        """Was an diesem Konto AUFFÄLLT -- als benannte Beobachtungen, nicht
        als Punktzahl. Ein Dump kann nicht sagen, dass ein Admin bösartig
        ist; er kann sagen, dass einer gestern angelegt wurde und sich nie
        angemeldet hat. Die Bewertung bleibt beim Analysten, die Reihenfolge
        macht sie nur auffindbar."""
        out = []
        registered = _parse_stamp(acc["registered"])
        if acc["admin"]:
            out.append({"id": "admin", "label": "Admin",
                        "why": "Konto mit vollen Rechten."})
        if registered and reference and 0 <= (reference - registered).days <= _YOUNG_DAYS:
            days = (reference - registered).days
            out.append({"id": "young",
                        "label": ("am Tag des Exports angelegt" if days == 0
                                  else f"vor {days} Tag{'' if days == 1 else 'en'} angelegt"),
                        "why": "Kurz vor dem Export registriert — bei einem "
                               "Vorfall die erste Frage: wer war das?"})
        if "weak" in (acc["hash_type"] or ""):
            out.append({"id": "weak_hash", "label": "schwacher Hash",
                        "why": "MD5 ohne Salt — solche Passwörter sind schnell "
                               "zu knacken."})
        if acc["admin"] and not acc["last_login"] and acc["cms"] == "Joomla":
            out.append({"id": "never", "label": "nie angemeldet",
                        "why": "Ein Administrator, der sich nie angemeldet hat, "
                               "wurde für etwas anderes angelegt."})
        if acc["sessions"]:
            out.append({"id": "session", "label": "offene Sitzung",
                        "why": "Beim Export war dieses Konto angemeldet."})
        if acc["blocked"]:
            out.append({"id": "blocked", "label": "gesperrt",
                        "why": "Vom CMS deaktiviert."})
        return out

    # Reihenfolge der Auffälligkeit -- nur fürs Sortieren.
    _SIGNAL_WEIGHT = {"admin": 4, "young": 3, "never": 2, "session": 2,
                      "weak_hash": 1, "blocked": 0}

    def _database_data(case_dir):
        conn = db.connect(case_dir)
        try:
            dumps = db.rows(conn, "SELECT * FROM db_dumps ORDER BY path")
            for d in dumps:
                d["meta"] = json.loads(d["meta"] or "{}")
            tables = db.rows(conn,
                             "SELECT * FROM db_tables ORDER BY rows DESC, name")
            accounts = db.rows(conn, "SELECT * FROM db_accounts")
            findings = db.rows(conn,
                               "SELECT * FROM findings WHERE source = 'sqldb' "
                               "ORDER BY severity, artifact LIMIT 500")
            flagged = db.rows(conn,
                              f"WITH art AS ({_ART_SQL}) "
                              f"SELECT artifact, worst, triage, findings FROM art "
                              f"WHERE artifact_kind = 'table'")
        finally:
            conn.close()

        # Bezugspunkt für "jung": wann wurde exportiert? Der Kopf des Dumps
        # sagt es meist; sonst das jüngste Konto darin. Ohne Bezug wird
        # nichts als jung markiert -- lieber kein Signal als ein erfundenes.
        reference = None
        for d in dumps:
            reference = reference or _parse_stamp(d["meta"].get("created"))
        if reference is None:
            stamps = [s for s in (_parse_stamp(a["registered"]) for a in accounts) if s]
            reference = max(stamps) if stamps else None

        for a in accounts:
            a["signals"] = _account_signals(a, reference)
            a["rank"] = sum(_SIGNAL_WEIGHT.get(s["id"], 0) for s in a["signals"])
        accounts.sort(key=lambda a: (-a["rank"], a["cms"], a["login"].lower()))

        by_table = {}
        for f in flagged:
            by_table[f["artifact"]] = f
        for t in tables:
            hit = by_table.get(t["name"])
            t["flagged"] = hit["findings"] if hit else 0
            t["worst"] = hit["worst"] if hit else None
            t["triage"] = hit["triage"] if hit else None
        return {"dumps": dumps, "tables": tables, "accounts": accounts,
                "findings": findings, "reference": reference.isoformat(sep=" ")
                if reference else ""}

    @app.get("/api/cases/{slug}/database", dependencies=[auth])
    def database_view(slug: str):
        """Was der Dump hergibt — mit dem Fall verknüpft: Tabellen wissen,
        ob auf ihnen Findings sitzen, Konten tragen ihre auffälligen
        Merkmale und stehen danach sortiert."""
        return _database_data(case_dir_or_404(slug))

    @app.get("/api/cases/{slug}/database/accounts.csv", dependencies=[auth])
    def accounts_csv(slug: str, only: str = ""):
        """Die Konten als Tabelle — für die Passwort-Reset-Liste, die nach
        jedem Vorfall ansteht. `only=admins` schneidet auf die zu, die
        volle Rechte haben. Passwort-Hashes stehen NICHT drin: dieses
        Werkzeug dokumentiert einen Vorfall, es bereitet keinen Angriff
        vor."""
        case_dir = case_dir_or_404(slug)
        data = _database_data(case_dir)
        rows = [a for a in data["accounts"]
                if only != "admins" or a["admin"]]
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["Login", "E-Mail", "Rolle", "CMS", "Tabelle", "Registriert",
                    "Letzter Login", "Hash-Verfahren", "Gesperrt", "Auffällig"])
        for a in rows:
            value = a["login"] or ""
            if value[:1] in ("=", "+", "-", "@"):
                value = "'" + value
            w.writerow([
                value, a["email"],
                "Administrator" if a["admin"] else "User",
                a["cms"], a["tbl"], a["registered"], a["last_login"] or "",
                a["hash_type"], "ja" if a["blocked"] else "nein",
                ", ".join(s["label"] for s in a["signals"]),
            ])
        stem = "admins" if only == "admins" else "accounts"
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition":
                                 f"attachment; filename={stem}_{slug}.csv"})

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
