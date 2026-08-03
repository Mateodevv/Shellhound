# server/workspace.py
"""Case lifecycle: one folder per case under the workspace, zip to archive.

Same shape as the legacy toolkit: a case is a directory, so two
investigations cannot bleed into each other, and closing a case produces one
archive file to hand over.
"""
import gc
import json
import os
import re
import shutil
import stat
import time
import zipfile
from datetime import datetime
from pathlib import Path

from server import db

ARCHIVE_DIR = "archive"
CASE_FILE = "case.json"          # human-readable identity next to case.db
_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slug(name):
    text = (name or "").strip().lower()
    text = (text.replace("ä", "ae").replace("ö", "oe").replace("ü", "ue")
                .replace("ß", "ss"))
    text = _SLUG_RE.sub("-", text).strip("-")
    return text[:60] or "case"


def _unique_dir(workspace, name):
    base = slug(name)
    candidate = workspace / base
    n = 2
    while candidate.exists():
        candidate = workspace / f"{base}-{n}"
        n += 1
    return candidate


def create_case(workspace, name, reference="", notes=""):
    workspace = Path(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    case_dir = _unique_dir(workspace, name)
    case_dir.mkdir()
    identity = {"name": name.strip() or case_dir.name, "reference": reference,
                "notes": notes, "created": datetime.now().isoformat(timespec="seconds")}
    (case_dir / CASE_FILE).write_text(
        json.dumps(identity, indent=2, ensure_ascii=False), encoding="utf-8")
    conn = db.connect(case_dir)
    try:
        conn.executemany("INSERT OR REPLACE INTO meta VALUES (?,?)",
                         list(identity.items()))
        conn.commit()
    finally:
        conn.close()
    return case_dir


def case_info(case_dir):
    case_dir = Path(case_dir)
    identity = {"name": case_dir.name, "reference": "", "notes": "", "created": ""}
    try:
        identity.update(json.loads((case_dir / CASE_FILE).read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
    info = {"slug": case_dir.name, "dir": str(case_dir), **identity}
    if db.case_db_path(case_dir).is_file():
        conn = db.connect(case_dir)
        try:
            info["findings"] = conn.execute(
                "SELECT count(*) FROM findings").fetchone()[0]
            # Artifacts, not findings: the case card should say how much WORK
            # a case is, and the unit of work is the artifact (see app.py).
            info["artifacts"] = conn.execute(
                "SELECT count(DISTINCT artifact) FROM findings").fetchone()[0]
            info["confirmed"] = conn.execute(
                "SELECT count(DISTINCT artifact) FROM findings "
                "WHERE triage='confirmed'").fetchone()[0]
            info["iocs"] = conn.execute("SELECT count(*) FROM iocs").fetchone()[0]
            info["evidence"] = conn.execute(
                "SELECT count(*) FROM evidence").fetchone()[0]
        finally:
            conn.close()
    return info


def list_cases(workspace):
    workspace = Path(workspace)
    if not workspace.is_dir():
        return []
    out = []
    for entry in sorted(workspace.iterdir()):
        if entry.is_dir() and entry.name != ARCHIVE_DIR and (entry / CASE_FILE).is_file():
            out.append(case_info(entry))
    return out


def resolve_case(workspace, case_slug):
    """The case directory for a slug -- refuses names that escape the
    workspace (slug comes from the client and is treated accordingly)."""
    workspace = Path(workspace).resolve()
    candidate = (workspace / str(case_slug)).resolve()
    if candidate.parent != workspace or not (candidate / CASE_FILE).is_file():
        return None
    return candidate


SUMMARY_FILE = "case_summary.json"
# Files the archive never carries. The log index is DERIVED: it is rebuilt
# from the evidence in minutes and can be larger than everything else in the
# case put together. WAL/SHM are transient SQLite sidecars.
_NOT_ARCHIVED = {db.LOG_DB, db.LOG_DB + "-wal", db.LOG_DB + "-shm",
                 db.CASE_DB + "-wal", db.CASE_DB + "-shm"}


def case_summary(case_dir):
    """What this case FOUND, as plain numbers -- written into the archive so
    the closed case can be listed (and handed over) without opening a
    database or unpacking the zip."""
    case_dir = Path(case_dir)
    info = case_info(case_dir)
    out = {"name": info["name"], "reference": info.get("reference", ""),
           "slug": case_dir.name, "created": info.get("created", ""),
           "closed": datetime.now().isoformat(timespec="seconds"),
           "findings": 0, "artifacts": 0, "confirmed": 0, "dismissed": 0,
           "iocs": 0, "evidence": [], "severity": {}}
    if not db.case_db_path(case_dir).is_file():
        return out
    conn = db.connect(case_dir)
    try:
        out["findings"] = conn.execute("SELECT count(*) FROM findings").fetchone()[0]
        out["artifacts"] = conn.execute(
            "SELECT count(DISTINCT artifact) FROM findings").fetchone()[0]
        # Decisions are counted in artifacts -- that is what was decided.
        for state in ("confirmed", "dismissed"):
            out[state] = conn.execute(
                "SELECT count(DISTINCT artifact) FROM findings WHERE triage = ?",
                (state,)).fetchone()[0]
        out["iocs"] = conn.execute("SELECT count(*) FROM iocs").fetchone()[0]
        # Severity per artifact: its worst finding, dismissed ones left out.
        out["severity"] = {str(r["worst"]): r["n"] for r in db.rows(
            conn, "SELECT worst, count(*) n FROM ("
                  "  SELECT artifact, MIN(severity) AS worst FROM findings"
                  "  WHERE triage != 'dismissed' GROUP BY artifact"
                  ") GROUP BY worst")}
        out["evidence"] = [{"kind": r["kind"], "path": r["path"]}
                           for r in db.rows(conn, "SELECT kind, path FROM evidence")]
    except Exception:
        pass          # a summary must never be the reason a case cannot close
    finally:
        conn.close()
    return out


def archive_case(workspace, case_dir):
    """Close a case: pack the folder into archive/<slug>_<ts>.zip and remove
    the working copy, so the case is out of the platform until it is
    imported again. Returns (zip_path, summary)."""
    workspace = Path(workspace)
    case_dir = Path(case_dir)
    archive = workspace / ARCHIVE_DIR
    archive.mkdir(exist_ok=True)
    summary = case_summary(case_dir)
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    zip_path = archive / f"{case_dir.name}_{stamp}.zip"
    # Checkpoint + close any WAL so the archived case.db is complete on its
    # own -- a database whose last writes live in a sidecar we do not pack
    # would come back missing them.
    try:
        conn = db.connect(case_dir)
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            # Close in a finally: a connection left open here would keep
            # case.db locked on Windows and make the rmtree below fail.
            conn.close()
    except Exception:
        pass
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(SUMMARY_FILE,
                    json.dumps(summary, indent=2, ensure_ascii=False))
        for path in sorted(case_dir.rglob("*")):
            if path.name in _NOT_ARCHIVED or path.name == SUMMARY_FILE:
                continue
            if path.is_file():
                zf.write(path, path.relative_to(case_dir))
    _remove_case_dir(case_dir)
    return zip_path, summary


def _remove_case_dir(case_dir, attempts=10, delay=0.25):
    """Delete the working copy -- robust against Windows file locking.

    On Windows, deleting a file that any handle still has open fails with
    PermissionError (WinError 32): a SQLite handle a worker thread has not
    released yet, an antivirus scan, an Explorer preview. Rather than let
    the whole close-case operation fall over on a lock that is gone half a
    second later, clear read-only bits, nudge the GC (closes abandoned
    in-process SQLite handles) and retry briefly. If the folder still
    cannot be removed, the last error is raised -- silently keeping the
    working copy after handing out the archive would leave the case in
    both places."""
    def _onerror(func, path, exc_info):
        os.chmod(path, stat.S_IWRITE)
        func(path)

    last_error = None
    for _ in range(attempts):
        try:
            shutil.rmtree(case_dir, onerror=_onerror)
            return
        except OSError as e:
            last_error = e
            gc.collect()
            time.sleep(delay)
    raise last_error


def list_archives(workspace):
    """Every closed case in archive/, newest first, with the summary it was
    closed with (read from the zip's own entry -- no unpacking)."""
    archive = Path(workspace) / ARCHIVE_DIR
    if not archive.is_dir():
        return []
    out = []
    for path in sorted(archive.glob("*.zip"), reverse=True):
        try:
            st = path.stat()
        except OSError:
            continue
        entry = {"file": path.name, "size": st.st_size,
                 "modified": datetime.fromtimestamp(st.st_mtime)
                 .isoformat(timespec="seconds"), "summary": None,
                 "readable": True}
        try:
            with zipfile.ZipFile(path) as zf:
                if SUMMARY_FILE in zf.namelist():
                    entry["summary"] = json.loads(zf.read(SUMMARY_FILE))
                elif CASE_FILE in zf.namelist():
                    identity = json.loads(zf.read(CASE_FILE))
                    entry["summary"] = {"name": identity.get("name", path.stem),
                                        "reference": identity.get("reference", "")}
        except (OSError, zipfile.BadZipFile, ValueError):
            entry["readable"] = False
        out.append(entry)
    return out


class ImportError_(Exception):
    """An archive that cannot become a case, with a readable reason."""


def _safe_member(name):
    """A zip entry that is allowed to be written. ZIP SLIP GUARD: an archive
    is a FILE FROM OUTSIDE -- it may be one this analyst never created -- so
    absolute paths, drive letters and any `..` traversal are refused rather
    than sanitised. Refusing is the only answer that cannot be tricked."""
    if name.endswith("/"):
        return None                      # directory entry: created implicitly
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or ":" in normalized.split("/")[0]:
        raise ImportError_(f"Archiv enthält einen absoluten Pfad: {name}")
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ImportError_(f"Archiv enthält einen Pfad mit '..': {name}")
    return Path(*parts) if parts else None


def import_archive(workspace, zip_path):
    """Restore a closed case from its archive.

    Never overwrites: if the slug is taken, the case comes back under a free
    one and the caller is told. The log index is not in the archive by
    design -- the restored case says so and rebuilds on the next analysis.
    """
    workspace = Path(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    zip_path = Path(zip_path).expanduser()
    if not zip_path.is_file():
        raise ImportError_(f"Datei nicht gefunden: {zip_path}")
    try:
        zf = zipfile.ZipFile(zip_path)
    except (OSError, zipfile.BadZipFile) as e:
        raise ImportError_(f"Kein lesbares ZIP-Archiv: {e}") from e
    with zf:
        names = zf.namelist()
        if CASE_FILE not in names:
            raise ImportError_(
                f"Das Archiv enthält kein {CASE_FILE} — es stammt nicht aus "
                "diesem Toolkit.")
        try:
            identity = json.loads(zf.read(CASE_FILE))
        except ValueError as e:
            raise ImportError_(f"{CASE_FILE} im Archiv ist beschädigt: {e}") from e
        members = [(n, _safe_member(n)) for n in names]

        wanted = slug(identity.get("name") or zip_path.stem)
        target = workspace / wanted
        renamed = False
        if target.exists():
            target = _unique_dir(workspace, identity.get("name") or zip_path.stem)
            renamed = True
        target.mkdir(parents=True)
        try:
            for name, rel in members:
                if rel is None:
                    continue
                dest = target / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(name) as src, open(dest, "wb") as out:
                    shutil.copyfileobj(src, out)
        except Exception:
            shutil.rmtree(target, ignore_errors=True)
            raise
    return {"slug": target.name, "dir": str(target), "renamed": renamed,
            "name": identity.get("name", target.name)}
