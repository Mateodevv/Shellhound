# server/jobs.py
"""Background jobs: the engines run here, off the request path.

Each job is a row in the case DB (survives restarts as history) plus a live
entry in this in-memory registry (progress, cancellation). Progress updates
are throttled to the DB but every tick is pushed to the event hub, so the UI
bar moves smoothly while the DB sees a handful of writes per second.
"""
import json
import sqlite3
import threading
import time
import traceback
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

from server import db
from server.analysis import decode_job, refresh_receipts
from server.events import hub
from server.paths import display_path

# Two heavy engines at once is plenty on an analyst workstation; more would
# just make both slower (regex parsing is CPU-bound).
_WORKERS = 2


class JobContext:
    """Handed to every engine: progress reporting + cancellation checks."""

    def __init__(self, manager, case_dir, job_id, scan_context=None):
        self.manager = manager
        self.case_dir = case_dir
        self.job_id = job_id
        self.cancel_event = threading.Event()
        self._last_db_write = 0.0
        self.skipped_files = []
        self.scan_context = scan_context or {}
        self._retry_entries = {(display_path(e["path"]), display_path(e["root"])): e["id"]
                               for e in self.scan_context.get("entries", [])}
        self.file_results = []
        self.progress_details = {}
        self.progress_value = 0.0
        self.progress_message = ""

    def skip(self, path, reason):
        # An engine may hold the case write lock. Persist with its final job
        # state after the engine releases that transaction, never from here.
        self.detailed_skip(path, reason, "other")

    def detailed_skip(self, path, reason, category="file", root=""):
        self.skipped_files.append((display_path(path), str(reason), category, display_path(root)))

    def file_result(self, path, root, status, reason=""):
        # Engines call this only after committing that file. Ordinals belong
        # to the original job, not the retry's new skipped-files log.
        ordinal = self._retry_entries.get((display_path(path), display_path(root)))
        if ordinal is not None:
            self.file_results.append((ordinal, status, str(reason)))

    def phase_progress(self, fraction, message, phase, completed=None, total=None):
        self.progress_details = {"phase": phase, "completed": completed, "total": total}
        self.progress(fraction, message)

    def cancelled(self):
        return self.cancel_event.is_set()

    def progress(self, fraction, message=""):
        """fraction 0..1; message is what the UI shows under the bar."""
        fraction = max(0.0, min(1.0, float(fraction)))
        self.progress_value = fraction
        self.progress_message = message
        event = {"type": "job", "case_slug": Path(self.case_dir).name, "job": {
            "id": self.job_id, "state": "running",
            "progress": round(fraction, 4), "message": message,
            "progress_details": self.progress_details}}
        hub.publish(event)
        nowts = time.monotonic()
        if nowts - self._last_db_write >= 1.0:
            self._last_db_write = nowts
            # BEST-EFFORT: the engine calling this may itself hold an open
            # write transaction on case.db -- waiting on the lock here would
            # deadlock the thread against its own connection. The DB copy of
            # progress is cosmetic (page-reload state); the hub event above
            # is the live channel.
            try:
                conn = sqlite3.connect(str(db.case_db_path(self.case_dir)),
                                       timeout=0.2)
                try:
                    conn.execute(
                        "UPDATE jobs SET progress = ?, message = ?, progress_details = ? WHERE id = ?",
                        (fraction, message, json.dumps(self.progress_details), self.job_id))
                    conn.commit()
                finally:
                    conn.close()
            except sqlite3.OperationalError:
                pass


def _key(case_dir, job_id):
    """The identity of a live job.

    A job id is a rowid in ONE case database, so two open cases both hand out
    1, 2, 3 -- the registry has to carry the case as well. Keyed by the id
    alone, submitting in case B evicted case A's context, `cancel` stopped a
    job in whichever case happened to collide, and `wait_for` reported "all
    quiet" while an engine in the other case was still writing. Closing that
    case would then pack a half-written database.
    """
    return (str(case_dir), int(job_id))


class JobManager:
    def __init__(self):
        self.pool = ThreadPoolExecutor(max_workers=_WORKERS,
                                       thread_name_prefix="engine")
        self.live = {}          # (case_dir, job_id) -> JobContext
        self._lock = threading.Lock()
        self._idle = threading.Condition(self._lock)
        self._schedule_lock = threading.RLock()

    @contextmanager
    def case_operation(self, case_dir):
        """Serialize submission and reject an overlapping case analysis batch."""
        with self._schedule_lock:
            with self._lock:
                busy = any(key[0] == str(case_dir) for key in self.live)
            if busy:
                raise CaseBusy("Analysis is already running in this case. Stop it or wait before retrying.")
            self.recover_interrupted(case_dir)
            yield

    def recover_interrupted(self, case_dir):
        """An old process cannot finish its queued/running jobs after restart."""
        with self._schedule_lock:
            with self._lock:
                active = {key[1] for key in self.live if key[0] == str(case_dir)}
            conn = db.connect(case_dir)
            try:
                stale = [r["id"] for r in db.rows(conn, "SELECT id FROM jobs "
                         "WHERE state IN ('running','queued')") if r["id"] not in active]
                if stale:
                    conn.executemany("UPDATE jobs SET state='failed', finished=?, error=? WHERE id=?",
                                     ((db.now(), "Interrupted before completion. Run analysis again.", job_id)
                                      for job_id in stale))
                    refresh_receipts(conn)
                    conn.commit()
            finally:
                conn.close()

    def progress_snapshot(self, case_dir, job_id):
        with self._lock:
            ctx = self.live.get(_key(case_dir, job_id))
            if ctx is None:
                return {}
            return {"progress": ctx.progress_value, "message": ctx.progress_message,
                    "progress_details": dict(ctx.progress_details)}

    def submit(self, case_dir, kind, fn, evidence_id=None, run_id="", on_cancel=None,
               scan_context=None):
        with self._schedule_lock:
            return self._submit(case_dir, kind, fn, evidence_id, run_id, on_cancel, scan_context)

    def _submit(self, case_dir, kind, fn, evidence_id=None, run_id="", on_cancel=None,
                scan_context=None):
        """Queue `fn(ctx)` as a job. fn returns a stats dict (stored as JSON)
        and may raise -- the traceback lands in the job row, never in a 500."""
        conn = db.connect(case_dir)
        try:
            cur = conn.execute(
                "INSERT INTO jobs (kind, evidence_id, state, created, run_id, scan_context) "
                "VALUES (?,?, 'queued', ?, ?, ?)",
                (kind, evidence_id, db.now(), str(run_id or ""), json.dumps(scan_context or {})))
            job_id = cur.lastrowid
            conn.commit()
        finally:
            conn.close()

        ctx = JobContext(self, case_dir, job_id, scan_context)
        with self._lock:
            self.live[_key(case_dir, job_id)] = ctx
        hub.publish({"type": "job", "case_slug": Path(case_dir).name, "job": {"id": job_id, "kind": kind,
                                            "state": "queued", "progress": 0,
                                            "scan_context": scan_context or {}}})
        self.pool.submit(self._run, ctx, kind, fn, on_cancel)
        return job_id

    def cancel(self, case_dir, job_id):
        with self._lock:
            ctx = self.live.get(_key(case_dir, job_id))
        if ctx is not None:
            ctx.cancel_event.set()
            return True
        return False

    def wait_for(self, case_dir, job_ids, timeout=20):
        """Block until these jobs have left the live registry (or the timeout
        expires). Used before a case is packed away: an engine still holding
        a write transaction would land half a run in the archive. Returns the
        ids that were STILL running when the wait gave up -- the caller can
        report that rather than pretend."""
        keys = {j: _key(case_dir, j) for j in job_ids}
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                remaining = [j for j, k in keys.items() if k in self.live]
            if not remaining:
                return []
            time.sleep(0.2)
        with self._lock:
            return [j for j, k in keys.items() if k in self.live]

    def cancel_all_and_wait(self):
        """Drain jobs after the HTTP server has stopped accepting work.

        Workers own their database transactions and final job status. Let them
        unwind instead of terminating a process while those writes are pending.
        Keep the pool reusable for applications served again in the same process.
        """
        with self._idle:
            for ctx in self.live.values():
                ctx.cancel_event.set()
            self._idle.wait_for(lambda: not self.live)

    def _set_state(self, ctx, state, error="", stats=None):
        conn = db.connect(ctx.case_dir)
        try:
            fields = {"state": state, "error": error}
            if state == "running":
                fields["started"] = db.now()
            if state in ("done", "failed", "cancelled"):
                fields["finished"] = db.now()
                stats = {**(stats or {}), "skip_details": len(ctx.skipped_files)}
                conn.executemany(
                    "INSERT OR REPLACE INTO job_skips (job_id, ordinal, path, reason, category, root) "
                    "VALUES (?,?,?,?,?,?)",
                    ((ctx.job_id, index, *entry)
                     for index, entry in enumerate(ctx.skipped_files)))
                conn.executemany(
                    "INSERT OR REPLACE INTO file_scan_results(job_id, ordinal, status, reason) "
                    "VALUES (?,?,?,?)", ((ctx.job_id, *result) for result in ctx.file_results))
                fields["progress_details"] = json.dumps(ctx.progress_details)
                if state == "done":
                    fields["progress"] = 1.0
            if stats is not None:
                fields["stats"] = json.dumps(stats)
            sets = ", ".join(f"{k} = ?" for k in fields)
            conn.execute(f"UPDATE jobs SET {sets} WHERE id = ?",
                         (*fields.values(), ctx.job_id))
            if state in ("done", "failed", "cancelled"):
                refresh_receipts(conn)
            conn.commit()
            job = db.one(conn, "SELECT * FROM jobs WHERE id = ?", (ctx.job_id,))
        finally:
            conn.close()
        if job:
            job = decode_job(job)
            hub.publish({"type": "job", "case_slug": Path(ctx.case_dir).name, "job": job})

    def _run(self, ctx, kind, fn, on_cancel=None):
        try:
            if ctx.cancelled():
                if on_cancel is not None:
                    on_cancel()
                self._set_state(ctx, "cancelled")
                return
            self._set_state(ctx, "running")
            stats = fn(ctx) or {}
            state = "cancelled" if ctx.cancelled() else "done"
            self._set_state(ctx, state, stats=stats)
            hub.publish({"type": "invalidate", "scope": kind})
        except Exception:
            self._set_state(ctx, "failed", error=traceback.format_exc(limit=8))
            # A retry may have committed earlier files before a later one
            # failed. Those findings and resolved warnings must refresh too.
            hub.publish({"type": "invalidate", "scope": kind})
        finally:
            with self._idle:
                self.live.pop(_key(ctx.case_dir, ctx.job_id), None)
                self._idle.notify_all()


class CaseBusy(ValueError):
    pass


manager = JobManager()
