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
from concurrent.futures import ThreadPoolExecutor

from server import db
from server.events import hub

# Two heavy engines at once is plenty on an analyst workstation; more would
# just make both slower (regex parsing is CPU-bound).
_WORKERS = 2


class JobContext:
    """Handed to every engine: progress reporting + cancellation checks."""

    def __init__(self, manager, case_dir, job_id):
        self.manager = manager
        self.case_dir = case_dir
        self.job_id = job_id
        self.cancel_event = threading.Event()
        self._last_db_write = 0.0

    def cancelled(self):
        return self.cancel_event.is_set()

    def progress(self, fraction, message=""):
        """fraction 0..1; message is what the UI shows under the bar."""
        fraction = max(0.0, min(1.0, float(fraction)))
        event = {"type": "job", "job": {
            "id": self.job_id, "state": "running",
            "progress": round(fraction, 4), "message": message}}
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
                        "UPDATE jobs SET progress = ?, message = ? WHERE id = ?",
                        (fraction, message, self.job_id))
                    conn.commit()
                finally:
                    conn.close()
            except sqlite3.OperationalError:
                pass


class JobManager:
    def __init__(self):
        self.pool = ThreadPoolExecutor(max_workers=_WORKERS,
                                       thread_name_prefix="engine")
        self.live = {}          # job_id -> JobContext
        self._lock = threading.Lock()

    def submit(self, case_dir, kind, fn, evidence_id=None):
        """Queue `fn(ctx)` as a job. fn returns a stats dict (stored as JSON)
        and may raise -- the traceback lands in the job row, never in a 500."""
        conn = db.connect(case_dir)
        try:
            cur = conn.execute(
                "INSERT INTO jobs (kind, evidence_id, state, created) "
                "VALUES (?,?, 'queued', ?)", (kind, evidence_id, db.now()))
            job_id = cur.lastrowid
            conn.commit()
        finally:
            conn.close()

        ctx = JobContext(self, case_dir, job_id)
        with self._lock:
            self.live[job_id] = ctx
        hub.publish({"type": "job", "job": {"id": job_id, "kind": kind,
                                            "state": "queued", "progress": 0}})
        self.pool.submit(self._run, ctx, kind, fn)
        return job_id

    def cancel(self, job_id):
        with self._lock:
            ctx = self.live.get(job_id)
        if ctx is not None:
            ctx.cancel_event.set()
            return True
        return False

    def wait_for(self, job_ids, timeout=20):
        """Block until these jobs have left the live registry (or the timeout
        expires). Used before a case is packed away: an engine still holding
        a write transaction would land half a run in the archive. Returns the
        ids that were STILL running when the wait gave up -- the caller can
        report that rather than pretend."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                remaining = [j for j in job_ids if j in self.live]
            if not remaining:
                return []
            time.sleep(0.2)
        with self._lock:
            return [j for j in job_ids if j in self.live]

    def _set_state(self, ctx, state, error="", stats=None):
        conn = db.connect(ctx.case_dir)
        try:
            fields = {"state": state, "error": error}
            if state == "running":
                fields["started"] = db.now()
            if state in ("done", "failed", "cancelled"):
                fields["finished"] = db.now()
                if state == "done":
                    fields["progress"] = 1.0
            if stats is not None:
                fields["stats"] = json.dumps(stats)
            sets = ", ".join(f"{k} = ?" for k in fields)
            conn.execute(f"UPDATE jobs SET {sets} WHERE id = ?",
                         (*fields.values(), ctx.job_id))
            conn.commit()
            job = db.one(conn, "SELECT * FROM jobs WHERE id = ?", (ctx.job_id,))
        finally:
            conn.close()
        if job:
            job["stats"] = json.loads(job.get("stats") or "{}")
            hub.publish({"type": "job", "job": job})

    def _run(self, ctx, kind, fn):
        self._set_state(ctx, "running")
        try:
            stats = fn(ctx) or {}
            state = "cancelled" if ctx.cancelled() else "done"
            self._set_state(ctx, state, stats=stats)
            hub.publish({"type": "invalidate", "scope": kind})
        except Exception:
            self._set_state(ctx, "failed", error=traceback.format_exc(limit=8))
        finally:
            with self._lock:
                self.live.pop(ctx.job_id, None)


manager = JobManager()
