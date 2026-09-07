"""Completion receipts for all engines scheduled against an evidence source."""
import json
import threading

from server import db
from server.engines.fsutil import canonical_file, path_within_any

FILE_ENGINES = {"webshell", "yara"}


def stats_complete(stats, engine=""):
    """A returned job is not necessarily a complete scan."""
    if (any(stats.get(key) for key in ("partial", "broken_rules", "discovery_errors"))
            or stats.get("available") is False):
        return False
    skipped = int(stats.get("skipped") or 0)
    return not skipped or (engine in FILE_ENGINES
                           and skipped == int(stats.get("file_skips") or 0))


def stats_status(stats, engine=""):
    if not stats_complete(stats, engine):
        return "partial"
    return "complete_with_warnings" if stats.get("file_skips") else "complete"


def decode_job(row):
    job = dict(row)
    for key in ("stats", "scan_context", "progress_details"):
        value = job.get(key)
        job[key] = json.loads(value or "{}") if isinstance(value, str) else (value or {})
    return job


def skip_outcomes(conn, job_id):
    """Latest committed outcome for each original skip; old attempts stay intact."""
    rows = db.rows(conn, """
        SELECT r.ordinal, r.status, r.reason, r.job_id FROM file_scan_results r
        JOIN jobs j ON j.id = r.job_id
        WHERE json_extract(j.scan_context, '$.parent_job_id') = ?
        ORDER BY r.job_id
    """, (job_id,))
    outcomes = {row["ordinal"]: row for row in rows}
    for review in db.rows(conn, "SELECT * FROM skip_reviews WHERE job_id=? ORDER BY id", (job_id,)):
        outcome = outcomes.get(review["ordinal"], {})
        # A subsequent retry failure needs a fresh review. Acceptance never
        # turns an unexamined file into a successful scan result.
        if (outcome.get("status") != "resolved"
                and outcome.get("job_id", 0) == review["outcome_job_id"]):
            outcomes[review["ordinal"]] = {**outcome, "status": "accepted",
                                            "accepted_at": review["accepted_at"]}
    return outcomes


def current_skip_entries(conn, job, entries):
    """A full job can remain current for one root after another was replaced."""
    if not job.get("warnings_current"):
        return []
    evidence = db.rows(conn, "SELECT id, path, stats FROM evidence WHERE kind='webroot'")
    registered = {e["id"]: e for e in evidence if
                  json.loads(e["stats"] or "{}").get("last_attempt", {}).get("run_id") == job["run_id"]}
    recorded = job["scan_context"].get("roots")
    if recorded:
        roots = [root["path"] for root in recorded if root["evidence_id"] in registered
                 and canonical_file(registered[root["evidence_id"]]["path"]) == root["identity"]]
    elif registered:
        roots = [root["path"] for root in registered.values()]
    else:
        return entries  # Truly legacy job, already checked against latest engine history.
    return [entry for entry in entries if path_within_any(entry["path"], roots)]


def describe_job(conn, row):
    job = decode_job(row)
    stats = job["stats"]
    skips = db.rows(conn, "SELECT ordinal, category, path FROM job_skips WHERE job_id = ?",
                    (job["id"],))
    # Old completed file jobs recorded individual skips before categories
    # existed. The count and broken-rule/partial checks must all agree.
    if (job["kind"] in FILE_ENGINES and "file_skips" not in stats
            and stats.get("skipped") and len(skips) == stats["skipped"]
            and all(s["category"] in ("file", "other") for s in skips)):
        stats = {**stats, "file_skips": stats["skipped"]}
        job["stats"] = stats
    outcomes = skip_outcomes(conn, job["id"])
    resolved = sum(outcomes.get(s["ordinal"], {}).get("status") in ("resolved", "accepted")
                   for s in skips)
    job["accepted_count"] = sum(outcomes.get(s["ordinal"], {}).get("status") == "accepted"
                                for s in skips)
    job["warning_count"] = max(0, int(stats.get("file_skips") or 0) - resolved)
    status = stats_status(stats, job["kind"])
    if status == "complete_with_warnings" and not job["warning_count"]:
        status = "complete"
    job["analysis_status"] = status if job["state"] == "done" else job["state"]
    attempts = [json.loads(e["stats"] or "{}").get("last_attempt", {}).get("run_id")
                for e in db.rows(conn, "SELECT stats FROM evidence WHERE kind='webroot'")]
    if job["scan_context"].get("mode") == "retry":
        job["warnings_current"] = False
    elif any(attempts):
        job["warnings_current"] = bool(job["run_id"] and job["run_id"] in attempts)
    else:
        latest = db.one(conn, "SELECT max(id) id FROM jobs WHERE kind=? AND "
                        "COALESCE(json_extract(scan_context, '$.mode'), '') != 'retry'", (job["kind"],))
        job["warnings_current"] = job["id"] == latest["id"]
    current = current_skip_entries(conn, job, skips)
    job["current_warning_count"] = sum(
        entry["category"] in ("file", "other")
        and outcomes.get(entry["ordinal"], {}).get("status") not in ("resolved", "accepted") for entry in current)
    job["current_accepted_count"] = sum(
        outcomes.get(entry["ordinal"], {}).get("status") == "accepted" for entry in current)
    if not job["warning_count"]:
        job["current_warning_count"] = 0
    return job


def current_warning_count(conn, *, accepted=False):
    paths, unknown = set(), 0
    for row in db.rows(conn, "SELECT * FROM jobs WHERE kind IN ('webshell','yara')"):
        job = describe_job(conn, row)
        count = job["accepted_count"] if accepted else job["warning_count"]
        if not job["warnings_current"] or not count:
            continue
        outcomes = skip_outcomes(conn, job["id"])
        entries = db.rows(conn, "SELECT ordinal, path FROM job_skips WHERE job_id=? "
                          "AND category IN ('file','other')", (job["id"],))
        for entry in current_skip_entries(conn, job, entries):
            state = outcomes.get(entry["ordinal"], {}).get("status")
            if (state == "accepted" if accepted else state not in ("resolved", "accepted")):
                paths.add(entry["path"].replace("\\", "/"))
        unknown += max(0, count - len(entries))
    return len(paths) + unknown


def refresh_receipts(conn):
    """Reconcile proven historical results and scoped retries, never guess success.

    A retry belongs to its original job. It cannot replace a failed full run
    or stand in for an unrelated prerequisite engine.
    """
    for row in db.rows(conn, "SELECT id, kind, path, scanned_at, stats FROM evidence"):
        stats = json.loads(row["stats"] or "{}")
        attempt = stats.get("last_attempt", {})
        engines = attempt.get("engines")
        if not engines or not attempt.get("run_id"):
            continue
        updated = {}
        warnings = 0
        warning_paths = set()
        finished = []
        for engine, outcome in engines.items():
            job = db.one(conn, "SELECT * FROM jobs WHERE run_id = ? AND kind = ? "
                         "AND COALESCE(json_extract(scan_context, '$.mode'), '') != 'retry' "
                         "ORDER BY id DESC LIMIT 1", (attempt["run_id"], engine))
            if job is None:
                updated[engine] = outcome
                warnings += int(outcome.get("stats", {}).get("file_skips") or 0)
                continue
            job = describe_job(conn, job)
            state = job["analysis_status"]
            updated[engine] = {"state": "running" if state == "queued" else state,
                               "stats": job["stats"]}
            if job["warning_count"]:
                outcomes = skip_outcomes(conn, job["id"])
                for entry in db.rows(conn, "SELECT ordinal, path, category FROM job_skips WHERE job_id=?",
                                     (job["id"],)):
                    if (entry["category"] in ("file", "other")
                            and outcomes.get(entry["ordinal"], {}).get("status") not in ("resolved", "accepted")
                            and path_within_any(entry["path"], [row["path"]])):
                        warning_paths.add(canonical_file(entry["path"]))
            if job.get("finished"):
                finished.append(job["finished"])
        states = {entry["state"] for entry in updated.values()}
        status = next((s for s in ("running", "failed", "cancelled", "partial",
                                  "complete_with_warnings") if s in states), "complete")
        warnings += len(warning_paths)
        if status == "complete_with_warnings" and not warnings:
            status = "complete"
        reconciled = {**attempt, "engines": updated, "status": status, "warnings": warnings}
        scanned_at = row["scanned_at"]
        if status in ("complete", "complete_with_warnings") and not scanned_at and finished:
            scanned_at = max(finished)
        if reconciled != attempt or scanned_at != row["scanned_at"]:
            stats["last_attempt"] = reconciled
            conn.execute("UPDATE evidence SET stats = ?, scanned_at = ? WHERE id = ?",
                         (json.dumps(stats), scanned_at, row["id"]))


class AnalysisReceipts:
    """Non-blocking join: the last successful engine writes the receipt.

    The entire plan is registered before any worker starts. Failed, cancelled
    or partial engines never contribute a success, so incremental retries can
    still select the evidence. No worker waits for a queued sibling.
    """

    def __init__(self, tasks, evidence, mark_scanned, record_attempt=None):
        self.required = {}
        for engine, _fn, kinds in tasks:
            for kind in kinds:
                self.required.setdefault(kind, set()).add(engine)
        self.evidence = evidence
        self.mark_scanned = mark_scanned
        self.record_attempt = record_attempt
        self.outcomes = {}
        self.finished = {}
        self.marked = set()
        self.lock = threading.Lock()
        self._record()

    def _record(self):
        if self.record_attempt is None:
            return
        for kind, required in self.required.items():
            engines = {name: self.outcomes.get(name, {"state": "running"})
                       for name in sorted(required)}
            states = {entry["state"] for entry in engines.values()}
            status = next((state for state in ("running", "failed", "cancelled", "partial", "complete_with_warnings")
                           if state in states), "complete")
            self.record_attempt([row["id"] for row in self.evidence[kind]],
                                {"status": status, "engines": engines,
                                 "warnings": sum(int(e.get("stats", {}).get("file_skips") or 0)
                                                 for e in engines.values())})

    def cancel(self, engine):
        """A queued engine may be cancelled before its wrapper ever runs."""
        with self.lock:
            self.outcomes[engine] = {"state": "cancelled"}
            self._record()

    def wrap(self, engine, fn):
        def run(ctx):
            try:
                stats = fn(ctx) or {}
            except Exception:
                with self.lock:
                    self.outcomes[engine] = {"state": "failed"}
                    self._record()
                raise
            with self.lock:
                state = ("cancelled" if ctx.cancelled() else
                         stats_status(stats, engine))
                self.outcomes[engine] = {"state": state, "stats": stats}
                if state not in ("complete", "complete_with_warnings"):
                    self._record()
                    return stats
                self.finished[engine] = (stats, ctx)
                for kind, required in self.required.items():
                    if kind in self.marked or not required.issubset(self.finished):
                        continue
                    if any(self.finished[name][1].cancelled() for name in required):
                        continue
                    primary = {"webroot": "webshell", "access_logs": "index_logs",
                               "sql_dump": "sqldb"}[kind]
                    receipt = dict(self.finished[primary][0])
                    receipt["engines"] = {
                        name: self.finished[name][0] for name in sorted(required)}
                    self.mark_scanned([row["id"] for row in self.evidence[kind]], receipt)
                    self.marked.add(kind)
                self._record()
            return stats
        return run
