"""Durable Pattern Hunt runs using the existing job and immutable test records."""
import json

from server import db
from server.analysis import decode_job


def public_test(row):
    item = dict(row)
    for source, target in (("rule_json", "rule"), ("coverage_json", "coverage")):
        try:
            item[target] = json.loads(item.pop(source))
        except (ValueError, TypeError, KeyError):
            item[target] = {}
            item.pop(source, None)
    for key in ("truncated", "legacy"):
        item[key] = bool(item.get(key))
    return item


def context(entries, snapshot):
    return {"mode": "hunt_batch", **snapshot, "patterns": [
        {**{key: entry.get(key, "") for key in
            ("id", "name", "cve", "description", "technology", "version", "rule_hash", "source")},
         "status": "pending", "error": ""}
        for entry in entries]}


def save_progress(ctx):
    conn = db.connect(ctx.case_dir)
    try:
        conn.execute("UPDATE jobs SET scan_context=? WHERE id=?",
                     (json.dumps(ctx.scan_context, ensure_ascii=False), ctx.job_id))
        conn.commit()
    finally:
        conn.close()


def execute(ctx, entries, store_test):
    roster = ctx.scan_context["patterns"]
    checked = failed = matched = 0
    for index, (entry, item) in enumerate(zip(entries, roster)):
        if ctx.cancelled():
            break
        item["status"] = "running"
        save_progress(ctx)
        ctx.phase_progress(index / len(roster), f"Checking pattern {index + 1} of {len(roster)}",
                           "patterns", index, len(roster))
        try:
            result = store_test(entry, ctx)
        except Exception:
            if ctx.cancelled():
                item["status"] = "not_run"
                break
            # Do not persist raw rule/SQL details or evidence from an exception.
            item.update(status="failed", error="This pattern could not be checked. Preview it in Manage patterns, then retry.")
            failed += 1
        else:
            item.update(status="done", test_id=result["test"]["id"])
            checked += 1
            matched += int(result["test"]["hits"] > 0)
        save_progress(ctx)
    for item in roster:
        if item["status"] in {"pending", "running"}:
            item["status"] = "not_run"
    save_progress(ctx)
    completed = checked + failed
    ctx.phase_progress(completed / len(roster),
                       f"Checked {checked} of {len(roster)} patterns",
                       "patterns", completed, len(roster))
    return {"tests": checked, "matched": matched, "failed": failed,
            "remaining": len(roster) - completed}


def runs(case_dir, fingerprint, batch_id="", limit=50):
    conn = db.connect(case_dir)
    try:
        where = "AND run_id=?" if batch_id else ""
        params = [batch_id] if batch_id else []
        jobs = db.rows(conn, "SELECT * FROM jobs WHERE kind='hunt' AND run_id!='' " +
                       where + " ORDER BY id DESC LIMIT ?", params + [max(1, min(limit, 100))])
        output = []
        for raw in jobs:
            job = decode_job(raw)
            saved = job["scan_context"]
            tests = [public_test(row) for row in db.rows(
                conn, "SELECT * FROM hunt_tests WHERE batch_id=? ORDER BY id", (job["run_id"],))]
            by_id = {test["id"]: test for test in tests}
            by_pattern = {test["pattern_id"]: test for test in tests}
            known = saved.get("mode") == "hunt_batch" and isinstance(saved.get("patterns"), list)
            roster = saved["patterns"] if known else [
                {"id": test["pattern_id"], "name": "", "cve": "", "description": "",
                 "technology": "", "version": test["pattern_version"],
                 "rule_hash": test["rule_hash"], "test_id": test["id"]} for test in tests]
            patterns = []
            active = job["state"] in {"queued", "running"}
            for entry in roster:
                item = dict(entry)
                test = by_id.get(item.get("test_id")) or by_pattern.get(item["id"])
                status = "done" if test else item.get("status", "pending")
                if not active and status in {"pending", "running"}:
                    status = "not_run"
                item.update(status=status, error=item.get("error", ""), test=test)
                patterns.append(item)
            checked = sum(item["status"] == "done" for item in patterns)
            failed = sum(item["status"] == "failed" for item in patterns)
            run_fingerprint = saved.get("index_fingerprint", "")
            if not run_fingerprint and tests:
                fingerprints = {test["index_fingerprint"] for test in tests}
                run_fingerprint = next(iter(fingerprints)) if len(fingerprints) == 1 else ""
            output.append({
                "batch_id": job["run_id"], "job_id": job["id"], "state": job["state"],
                "created": job["created"], "started": job.get("started"),
                "finished": job.get("finished"), "progress": job["progress"],
                "index_fingerprint": run_fingerprint,
                "index_summary": saved.get("index_summary"),
                "fresh": bool(fingerprint and fingerprint == run_fingerprint),
                "roster_known": known,
                "counts": {"total": len(patterns) if known else None,
                           "checked": checked, "failed": failed,
                           "matched": sum(bool(item["test"] and item["test"]["hits"]) for item in patterns),
                           "remaining": len(patterns) - checked - failed if known else None},
                "patterns": patterns,
                "error": "This run was interrupted or could not finish. Check patterns again."
                         if job["state"] == "failed" else "",
            })
        return output
    finally:
        conn.close()


def dashboard_summary(case_dir, fingerprint):
    """Preview one saved check, without adding its matches to Findings."""
    latest = runs(case_dir, fingerprint, limit=1)
    if not latest or not latest[0]["counts"]["matched"]:
        return None
    run = latest[0]
    counts = run["counts"]
    return {
        "batch_id": run["batch_id"], "created": run["created"],
        "state": run["state"], "fresh": run["fresh"],
        "matched": counts["matched"], "checked": counts["checked"],
        "total": counts["total"],
        "complete": (run["state"] == "done" and run["roster_known"]
                     and not counts["failed"] and counts["remaining"] == 0),
        "pattern_names": [item["name"] for item in run["patterns"]
                          if item["test"] and item["test"]["hits"]][:3],
    }
