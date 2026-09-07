"""Recorded-file retries: paths come from case history, never the HTTP body."""
import hashlib
import json
import os
from pathlib import Path

from server import db, ruleswitch, settings
from server.analysis import (FILE_ENGINES, current_skip_entries, describe_job,
                             refresh_receipts, skip_outcomes)
from server.engines import webshell, yarascan
from server.engines.scan_limits import MAX_OVERRIDE_SCAN_BYTES
from server.paths import display_path, io_path
from server.skip_reasons import classify_skip


class RetryError(ValueError):
    def __init__(self, message, status=409):
        super().__init__(message)
        self.status = status


def path_key(path):
    return os.path.normcase(os.path.realpath(io_path(path)))


def scanner_signature(kind, workspace):
    """A digest only: never save rule contents or credential-bearing settings."""
    engine = webshell if kind == "webshell" else yarascan
    digest = hashlib.sha256()
    for source in (Path(engine.__file__), Path(__file__).parent / "engines" / "fsutil.py",
                   Path(__file__).parent / "engines" / "scan_limits.py"):
        digest.update(source.read_bytes())
    if kind == "webshell":
        digest.update(json.dumps(sorted(ruleswitch.disabled_ids(workspace))).encode())
        # The shipped content rules are compiled from this local asset.
        digest.update((Path(__file__).parent / "bundled_rules.py").read_bytes())
        for rule in sorted((Path(__file__).parent / "rules_bundled").rglob("*.yar*")):
            digest.update(rule.name.encode())
            digest.update(rule.read_bytes())
    else:
        digest.update(json.dumps(sorted(settings.yara_disabled(workspace))).encode())
        for filename in yarascan.rule_files(workspace):
            digest.update(Path(filename).name.encode())
            try:
                content = Path(filename).read_bytes()
            except OSError:
                content = b"unreadable rule"
            digest.update(content)
            # Includes can depend on files outside the managed rule directory.
            # Their complete dependency set is not recorded by the compiler.
            if b"include " in content or b"include\t" in content:
                return ""
    return digest.hexdigest()


def make_context(kind, roots, mode, workspace):
    if kind not in FILE_ENGINES:
        return {"mode": mode}
    return {"mode": mode, "signature": scanner_signature(kind, workspace),
            "roots": [{"evidence_id": r["id"], "path": r["path"],
                       "identity": path_key(r["path"])} for r in roots]}


def _block_reason(job, workspace):
    if job["kind"] not in FILE_ENGINES:
        return "Targeted retries are available for Webshell and YARA evidence files."
    if job["scan_context"].get("mode") == "retry":
        return "Use the skipped-files list in the original scan to retry unresolved files."
    if job["state"] != "done" or job["analysis_status"] not in ("complete", "complete_with_warnings"):
        return "This scan did not finish successfully. Run full analysis to cover unfinished work."
    signature = job["scan_context"].get("signature")
    if not signature:
        return "This scan has no verifiable rule and source snapshot. Run full analysis before targeted retries."
    if signature != scanner_signature(job["kind"], workspace):
        return "Scanner rules or settings have changed. Run full analysis to apply them to every file."
    return ""


def _target(conn, job, entry):
    if entry["category"] != "file":
        raise RetryError("This entry is a rule or discovery problem, not an individual evidence file.")
    roots = job["scan_context"].get("roots", [])
    matching = [root for root in roots if path_key(root["path"]) == path_key(entry["root"])
                or (path_key(root["path"]) == path_key(entry["path"])
                    and path_key(os.path.dirname(root["path"])) == path_key(entry["root"]))]
    if len(matching) != 1:
        raise RetryError("The original evidence root is ambiguous. Run full analysis.")
    root = matching[0]
    registered = db.one(conn, "SELECT * FROM evidence WHERE id = ? AND kind = 'webroot'",
                        (root["evidence_id"],))
    if (registered is None or path_key(registered["path"]) != root["identity"]
            or path_key(root["path"]) != root["identity"]):
        raise RetryError("The original evidence root was removed or changed. Register it and run full analysis.")
    attempt = json.loads(registered["stats"] or "{}").get("last_attempt", {})
    if attempt.get("run_id") != job["run_id"]:
        raise RetryError("A newer analysis superseded this scan. Open its skipped-files list.")
    candidate = path_key(entry["path"])
    try:
        inside = os.path.commonpath((candidate, root["identity"])) == root["identity"]
    except ValueError:
        inside = False
    if not inside:
        raise RetryError("This file no longer belongs to its original evidence root.")
    if os.path.isdir(io_path(entry["path"])):
        raise RetryError("This file path is now a folder. Run full analysis to discover its contents.")
    return {"id": entry["ordinal"], "path": display_path(entry["path"]),
            "root": display_path(entry["root"])}


def _job(conn, job_id):
    row = db.one(conn, "SELECT * FROM jobs WHERE id = ?", (job_id,))
    if row is None:
        raise RetryError("Job not found", 404)
    return describe_job(conn, row)


def _filters(group, status):
    if group not in ("all", "size_limit", "other") or status not in ("all", "pending", "accepted"):
        raise RetryError("Choose a valid skip group and review status.", 400)


def _matches(entry, group, status):
    return ((group == "all" or entry["group"] == group)
            and (status == "all" or (entry["status"] == "accepted" if status == "accepted"
                                     else entry["status"] not in ("accepted", "resolved"))))


def _selection(mode, ids, entries):
    if (mode not in ("all", "selected") or (mode == "selected" and not ids)
            or (mode == "all" and ids)):
        raise RetryError("Choose all matching files or at least one selected file.", 400)
    known = {entry["ordinal"] for entry in entries}
    if any(type(value) is not int or value not in known for value in ids):
        raise RetryError("A selected skipped-file ID does not belong to this job.", 400)


def _entry_state(entry, outcomes):
    outcome = outcomes.get(entry["ordinal"], {})
    reason = outcome.get("reason") or entry["reason"]
    return {**classify_skip(reason, entry["category"]),
            "status": outcome.get("status", "unresolved"), "latest_reason": reason}


def _large_target(target, kind):
    try:
        size = os.stat(io_path(target["path"])).st_size
    except OSError as exc:
        raise RetryError("This file cannot currently be read. Restore access before scanning it.") from exc
    if size > MAX_OVERRIDE_SCAN_BYTES:
        raise RetryError("This file exceeds the 256 MiB per-file retry ceiling. "
                         "Inspect it separately, or accept this coverage gap.")
    normal = webshell.MAX_CONTENT_SCAN_BYTES if kind == "webshell" else yarascan.MAX_SCAN_BYTES
    return {**target, "max_bytes": max(normal, size)}


def _can_accept(job, entry, state, current_ids):
    if (state["group"] != "size_limit" or state["status"] in ("accepted", "resolved")
            or job["kind"] not in FILE_ENGINES or job["scan_context"].get("mode") == "retry"
            or job["state"] != "done" or job["analysis_status"] not in ("complete", "complete_with_warnings")):
        return False
    # Acceptance records a coverage decision, so it does not need unchanged
    # scanner code or access to the file. It must still belong to current evidence.
    return entry["ordinal"] in current_ids


def skipped_details(conn, job_id, workspace, offset=0, limit=100, busy=False,
                    group="all", status="all"):
    _filters(group, status)
    job = _job(conn, job_id)
    blocked = _block_reason(job, workspace)
    outcomes = skip_outcomes(conn, job_id)
    entries = db.rows(conn, "SELECT * FROM job_skips WHERE job_id = ? ORDER BY ordinal", (job_id,))
    current_ids = {entry["ordinal"] for entry in current_skip_entries(conn, job, entries)}
    pending = set()
    for retry in db.rows(conn, "SELECT scan_context FROM jobs WHERE state IN ('running','queued') "
                         "AND json_extract(scan_context, '$.parent_job_id') = ?", (job_id,)):
        pending.update(e["id"] for e in json.loads(retry["scan_context"]).get("entries", []))
    items, unresolved, accepted = [], 0, 0
    counts = {"size_limit": 0, "other": 0, "accepted": 0}
    selection_ids = {"retryable": [], "acceptable": [], "forceable": []}
    for entry in entries:
        outcome = outcomes.get(entry["ordinal"], {})
        state = _entry_state(entry, outcomes)
        resolved = state["status"] == "resolved"
        is_accepted = state["status"] == "accepted"
        unresolved += not resolved and not is_accepted
        accepted += is_accepted
        if not resolved:
            counts[state["group"]] += 1
        counts["accepted"] += is_accepted
        reason = blocked
        target = None
        if not reason and not resolved:
            try:
                target = _target(conn, job, entry)
            except RetryError as exc:
                reason = str(exc)
        can_retry = not resolved and not reason
        forceable = can_retry and state["group"] == "size_limit"
        action_reason = reason
        if forceable:
            try:
                _large_target(target, job["kind"])
            except RetryError as exc:
                forceable, action_reason = False, str(exc)
        item = {**state, "id": entry["ordinal"], "path": entry["path"], "reason": entry["reason"],
                "category": entry["category"], "retryable": can_retry,
                "acceptable": _can_accept(job, entry, state, current_ids), "forceable": forceable,
                "status": "retrying" if entry["ordinal"] in pending else
                          "accepted" if is_accepted else "resolved" if resolved else "unresolved",
                "latest_reason": outcome.get("reason") or action_reason or entry["reason"],
                "action_reason": action_reason, "accepted_at": outcome.get("accepted_at"),
                "retry_job_id": outcome.get("job_id")}
        # Filter on persisted status, so an accepted file stays on its page
        # while a new explicit retry is running.
        if _matches(state, group, status):
            items.append(item)
            for action in selection_ids:
                if item[action]:
                    selection_ids[action].append(item["id"])
    offset, limit = max(0, offset), max(1, min(limit, 200))
    return {"items": items[offset:offset + limit], "total": len(items),
            "recorded": "skip_details" in job["stats"], "unresolved": unresolved,
            "accepted": accepted, "counts": counts, "selection_ids": selection_ids,
            **{key: len(ids) for key, ids in selection_ids.items()},
            "busy": busy, "blocked_reason": blocked}


def prepare_retry(conn, job_id, mode, ids, workspace, *, group="all", status="pending",
                  allow_large_files=False):
    _filters(group, status)
    job = _job(conn, job_id)
    blocked = _block_reason(job, workspace)
    if blocked:
        raise RetryError(blocked)
    entries = db.rows(conn, "SELECT * FROM job_skips WHERE job_id = ? ORDER BY ordinal", (job_id,))
    _selection(mode, ids, entries)
    if allow_large_files and group != "size_limit":
        raise RetryError("A size override must target the size-limit group explicitly.", 400)
    outcomes = skip_outcomes(conn, job_id)
    selected, seen = [], set()
    for entry in entries:
        if mode == "selected" and entry["ordinal"] not in ids:
            continue
        state = _entry_state(entry, outcomes)
        if state["status"] == "resolved":
            continue
        if not _matches(state, group, status):
            if mode == "selected":
                raise RetryError("A selected file no longer matches this group or review status. Refresh the list.")
            continue
        try:
            target = _target(conn, job, entry)
            if allow_large_files:
                target = _large_target(target, job["kind"])
        except RetryError:
            if mode == "all":
                continue
            raise
        identity = path_key(target["path"])
        if identity in seen:
            raise RetryError("Overlapping evidence registrations make this retry ambiguous. Run full analysis.")
        seen.add(identity)
        selected.append(target)
    if not selected:
        raise RetryError("These files have already been resolved. Refresh the skipped-files list.")
    context = {**job["scan_context"], "mode": "retry", "parent_job_id": job_id,
               "entries": selected, "allow_large_files": allow_large_files,
               "group": group, "review_status": status}
    return job["kind"], context


def accept_skipped(conn, job_id, mode, ids, *, group="size_limit", status="pending"):
    _filters(group, status)
    if group != "size_limit":
        raise RetryError("Only size-limit skips can be accepted as a coverage decision.", 400)
    job = _job(conn, job_id)
    entries = db.rows(conn, "SELECT * FROM job_skips WHERE job_id=? ORDER BY ordinal", (job_id,))
    current_ids = {entry["ordinal"] for entry in current_skip_entries(conn, job, entries)}
    _selection(mode, ids, entries)
    outcomes = skip_outcomes(conn, job_id)
    selected = []
    for entry in entries:
        if mode == "selected" and entry["ordinal"] not in ids:
            continue
        state = _entry_state(entry, outcomes)
        if state["status"] in ("accepted", "resolved"):
            continue
        if not _matches(state, group, status) or not _can_accept(job, entry, state, current_ids):
            if mode == "selected":
                raise RetryError("Only current size-limit skips can be accepted. Refresh the list.")
            continue
        selected.append((job_id, entry["ordinal"], outcomes.get(entry["ordinal"], {}).get("job_id", 0), db.now()))
    if not selected:
        raise RetryError("No pending size-limit skips match this selection. Refresh the list.")
    conn.executemany("INSERT INTO skip_reviews(job_id,ordinal,outcome_job_id,accepted_at) VALUES (?,?,?,?)",
                     selected)
    refresh_receipts(conn)
    conn.commit()
    return {"accepted": len(selected)}


def execute_retry(case_dir, workspace, kind, context, ctx):
    # Recheck after queueing too: settings/evidence can change while another
    # engine finishes. Nothing is read outside the recorded registered roots.
    conn = db.connect(case_dir)
    try:
        _kind, validated = prepare_retry(conn, context["parent_job_id"], "selected",
                                         [entry["id"] for entry in context["entries"]], workspace,
                                         group=context.get("group", "all"),
                                         status=context.get("review_status", "pending"),
                                         allow_large_files=context.get("allow_large_files", False))
    finally:
        conn.close()
    targets = validated["entries"]
    approved = {entry["id"]: entry for entry in context["entries"]}
    for target in targets:
        if "max_bytes" in target:
            # A queued file may grow; that must not increase the approved read.
            target["max_bytes"] = min(target["max_bytes"], approved[target["id"]]["max_bytes"])
    if kind == "webshell":
        return webshell.scan(case_dir, [], ctx, workspace, authoritative=False, file_targets=targets)
    return yarascan.scan(case_dir, [], workspace, ctx, authoritative=False, file_targets=targets)
