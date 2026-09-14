"""Read-only evidence used by the bounded artifact review workspace."""
import os
import lzma
import sqlite3
import time
from urllib.parse import urlsplit, unquote
from server import db
from server.artifacts import web_path, uri_targets
from server.engines import logindex
from server.engines.fsutil import open_text_auto


def successful_accesses(case_dir, ip, offset=0, limit=50):
    index = logindex._open_ro(case_dir)
    if index is None:
        return {"available": False, "total": 0, "rows": []}
    conn = db.connect(case_dir)
    try:
        # Group query variants by their requested path; never infer execution.
        index.create_function("review_path", 1, lambda value: str(value or "").split("?", 1)[0].split("#", 1)[0])
        base = "FROM requests r JOIN ips i ON i.id=r.ip JOIN strings u ON u.id=r.uri WHERE i.ip=? AND r.status BETWEEN 200 AND 299"
        total = index.execute("SELECT count(DISTINCT review_path(u.text)) " + base, (ip,)).fetchone()[0]
        rows = [dict(row) for row in index.execute(
            "SELECT review_path(u.text) AS path,count(*) AS hits,max(r.epoch) AS last_epoch,"
            "group_concat(DISTINCT r.status) AS statuses " + base +
            " GROUP BY review_path(u.text) ORDER BY last_epoch DESC,path LIMIT ? OFFSET ?", (ip, limit, offset))]
        files = db.rows(conn, "SELECT DISTINCT artifact AS path FROM findings WHERE artifact_kind='file' "
                       "UNION SELECT local_path AS path FROM ioc_observations WHERE kind='file-location' AND active=1 AND local_path!=''")
        candidates = [(item["path"], web_path(conn, item["path"])) for item in files]
        roots = db.rows(conn, "SELECT path FROM evidence WHERE kind='webroot'")
        for row in rows:
            paths = {path for path, relative in candidates if uri_targets(row["path"], relative) and os.path.isfile(path)}
            # Also offer collected source files which have no finding. Scope is
            # verified again by the file reader before any content is returned.
            try:
                relative = unquote(urlsplit(row["path"]).path).lstrip("/")
            except ValueError:
                relative = ""
            if relative and not any(part in ("..", ".") for part in relative.replace("\\", "/").split("/")):
                for root in roots:
                    base_path = os.path.realpath(root["path"])
                    target = os.path.realpath(os.path.join(base_path, relative))
                    try:
                        if os.path.commonpath([target, base_path]) == base_path and os.path.isfile(target):
                            paths.add(target)
                    except ValueError:
                        pass
            row["files"] = [{"path": path, "name": os.path.basename(path.replace("\\", "/"))} for path in sorted(paths)]
            row["statuses"] = sorted(int(value) for value in row["statuses"].split(","))
        return {"available": True, "total": total, "rows": rows}
    finally:
        index.close()
        conn.close()


def sql_preview(path, focus=None, expanded=False):
    """Bounded decoded SQL text, including compressed exports; never execute."""
    cap = 1000 if expanded else 80
    start = max(1, (focus or 1) - 12)
    end = start + cap
    result = {"from_line": start, "focus": focus, "lines": [], "truncated": False}
    consumed = 0
    try:
        with open_text_auto(path) as stream:
            for number in range(1, 100001):
                line = stream.readline(65537)
                if not line:
                    break
                consumed += len(line.encode("utf-8"))
                if consumed > 8 * 1024 * 1024 or len(line) > 65536:
                    result["truncated"] = True
                    break
                if number >= end:
                    result["truncated"] = True
                    break
                if number >= start:
                    result["lines"].append(line.rstrip("\r\n")[:4000])
                    result["truncated"] |= len(line) > 4000
            else:
                result["truncated"] = True
    except (OSError, EOFError, UnicodeError, lzma.LZMAError):
        result["error"] = "The SQL export could not be read. Check that the evidence is available and intact."
    if focus and not start <= focus < start + len(result["lines"]):
        result["focus"] = None
    return result


def finding_rule_kind(finding):
    rule_id = finding.get("rule_id") or ""
    kind = rule_id.removeprefix("logs.") if rule_id.startswith("logs.") else ""
    if not rule_id and finding.get("source") == "logs":
        kind = next((key for key, (_, title) in logindex._ALERT_FINDING.items() if title == finding.get("rule")), "")
    return kind


def finding_requests(case_dir, finding, offset=0, limit=50):
    """Reconstruct supporting requests using the indexer's exact rule predicates.

    These are current-index matches, never a persisted historic request snapshot.
    Unsupported and retired findings deliberately do not fall back to all traffic.
    """
    empty = {"available": False, "total": 0, "rows": []}
    if finding.get("retired"):
        return dict(empty, reason="retired")
    kind = finding_rule_kind(finding)
    if kind not in logindex._ALERT_FINDING:
        return dict(empty, reason="unsupported")
    conn = logindex.open_readonly(case_dir)
    if conn is None:
        return dict(empty, reason="index")

    def matches(uri, method, status, agent):
        return int(logindex.request_matches_alert(kind, uri, method, status, agent))

    deadline = time.monotonic() + 3
    conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
    conn.create_function("review_match", 4, matches)
    joins = "FROM requests r JOIN ips i ON i.id=r.ip LEFT JOIN strings u ON u.id=r.uri LEFT JOIN strings a ON a.id=r.agent LEFT JOIN sources s ON s.id=r.source "
    where = "WHERE i.ip=? AND review_match(u.text,r.method,r.status,a.text)=1"
    try:
        total = conn.execute("SELECT count(*) " + joins + where, (finding["artifact"],)).fetchone()[0]
        rows = [dict(row) for row in conn.execute(
            "SELECT r.rowid AS request_id,r.epoch,r.tz,r.method,u.text AS uri,r.status,r.size,a.text AS agent,s.path AS source,r.line_no AS line " + joins + where +
            " ORDER BY r.epoch,r.rowid LIMIT ? OFFSET ?", (finding["artifact"],limit,offset))]
        for row in rows:
            row["source"] = os.path.basename((row.get("source") or "").replace("\\", "/"))
        return {"available": True, "total": total, "rows": rows, "rule_kind": kind}
    except sqlite3.OperationalError as error:
        if "interrupted" not in str(error).lower():
            raise
        return dict(empty, reason="timeout")
    finally:
        conn.set_progress_handler(None, 0)
        conn.close()
