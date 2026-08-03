# server/engines/logindex.py
"""The access logs, parsed ONCE into a queryable index -- the core of the
web-native rewrite.

Every question afterwards is a SQL query: "what did these 20 clients do" is
answered from the (ip, epoch) index in milliseconds, never by another pass
over gigabytes of log files. Evolved from legacy core/logindex.py with three
additions:

  * IPs are interned like strings, and per-actor statistics (request counts,
    error counts, login-POST behaviour, hourly activity buckets) are computed
    DURING the one parsing pass -- the Actors view reads a finished table.
  * Detection regexes (scanner UAs, login endpoints, SQLi/traversal/upload-
    PHP probes) run ONCE PER DISTINCT STRING at intern time, not per line.
    A 10M-line log has tens of thousands of distinct URIs; that turns the
    detection cost from O(lines) into O(distinct strings).
  * Alerts follow the tuning learned on real cases: probe alerts (SQLi,
    traversal, PHP-in-upload-dir) fire only when at least one such request
    was ANSWERED 2xx -- attempts stay visible as counts on the actor, but a
    blocked probe wave does not become a red alert.

The index is derived data: it can always be rebuilt from the evidence, a
stale one refuses to answer (sources fingerprint), and it is excluded from
the case archive.
"""
import os
import re
import sqlite3
from collections import Counter
from pathlib import Path

from server import db
from server.engines import accesslog
from server.engines.fsutil import (get_files_recursive, is_compressed,
                                   is_scannable_text, open_text_auto)

SCHEMA_VERSION = "2"
_BATCH = 20000

# --- detection patterns (evaluated once per distinct string) ----------------

SCANNER_UA_RE = re.compile(
    r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|feroxbuster|wpscan|"
    r"joomscan|hydra|acunetix|nessus|nuclei|zgrab|censys|httpx|wfuzz|ffuf)")

LOGIN_POST_ENDPOINTS = re.compile(
    r"(?i)(wp-login\.php|xmlrpc\.php|/administrator/index\.php|/administrator/?(?=[?\s]|$)|"
    r"option=com_login|task=user\.login|option=com_users)")

SQLI_URI_RE = re.compile(
    r"(?i)(union[+%20\s]+select|information_schema|concat\s*\(|"
    r"%27\s*or\s*1=1|'\s*or\s*1=1|benchmark\s*\(|sleep\s*\()")

TRAVERSAL_URI_RE = re.compile(r"(?:\.\./|\.\.%2f|%2e%2e%2f){2,}", re.I)

# A request FOR a PHP file inside a writable upload/cache directory: either a
# probe for a known shell path or -- answered 200 -- the attacker driving a
# dropped shell. Mirrors the webshell scanner's location rule.
UPLOAD_PHP_RE = re.compile(
    r"(?i)/(images|tmp|cache|media|files|assets|upload|uploads|"
    r"wp-content/uploads|wp-content/cache)/[^?\s]*\.ph(p\d?|tml|ar)\b")

BF_THRESHOLD = 30            # login POSTs per client before it is a flood

# Alert kinds that are CONTEXT rather than a statement about this system.
# Defined by NAME, not by the severity stored in the index: an index built by
# an earlier version still holds the old number, and a derived file must not
# be the authority on what counts as an incident.
INFO_ALERT_KINDS = ("scanner_ua",)

# uri intern flags (bitmask)
F_LOGIN = 1
F_SQLI = 2
F_TRAVERSAL = 4
F_UPLOAD_PHP = 8

_LOG_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE sources (
    id INTEGER PRIMARY KEY, path TEXT UNIQUE, size INTEGER, mtime INTEGER,
    lines INTEGER DEFAULT 0, unparsed INTEGER DEFAULT 0,
    skipped_reason TEXT DEFAULT ''
);
CREATE TABLE strings (id INTEGER PRIMARY KEY, text TEXT);
CREATE TABLE ips (id INTEGER PRIMARY KEY, ip TEXT UNIQUE);
CREATE TABLE requests (
    ip INTEGER, epoch INTEGER, tz INTEGER,
    method TEXT, uri INTEGER, leaf INTEGER,
    status INTEGER, size INTEGER,
    referrer INTEGER, agent INTEGER, source INTEGER
);
CREATE TABLE actors (
    ip_id INTEGER PRIMARY KEY,
    ip TEXT,
    requests INTEGER, first_epoch INTEGER, last_epoch INTEGER, tz INTEGER,
    err4 INTEGER, err5 INTEGER, bytes INTEGER,
    posts INTEGER, login_posts INTEGER, login_redirects INTEGER,
    login_statuses TEXT DEFAULT '{}',
    scanner_uas TEXT DEFAULT '[]',
    sqli_attempts INTEGER, sqli_ok INTEGER,
    traversal_attempts INTEGER, traversal_ok INTEGER,
    upload_php_attempts INTEGER, upload_php_ok INTEGER,
    agents INTEGER
);
CREATE TABLE actor_hours (
    ip_id INTEGER, hour INTEGER, n INTEGER,
    PRIMARY KEY (ip_id, hour)
) WITHOUT ROWID;
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY, ip_id INTEGER, kind TEXT, severity INTEGER,
    detail TEXT, example TEXT DEFAULT ''
);
CREATE TABLE days (
    day TEXT PRIMARY KEY, requests INTEGER, errors INTEGER, new_clients INTEGER
);
"""


def _leaf(uri):
    """Last path segment without query string -- what a file name matches."""
    path = str(uri or "").split("?", 1)[0].split("#", 1)[0]
    return path.rstrip("/").rsplit("/", 1)[-1].lower()


def _source_fingerprint(paths):
    out = []
    for target in paths:
        for p in get_files_recursive(target) if os.path.isdir(target) else [target]:
            try:
                st = os.stat(p)
            except OSError:
                continue
            out.append((os.path.abspath(p), st.st_size, int(st.st_mtime)))
    return sorted(out)


# --- building ---------------------------------------------------------------

class _Actor:
    """Per-client accumulator for the single parsing pass. __slots__ because
    a big log can carry six figures of distinct clients."""
    __slots__ = ("requests", "first", "last", "tz", "err4", "err5", "bytes",
                 "posts", "login_posts", "login_statuses", "login_redirects",
                 "scanner_uas", "sqli", "sqli_ok", "trav", "trav_ok",
                 "uphp", "uphp_ok", "agents", "examples")

    def __init__(self):
        self.requests = 0
        self.first = None
        self.last = None
        self.tz = 0
        self.err4 = 0
        self.err5 = 0
        self.bytes = 0
        self.posts = 0
        self.login_posts = 0
        self.login_statuses = Counter()
        self.login_redirects = 0
        self.scanner_uas = set()
        self.sqli = 0
        self.sqli_ok = 0
        self.trav = 0
        self.trav_ok = 0
        self.uphp = 0
        self.uphp_ok = 0
        self.agents = set()
        self.examples = {}          # kind -> first matching uri


def build(case_dir, targets, ctx=None):
    """Parse every access-log file under `targets` into <case>/logindex.db.

    Returns a stats dict. Rebuilds from scratch -- the index is cheap relative
    to the questions it answers, and partial updates are how a stale answer
    sneaks in.
    """
    log_db = db.log_db_path(case_dir)
    if log_db.exists():
        log_db.unlink()
    stats = {"files": 0, "lines": 0, "unparsed": 0, "skipped": 0,
             "clients": 0, "alerts": 0, "bytes": 0}

    files = []
    for target in targets:
        if os.path.isfile(target):
            files.append(target)
        elif os.path.isdir(target):
            files.extend(get_files_recursive(target))
    total_size = 0
    sized = []
    for p in files:
        try:
            total_size += os.path.getsize(p)
            sized.append((p, os.path.getsize(p)))
        except OSError:
            sized.append((p, 0))

    conn = sqlite3.connect(str(log_db))
    try:
        # Derived data: durability off during the build, indexes after load.
        conn.execute("PRAGMA journal_mode = OFF")
        conn.execute("PRAGMA synchronous = OFF")
        conn.execute("PRAGMA cache_size = -262144")          # 256 MiB
        conn.executescript(_LOG_SCHEMA)

        strings = {}          # text -> id (uris, leafs, referrers, agents, source names)
        # Per-line regexes are the enemy: everything derivable from the URI
        # STRING (leaf, detection flags) is computed once at intern time and
        # served from this cache -- one dict hit per line afterwards.
        uri_cache = {}        # uri text -> (uri_id, leaf_id, flags)
        agent_cache = {}      # agent text -> (agent_id, is_scanner)
        ips = {}              # ip -> id
        actors = {}           # ip id -> _Actor
        hours = Counter()     # (ip id, epoch-hour local) -> n
        days = {}             # local epoch-day -> [requests, errors, new_clients]
        batch = []

        parse_line = accesslog.parse_line
        fast_epoch = accesslog.fast_epoch

        def intern(text):
            got = strings.get(text)
            if got is None:
                got = strings[text] = len(strings) + 1
            return got

        def uri_entry(text):
            got = uri_cache.get(text)
            if got is None:
                uri_id = intern(text)
                leaf_id = intern(_leaf(text))
                flags = 0
                if LOGIN_POST_ENDPOINTS.search(text):
                    flags |= F_LOGIN
                if SQLI_URI_RE.search(text):
                    flags |= F_SQLI
                if TRAVERSAL_URI_RE.search(text):
                    flags |= F_TRAVERSAL
                if UPLOAD_PHP_RE.search(text):
                    flags |= F_UPLOAD_PHP
                got = uri_cache[text] = (uri_id, leaf_id, flags)
            return got

        def agent_entry(text):
            got = agent_cache.get(text)
            if got is None:
                got = agent_cache[text] = (
                    intern(text), bool(text and SCANNER_UA_RE.search(text)))
            return got

        done_size = 0
        for file_path, file_size in sized:
            if ctx is not None and ctx.cancelled():
                break
            name = os.path.basename(file_path)
            abs_path = os.path.abspath(file_path)
            if not is_scannable_text(file_path):
                conn.execute(
                    "INSERT OR IGNORE INTO sources (path, size, mtime, skipped_reason)"
                    " VALUES (?,?,?,?)",
                    (abs_path, file_size, 0, "binary/unreadable file"))
                stats["skipped"] += 1
                done_size += file_size
                continue
            if accesslog.sniff_error_log(file_path, open_text_auto):
                conn.execute(
                    "INSERT OR IGNORE INTO sources (path, size, mtime, skipped_reason)"
                    " VALUES (?,?,?,?)",
                    (abs_path, file_size, 0, accesslog.ERROR_LOG_SKIP_REASON))
                stats["skipped"] += 1
                done_size += file_size
                continue

            src_id = intern(name)
            file_lines = file_unparsed = 0
            chars = 0
            # Compressed logs decompress to roughly 3-10x; the per-file
            # progress fraction is an estimate and is clamped to the file's
            # share of the total.
            denom = max(1, file_size * (6 if is_compressed(file_path) else 1))
            try:
                with open_text_auto(file_path) as fh:
                    for line in fh:
                        data = parse_line(line)
                        if data is None:
                            if line.strip():
                                file_unparsed += 1
                            continue
                        te = fast_epoch(data["time"])
                        epoch, tz = te if te else (0, 0)
                        ip = data["ip"]
                        ip_id = ips.get(ip)
                        if ip_id is None:
                            ip_id = ips[ip] = len(ips) + 1
                        uri = data.get("uri") or "-"
                        uri_id, leaf_id, flags = uri_entry(uri)
                        agent_id, is_scanner = agent_entry(data.get("user_agent") or "")
                        try:
                            status = int(data["status"])
                        except (ValueError, TypeError):
                            status = 0
                        size_raw = data.get("size")
                        size = int(size_raw) if size_raw and size_raw.isdigit() else 0
                        method = data["method"]

                        batch.append((ip_id, epoch, tz, method, uri_id,
                                      leaf_id, status, size,
                                      intern(data.get("referrer") or ""),
                                      agent_id, src_id))
                        file_lines += 1

                        # --- actor accumulation (the one pass) -----------
                        a = actors.get(ip_id)
                        if a is None:
                            a = actors[ip_id] = _Actor()
                        a.requests += 1
                        a.bytes += size
                        if epoch:
                            a.tz = tz
                            if a.first is None or epoch < a.first:
                                a.first = epoch
                            if a.last is None or epoch > a.last:
                                a.last = epoch
                            hours[(ip_id, (epoch + tz) // 3600)] += 1
                        if 400 <= status < 500:
                            a.err4 += 1
                        elif status >= 500:
                            a.err5 += 1
                        if method == "POST":
                            a.posts += 1
                        if flags:
                            ok = 200 <= status < 300
                            if flags & F_LOGIN and method == "POST":
                                a.login_posts += 1
                                a.login_statuses[status] += 1
                                if status in (301, 302, 303):
                                    a.login_redirects += 1
                            if flags & F_SQLI:
                                a.sqli += 1
                                if ok:
                                    a.sqli_ok += 1
                                a.examples.setdefault("sqli", uri)
                            if flags & F_TRAVERSAL:
                                a.trav += 1
                                if ok:
                                    a.trav_ok += 1
                                a.examples.setdefault("traversal", uri)
                            if flags & F_UPLOAD_PHP:
                                a.uphp += 1
                                if ok:
                                    a.uphp_ok += 1
                                a.examples.setdefault("upload_php", uri)
                        if is_scanner:
                            a.scanner_uas.add(data.get("user_agent") or "")
                        a.agents.add(agent_id)

                        if epoch:
                            day = (epoch + tz) // 86400
                            d = days.get(day)
                            if d is None:
                                d = days[day] = [0, 0, 0]
                            d[0] += 1
                            if status >= 400:
                                d[1] += 1

                        chars += len(line)
                        if len(batch) >= _BATCH:
                            conn.executemany(
                                "INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                                batch)
                            batch.clear()
                            if ctx is not None:
                                if ctx.cancelled():
                                    break
                                frac = (done_size + min(file_size, chars * file_size // denom)) / max(1, total_size)
                                ctx.progress(0.02 + frac * 0.82,
                                             f"{name}: {stats['lines'] + file_lines:,} Zeilen indiziert")
            except (OSError, EOFError) as e:
                conn.execute(
                    "INSERT OR IGNORE INTO sources (path, size, mtime, skipped_reason)"
                    " VALUES (?,?,?,?)", (abs_path, file_size, 0, f"read error: {e}"))
                stats["skipped"] += 1
                done_size += file_size
                continue

            try:
                mtime = int(os.stat(file_path).st_mtime)
            except OSError:
                mtime = 0
            conn.execute(
                "INSERT OR REPLACE INTO sources (path, size, mtime, lines, unparsed)"
                " VALUES (?,?,?,?,?)",
                (abs_path, file_size, mtime, file_lines, file_unparsed))
            stats["files"] += 1
            stats["lines"] += file_lines
            stats["unparsed"] += file_unparsed
            stats["bytes"] += file_size
            done_size += file_size

        if batch:
            conn.executemany(
                "INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?)", batch)
            batch.clear()

        if ctx is not None:
            ctx.progress(0.86, "Schreibe Interning-Tabellen…")
        conn.executemany("INSERT INTO strings (id, text) VALUES (?,?)",
                         ((i, t) for t, i in strings.items()))
        conn.executemany("INSERT INTO ips (id, ip) VALUES (?,?)",
                         ((i, ip) for ip, i in ips.items()))

        # --- actors + first-seen day ------------------------------------
        if ctx is not None:
            ctx.progress(0.88, "Berechne Actor-Statistiken…")
        import json as _json
        ip_by_id = {i: ip for ip, i in ips.items()}
        actor_rows = []
        for ip_id, a in actors.items():
            if a.first is not None:
                day = (a.first + a.tz) // 86400
                if day in days:
                    days[day][2] += 1
            actor_rows.append((
                ip_id, ip_by_id.get(ip_id, "?"), a.requests, a.first, a.last,
                a.tz, a.err4, a.err5, a.bytes, a.posts, a.login_posts,
                a.login_redirects,
                _json.dumps({str(k): v for k, v in a.login_statuses.items()}),
                _json.dumps(sorted(a.scanner_uas)[:5]),
                a.sqli, a.sqli_ok, a.trav, a.trav_ok, a.uphp, a.uphp_ok,
                len(a.agents)))
        conn.executemany(
            "INSERT INTO actors VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            actor_rows)
        conn.executemany(
            "INSERT INTO actor_hours VALUES (?,?,?)",
            ((ip_id, hour, n) for (ip_id, hour), n in hours.items()))
        conn.executemany(
            "INSERT INTO days VALUES (?,?,?,?)",
            ((_day_iso(day), v[0], v[1], v[2])
             for day, v in sorted(days.items())))

        # --- alerts (outcome-gated, see module docstring) ----------------
        if ctx is not None:
            ctx.progress(0.90, "Leite Alerts ab…")
        alert_rows = []
        for ip_id, a in actors.items():
            if a.login_posts >= BF_THRESHOLD:
                breakdown = ", ".join(
                    f"{s} ×{n}" for s, n in sorted(a.login_statuses.items()))
                alert_rows.append((ip_id, "login_flood", 1,
                                   f"{a.login_posts} POSTs auf Login-Endpoints "
                                   f"(Status: {breakdown})", ""))
                if a.login_redirects:
                    alert_rows.append((
                        ip_id, "login_success", 0,
                        f"{a.login_redirects} Redirect(s) unter {a.login_posts} "
                        f"Login-POSTs — nach einer Flood bedeutet 301/302/303 "
                        f"meist einen erfolgreichen Login. Verifizieren!", ""))
            for ua in sorted(a.scanner_uas):
                # INFORMATIONAL (severity 3): every host on the internet is
                # scanned around the clock, so "a scanner said hello" is
                # context, not a lead. It stays recorded and filterable; it
                # just no longer competes with findings about THIS system.
                alert_rows.append((ip_id, "scanner_ua", 3, f"UA: {ua}", ""))
            if a.uphp_ok:
                alert_rows.append((
                    ip_id, "upload_php", 0,
                    f"{a.uphp_ok} von {a.uphp} Request(s) auf PHP in Upload-/"
                    f"Cache-Verzeichnissen wurden 2xx beantwortet — Zugriff auf "
                    f"eine abgelegte Shell?", a.examples.get("upload_php", "")))
            if a.sqli_ok:
                alert_rows.append((
                    ip_id, "sqli", 1,
                    f"{a.sqli_ok} von {a.sqli} SQL-Injection-Mustern in URIs "
                    f"wurden 2xx beantwortet", a.examples.get("sqli", "")))
            if a.trav_ok:
                alert_rows.append((
                    ip_id, "traversal", 1,
                    f"{a.trav_ok} von {a.trav} Path-Traversal-Mustern wurden "
                    f"2xx beantwortet", a.examples.get("traversal", "")))
        conn.executemany(
            "INSERT INTO alerts (ip_id, kind, severity, detail, example) "
            "VALUES (?,?,?,?,?)", alert_rows)
        stats["alerts"] = len(alert_rows)
        stats["clients"] = len(actors)

        if ctx is not None:
            ctx.progress(0.92, "Baue Indizes…")
        conn.execute("CREATE INDEX idx_req_ip ON requests(ip, epoch)")
        conn.execute("CREATE INDEX idx_req_leaf ON requests(leaf)")
        conn.execute("CREATE INDEX idx_req_epoch ON requests(epoch)")
        conn.executemany("INSERT INTO meta VALUES (?,?)", [
            ("schema", SCHEMA_VERSION),
            ("targets", _json.dumps([str(t) for t in targets])),
            ("lines", str(stats["lines"])),
            ("clients", str(stats["clients"])),
            ("unparsed", str(stats["unparsed"])),
        ])
        conn.commit()
    finally:
        conn.close()

    # --- alert findings into the case DB (one truth, two views) -----------
    _write_alert_findings(case_dir)
    try:
        stats["index_size"] = log_db.stat().st_size
    except OSError:
        stats["index_size"] = 0
    return stats


def _day_iso(epoch_day):
    """Integer epoch-day (local) -> ISO date. 1970-01-01 is ordinal 719163."""
    from datetime import date
    return date.fromordinal(int(epoch_day) + 719163).isoformat()


_ALERT_FINDING = {
    # kind -> (severity, rule text)
    "login_success": (0, "Possible successful brute-force (redirect after login flood)"),
    "upload_php": (0, "Requested PHP in upload/cache directory answered 2xx"),
    "login_flood": (1, "CMS login POST flood"),
    "sqli": (1, "SQL injection patterns in URIs answered 2xx"),
    "traversal": (1, "Path traversal patterns answered 2xx"),
    "scanner_ua": (3, "Scanner tool User-Agent"),
}


def _write_alert_findings(case_dir):
    """Restate the index's alerts as findings (artifact = the client IP), so
    the Findings view is the one list of everything the case knows."""
    log_db = db.log_db_path(case_dir)
    if not log_db.is_file():
        return
    lconn = sqlite3.connect(f"file:{log_db.as_posix()}?mode=ro", uri=True)
    try:
        alert_rows = lconn.execute(
            "SELECT a.kind, a.detail, i.ip FROM alerts a "
            "JOIN ips i ON i.id = a.ip_id").fetchall()
    finally:
        lconn.close()
    conn = db.connect(case_dir)
    try:
        for kind, detail, ip in alert_rows:
            sev, rule = _ALERT_FINDING.get(kind, (2, kind))
            db.upsert_finding(conn, "logs", sev, rule, "client", ip,
                              evidence=detail)
        conn.commit()
    finally:
        conn.close()


# --- querying ---------------------------------------------------------------

def _open_ro(case_dir):
    path = db.log_db_path(case_dir)
    if not path.is_file():
        return None
    conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def status(case_dir, targets=None):
    """Whether the index exists and can be trusted for these targets."""
    out = {"exists": False, "fresh": False, "reason": "kein Index gebaut",
           "lines": 0, "clients": 0, "unparsed": 0, "size": 0}
    conn = _open_ro(case_dir)
    if conn is None:
        return out
    try:
        out["exists"] = True
        out["size"] = db.log_db_path(case_dir).stat().st_size
        meta = dict(conn.execute("SELECT key, value FROM meta"))
        if meta.get("schema") != SCHEMA_VERSION:
            out["reason"] = "Index stammt von einer älteren Version"
            return out
        for k in ("lines", "clients", "unparsed"):
            out[k] = int(meta.get(k, 0) or 0)
        stored = {(r[0], r[1], r[2]) for r in conn.execute(
            "SELECT path, size, mtime FROM sources WHERE skipped_reason = ''")}
    except sqlite3.Error as e:
        out["reason"] = f"Index nicht lesbar: {e}"
        return out
    finally:
        conn.close()
    if targets is None:
        out["fresh"] = True
        out["reason"] = ""
        return out
    current = set(_source_fingerprint(targets))
    if current != stored:
        added = len(current - stored)
        gone = len(stored - current)
        out["reason"] = (f"Evidence hat sich geändert ({added} Datei(en) "
                         f"neu/verändert, {gone} entfernt) — Index neu bauen")
        return out
    out["fresh"] = True
    out["reason"] = ""
    return out


def actors_list(case_dir, search="", sort="requests", flag="", limit=200,
                offset=0):
    """The Actors view: one finished row per client, filter + sort in SQL."""
    conn = _open_ro(case_dir)
    if conn is None:
        return {"total": 0, "actors": []}
    try:
        where, params = [], []
        if search:
            where.append("ip LIKE ?")
            params.append(f"%{search}%")
        if flag == "alerted":
            # "Auffällig" means something happened TO THIS SYSTEM. A client
            # whose only mark is "announced itself as a scanner" is context
            # and belongs under the Scanner filter, not here -- otherwise the
            # useful list is 39 rows of background noise plus 4 real ones.
            marks = ",".join("?" * len(INFO_ALERT_KINDS))
            where.append(f"ip_id IN (SELECT DISTINCT ip_id FROM alerts "
                         f"WHERE kind NOT IN ({marks}))")
            params.extend(INFO_ALERT_KINDS)
        elif flag == "scanner":
            where.append("scanner_uas != '[]'")
        elif flag == "bruteforce":
            where.append(f"login_posts >= {BF_THRESHOLD}")
        elif flag == "probes":
            where.append("(sqli_attempts > 0 OR traversal_attempts > 0 "
                         "OR upload_php_attempts > 0)")
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        order = {
            "requests": "requests DESC",
            "first": "first_epoch ASC",
            "last": "last_epoch DESC",
            "errors": "(err4 + err5) DESC",
            "alerts": "login_posts DESC",
        }.get(sort, "requests DESC")
        total = conn.execute(
            f"SELECT count(*) FROM actors {clause}", params).fetchone()[0]
        rows = [dict(r) for r in conn.execute(
            f"SELECT * FROM actors {clause} ORDER BY {order} LIMIT ? OFFSET ?",
            params + [limit, offset])]
        ids = [r["ip_id"] for r in rows]
        alerts_by_ip = {}
        if ids:
            marks = ",".join("?" * len(ids))
            for r in conn.execute(
                    f"SELECT ip_id, kind, severity, detail FROM alerts "
                    f"WHERE ip_id IN ({marks})", ids):
                # Same normalisation as the filter: the KIND decides, so an
                # index from an earlier version does not show a scanner
                # sighting in warning colours.
                sev = 3 if r["kind"] in INFO_ALERT_KINDS else r["severity"]
                alerts_by_ip.setdefault(r["ip_id"], []).append(
                    {"kind": r["kind"], "severity": sev,
                     "detail": r["detail"]})
        for r in rows:
            r["alerts"] = alerts_by_ip.get(r["ip_id"], [])
        return {"total": total, "actors": rows}
    finally:
        conn.close()


def actor_sparklines(case_dir, ip_ids, buckets=48):
    """Per-actor activity histogram over the case's whole time span, one
    fixed-size array per actor -- the sparkline cells of the Actors view."""
    conn = _open_ro(case_dir)
    if conn is None or not ip_ids:
        return {"span": None, "series": {}}
    try:
        span = conn.execute(
            "SELECT min(hour), max(hour) FROM actor_hours").fetchone()
        if not span or span[0] is None:
            return {"span": None, "series": {}}
        lo, hi = span
        width = max(1, hi - lo + 1)
        marks = ",".join("?" * len(ip_ids))
        series = {int(i): [0] * buckets for i in ip_ids}
        for ip_id, hour, n in conn.execute(
                f"SELECT ip_id, hour, n FROM actor_hours WHERE ip_id IN ({marks})",
                list(ip_ids)):
            idx = min(buckets - 1, (hour - lo) * buckets // width)
            series[int(ip_id)][idx] += n
        return {"span": {"from_hour": lo * 3600, "to_hour": (hi + 1) * 3600},
                "series": series}
    finally:
        conn.close()


def actor_profile(case_dir, ip):
    """Everything the index knows about ONE client, for assessing a finding
    in place: the actor row, its alerts, the URIs it hit most and the agents
    it used. All indexed lookups -- this answers in milliseconds."""
    conn = _open_ro(case_dir)
    if conn is None:
        return None
    try:
        row = conn.execute("SELECT * FROM actors WHERE ip = ?",
                           (str(ip).strip(),)).fetchone()
        if row is None:
            return None
        actor = dict(row)
        ip_id = actor["ip_id"]
        alerts = [dict(r) for r in conn.execute(
            "SELECT kind, severity, detail, example FROM alerts "
            "WHERE ip_id = ? ORDER BY severity", (ip_id,))]
        top_paths = [dict(r) for r in conn.execute(
            """SELECT u.text AS uri, count(*) AS n,
                      sum(CASE WHEN r.status BETWEEN 200 AND 299
                          THEN 1 ELSE 0 END) AS ok
               FROM requests r JOIN strings u ON u.id = r.uri
               WHERE r.ip = ? GROUP BY r.uri ORDER BY n DESC LIMIT 12""",
            (ip_id,))]
        top_agents = [dict(r) for r in conn.execute(
            """SELECT a.text AS agent, count(*) AS n
               FROM requests r JOIN strings a ON a.id = r.agent
               WHERE r.ip = ? GROUP BY r.agent ORDER BY n DESC LIMIT 5""",
            (ip_id,))]
        return {"actor": actor, "alerts": alerts, "top_paths": top_paths,
                "top_agents": top_agents}
    finally:
        conn.close()


def trace(case_dir, ips, from_epoch=None, to_epoch=None, limit=5000,
          offset=0):
    """Every request of these clients, oldest first -- THE instant trace.
    Twenty clients cost one indexed query, not twenty log passes."""
    conn = _open_ro(case_dir)
    if conn is None:
        return {"total": 0, "rows": []}
    try:
        wanted = [str(ip).strip() for ip in ips if str(ip).strip()]
        if not wanted:
            return {"total": 0, "rows": []}
        marks = ",".join("?" * len(wanted))
        where = [f"r.ip IN (SELECT id FROM ips WHERE ip IN ({marks}))"]
        params = list(wanted)
        if from_epoch:
            where.append("r.epoch >= ?")
            params.append(int(from_epoch))
        if to_epoch:
            where.append("r.epoch <= ?")
            params.append(int(to_epoch))
        clause = " AND ".join(where)
        total = conn.execute(
            f"SELECT count(*) FROM requests r WHERE {clause}", params
        ).fetchone()[0]
        rows = conn.execute(
            f"""SELECT i.ip AS client, r.epoch, r.tz, r.method,
                       u.text AS uri, r.status, r.size,
                       f.text AS referrer, a.text AS agent, s.text AS source
                FROM requests r
                JOIN ips i ON i.id = r.ip
                LEFT JOIN strings u ON u.id = r.uri
                LEFT JOIN strings f ON f.id = r.referrer
                LEFT JOIN strings a ON a.id = r.agent
                LEFT JOIN strings s ON s.id = r.source
                WHERE {clause}
                ORDER BY r.epoch LIMIT ? OFFSET ?""",
            params + [limit, offset]).fetchall()
        return {"total": total, "rows": [dict(r) for r in rows]}
    finally:
        conn.close()


def who_requested(case_dir, names, limit=200):
    """WHO requested any of these file names -- the file-to-log pivot."""
    conn = _open_ro(case_dir)
    if conn is None:
        return []
    try:
        wanted = [_leaf(n) for n in names if str(n).strip()]
        wanted = [w for w in dict.fromkeys(wanted) if w]
        if not wanted:
            return []
        marks = ",".join("?" * len(wanted))
        rows = conn.execute(
            f"""SELECT i.ip, s.text AS name, count(*) AS hits,
                       sum(CASE WHEN r.status BETWEEN 200 AND 299
                           THEN 1 ELSE 0 END) AS ok_hits
                FROM requests r
                JOIN ips i ON i.id = r.ip
                JOIN strings s ON s.id = r.leaf
                WHERE r.leaf IN (SELECT id FROM strings WHERE text IN ({marks}))
                GROUP BY i.ip, s.text ORDER BY hits DESC LIMIT ?""",
            wanted + [limit]).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def requests_for_names(case_dir, names, limit=20000):
    """Every (client, URI) pair that requested one of these FILE NAMES, with
    hit counts and how many of them were answered 2xx.

    The name is only the PREFILTER -- it hits the index on requests(leaf).
    The caller compares the full URI against the path it actually means,
    because a name alone is not an identity: a shell called `index.php`
    shares its name with every landing page on the server, and collecting
    those visitors would put unrelated people in a case file.
    """
    conn = _open_ro(case_dir)
    if conn is None:
        return []
    try:
        wanted = [_leaf(n) for n in names if str(n).strip()]
        wanted = [w for w in dict.fromkeys(wanted) if w]
        if not wanted:
            return []
        marks = ",".join("?" * len(wanted))
        rows = conn.execute(
            f"""SELECT i.ip AS ip, u.text AS uri, s.text AS name,
                       count(*) AS hits,
                       sum(CASE WHEN r.status BETWEEN 200 AND 299
                           THEN 1 ELSE 0 END) AS ok_hits
                FROM requests r
                JOIN ips i ON i.id = r.ip
                JOIN strings s ON s.id = r.leaf
                JOIN strings u ON u.id = r.uri
                WHERE r.leaf IN (SELECT id FROM strings WHERE text IN ({marks}))
                GROUP BY i.ip, u.text
                ORDER BY ok_hits DESC, hits DESC LIMIT ?""",
            wanted + [limit]).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def timeline(case_dir):
    """Requests/errors/new clients per day -- the dashboard's coverage chart."""
    conn = _open_ro(case_dir)
    if conn is None:
        return []
    try:
        return [dict(r) for r in conn.execute(
            "SELECT day, requests, errors, new_clients FROM days ORDER BY day")]
    finally:
        conn.close()


def overview(case_dir):
    """Headline numbers for the dashboard."""
    conn = _open_ro(case_dir)
    if conn is None:
        return None
    try:
        meta = dict(conn.execute("SELECT key, value FROM meta"))
        first, last = conn.execute(
            "SELECT min(first_epoch), max(last_epoch) FROM actors").fetchone()
        alerted = conn.execute(
            "SELECT count(DISTINCT ip_id) FROM alerts").fetchone()[0]
        return {"lines": int(meta.get("lines", 0) or 0),
                "clients": int(meta.get("clients", 0) or 0),
                "unparsed": int(meta.get("unparsed", 0) or 0),
                "alerted_clients": alerted,
                "first_epoch": first, "last_epoch": last}
    finally:
        conn.close()
