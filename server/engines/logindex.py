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
from server.i18n import t
from server.engines.fsutil import (get_files_recursive, is_compressed,
                                   is_scannable_text, open_text_auto)

# 3: days.ok (mit 2xx beantwortete Anfragen je Tag) für die Verlaufskurven.
SCHEMA_VERSION = "3"
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
    day TEXT PRIMARY KEY, requests INTEGER, errors INTEGER, new_clients INTEGER,
    -- Mit 2xx beantwortet. Getrennt von `requests`, weil erst das Verhältnis
    -- etwas sagt: 500 Anfragen mit 20 Erfolgen sind ein Abklopfen, 500 mit
    -- 480 Erfolgen sind Betrieb.
    ok INTEGER
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
                                # [requests, errors, new_clients, ok]
                                d = days[day] = [0, 0, 0, 0]
                            d[0] += 1
                            if status >= 400:
                                d[1] += 1
                            elif 200 <= status <= 299:
                                d[3] += 1

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
            "INSERT INTO days VALUES (?,?,?,?,?)",
            ((_day_iso(day), v[0], v[1], v[2], v[3])
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


def status(case_dir, targets=None, lang="en"):
    """Whether the index exists and can be trusted for these targets."""
    out = {"exists": False, "fresh": False, "reason": t(lang, "index.none"),
           "lines": 0, "clients": 0, "unparsed": 0, "size": 0}
    conn = _open_ro(case_dir)
    if conn is None:
        return out
    try:
        out["exists"] = True
        out["size"] = db.log_db_path(case_dir).stat().st_size
        meta = dict(conn.execute("SELECT key, value FROM meta"))
        if meta.get("schema") != SCHEMA_VERSION:
            out["reason"] = t(lang, "index.oldVersion")
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


# The flag conditions, usable in BOTH directions: `flag=` selects a class,
# `hide=` removes it from view. One source of truth so the two can never
# drift apart. "Auffällig" means something happened TO THIS SYSTEM: a client
# whose only mark is "announced itself as a scanner" is context and belongs
# under the Scanner flag, not here -- otherwise the useful list is 39 rows of
# background noise plus 4 real ones.
def _flag_condition(flag):
    if flag == "alerted":
        marks = ",".join("?" * len(INFO_ALERT_KINDS))
        return (f"ip_id IN (SELECT DISTINCT ip_id FROM alerts "
                f"WHERE kind NOT IN ({marks}))", list(INFO_ALERT_KINDS))
    if flag == "scanner":
        return "scanner_uas != '[]'", []
    if flag == "bruteforce":
        return f"login_posts >= {BF_THRESHOLD}", []
    if flag == "probes":
        return ("(sqli_attempts > 0 OR traversal_attempts > 0 "
                "OR upload_php_attempts > 0)", [])
    if flag == "quiet":
        # "Unauffällig" ist genau das Gegenteil dessen, was in der Liste ein
        # Abzeichen erzeugt -- die Bedingung spiegelt actorBadges() in der
        # Oberfläche, damit „unauffällig ausblenden" exakt die Zeilen
        # entfernt, an denen „unauffällig" steht.
        return ("NOT ((login_redirects > 0 AND login_posts >= "
                f"{BF_THRESHOLD}) OR upload_php_ok > 0 OR login_posts >= "
                f"{BF_THRESHOLD} OR scanner_uas != '[]' OR sqli_ok > 0 "
                "OR sqli_attempts > 0 OR traversal_ok > 0)", [])
    return None, []


# SQLite bindet nur eine begrenzte Zahl von Variablen pro Anweisung (999 in
# älteren Builds). Eine IN-Liste, deren Länge von den DATEN abhängt statt von
# einer Auswahl, läuft damit irgendwann in "too many SQL variables" -- auf
# einem Testfall nie, auf einem echten mit zehntausenden Adressen sofort.
_VAR_CHUNK = 500


def _alerts_by_ip(conn, ip_ids):
    """Die Alarme zu diesen Clients, stückweise abgefragt.

    Die Normalisierung steht hier und nicht bei den Aufrufern: der KIND
    entscheidet über den Schweregrad, damit ein Index aus einer früheren
    Version eine Scanner-Sichtung nicht in Warnfarben zeigt.

    `example` reist mit: es ist die URI, DIE DEN ALARM AUSGELÖST hat, und der
    Trace kann sie damit rot markieren -- sonst sucht man die auslösende
    Zeile unter tausenden von Hand."""
    out = {}
    for chunk in _chunks(list(ip_ids), _VAR_CHUNK):
        marks = ",".join("?" * len(chunk))
        for r in conn.execute(
                f"SELECT ip_id, kind, severity, detail, example FROM alerts "
                f"WHERE ip_id IN ({marks})", chunk):
            sev = 3 if r["kind"] in INFO_ALERT_KINDS else r["severity"]
            out.setdefault(r["ip_id"], []).append(
                {"kind": r["kind"], "severity": sev,
                 "detail": r["detail"], "example": r["example"] or ""})
    return out


def actors_by_ip(case_dir, ips):
    """Die Actor-Zeilen zu GENAU diesen Adressen.

    Wer nur ein paar ausgewählte Clients nachschlagen will, hat vorher die
    ganze Tabelle geholt und darin gesucht. Auf einem echten Fall sind das
    zehntausende Zeilen für eine Handvoll Treffer -- und die Alarm-Abfrage
    darüber sprengte SQLites Variablen-Limit."""
    wanted = [w for w in dict.fromkeys(str(i).strip() for i in ips) if w]
    conn = _open_ro(case_dir)
    if conn is None or not wanted:
        if conn is not None:
            conn.close()
        return {}
    try:
        out = {}
        for chunk in _chunks(wanted, _VAR_CHUNK):
            marks = ",".join("?" * len(chunk))
            for r in conn.execute(
                    f"SELECT * FROM actors WHERE ip IN ({marks})", chunk):
                out[r["ip"]] = dict(r)
        alerts = _alerts_by_ip(conn, [r["ip_id"] for r in out.values()])
        for r in out.values():
            r["alerts"] = alerts.get(r["ip_id"], [])
        return out
    finally:
        conn.close()


def actors_list(case_dir, search="", sort="requests", flag="", hide=(),
                limit=200, offset=0):
    """The Actors view: one finished row per client, filter + sort in SQL.
    `flag` selects one class; `hide` removes classes -- the UI's chips are
    hide-toggles, several can stack."""
    conn = _open_ro(case_dir)
    if conn is None:
        return {"total": 0, "actors": []}
    try:
        where, params = [], []
        if search:
            where.append("ip LIKE ?")
            params.append(f"%{search}%")
        cond, extra = _flag_condition(flag)
        if cond:
            where.append(cond)
            params.extend(extra)
        for h in hide:
            cond, extra = _flag_condition(h)
            if cond:
                where.append(f"NOT ({cond})")
                params.extend(extra)
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
        alerts_by_ip = _alerts_by_ip(conn, [r["ip_id"] for r in rows])
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
        series = {int(i): [0] * buckets for i in ip_ids}
        for chunk in _chunks(list(ip_ids), _VAR_CHUNK):
            marks = ",".join("?" * len(chunk))
            for ip_id, hour, n in conn.execute(
                    f"SELECT ip_id, hour, n FROM actor_hours "
                    f"WHERE ip_id IN ({marks})", chunk):
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


# Sortierungen des Trace. Der Zeitverlauf ist die Voreinstellung, weil ein
# Trace eine GESCHICHTE ist -- die anderen Ordnungen beantworten Fragen
# ("was war erfolgreich?", "was war groß?"), die man im Verlauf sonst suchen
# müsste. Feste Liste statt durchgereichtem SQL: der Sortierschlüssel geht in
# die Abfrage ein und darf deshalb nie vom Client bestimmt werden.
TRACE_SORTS = {
    "time": "r.epoch ASC, r.rowid ASC",
    "time_desc": "r.epoch DESC, r.rowid DESC",
    "status": "r.status DESC, r.epoch ASC",
    "size": "r.size DESC, r.epoch ASC",
    "uri": "uri ASC, r.epoch ASC",
}

# Statusklassen als Filter: "2xx" ist die Frage "was hat der Server
# ausgeliefert?", "err" fasst 4xx und 5xx zusammen.
_STATUS_RANGES = {
    "2xx": (200, 299), "3xx": (300, 399), "4xx": (400, 499),
    "5xx": (500, 599), "err": (400, 599),
}


def trace(case_dir, ips, from_epoch=None, to_epoch=None, limit=5000,
          offset=0, search="", status="", method="", sort="time"):
    """Every request of these clients -- THE instant trace. Twenty clients
    cost one indexed query, not twenty log passes.

    `search` sucht in URI und User-Agent, `status` filtert eine Statusklasse,
    `method` die HTTP-Methode. Gefiltert wird in SQL, damit auch der zwölfte
    Blättern-Klick noch dieselbe Antwortzeit hat wie der erste."""
    conn = _open_ro(case_dir)
    if conn is None:
        return {"total": 0, "rows": [], "methods": []}
    try:
        wanted = [str(ip).strip() for ip in ips if str(ip).strip()]
        if not wanted:
            return {"total": 0, "rows": [], "methods": []}
        marks = ",".join("?" * len(wanted))
        where = [f"r.ip IN (SELECT id FROM ips WHERE ip IN ({marks}))"]
        params = list(wanted)
        if from_epoch:
            where.append("r.epoch >= ?")
            params.append(int(from_epoch))
        if to_epoch:
            where.append("r.epoch <= ?")
            params.append(int(to_epoch))
        if status in _STATUS_RANGES:
            lo, hi = _STATUS_RANGES[status]
            where.append("r.status BETWEEN ? AND ?")
            params += [lo, hi]
        if method.strip():
            where.append("r.method = ?")
            params.append(method.strip().upper())
        if search.strip():
            where.append("(u.text LIKE ? ESCAPE '\\' OR a.text LIKE ? ESCAPE '\\')")
            like = "%" + (search.strip().replace("\\", "\\\\")
                          .replace("%", "\\%").replace("_", "\\_")) + "%"
            params += [like, like]
        clause = " AND ".join(where)
        # Die Joins auf u/a stehen auch in der COUNT-Abfrage, weil `search`
        # auf ihnen filtert -- sonst zählte sie etwas anderes als die Liste.
        joins = ("LEFT JOIN strings u ON u.id = r.uri "
                 "LEFT JOIN strings a ON a.id = r.agent")
        total = conn.execute(
            f"SELECT count(*) FROM requests r {joins} WHERE {clause}", params
        ).fetchone()[0]
        rows = conn.execute(
            f"""SELECT i.ip AS client, r.epoch, r.tz, r.method,
                       u.text AS uri, r.status, r.size,
                       f.text AS referrer, a.text AS agent, s.text AS source
                FROM requests r
                JOIN ips i ON i.id = r.ip
                {joins}
                LEFT JOIN strings f ON f.id = r.referrer
                LEFT JOIN strings s ON s.id = r.source
                WHERE {clause}
                ORDER BY {TRACE_SORTS.get(sort, TRACE_SORTS['time'])}
                LIMIT ? OFFSET ?""",
            params + [limit, offset]).fetchall()
        # Welche Methoden überhaupt vorkommen -- der Filter soll nur
        # anbieten, was es hier auch gibt.
        methods = [r[0] for r in conn.execute(
            f"SELECT DISTINCT r.method FROM requests r "
            f"WHERE r.ip IN (SELECT id FROM ips WHERE ip IN ({marks})) "
            f"ORDER BY r.method", wanted) if r[0]]
        return {"total": total, "rows": [dict(r) for r in rows],
                "methods": methods}
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


# --- Muster-Jagd ------------------------------------------------------------
# Der Analyst hinterlegt URL-Pfade, von denen er weiß, dass sie zu einem
# Exploit gehören; das Werkzeug sagt, WER sie abgerufen hat.
#
# Das läuft in zwei Stufen, damit es auch auf einem 10-Millionen-Zeilen-Log
# eine Abfrage bleibt und keinen neuen Index braucht:
#   1. Das Muster wird gegen die DISTINKTEN URIs geprüft (Tabelle `strings`) --
#      einmal je eindeutiger Zeichenkette, nicht je Logzeile.
#   2. Die Requests dazu holt der BESTEHENDE leaf-Index: aus jeder getroffenen
#      URI ergibt sich ihr Dateiname, und `requests(leaf)` ist indiziert. Die
#      volle URI entscheidet dann, welche Zeile wirklich zählt.

# Wie viele DISTINKTE URIs ein Muster höchstens einsammelt. Wer ein Muster
# schreibt, das mehr trifft, hat kein Muster, sondern eine Suche -- das sagt
# die Antwort dann auch (`truncated`), statt stillschweigend zu kürzen.
_PATTERN_URI_CAP = 4000

# Wie viele davon die Antwort einzeln aufzählt. Die Liste dient der
# Stichprobe ("passt mein Muster?"), die Gesamtzahl steht daneben.
_PATTERN_URI_SHOWN = 50


def _like_from_pattern(pattern):
    """Teilstring, Groß-/Kleinschreibung egal, `*` als Platzhalter.

    Bewusst kein Regex: was ein Muster trifft, muss man in einem Bericht
    erklären können. %/_ werden entwertet, sonst wäre jedes `_` im Pfad
    ein stiller Platzhalter."""
    esc = (str(pattern).replace("\\", "\\\\")
           .replace("%", "\\%").replace("_", "\\_"))
    return "%" + esc.replace("*", "%") + "%"


def match_pattern(case_dir, pattern, limit=200):
    """Wer hat URIs abgerufen, auf die dieses Muster passt?

    Liefert die getroffenen URIs (damit sichtbar ist, ob das Muster zu weit
    greift), je Client Trefferzahl, davon 2xx, sowie erste/letzte Anfrage --
    und die Kennzahlen der Suche selbst, damit ein Lauf in einem Satz
    zusammenfassbar ist."""
    empty = {"pattern": pattern, "uris": [], "clients": [], "hits": 0,
             "ok_hits": 0, "clients_total": 0, "ok_clients": 0, "uri_total": 0,
             "first_epoch": None, "last_epoch": None, "tz": 0,
             "truncated": False}
    conn = _open_ro(case_dir)
    if conn is None or not str(pattern).strip():
        if conn is not None:
            conn.close()
        return empty
    try:
        rows = conn.execute(
            "SELECT id, text FROM strings WHERE text LIKE ? ESCAPE '\\' "
            "LIMIT ?", (_like_from_pattern(pattern), _PATTERN_URI_CAP + 1)
        ).fetchall()
        truncated = len(rows) > _PATTERN_URI_CAP
        rows = rows[:_PATTERN_URI_CAP]
        if not rows:
            return empty

        # `strings` interniert AUCH User-Agents und Referrer. Erst der Join
        # über requests.uri entscheidet, was wirklich eine abgerufene URI war.
        conn.execute("CREATE TEMP TABLE want_uri (id INTEGER PRIMARY KEY)")
        conn.executemany("INSERT OR IGNORE INTO want_uri VALUES (?)",
                         [(r["id"],) for r in rows])
        leaves = {_leaf(r["text"]) for r in rows}
        conn.execute("CREATE TEMP TABLE want_leaf (id INTEGER PRIMARY KEY)")
        for chunk in _chunks(sorted(leaves), 800):
            marks = ",".join("?" * len(chunk))
            conn.execute(
                f"INSERT OR IGNORE INTO want_leaf "
                f"SELECT id FROM strings WHERE text IN ({marks})", chunk)

        clients = [dict(r) for r in conn.execute(
            """SELECT i.ip AS ip, count(*) AS hits,
                      sum(CASE WHEN r.status BETWEEN 200 AND 299
                          THEN 1 ELSE 0 END) AS ok_hits,
                      min(r.epoch) AS first_epoch, max(r.epoch) AS last_epoch,
                      max(r.tz) AS tz
               FROM requests r
               JOIN want_leaf wl ON wl.id = r.leaf
               JOIN want_uri wu ON wu.id = r.uri
               JOIN ips i ON i.id = r.ip
               GROUP BY i.ip
               ORDER BY ok_hits DESC, hits DESC LIMIT ?""", (limit,))]
        uris = [dict(r) for r in conn.execute(
            """SELECT s.text AS uri, count(*) AS hits,
                      sum(CASE WHEN r.status BETWEEN 200 AND 299
                          THEN 1 ELSE 0 END) AS ok_hits
               FROM requests r
               JOIN want_leaf wl ON wl.id = r.leaf
               JOIN want_uri wu ON wu.id = r.uri
               JOIN strings s ON s.id = r.uri
               GROUP BY s.text ORDER BY hits DESC LIMIT ?""",
            (_PATTERN_URI_SHOWN,))]
        # Wie viele es WIRKLICH sind. Die Liste oben ist gedeckelt, und "50
        # getroffene URLs" ist eine falsche Angabe, wenn es 3.000 waren --
        # gerade diese Zahl soll ja verraten, dass das Muster zu weit greift.
        uri_total = conn.execute(
            """SELECT count(DISTINCT r.uri) FROM requests r
               JOIN want_leaf wl ON wl.id = r.leaf
               JOIN want_uri wu ON wu.id = r.uri""").fetchone()[0]
        firsts = [c["first_epoch"] for c in clients if c["first_epoch"]]
        lasts = [c["last_epoch"] for c in clients if c["last_epoch"]]
        tzs = [c["tz"] for c in clients if c["tz"] is not None]
        return {"pattern": pattern, "uris": uris, "clients": clients,
                "hits": sum(c["hits"] for c in clients),
                "ok_hits": sum(c["ok_hits"] for c in clients),
                # Die Kennzahlen der Suche. `ok_clients` ist die Zahl, die im
                # Bericht steht: nicht wie oft geklopft wurde, sondern wie
                # viele durchkamen.
                "clients_total": len(clients),
                "ok_clients": sum(1 for c in clients if c["ok_hits"] > 0),
                "uri_total": uri_total,
                "first_epoch": min(firsts) if firsts else None,
                "last_epoch": max(lasts) if lasts else None,
                "tz": max(tzs) if tzs else 0,
                "truncated": truncated}
    finally:
        conn.close()


def _chunks(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


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


def chain_facts(case_dir, leaves=(), ips=()):
    """Die Zeitanker für die Fall-Chronologie -- alles GEMESSEN, nichts
    geschlossen.

    Für jeden Dateinamen: wann wurde er zum ersten Mal angefragt, wann zum
    ersten Mal mit 2xx beantwortet, wann zuletzt. Der erste 2xx ist der
    belastbarste Anker, den ein Fall für "diese Datei lag da" hat -- die
    mtime der Kopie auf der Forensik-Maschine ist es nicht, weil niemand ihr
    ansieht, ob sie vom Original stammt oder vom Kopiervorgang.

    Für jeden Client: erste und letzte Anfrage sowie der Zeitpunkt der URI,
    die seinen Alarm ausgelöst hat -- die Alarm-Tabelle selbst führt keine
    Zeit, wohl aber die Anfrage dahinter.

    Die Zuordnung Name -> Pfad passiert beim Aufrufer: hier steht nur der
    Dateiname, weil `requests(leaf)` der indizierte Zugriff ist. Welche der
    Treffer wirklich zu DIESEM Pfad gehören, entscheidet dort der Vergleich
    der vollen URI."""
    out = {"files": {}, "clients": {}}
    names = [w for w in dict.fromkeys(_leaf(n) for n in leaves) if w]
    wanted_ips = [w for w in dict.fromkeys(str(i).strip() for i in ips) if w]
    conn = _open_ro(case_dir)
    if conn is None:
        return out
    try:
        for chunk in _chunks(names, _VAR_CHUNK):
            marks = ",".join("?" * len(chunk))
            for r in conn.execute(
                    f"""SELECT s.text AS name, u.text AS uri, i.ip AS ip,
                               min(r.epoch) AS first_epoch,
                               max(r.epoch) AS last_epoch,
                               max(r.tz) AS tz, count(*) AS hits,
                               sum(CASE WHEN r.status BETWEEN 200 AND 299
                                   THEN 1 ELSE 0 END) AS ok_hits,
                               min(CASE WHEN r.status BETWEEN 200 AND 299
                                   THEN r.epoch END) AS first_ok,
                               max(CASE WHEN r.status BETWEEN 200 AND 299
                                   THEN r.epoch END) AS last_ok
                          FROM requests r
                          JOIN strings s ON s.id = r.leaf
                          JOIN strings u ON u.id = r.uri
                          JOIN ips i ON i.id = r.ip
                         WHERE r.leaf IN (SELECT id FROM strings
                                           WHERE text IN ({marks}))
                         GROUP BY s.text, u.text, i.ip""", chunk):
                out["files"].setdefault(r["name"], []).append(dict(r))

        for chunk in _chunks(wanted_ips, _VAR_CHUNK):
            marks = ",".join("?" * len(chunk))
            for r in conn.execute(
                    f"""SELECT i.ip AS ip, a.requests, a.first_epoch,
                               a.last_epoch, a.tz
                          FROM actors a JOIN ips i ON i.id = a.ip_id
                         WHERE i.ip IN ({marks})""", chunk):
                out["clients"][r["ip"]] = {**dict(r), "alerts": []}

        ids = {}
        for chunk in _chunks(list(out["clients"]), _VAR_CHUNK):
            marks = ",".join("?" * len(chunk))
            for ip_id, ip in conn.execute(
                    f"SELECT id, ip FROM ips WHERE ip IN ({marks})", chunk):
                ids[ip_id] = ip
        for ip_id, alerts in _alerts_by_ip(conn, ids).items():
            ip = ids[ip_id]
            for a in alerts:
                # Wann diese URI von diesem Client zum ersten Mal kam. Ohne
                # Beispiel-URI bleibt der Alarm ohne Zeit -- dann steht er in
                # der Kette nicht, statt an einer erfundenen Stelle.
                stamp = None
                if a["example"]:
                    stamp = conn.execute(
                        "SELECT min(r.epoch) FROM requests r "
                        "WHERE r.ip = ? AND r.uri = (SELECT id FROM strings "
                        "WHERE text = ?)", (ip_id, a["example"])).fetchone()[0]
                out["clients"][ip]["alerts"].append({**a, "epoch": stamp})
        return out
    finally:
        conn.close()


def timeline(case_dir):
    """Requests/2xx/Fehler/neue Clients je Tag -- die Verlaufskurve.

    Ein Index aus einer älteren Version kennt `days.ok` noch nicht. Das darf
    das Dashboard nicht sprengen: dann fehlt eben die Erfolgskurve, bis der
    Index neu gebaut ist (worauf die Evidence-Ansicht ohnehin hinweist)."""
    conn = _open_ro(case_dir)
    if conn is None:
        return []
    try:
        have_ok = any(r[1] == "ok" for r in conn.execute("PRAGMA table_info(days)"))
        ok_col = "ok" if have_ok else "NULL AS ok"
        return [dict(r) for r in conn.execute(
            f"SELECT day, requests, errors, new_clients, {ok_col} "
            f"FROM days ORDER BY day")]
    finally:
        conn.close()


def timeline_for_ips(case_dir, ips):
    """Dieselbe Auswertung, aber nur für diese Clients -- der Verlauf, den
    man beim Tracen sehen will: wann war dieser Client aktiv, und hat der
    Server ihm geantwortet?

    Läuft über idx_req_ip(ip, epoch), ist also eine indizierte Abfrage und
    kein Durchlauf durch das Log."""
    conn = _open_ro(case_dir)
    if conn is None:
        return []
    try:
        wanted = [str(ip).strip() for ip in ips if str(ip).strip()]
        if not wanted:
            return []
        marks = ",".join("?" * len(wanted))
        rows = conn.execute(
            f"""SELECT (r.epoch + r.tz) / 86400 AS d,
                       count(*) AS requests,
                       sum(CASE WHEN r.status BETWEEN 200 AND 299
                           THEN 1 ELSE 0 END) AS ok,
                       sum(CASE WHEN r.status >= 400 THEN 1 ELSE 0 END) AS errors
                FROM requests r
                WHERE r.ip IN (SELECT id FROM ips WHERE ip IN ({marks}))
                  AND r.epoch IS NOT NULL
                GROUP BY d ORDER BY d""", wanted).fetchall()
        return [{"day": _day_iso(r["d"]), "requests": r["requests"],
                 "ok": r["ok"], "errors": r["errors"], "new_clients": 0}
                for r in rows]
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
