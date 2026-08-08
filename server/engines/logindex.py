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
import json as _json
import os
import re
import sqlite3
from collections import Counter
from pathlib import Path

from server import db, ruleswitch
from server.engines import accesslog
from server.i18n import t
from server.engines.fsutil import (get_files_recursive, is_compressed,
                                   is_scannable_text, open_text_auto)

# 3: days.ok (requests answered with 2xx per day) for the timeline curves.
# 5: actors.admin_ok -- 2xx responses from the admin backend, which is
#    what a successful login leaves behind. A redirect is not: Joomla
#    answers every login POST with one, right or wrong.
# 4: requests.source points at sources.id instead of an interned BASENAME.
#    Two vhosts each with an access.log used to share one source, so the
#    coverage check compared one file's mtime against the other's newest
#    entry and announced forged timestamps.
SCHEMA_VERSION = "8"
_BATCH = 20000

# --- detection patterns (evaluated once per distinct string) ----------------

SCANNER_UA_RE = re.compile(
    r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|feroxbuster|wpscan|"
    r"joomscan|hydra|acunetix|nessus|nuclei|zgrab|censys|httpx|wfuzz|ffuf)")

# A POST that is an ATTEMPT TO LOG IN -- not any POST the backend receives.
#
# `/administrator/index.php` used to be in here on its own, and in Joomla that
# is the URL of the entire admin application: saving an article, reordering a
# menu, running a backup, every ajax call. On a real case the site's own
# administrator was credited with 127 login attempts, of which 8 were logins
# and 119 were article edits and backup jobs -- and was then reported at HIGH
# as a break-in. An accusation like that costs an analyst hours and points
# them at the wrong person.
#
# The backend is therefore only a login endpoint when the request carries NO
# `option=com_*`: Joomla's login form posts to the bare URL, its application
# always names the component it is talking to.
LOGIN_POST_ENDPOINTS = re.compile(
    r"(?i)(wp-login\.php|xmlrpc\.php|"
    r"/administrator/(index\.php)?(?![^?\s]*\?[^\s]*option=com_(?!login|users))"
    r"(?=[?\s]|$|\?(?![^\s]*option=com_(?!login|users)))|"
    r"option=com_login|task=user\.login|option=com_users)")

# A page only an AUTHENTICATED session is served. Joomla answers every login
# POST with a 303 whether the credentials were right or wrong -- it is a
# plain POST-Redirect-GET -- so the redirect proves nothing on its own. What
# an unauthenticated client cannot obtain is a 2xx on the backend itself.
AUTHENTICATED_AREA_RE = re.compile(
    r"(?i)/administrator/index\.php\?[^\s]*option=com_(?!login|users\b)")

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

# A PHP file lying DIRECTLY in a directory the CMS owns. Joomla puts
# nothing there: a template is `templates/<name>/...`, a module
# `modules/mod_<name>/...`, a plugin `plugins/<group>/<name>/...`. So a
# bare `.php` one level in is not a shape the CMS ships -- it is
# something that was put there.
#
# NOT PART OF THE UPLOAD RULE, which is about directories the WEB SERVER
# may write into and which therefore hold thousands of legitimate files.
# These directories are the opposite: full of legitimate PHP, none of it
# at this depth. Measured on a compromised Joomla with 1744 files -- 615
# PHP files under these four directories, and not ONE of them directly
# inside. The log held three: /templates/x.php answered 2xx five
# times, /plugins/function.php and /plugins/shell.php. No rule said a
# word about any of them.
#
# The depth is the whole rule, so the regex has to anchor at the start
# of the path and refuse a second slash.
CMS_DIR_PHP_RE = re.compile(
    r"(?i)^/?(?:administrator/)?(?:templates|modules|plugins|components)"
    r"/[^/?\s]+\.ph(?:p\d?|tml|ar)(?=[?\s]|$)")

BF_THRESHOLD = 30            # login POSTs per client before it is a flood
# THE WINDOW THE HIGH IS GATED ON. `login_posts >= BF_THRESHOLD` stays a plain
# count, deliberately: a rate in the FLOOD condition would silently drop
# findings on a case whose logs are thin, and a count is what an analyst can
# check by hand.
#
# The HIGH is different. `admin_ok` separates "somebody got in" from "somebody
# kept failing"; it does not separate an intruder who got in from the operator
# who got in, and it never could -- the operator matches it BECAUSE they are
# the operator. What separates those two is the SHAPE of the attempts before
# the success. Measured, generated corpus: two site administrators reached 8
# and 10 login POSTs in their busiest 24 hours across nine weeks of daily
# work, while an intruder reached 70 inside a single hour.
#
# 24 h and not the whole span, because the span collapses the moment one late
# login arrives weeks after a burst.
BF_WINDOW = 86400            # seconds the burst is measured over
# THE THRESHOLD KNOWS NO TIME, and deliberately keeps not knowing it. Adding
# a rate to the CONDITION would silently drop findings on a case whose logs
# are thin, and the count is what an analyst can check by hand.
#
# What was missing is the WINDOW in the sentence. Measured on a real case,
# four clients crossed the threshold: 92 POSTs over twenty-three days
# (0.2/h), 714 over eight days (3.9/h), and two that fired 40 and 32 inside
# the same second (thousands per hour). All four were reported with the same
# word and the same number of digits, and nothing on screen told them apart.
# The count alone cannot: the rate is the difference between somebody
# signing in and somebody guessing.

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
# The backend itself, named with a component: what a login has
# to have succeeded for.
F_ADMIN_AREA = 16
F_CMS_DIR_PHP = 32

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
    admin_ok INTEGER DEFAULT 0,
    login_statuses TEXT DEFAULT '{}',
    scanner_uas TEXT DEFAULT '[]',
    sqli_attempts INTEGER, sqli_ok INTEGER,
    traversal_attempts INTEGER, traversal_ok INTEGER,
    upload_php_attempts INTEGER, upload_php_ok INTEGER,
    cms_dir_php_attempts INTEGER DEFAULT 0,
    cms_dir_php_ok INTEGER DEFAULT 0,
    login_first INTEGER, login_last INTEGER, login_burst INTEGER,
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
    -- Answered with 2xx. Separate from `requests`, because only the ratio
    -- says anything: 500 requests with 20 successes are probing, 500 with
    -- 480 successes are business as usual.
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
                 "admin_ok",
                 "scanner_uas", "sqli", "sqli_ok", "trav", "trav_ok",
                 "uphp", "uphp_ok", "cmsphp", "cmsphp_ok",
                 "login_first", "login_last", "login_epochs",
                 "agents", "examples")

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
        self.admin_ok = 0
        self.scanner_uas = set()
        self.sqli = 0
        self.sqli_ok = 0
        self.trav = 0
        self.trav_ok = 0
        self.uphp = 0
        self.uphp_ok = 0
        self.cmsphp = 0
        self.cmsphp_ok = 0
        self.login_first = None
        self.login_last = None
        # Every login-POST timestamp, for the busiest-window count at
        # flush. A LIST rather than a sliding deque: sources are read in
        # file order, which is not time order across rotated logs, and a
        # window that assumes sorted input silently under-counts. Login
        # POSTs are a small subset of requests -- the largest single
        # actor measured on a real corpus carried 714.
        self.login_epochs = []
        self.agents = set()
        self.examples = {}          # kind -> first matching uri


def build(case_dir, targets, ctx=None, workspace=None):
    """Parse every access-log file under `targets` into <case>/logindex.db.

    Returns a stats dict. Rebuilds from scratch -- the index is cheap relative
    to the questions it answers, and partial updates are how a stale answer
    sneaks in.
    """
    log_db = db.log_db_path(case_dir)
    if log_db.exists():
        log_db.unlink()
    stats = {"files": 0, "lines": 0, "unparsed": 0, "undated": 0,
             "partial": False,
             "skipped": 0,
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
                if CMS_DIR_PHP_RE.match(text):
                    flags |= F_CMS_DIR_PHP
                if UPLOAD_PHP_RE.search(text):
                    flags |= F_UPLOAD_PHP
                if AUTHENTICATED_AREA_RE.search(text):
                    flags |= F_ADMIN_AREA
                got = uri_cache[text] = (uri_id, leaf_id, flags)
            return got

        def agent_entry(text):
            got = agent_cache.get(text)
            if got is None:
                got = agent_cache[text] = (
                    intern(text), bool(text and SCANNER_UA_RE.search(text)))
            return got

        done_size = 0
        # A CANCELLED BUILD IS A FRAGMENT AND HAS TO SAY SO. Everything below
        # still runs after the break -- the batch is flushed, the interning
        # tables and actors are written, the index commits -- so what comes out
        # looks exactly like a complete index and `overview()` reported its
        # numbers as the whole truth. The dashboard counts, the chronology's
        # span and the coverage windows were then all computed from a
        # fraction of the evidence, with nothing on screen saying so.
        cancelled = False
        for file_path, file_size in sized:
            if ctx is not None and ctx.cancelled():
                cancelled = True
                break
            name = os.path.basename(file_path)
            abs_path = os.path.abspath(file_path)
            try:
                file_mtime = int(os.stat(file_path).st_mtime)
            except OSError:
                file_mtime = 0
            if not is_scannable_text(file_path):
                conn.execute(
                    "INSERT OR IGNORE INTO sources (path, size, mtime, skipped_reason)"
                    " VALUES (?,?,?,?)",
                    (abs_path, file_size, file_mtime, "binary/unreadable file"))
                stats["skipped"] += 1
                done_size += file_size
                continue
            if accesslog.sniff_error_log(file_path, open_text_auto):
                conn.execute(
                    "INSERT OR IGNORE INTO sources (path, size, mtime, skipped_reason)"
                    " VALUES (?,?,?,?)",
                    (abs_path, file_size, file_mtime,
                     accesslog.ERROR_LOG_SKIP_REASON))
                stats["skipped"] += 1
                done_size += file_size
                continue

            # THE SOURCE IS THE FILE, NOT ITS NAME. Interning the basename
            # made two vhosts that each keep an `access.log` one and the same
            # source: the coverage check then held one file's mtime against
            # the other's newest entry and told the analyst the file had been
            # written before its own last line -- a tampering claim produced
            # from two honestly timestamped files.
            cur = conn.execute(
                "INSERT OR REPLACE INTO sources (path, size, mtime, lines,"
                " unparsed) VALUES (?,?,?,0,0)",
                (abs_path, file_size, file_mtime))
            src_id = cur.lastrowid
            file_lines = file_unparsed = file_undated = 0
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
                        # A line whose TIMESTAMP cannot be read is still a
                        # request: it has a client, a method and a target, and
                        # throwing it away would understate what the server
                        # was asked for. It is kept at epoch 0 -- but it is
                        # counted, because a request the case cannot place in
                        # time is a limitation and has to be sayable. It used
                        # to be silently filed under 1970 and counted nowhere.
                        if te:
                            epoch, tz = te
                        else:
                            epoch, tz = 0, None
                            file_undated += 1
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
                                # The window of the LOGIN POSTS, not of the
                                # client. A visitor who browses for three
                                # weeks and guesses passwords for one minute
                                # would otherwise be measured as a very slow
                                # attacker.
                                if epoch:
                                    if a.login_first is None or epoch < a.login_first:
                                        a.login_first = epoch
                                    if a.login_last is None or epoch > a.login_last:
                                        a.login_last = epoch
                                    a.login_epochs.append(epoch)
                            # Any method: reaching the backend is a GET.
                            if flags & F_ADMIN_AREA and ok:
                                a.admin_ok += 1
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
                            if flags & F_CMS_DIR_PHP:
                                a.cmsphp += 1
                                if ok:
                                    a.cmsphp_ok += 1
                                a.examples.setdefault("cms_dir_php", uri)
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
                                             f"{name}: {stats['lines'] + file_lines:,} lines indexed")
            except (OSError, EOFError) as e:
                conn.execute(
                    "INSERT OR IGNORE INTO sources (path, size, mtime, skipped_reason)"
                    " VALUES (?,?,?,?)",
                    (abs_path, file_size, file_mtime, f"read error: {e}"))
                stats["skipped"] += 1
                done_size += file_size
                continue

            conn.execute(
                "UPDATE sources SET lines = ?, unparsed = ? WHERE id = ?",
                (file_lines, file_unparsed, src_id))
            stats["files"] += 1
            stats["lines"] += file_lines
            stats["unparsed"] += file_unparsed
            stats["undated"] += file_undated
            stats["bytes"] += file_size
            done_size += file_size

        if batch:
            conn.executemany(
                "INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?)", batch)
            batch.clear()

        if ctx is not None:
            ctx.progress(0.86, "Writing interning tables…")
        conn.executemany("INSERT INTO strings (id, text) VALUES (?,?)",
                         ((i, t) for t, i in strings.items()))
        conn.executemany("INSERT INTO ips (id, ip) VALUES (?,?)",
                         ((i, ip) for ip, i in ips.items()))

        # --- actors + first-seen day ------------------------------------
        if ctx is not None:
            ctx.progress(0.88, "Computing actor statistics…")
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
                a.login_redirects, a.admin_ok,
                _json.dumps({str(k): v for k, v in a.login_statuses.items()}),
                _json.dumps(sorted(a.scanner_uas)[:5]),
                a.sqli, a.sqli_ok, a.trav, a.trav_ok, a.uphp, a.uphp_ok,
                a.cmsphp, a.cmsphp_ok, a.login_first, a.login_last,
                _busiest_window(a.login_epochs),
                len(a.agents)))
        conn.executemany(
            "INSERT INTO actors VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
            ctx.progress(0.90, "Deriving alerts…")
        alert_rows = []
        for ip_id, a in actors.items():
            if a.login_posts >= BF_THRESHOLD:
                breakdown = ", ".join(
                    f"{s} ×{n}" for s, n in sorted(a.login_statuses.items()))
                alert_rows.append((ip_id, "login_flood", 1,
                                   f"{a.login_posts} POSTs against login "
                                   f"endpoints {_login_rate(a)}"
                                   f"(status: {breakdown})", ""))
                # A REDIRECT IS NOT A SUCCESS. Joomla answers EVERY login POST
                # with a 303 -- plain POST-Redirect-GET -- whether the
                # credentials were right or wrong, so on a real case a client
                # whose 121 attempts ALL failed was reported at HIGH as a
                # break-in, and the 100 % redirect rate that proved the
                # opposite was the very thing that triggered it.
                #
                # What an unauthenticated client cannot obtain is a 2xx on the
                # backend with a component named. The flood plus that is a
                # statement worth making; the flood plus a redirect is not.
                #
                # AND `admin_ok` IS STILL NOT ENOUGH. It says somebody got in.
                # It cannot say WHO, and the site's own administrator gets in
                # every working morning -- so on a log covering nine weeks the
                # operator crossed the flood threshold by turning up for work
                # and was then reported, at HIGH, as a break-in on their own
                # site. Nothing about the site had changed; the case simply
                # covered a longer period.
                #
                # The burst is what the two do not share. Measured: the
                # operators peaked at 8 and 10 login POSTs in their busiest
                # 24 hours; the intruder reached 70 inside one hour.
                burst = _busiest_window(a.login_epochs)
                if a.admin_ok and burst >= BF_THRESHOLD:
                    alert_rows.append((
                        ip_id, "login_success", 0,
                        f"{a.login_posts} login POSTs, {burst} of them inside "
                        f"24 h, then {a.admin_ok} request(s) to the admin "
                        f"backend answered 2xx — a page an unauthenticated "
                        f"session does not get. Verify!", ""))
            for ua in sorted(a.scanner_uas):
                # INFORMATIONAL (severity 3): every host on the internet is
                # scanned around the clock, so "a scanner said hello" is
                # context, not a lead. It stays recorded and filterable; it
                # just no longer competes with findings about THIS system.
                alert_rows.append((ip_id, "scanner_ua", 3, f"UA: {ua}", ""))
            if a.uphp_ok:
                alert_rows.append((
                    ip_id, "upload_php", 0,
                    f"{a.uphp_ok} of {a.uphp} request(s) for PHP in upload/"
                    f"cache directories were answered 2xx — access to a "
                    f"dropped shell?", a.examples.get("upload_php", "")))
            if a.cmsphp_ok:
                alert_rows.append((
                    ip_id, "cms_dir_php", 0,
                    f"{a.cmsphp_ok} of {a.cmsphp} request(s) for a PHP file "
                    f"lying directly in templates/, modules/, plugins/ or "
                    f"components/ were answered 2xx — the CMS ships nothing "
                    f"at that depth", a.examples.get("cms_dir_php", "")))
            if a.sqli_ok:
                alert_rows.append((
                    ip_id, "sqli", 1,
                    f"{a.sqli_ok} of {a.sqli} SQL injection patterns in URIs "
                    f"were answered 2xx", a.examples.get("sqli", "")))
            if a.trav_ok:
                alert_rows.append((
                    ip_id, "traversal", 1,
                    f"{a.trav_ok} of {a.trav} path traversal patterns were "
                    f"answered 2xx", a.examples.get("traversal", "")))
        conn.executemany(
            "INSERT INTO alerts (ip_id, kind, severity, detail, example) "
            "VALUES (?,?,?,?,?)", alert_rows)
        stats["alerts"] = len(alert_rows)
        stats["clients"] = len(actors)
        stats["partial"] = cancelled

        if ctx is not None:
            ctx.progress(0.92, "Building indexes…")
        conn.execute("CREATE INDEX idx_req_ip ON requests(ip, epoch)")
        conn.execute("CREATE INDEX idx_req_leaf ON requests(leaf)")
        conn.execute("CREATE INDEX idx_req_epoch ON requests(epoch)")
        conn.executemany("INSERT INTO meta VALUES (?,?)", [
            ("schema", SCHEMA_VERSION),
            ("targets", _json.dumps([str(t) for t in targets])),
            ("lines", str(stats["lines"])),
            ("clients", str(stats["clients"])),
            ("unparsed", str(stats["unparsed"])),
            ("undated", str(stats["undated"])),
            ("partial", "1" if cancelled else ""),
            # Which UTC offsets appear in these logs. Usually one, but a
            # server that ran through a DST change writes two -- an Austrian
            # log crosses +0100/+0200 twice a year -- and several servers in
            # one case can write anything. Collected once here, because the
            # alternative is a DISTINCT over every request row later.
            ("tz_offsets", _json.dumps(sorted(
                r[0] for r in conn.execute(
                    "SELECT DISTINCT tz FROM requests WHERE tz IS NOT NULL")))),
        ])
        conn.commit()
    finally:
        conn.close()

    # --- alert findings into the case DB (one truth, two views) -----------
    _write_alert_findings(case_dir, workspace)
    try:
        stats["index_size"] = log_db.stat().st_size
    except OSError:
        stats["index_size"] = 0
    return stats


def _day_iso(epoch_day):
    """Integer epoch-day (local) -> ISO date. 1970-01-01 is ordinal 719163."""
    from datetime import date
    return date.fromordinal(int(epoch_day) + 719163).isoformat()


# The alert KIND is the rule id, prefixed. It was already a stable string
# stored in the log index, so inventing a second identifier beside it would
# only create something to keep in sync.
def _busiest_window(epochs):
    """The most login POSTs that fall inside any BF_WINDOW seconds.

    Two pointers over the sorted times: for each end, advance the start past
    everything older than the window and take the largest span. O(n log n) for
    the sort and O(n) for the walk, on a list that holds login POSTs only."""
    if not epochs:
        return 0
    times = sorted(epochs)
    best = start = 0
    for end, t in enumerate(times):
        while t - times[start] >= BF_WINDOW:
            start += 1
        best = max(best, end - start + 1)
    return best


def _span_words(seconds):
    """`3 s`, `47 min`, `8 h`, `23 d` -- one unit, the biggest that fits.

    Stored English, like every other measured string this module writes."""
    seconds = int(seconds)
    if seconds < 90:
        return f"{seconds} s"
    if seconds < 5400:
        return f"{seconds // 60} min"
    if seconds < 172800:
        return f"{seconds / 3600:.0f} h"
    return f"{seconds / 86400:.0f} d"


def _login_rate(a):
    """"over 23 d (0.2/h) " -- or "" when there is no window to state.

    THE SENTENCE USED TO CARRY A COUNT AND NOTHING ELSE. On a real case
    "92 POSTs against login endpoints" and "40 POSTs against login
    endpoints" stood side by side: the first spread over twenty-three days,
    the second fired inside one second. Same word, same shape, and no way to
    tell somebody signing in from somebody guessing.

    Empty when the log carries no readable time for these requests. An
    invented rate would be worse than a missing one."""
    first, last = a.login_first, a.login_last
    if not first or not last:
        return ""
    span = int(last) - int(first)
    if span <= 0:
        # Every login POST in the same second the log can resolve. A rate
        # per hour off a zero-length window is a number about the log's
        # granularity, not about the client.
        return "within one second "
    rate = a.login_posts / (span / 3600)
    # NOT `%g` throughout: it renders a real burst as `2.03e+03/h`, and a
    # number in that shape is one a reader skips. Thousands separators above
    # a hundred, three significant digits below -- the range where the
    # fraction is the whole statement (`0.16/h` is somebody signing in).
    shown = f"{rate:,.0f}" if rate >= 100 else f"{rate:.3g}"
    return f"over {_span_words(span)} ({shown}/h) "


_ALERT_FINDING = {
    # kind -> (severity, rule text)
    "login_success": (0, "Possible successful brute-force (redirect after login flood)"),
    "upload_php": (0, "Requested PHP in upload/cache directory answered 2xx"),
    "cms_dir_php": (0, "Requested PHP directly in a CMS extension directory answered 2xx"),
    "login_flood": (1, "CMS login POST flood"),
    "sqli": (1, "SQL injection patterns in URIs answered 2xx"),
    "traversal": (1, "Path traversal patterns answered 2xx"),
    "scanner_ua": (3, "Scanner tool User-Agent"),
}


def _write_alert_findings(case_dir, workspace=None):
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
        off = ruleswitch.disabled_ids(workspace) if workspace else set()
        for kind, detail, ip in alert_rows:
            if f"logs.{kind}" in off:
                continue
            sev, rule = _ALERT_FINDING.get(kind, (2, kind))
            db.upsert_finding(conn, "logs", sev, rule, "client", ip,
                              evidence=detail, rule_id=f"logs.{kind}")
        conn.commit()
    finally:
        conn.close()


# --- querying ---------------------------------------------------------------

def open_readonly(case_dir):
    """Public name for the read-only handle. `sigmascan` needs it too, and
    reaching into another module's underscore is how a private helper turns
    into an accidental interface."""
    return _open_ro(case_dir)


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
           "lines": 0, "clients": 0, "unparsed": 0, "undated": 0,
           "size": 0}
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
        # EVERY source, skipped ones included. The fingerprint on the other
        # side of this comparison is built from the files on disk, and a file
        # the engine deliberately skipped -- an error log lying in the
        # access-log directory -- is still on disk. Leaving it out of `stored`
        # made the two sets differ permanently, so the index reported itself
        # stale forever and no rebuild could ever satisfy it.
        stored = {(r[0], r[1], r[2]) for r in conn.execute(
            "SELECT path, size, mtime FROM sources")}
    except sqlite3.Error as e:
        out["reason"] = f"index not readable: {e}"
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
        out["reason"] = t(lang, "index.stale", added=added, gone=gone)
        return out
    out["fresh"] = True
    out["reason"] = ""
    return out


# The flag conditions, usable in BOTH directions: `flag=` selects a class,
# `hide=` removes it from view. One source of truth so the two can never
# drift apart. "Conspicuous" means something happened TO THIS SYSTEM: a client
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
        # "Inconspicuous" is exactly the opposite of what produces a badge
        # in the list -- the condition mirrors actorBadges() in the
        # interface, so that "hide inconspicuous" removes precisely the rows
        # marked "inconspicuous".
        return ("NOT ((login_redirects > 0 AND login_posts >= "
                f"{BF_THRESHOLD}) OR upload_php_ok > 0 OR login_posts >= "
                f"{BF_THRESHOLD} OR scanner_uas != '[]' OR sqli_ok > 0 "
                "OR sqli_attempts > 0 OR traversal_ok > 0)", [])
    return None, []


# SQLite binds only a limited number of variables per statement (999 in
# older builds). An IN list whose length depends on the DATA rather than on a
# selection therefore runs into "too many SQL variables" sooner or later --
# never on a test case, immediately on a real one with tens of thousands of
# addresses.
_VAR_CHUNK = 500


def _alerts_by_ip(conn, ip_ids):
    """The alerts for these clients, queried in chunks.

    The normalisation sits here and not at the callers: the KIND decides the
    severity, so that an index from an earlier version does not show a
    scanner sighting in warning colours.

    `example` travels along: it is the URI THAT TRIGGERED THE ALERT, and the
    trace can mark it red with it -- otherwise one hunts for the triggering
    line among thousands by hand."""
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
    """The actor rows for EXACTLY these addresses.

    Whoever only wants to look up a few selected clients used to fetch the
    whole table and search inside it. On a real case that is tens of
    thousands of rows for a handful of hits -- and the alert query on top of
    it blew SQLite's variable limit."""
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


# Sort orders of the trace. Chronological is the default, because a trace is
# a STORY -- the other orders answer questions ("what succeeded?", "what was
# large?") one would otherwise have to search for in the sequence. A fixed
# list instead of pass-through SQL: the sort key goes into the query and must
# therefore never be determined by the client.
TRACE_SORTS = {
    "time": "r.epoch ASC, r.rowid ASC",
    "time_desc": "r.epoch DESC, r.rowid DESC",
    "status": "r.status DESC, r.epoch ASC",
    "size": "r.size DESC, r.epoch ASC",
    "uri": "uri ASC, r.epoch ASC",
}

# Status classes as a filter: "2xx" is the question "what did the server
# deliver?", "err" gathers 4xx and 5xx.
_STATUS_RANGES = {
    "2xx": (200, 299), "3xx": (300, 399), "4xx": (400, 499),
    "5xx": (500, 599), "err": (400, 599),
}


def trace(case_dir, ips, from_epoch=None, to_epoch=None, limit=5000,
          offset=0, search="", status="", method="", sort="time"):
    """Every request of these clients -- THE instant trace. Twenty clients
    cost one indexed query, not twenty log passes.

    `search` searches URI and user agent, `status` filters a status class,
    `method` the HTTP method. Filtering happens in SQL, so that the twelfth
    paging click still has the same response time as the first."""
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
        # The joins on u/a are in the COUNT query too, because `search`
        # filters on them -- otherwise it would count something other than
        # the list.
        joins = ("LEFT JOIN strings u ON u.id = r.uri "
                 "LEFT JOIN strings a ON a.id = r.agent")
        total = conn.execute(
            f"SELECT count(*) FROM requests r {joins} WHERE {clause}", params
        ).fetchone()[0]
        rows = conn.execute(
            f"""SELECT i.ip AS client, r.epoch, r.tz, r.method,
                       u.text AS uri, r.status, r.size,
                       f.text AS referrer, a.text AS agent, s.path AS source
                FROM requests r
                JOIN ips i ON i.id = r.ip
                {joins}
                LEFT JOIN strings f ON f.id = r.referrer
                LEFT JOIN sources s ON s.id = r.source
                WHERE {clause}
                ORDER BY {TRACE_SORTS.get(sort, TRACE_SORTS['time'])}
                LIMIT ? OFFSET ?""",
            params + [limit, offset]).fetchall()
        # Which methods occur at all -- the filter should only offer what
        # actually exists here.
        methods = [r[0] for r in conn.execute(
            f"SELECT DISTINCT r.method FROM requests r "
            f"WHERE r.ip IN (SELECT id FROM ips WHERE ip IN ({marks})) "
            f"ORDER BY r.method", wanted) if r[0]]
        # The source column now holds the file's PATH, because that is what
        # identifies it. What travels out is the name: the trace ends up in
        # exports, and an absolute path there would carry the analyst's own
        # directory layout into somebody else's hands.
        out = []
        for row in rows:
            item = dict(row)
            item["source"] = os.path.basename(item.get("source") or "")
            out.append(item)
        return {"total": total, "rows": out, "methods": methods}
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


# --- pattern hunt -----------------------------------------------------------
# The analyst stores URL paths they know belong to an exploit; the tool says
# WHO requested them.
#
# This runs in two stages so that it stays one query even on a ten-million-
# line log and needs no new index:
#   1. The pattern is checked against the DISTINCT URIs (table `strings`) --
#      once per unique string, not once per log line.
#   2. The requests for them are fetched by the EXISTING leaf index: every
#      URI hit yields its file name, and `requests(leaf)` is indexed. The
#      full URI then decides which row really counts.

# How many DISTINCT URIs a pattern collects at most. Whoever writes a
# pattern that hits more has no pattern but a search -- and the response says
# so (`truncated`) instead of truncating in silence.
_PATTERN_URI_CAP = 4000

# How many of those the response enumerates individually. The list serves as
# a sample ("does my pattern fit?"), the total stands next to it.
_PATTERN_URI_SHOWN = 50


def _like_from_pattern(pattern):
    """Substring, case-insensitive, `*` as a wildcard.

    Deliberately not a regex: what a pattern hits has to be explainable in a
    report. %/_ are escaped, otherwise every `_` in a path would be a silent
    wildcard."""
    esc = (str(pattern).replace("\\", "\\\\")
           .replace("%", "\\%").replace("_", "\\_"))
    return "%" + esc.replace("*", "%") + "%"


def match_pattern(case_dir, pattern, limit=200, only_ips=None):
    """Who requested URIs that this pattern matches?

    `only_ips` narrows every figure to those clients. The AND-combination in
    `match_patterns` needs it: after dropping the clients that hit only some
    of the paths, the URIs of the dropped ones must not stay in the result --
    they would show the rule matching things it did not report.

    Returns the URIs hit (so that it is visible whether the pattern reaches
    too far), per client the hit count, of those the 2xx, plus first/last
    request -- and the key figures of the search itself, so a run can be
    summarised in one sentence."""
    # THE SAME SHAPE AS A REAL RESULT. A caller cannot know in advance which
    # of the two it is holding, so a key that exists only when something was
    # found raises where it should simply answer "no".
    empty = {"pattern": pattern, "uris": [], "clients": [], "hits": 0,
             "ok_hits": 0, "clients_total": 0, "ok_clients": 0, "uri_total": 0,
             "first_epoch": None, "last_epoch": None, "tz": 0,
             "clients_truncated": False, "uris_truncated": False,
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

        # `strings` interns user agents and referrers TOO. Only the join
        # over requests.uri decides what really was a requested URI.
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

        ip_params = sorted(only_ips) if only_ips else []
        ip_filter = (f"WHERE i.ip IN ({','.join('?' * len(ip_params))})"
                     if ip_params else "")

        # THE FIGURES ARE COUNTED OVER EVERYTHING, THE LIST IS CAPPED.
        # `clients_total` used to be len() of the capped list, so a hunt that
        # found 3,000 addresses reported 200 -- and `truncated` tracked only
        # the URI cap, so nothing on screen said otherwise. For a pattern
        # matching a mass-exploitation campaign, which is what this feature is
        # for, that is the number that goes into the report.
        totals = conn.execute(
            f"""SELECT count(*) AS clients, sum(ok) AS ok_clients,
                      sum(hits) AS hits, sum(ok_hits) AS ok_hits
               FROM (SELECT count(*) AS hits,
                            sum(CASE WHEN r.status BETWEEN 200 AND 299
                                THEN 1 ELSE 0 END) AS ok_hits,
                            CASE WHEN sum(CASE WHEN r.status BETWEEN 200
                                 AND 299 THEN 1 ELSE 0 END) > 0
                                 THEN 1 ELSE 0 END AS ok
                     FROM requests r
                     JOIN want_leaf wl ON wl.id = r.leaf
                     JOIN want_uri wu ON wu.id = r.uri
                     JOIN ips i ON i.id = r.ip
                     {ip_filter}
                     GROUP BY r.ip)""", ip_params).fetchone()
        clients = [dict(r) for r in conn.execute(
            f"""SELECT i.ip AS ip, count(*) AS hits,
                      sum(CASE WHEN r.status BETWEEN 200 AND 299
                          THEN 1 ELSE 0 END) AS ok_hits,
                      min(r.epoch) AS first_epoch, max(r.epoch) AS last_epoch,
                      max(r.tz) AS tz
               FROM requests r
               JOIN want_leaf wl ON wl.id = r.leaf
               JOIN want_uri wu ON wu.id = r.uri
               JOIN ips i ON i.id = r.ip
               {ip_filter}
               GROUP BY i.ip
               ORDER BY ok_hits DESC, hits DESC LIMIT ?""",
            ip_params + [limit])]
        uris = [dict(r) for r in conn.execute(
            f"""SELECT s.text AS uri, count(*) AS hits,
                      sum(CASE WHEN r.status BETWEEN 200 AND 299
                          THEN 1 ELSE 0 END) AS ok_hits
               FROM requests r
               JOIN want_leaf wl ON wl.id = r.leaf
               JOIN want_uri wu ON wu.id = r.uri
               JOIN strings s ON s.id = r.uri
               JOIN ips i ON i.id = r.ip
               {ip_filter}
               GROUP BY s.text ORDER BY hits DESC LIMIT ?""",
            ip_params + [_PATTERN_URI_SHOWN])]
        # How many there REALLY are. The list above is capped, and "50 URLs
        # hit" is a false statement when there were 3,000 -- that number of
        # all things is supposed to reveal that the pattern reaches too
        # far.
        uri_total = conn.execute(
            f"""SELECT count(DISTINCT r.uri) FROM requests r
               JOIN want_leaf wl ON wl.id = r.leaf
               JOIN want_uri wu ON wu.id = r.uri
               JOIN ips i ON i.id = r.ip
               {ip_filter}""", ip_params).fetchone()[0]
        firsts = [c["first_epoch"] for c in clients if c["first_epoch"]]
        lasts = [c["last_epoch"] for c in clients if c["last_epoch"]]
        tzs = [c["tz"] for c in clients if c["tz"] is not None]
        return {"pattern": pattern, "uris": uris, "clients": clients,
                "hits": int(totals["hits"] or 0),
                "ok_hits": int(totals["ok_hits"] or 0),
                # The key figures of the search. `ok_clients` is the number
                # that goes into the report: not how often someone knocked,
                # but how many got through. Counted over the whole result,
                # not over the sample above it.
                "clients_total": int(totals["clients"] or 0),
                "ok_clients": int(totals["ok_clients"] or 0),
                "clients_truncated": len(clients) < int(totals["clients"] or 0),
                # The URI list has its own cap, and `truncated` is about a
                # different one entirely -- the 4000 interned strings the
                # pattern was matched against. A search over 120 distinct URIs
                # returned 50 rows next to uri_total=120 and truncated=False,
                # so the result actively claimed to be complete. uri_total
                # exists precisely so a pattern reaching too far is visible.
                "uris_truncated": len(uris) < uri_total,
                "uri_total": uri_total,
                "first_epoch": min(firsts) if firsts else None,
                "last_epoch": max(lasts) if lasts else None,
                "tz": max(tzs) if tzs else 0,
                "truncated": truncated}
    finally:
        conn.close()


def match_patterns(case_dir, patterns, mode="any", limit=200):
    """Several paths, combined OVER CLIENTS.

    A URI cannot be two paths at once, so combining them per REQUEST would
    be nonsense. Per client it is the sentence an analyst actually wants:
    "this address fetched the exploit path AND the thing it dropped" is a
    different claim from "it fetched one of them", and only the first one
    survives a defence lawyer.

      any -- a client that hit at least one of the paths (union)
      all -- only clients that hit every one of them (intersection)

    The per-path results are kept whole and merged here rather than pushed
    into one SQL statement: `all` needs to know WHICH client appeared in
    which path's result, and a single query that answers that is a query
    nobody can read six months later.
    """
    paths = [p for p in (patterns or []) if str(p).strip()]
    if not paths:
        return match_pattern(case_dir, "", limit)
    if len(paths) == 1:
        out = match_pattern(case_dir, paths[0], limit)
        out["patterns"] = paths
        out["match"] = mode
        return out

    parts = [match_pattern(case_dir, p, limit) for p in paths]
    per_path = [{c["ip"] for c in part["clients"]} for part in parts]
    if mode == "all":
        keep = set.intersection(*per_path) if per_path else set()
        # The AND-combination DROPS clients, and everything the dropped ones
        # requested has to go with them: their URIs and the URI count would
        # otherwise show the rule matching things it did not report. The
        # per-path results are recomputed against the survivors -- a second
        # pass, but only for AND patterns and only when it changes anything.
        if keep and any(keep != found for found in per_path):
            parts = [match_pattern(case_dir, p, limit, only_ips=keep)
                     for p in paths]
    else:
        keep = set.union(*per_path) if per_path else set()

    merged = {}
    for part in parts:
        for client in part["clients"]:
            if client["ip"] not in keep:
                continue
            acc = merged.setdefault(client["ip"], {
                "ip": client["ip"], "hits": 0, "ok_hits": 0,
                "first_epoch": None, "last_epoch": None, "tz": client["tz"]})
            acc["hits"] += client["hits"]
            acc["ok_hits"] += client["ok_hits"]
            for key, pick in (("first_epoch", min), ("last_epoch", max)):
                value = client[key]
                if value is None:
                    continue
                acc[key] = value if acc[key] is None else pick(acc[key], value)
    clients = sorted(merged.values(), key=lambda c: -c["hits"])

    # The URIs shown are those of the clients that survived the combination.
    # Under `all` the ones only a dropped client requested would otherwise
    # suggest the rule matched things it did not report.
    uris, seen = [], set()
    for part in parts:
        for uri in part["uris"]:
            if uri["uri"] not in seen:
                seen.add(uri["uri"])
                uris.append(uri)
    firsts = [c["first_epoch"] for c in clients if c["first_epoch"]]
    lasts = [c["last_epoch"] for c in clients if c["last_epoch"]]
    tzs = [c["tz"] for c in clients if c["tz"] is not None]
    # COUNTED ONCE, NOT ONCE PER PATH. Summing each path's URI total counts
    # every URI that matches two of them twice, and an AND-combination is
    # written precisely because its paths describe the same requests -- the
    # shipped JCE rule reported 39 distinct URIs on a real case that had 29.
    # A figure that exists to show whether a pattern reaches too far must not
    # be the one that overstates its reach.
    uri_total = _distinct_uris(case_dir, paths, {c["ip"] for c in clients})
    return {
        "pattern": (" AND " if mode == "all" else " OR ").join(paths),
        "patterns": paths, "match": mode,
        "uris": uris[:_PATTERN_URI_SHOWN], "clients": clients,
        "hits": sum(c["hits"] for c in clients),
        "ok_hits": sum(c["ok_hits"] for c in clients),
        "clients_total": len(clients),
        "ok_clients": sum(1 for c in clients if c["ok_hits"] > 0),
        "uri_total": uri_total,
        # THE SAME QUESTIONS A SINGLE-PATH RESULT ANSWERS. This branch has its
        # own return, so the caps fixed in `match_pattern` were never fixed
        # here -- and this is the branch the application actually calls for
        # every pattern with more than one path, which the bundled rule is.
        "clients_truncated": any(p.get("clients_truncated") for p in parts),
        "uris_truncated": len(uris[:_PATTERN_URI_SHOWN]) < uri_total,
        "first_epoch": min(firsts) if firsts else None,
        "last_epoch": max(lasts) if lasts else None,
        "tz": max(tzs) if tzs else 0,
        "truncated": any(p["truncated"] for p in parts),
    }


def _distinct_uris(case_dir, paths, ips):
    """How many distinct URIs these clients requested that any of the paths
    matches. One query, so a URI matching several paths counts once."""
    if not ips or not paths:
        return 0
    conn = _open_ro(case_dir)
    if conn is None:
        return 0
    try:
        ip_list = sorted(ips)
        likes = " OR ".join("s.text LIKE ? ESCAPE '\\'" for _ in paths)
        marks = ",".join("?" * len(ip_list))
        return conn.execute(
            f"""SELECT count(DISTINCT r.uri) FROM requests r
                JOIN strings s ON s.id = r.uri
                JOIN ips i ON i.id = r.ip
                WHERE i.ip IN ({marks}) AND ({likes})""",
            ip_list + [_like_from_pattern(p) for p in paths]).fetchone()[0]
    except sqlite3.Error:
        return 0
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
    """The time anchors for the case chronology -- all MEASURED, nothing
    inferred.

    For every file name: when was it first requested, when was it first
    answered with 2xx, when last. The first 2xx is the most defensible anchor
    a case has for "this file was there" -- the mtime of the copy on the
    forensic machine is not, because nobody can tell from it whether it comes
    from the original or from the copying.

    For every client: first and last request as well as the time of the URI
    that triggered its alert -- the alert table itself carries no time, but
    the request behind it does.

    The mapping name -> path happens at the caller: only the file name stands
    here, because `requests(leaf)` is the indexed access. Which of the hits
    really belong to THAT path is decided there by comparing the full URI."""
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
                # When this URI first came from this client. Without an
                # example URI the alert stays without a time -- then it is
                # absent from the chain instead of sitting at an invented
                # place.
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
    """Requests/2xx/errors/new clients per day -- the timeline curve.

    An index from an older version does not know `days.ok` yet. That must not
    blow up the dashboard: the success curve is simply missing until the
    index is rebuilt (which the evidence view points out anyway)."""
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
    """The same evaluation, but only for these clients -- the timeline one
    wants to see while tracing: when was this client active, and did the
    server answer it?

    Runs over idx_req_ip(ip, epoch), so it is an indexed query and not a pass
    through the log."""
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
        # Informational sightings are NOT alerts about this system -- a
        # scanner announcing itself says something about the internet, not
        # about this server. The Actors view has excluded them from its
        # `alerted` filter all along; counting them here gave the dashboard a
        # different number for the same question.
        marks = ",".join("?" * len(INFO_ALERT_KINDS))
        alerted = conn.execute(
            f"SELECT count(DISTINCT ip_id) FROM alerts "
            f"WHERE kind NOT IN ({marks})", INFO_ALERT_KINDS).fetchone()[0]
        try:
            offsets = sorted(set(_json.loads(meta.get("tz_offsets") or "[]")))
        except ValueError:
            offsets = []
        return {"lines": int(meta.get("lines", 0) or 0),
                "clients": int(meta.get("clients", 0) or 0),
                "unparsed": int(meta.get("unparsed", 0) or 0),
                "undated": int(meta.get("undated", 0) or 0),
                # Built from a run somebody stopped: the
                # numbers above describe part of the evidence.
                "partial": bool(meta.get("partial")),
                "alerted_clients": alerted,
                # Every UTC offset the logs carry. A case is only unambiguous
                # in log time when there is exactly one.
                "tz_offsets": offsets,
                "first_epoch": first, "last_epoch": last}
    finally:
        conn.close()
