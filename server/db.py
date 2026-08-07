# server/db.py
"""The case database: one SQLite file per case, the single source of truth.

Everything the five views show lives here -- findings with their triage
state, the IOC box, the CMS inventory, the database-dump results, evidence
registrations and job history. The bulk access-log index lives in a SEPARATE
file (logindex.db, see engines/logindex.py) because it is derived data that
can reach gigabytes and be rebuilt at will; case.db stays small and is the
part that must never be lost.

Connections are opened per operation in WAL mode: API threads and job worker
threads read and write concurrently without hand-rolled file locking.
"""
import json
import sqlite3
from datetime import datetime
from pathlib import Path

CASE_DB = "case.db"
LOG_DB = "logindex.db"

# How long a connection waits on a held lock before giving up. Generous,
# because an engine may well hold a write transaction for seconds -- better
# to wait than to abort the analyst's request. The tests turn the value down;
# otherwise a test that deliberately provokes a lock would stand around for
# minutes.
BUSY_TIMEOUT_MS = 30000

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY, value TEXT
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,                -- webroot | access_logs | sql_dump
    path TEXT NOT NULL,
    added TEXT NOT NULL,
    -- What the last indexing/scan of this evidence saw; '' = never scanned.
    scanned_at TEXT DEFAULT '',
    stats TEXT DEFAULT '{}',
    -- A name the ANALYST gave this piece of evidence ("Webroot Produktivsystem").
    -- Empty means the UI falls back to the folder name -- a path is an
    -- address, not a name, and a hand-over reads better with both.
    label TEXT DEFAULT '',
    -- How much evidence this is (bounded scan, see app._evidence_meta).
    files INTEGER DEFAULT 0,
    bytes INTEGER DEFAULT 0,
    meta_at TEXT DEFAULT '',
    meta_partial INTEGER DEFAULT 0,
    UNIQUE(kind, path)
);
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    evidence_id INTEGER,
    state TEXT NOT NULL DEFAULT 'queued',   -- queued|running|done|failed|cancelled
    progress REAL NOT NULL DEFAULT 0,
    message TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    created TEXT NOT NULL,
    started TEXT, finished TEXT,
    stats TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    fingerprint TEXT UNIQUE NOT NULL,  -- stable across re-scans: source|rule|artifact|line
    source TEXT NOT NULL,              -- webshell | sqldb | logs
    severity INTEGER NOT NULL,         -- 0=HIGH 1=MEDIUM 2=LOW
    rule TEXT NOT NULL,
    -- WHICH rule, as a stable id. `rule` is the text a report quotes and can
    -- be reworded; this is what the off-switch stores. Deliberately NOT part
    -- of the fingerprint: adding it there would orphan every triage decision
    -- made before the column existed.
    rule_id TEXT NOT NULL DEFAULT '',
    artifact_kind TEXT NOT NULL,       -- file | table | client | dump
    artifact TEXT NOT NULL,
    line INTEGER,
    evidence TEXT NOT NULL DEFAULT '',
    created TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    -- Triage never deletes: dismissed stays visible and filterable, with the
    -- note why. The fingerprint keeps decisions stable across re-scans.
    triage TEXT NOT NULL DEFAULT 'new',    -- new|reviewed|confirmed|dismissed
    triage_note TEXT NOT NULL DEFAULT '',
    triaged_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity, artifact);
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY,
    value TEXT UNIQUE NOT NULL,
    type TEXT NOT NULL,                -- ip|hash|url|domain|email|path|user|other
    note TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '[]',   -- JSON array (provenance/kind/observed)
    origin TEXT NOT NULL DEFAULT '',
    added TEXT NOT NULL
);
-- HOW TWO INDICATORS BELONG TOGETHER.
-- A hash and the path whose file it describes come into being in the same
-- moment from the same find -- until now only the sentence
-- "sha-256 of kb-media.php" in the origin field survived that. This is
-- prose: it reads well and cannot be evaluated. The edge here records the
-- same statement in a form the export carries out with it (STIX has
-- relationship objects for this) and the box can show on the entry.
--
-- ALL edges arise automatically on collection. There is deliberately no
-- "link these two by hand": an edge the analyst has to maintain will not be
-- maintained after the third case. And it only carries information when it
-- is SPECIFIC -- "belongs to the same case" holds for every pair in this
-- table and therefore says nothing.
CREATE TABLE IF NOT EXISTS ioc_links (
    id INTEGER PRIMARY KEY,
    src INTEGER NOT NULL,              -- iocs.id, the statement starts here
    dst INTEGER NOT NULL,              -- iocs.id
    kind TEXT NOT NULL,                -- hash-of | requested | host-in
    note TEXT NOT NULL DEFAULT '',
    added TEXT NOT NULL,
    UNIQUE(src, dst, kind)
);
CREATE INDEX IF NOT EXISTS idx_ioc_links_src ON ioc_links(src);
CREATE INDEX IF NOT EXISTS idx_ioc_links_dst ON ioc_links(dst);
CREATE TABLE IF NOT EXISTS cms_installs (
    id INTEGER PRIMARY KEY,
    root TEXT UNIQUE NOT NULL,
    cms TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    -- The file the version was READ FROM (wp-includes/version.php resp.
    -- libraries/.../version.php). Without it the version cannot be verified
    -- -- and a fact that cannot be checked belongs in no report.
    version_source TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS cms_items (
    id INTEGER PRIMARY KEY,
    install_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    slug TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    -- Where the extension SITS (directory or single file) ...
    path TEXT NOT NULL DEFAULT '',
    -- ... and where the version comes from: manifest XML, style.css,
    -- plugin header. Empty when no version could be found.
    version_source TEXT NOT NULL DEFAULT ''
);
-- CORRECTIONS BY THE ANALYST, SEPARATE FROM THE MEASUREMENT.
-- cms_items/cms_installs are derived: every analysis deletes and rewrites
-- them. A version set by hand is the opposite of that -- it is a statement
-- of the analyst and must not disappear through a re-analysis. It therefore
-- sits in its own table and is laid over the measured version on read; the
-- measured value stays visible next to it so the correction can be
-- followed.
CREATE TABLE IF NOT EXISTS cms_version_overrides (
    id INTEGER PRIMARY KEY,
    scope TEXT NOT NULL,               -- install | item
    key TEXT NOT NULL,                 -- install: root; item: root|type|slug
    version TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    set_at TEXT NOT NULL,
    UNIQUE(scope, key)
);
CREATE TABLE IF NOT EXISTS db_dumps (
    id INTEGER PRIMARY KEY,
    path TEXT UNIQUE NOT NULL,
    meta TEXT NOT NULL DEFAULT '{}',   -- header: tool/server/database/created
    statements INTEGER NOT NULL DEFAULT 0,
    size INTEGER NOT NULL DEFAULT 0,
    cms TEXT NOT NULL DEFAULT '',
    -- export = a real database export (mysqldump/phpMyAdmin).
    -- schema = a SQL file SHIPPED with an extension
    --          (install/uninstall/updates). It contains no data and no
    --          export header; as database evidence it is worthless and in
    --          the view it buries the one real export. It is scanned all
    --          the same: a manipulated install.sql runs again on the next
    --          installation.
    kind TEXT NOT NULL DEFAULT 'export'
);
CREATE TABLE IF NOT EXISTS db_tables (
    id INTEGER PRIMARY KEY,
    dump_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    columns INTEGER NOT NULL DEFAULT 0,
    rows INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    col_list TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS db_accounts (
    id INTEGER PRIMARY KEY,
    dump_id INTEGER NOT NULL,
    cms TEXT NOT NULL DEFAULT '',
    tbl TEXT NOT NULL DEFAULT '',
    user_id TEXT NOT NULL DEFAULT '',
    login TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    registered TEXT NOT NULL DEFAULT '',
    hash_type TEXT NOT NULL DEFAULT '',
    admin INTEGER NOT NULL DEFAULT 0,
    -- Empty does NOT mean "never signed in" but "the dump does not say":
    -- Joomla carries lastvisitDate in its schema, WordPress core not at
    -- all.
    last_login TEXT NOT NULL DEFAULT '',
    blocked INTEGER NOT NULL DEFAULT 0,
    -- An open session in the dump: the account was signed in at the time
    -- of the export.
    sessions INTEGER NOT NULL DEFAULT 0
);
-- What was searched for in THIS case. The patterns themselves live in the
-- workspace (server/patterns.py) and hold across cases; here stands the
-- record: which pattern ran when, and what it found. A run WITHOUT hits is
-- the more valuable row -- "we checked for this, there was nothing" is
-- written down nowhere else, because findings only record finds.
CREATE TABLE IF NOT EXISTS hunt_runs (
    id INTEGER PRIMARY KEY,
    pattern TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    ran_at TEXT NOT NULL,
    hits INTEGER NOT NULL DEFAULT 0,
    ok_hits INTEGER NOT NULL DEFAULT 0,
    clients INTEGER NOT NULL DEFAULT 0,
    -- The key figures of the run, so the record states what was found
    -- without a second run. ok_clients is the number that counts: how many
    -- addresses got through, not how often someone knocked.
    ok_clients INTEGER NOT NULL DEFAULT 0,
    uris INTEGER NOT NULL DEFAULT 0,
    first_epoch INTEGER,
    last_epoch INTEGER,
    tz INTEGER NOT NULL DEFAULT 0,
    UNIQUE(pattern)
);
-- WHAT A THIRD PARTY SAYS -- kept apart from what the case measured.
-- A reputation score is somebody else's conclusion about somebody else's
-- data. It never becomes a finding, never moves a severity and never
-- decides a triage; it sits beside the indicator as a foreign opinion, with
-- the time it was fetched, because a verdict from six weeks ago is a
-- different statement from one fetched this morning.
CREATE TABLE IF NOT EXISTS enrichment (
    id INTEGER PRIMARY KEY,
    service TEXT NOT NULL,             -- virustotal | abuseipdb
    value TEXT NOT NULL,               -- the ONE thing that was sent
    kind TEXT NOT NULL DEFAULT '',     -- hash | ip
    fetched TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}',
    UNIQUE(service, value)
);
-- The result of the last webroot comparison (engines/webrootdiff.py).
-- A derivation from two trees, not a history: every run replaces the
-- previous one. Paths relative to the respective root, with /.
CREATE TABLE IF NOT EXISTS webroot_diff (
    id INTEGER PRIMARY KEY,
    webroot_id INTEGER NOT NULL,       -- evidence.id of the webroot
    reference_id INTEGER NOT NULL,     -- evidence.id of the reference copy
    status TEXT NOT NULL,              -- extra | missing | modified | too_big
    path TEXT NOT NULL,
    size INTEGER NOT NULL DEFAULT 0,
    ref_size INTEGER NOT NULL DEFAULT 0,
    ran_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webroot_diff_status ON webroot_diff(status);
CREATE TABLE IF NOT EXISTS inert_php (
    id INTEGER PRIMARY KEY, path TEXT NOT NULL, reason TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS skipped (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL, path TEXT NOT NULL, reason TEXT NOT NULL DEFAULT ''
);
"""

TRIAGE_STATES = ("new", "reviewed", "confirmed", "dismissed")

# Severity levels. INFO is not a weaker finding -- it is CONTEXT: something
# the case should record but that says nothing about this system being
# compromised. A scanner announcing itself in a User-Agent is the example:
# it happens to every host on the internet, all day. Keeping it at LOW meant
# real work drowned in it.
SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO = 0, 1, 2, 3


def now():
    return datetime.now().isoformat(timespec="seconds")


def case_db_path(case_dir):
    return Path(case_dir) / CASE_DB


def log_db_path(case_dir):
    return Path(case_dir) / LOG_DB


# Columns added after the first release. CREATE TABLE IF NOT EXISTS does not
# touch a table that already exists, so a case opened from an older version
# (or restored from an archive) needs them added explicitly -- otherwise the
# first query against a new column would fail on a real analyst's case.
_ADDED_COLUMNS = {
    "evidence": [
        ("label", "TEXT DEFAULT ''"),
        ("files", "INTEGER DEFAULT 0"),
        ("bytes", "INTEGER DEFAULT 0"),
        ("meta_at", "TEXT DEFAULT ''"),
        ("meta_partial", "INTEGER DEFAULT 0"),
    ],
    "findings": [("rule_id", "TEXT NOT NULL DEFAULT ''")],
    "cms_installs": [("version_source", "TEXT NOT NULL DEFAULT ''")],
    "cms_items": [("version_source", "TEXT NOT NULL DEFAULT ''")],
    "db_accounts": [
        ("last_login", "TEXT NOT NULL DEFAULT ''"),
        ("blocked", "INTEGER NOT NULL DEFAULT 0"),
        ("sessions", "INTEGER NOT NULL DEFAULT 0"),
    ],
    "db_dumps": [("kind", "TEXT NOT NULL DEFAULT 'export'")],
    "hunt_runs": [
        ("ok_clients", "INTEGER NOT NULL DEFAULT 0"),
        ("uris", "INTEGER NOT NULL DEFAULT 0"),
        ("first_epoch", "INTEGER"),
        ("last_epoch", "INTEGER"),
        ("tz", "INTEGER NOT NULL DEFAULT 0"),
    ],
}


# The version of the case schema. BUMP IT when SCHEMA, _ADDED_COLUMNS or one
# of the data corrections in _upgrade() changes -- that is how an existing
# case database recognises that it has to be touched once.
# 4: path indicators lose the evidence root's own folder name, so a
#    collected `webroot/images/x.php` becomes `images/x.php`.
CASE_SCHEMA_VERSION = 4


def _stored_version(conn):
    """The version this file stands at. 0 = new, or from before versioning.
    Read-only -- it must never block."""
    try:
        row = conn.execute(
            "SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        return int(row[0]) if row and str(row[0]).isdigit() else 0
    except sqlite3.Error:
        # `meta` does not exist yet: a fresh file.
        return 0


def _is_fresh(conn):
    """Does this file have any tables at all yet? Read-only."""
    row = conn.execute(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' "
        "AND name = 'findings'").fetchone()
    return not (row and row[0])


def _upgrade(conn):
    """Create the schema and bring data corrections along -- the ONLY path on
    which a connection writes before the caller wants anything."""
    conn.executescript(SCHEMA)
    for table, columns in _ADDED_COLUMNS.items():
        have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        for name, decl in columns:
            if name not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
    # Scanner sightings were filed as LOW before INFO existed. Re-grading them
    # here (rather than only on the next re-index) means a case that is
    # already open stops drowning in them without having to be re-analysed.
    # Idempotent, and it touches nothing the analyst decided: the triage
    # state, the note and the finding's identity are untouched.
    conn.execute(
        "UPDATE findings SET severity = ? "
        "WHERE source = 'logs' AND rule LIKE 'Scanner tool User-Agent%' "
        "AND severity != ?", (SEV_INFO, SEV_INFO))
    _relativize_ioc_paths(conn)
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(CASE_SCHEMA_VERSION),))
    conn.commit()


def _relativize_ioc_paths(conn):
    """Bring path IOCs from earlier runs into the case-relative form.

    A case should not carry half absolute, half relative paths. Runs
    idempotently (an already relative path no longer matches any root) and
    steps around every conflict: if the target value already exists, the old
    entry stays as it is -- losing data would be worse than two spellings.

    TWO SPELLINGS TO UNDO, not one. Until the evidence root's own folder name
    was dropped from the relative form, a case collected
    `joomla-webshells/images/x.phtml` -- no longer absolute, so the loop
    below walks straight past it. Those get the second pass."""
    try:
        rows = conn.execute(
            "SELECT id, value FROM iocs WHERE type = 'path'").fetchall()
    except Exception:
        return
    stale = tuple(root.rsplit("/", 1)[-1].lower() + "/"
                  for root in evidence_roots(conn) if "/" in root)
    for ioc_id, value in rows:
        relative = case_relative_path(conn, value)
        if relative == value:
            low = str(value).replace("\\", "/").lstrip("/").lower()
            for prefix in stale:
                if low.startswith(prefix):
                    relative = str(value).replace("\\", "/")[len(prefix):]
                    break
        if relative == value:
            continue
        exists = conn.execute("SELECT 1 FROM iocs WHERE value = ?",
                              (relative,)).fetchone()
        if exists:
            continue
        conn.execute("UPDATE iocs SET value = ? WHERE id = ?", (relative, ioc_id))


def connect(case_dir):
    """Open (and if needed create) the case database.

    OPENING MUST NOT WRITE. This function runs on EVERY request -- including
    purely reading ones such as the job list the interface polls once per
    second while an analysis runs. As long as it wrote schema and data
    corrections unconditionally, every one of those read requests met the
    write lock of the running engine and died with "database is locked" --
    in the middle of the work, visible as a crash in the server window.

    A write therefore only happens when the stored version differs from
    CASE_SCHEMA_VERSION: once per case instead of once per request. The
    normal path is thereby read-only and collides with nothing."""
    path = case_db_path(case_dir)
    conn = sqlite3.connect(str(path), timeout=BUSY_TIMEOUT_MS / 1000)
    # Explicitly, not only via `timeout`: this makes SQLite wait on a held
    # lock instead of giving up immediately.
    conn.execute(f"PRAGMA busy_timeout = {int(BUSY_TIMEOUT_MS)}")
    # Set WAL only when needed -- switching the journal mode briefly requires
    # exclusive access, reading it does not.
    if (conn.execute("PRAGMA journal_mode").fetchone() or [""])[0] != "wal":
        conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.row_factory = sqlite3.Row

    if _stored_version(conn) != CASE_SCHEMA_VERSION:
        if _is_fresh(conn):
            # Without tables the caller can do nothing -- here a write MUST
            # happen, and an error belongs upstairs.
            _upgrade(conn)
        else:
            try:
                _upgrade(conn)
            except sqlite3.OperationalError:
                # The upgrade is MAINTENANCE, not an answer to the caller's
                # question. If an engine currently holds the write lock, the
                # upgrade gets the next attempt -- the running read request
                # does not fail because of it. The tables are already there.
                conn.rollback()
    return conn


def rows(conn, sql, params=()):
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def one(conn, sql, params=()):
    r = conn.execute(sql, params).fetchone()
    return dict(r) if r is not None else None


def fingerprint(source, rule, artifact, line):
    """Stable finding identity across re-scans (same rule, same location =
    same finding; the analyst's decision must carry over)."""
    import hashlib
    parts = "\x1f".join((str(source), str(rule), str(artifact), str(line or "")))
    return hashlib.sha1(parts.encode("utf-8", "replace")).hexdigest()[:16]


def upsert_finding(conn, source, severity, rule, artifact_kind, artifact,
                   line=None, evidence="", rule_id=""):
    """Insert a finding or refresh last_seen -- triage state is never reset.

    `rule_id` is stored but NOT fingerprinted. The fingerprint is what keeps
    a decision attached to a finding across re-scans, so a new field in it
    would silently orphan every decision an analyst has already made."""
    fp = fingerprint(source, rule, artifact, line)
    ts = now()
    conn.execute(
        """INSERT INTO findings (fingerprint, source, severity, rule, rule_id,
               artifact_kind, artifact, line, evidence, created, last_seen)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(fingerprint) DO UPDATE SET
               severity=excluded.severity, evidence=excluded.evidence,
               rule_id=excluded.rule_id, last_seen=excluded.last_seen""",
        (fp, source, int(severity), rule, str(rule_id or ""), artifact_kind,
         artifact, line, evidence, ts, ts))
    return fp


def _norm(path):
    return str(path).replace("\\", "/").rstrip("/")


def evidence_roots(conn):
    """Every registered evidence root, longest first.

    Longest first because a webroot may lie INSIDE another registered path,
    and then the more specific one is the one that answers."""
    roots = [_norm(row[0]) for row in conn.execute("SELECT path FROM evidence")]
    return sorted((r for r in roots if r), key=len, reverse=True)


def relative_to_evidence(roots, path):
    """`images/shell.php` -- the path BELOW the evidence root, nothing above.

    THE ROOT'S OWN FOLDER NAME GOES TOO. It used to stay in ("the folder name
    says which evidence this is about, and with two webroots in the same case
    it is the difference"), and on a real case that produced the indicator
    `joomla-webshells/images/dlbjbz.phtml` -- where `joomla-webshells` is
    what the ANALYST called a directory on their own machine. Handed to
    anyone else that path matches nothing: the web server calls the file
    `/images/dlbjbz.phtml`, and so does every other view in this tool. Two
    answers to one question, and the one that leaves the machine was the
    wrong one.

    Telling two webroots apart is a real need and this was the wrong place
    for it: an indicator has to be what the other side can look for. The
    distinction survives in the SHA-256 beside it and in the edge between
    them, which is where a difference between two files belongs.

    Pure string work so the file browser can call it per entry without a
    database. If no root matches, the value is handed back UNCHANGED -- an
    absolute path is better than an invented relative one."""
    norm = _norm(path)
    low = norm.lower()
    for root in roots:
        if low == root.lower():
            return norm.rsplit("/", 1)[-1]
        if low.startswith(root.lower() + "/"):
            return norm[len(root) + 1:]
    return str(path)


def case_relative_path(conn, path):
    """`relative_to_evidence` for a single path, roots read from the case."""
    return relative_to_evidence(evidence_roots(conn), path)


def add_ioc(conn, value, ioc_type, tags=(), note="", origin=""):
    """Insert an IOC or merge tags into the existing entry. Existing type and
    note win -- the analyst's correction must never be overwritten by a sync.

    Returns the id (on a merge as well) so the caller can draw the edge to
    the neighbouring indicator: path and hash come into being in the same
    loop, and only there is it still known that they belong together."""
    value = str(value).strip()
    if not value:
        return None
    existing = one(conn, "SELECT * FROM iocs WHERE value = ?", (value,))
    if existing is None:
        cur = conn.execute(
            "INSERT INTO iocs (value, type, note, tags, origin, added) "
            "VALUES (?,?,?,?,?,?)",
            (value, ioc_type, note, json.dumps(sorted(set(tags))), origin, now()))
        return cur.lastrowid
    merged = sorted(set(json.loads(existing["tags"] or "[]")) | set(tags))
    conn.execute("UPDATE iocs SET tags = ? WHERE id = ?",
                 (json.dumps(merged), existing["id"]))
    return existing["id"]


def link_iocs(conn, src_id, dst_id, kind, note=""):
    """Draw an edge between two indicators.

    Tolerates None on both sides: the caller holds add_ioc results, and an
    empty value yields None there. An edge onto itself would be a statement
    without content and is dropped as well."""
    if not src_id or not dst_id or src_id == dst_id:
        return
    conn.execute(
        "INSERT OR IGNORE INTO ioc_links (src, dst, kind, note, added) "
        "VALUES (?,?,?,?,?)", (src_id, dst_id, kind, note[:200], now()))


def ioc_links(conn):
    """All edges with the values of both ends.

    The INNER JOIN doubles as the cleanup: an edge whose indicator was
    deleted disappears from every view without any delete path having had to
    think of it."""
    return rows(conn, """
        SELECT l.id, l.kind, l.note, l.added,
               l.src AS src_id, s.value AS src_value, s.type AS src_type,
               l.dst AS dst_id, d.value AS dst_value, d.type AS dst_type
          FROM ioc_links l
          JOIN iocs s ON s.id = l.src
          JOIN iocs d ON d.id = l.dst
         ORDER BY l.id""")
