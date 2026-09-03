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
import hashlib
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
    stats TEXT NOT NULL DEFAULT '{}',
    run_id TEXT NOT NULL DEFAULT ''        -- one click starts one analysis run
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
    triaged_at TEXT,
    -- WHICH ENGINE produced this row, and in WHICH run it was last seen.
    -- Together they answer the question the fingerprint cannot: is this
    -- observation still current? A row whose seen_run is older than its
    -- engine's last COMPLETED run was not reproduced by a scan that saw
    -- everything -- the payload moved, the file is gone, or the rule was
    -- switched off. Such a row is RETIRED: it keeps its triage and its
    -- note, stays in the table and stays fetchable, but no longer counts
    -- as a statement about the case. Neither column is in the fingerprint;
    -- widening that would orphan every decision already made.
    engine TEXT NOT NULL DEFAULT '',       -- '' = unmanaged (hunts, legacy)
    seen_run INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity, artifact);
CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(source, artifact);
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
-- Structured provenance for indicators generated by a triage decision.
-- `origin` on iocs is readable prose; this table is the reversible fact:
-- which artifact caused which indicator to enter the box, and whether that
-- confirmation still stands.
CREATE TABLE IF NOT EXISTS ioc_sources (
    id INTEGER PRIMARY KEY,
    ioc_id INTEGER NOT NULL,
    artifact TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'direct',
    active INTEGER NOT NULL DEFAULT 1,
    added TEXT NOT NULL,
    UNIQUE(ioc_id, artifact, role)
);
CREATE INDEX IF NOT EXISTS idx_ioc_sources_artifact ON ioc_sources(artifact);
CREATE INDEX IF NOT EXISTS idx_ioc_sources_ioc ON ioc_sources(ioc_id);
CREATE TABLE IF NOT EXISTS triage_events (
    id INTEGER PRIMARY KEY,
    artifact TEXT NOT NULL,
    artifact_kind TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    propagated INTEGER NOT NULL DEFAULT 0,
    at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_triage_events_at ON triage_events(at);
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
    -- Bounded, derived CMS semantics from this snapshot: extension state,
    -- access metadata, persistence and content observations.  It contains
    -- no password hash, session verifier or complete content value.
    intelligence TEXT NOT NULL DEFAULT '{}',
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
-- Append-only Pattern-Hunt audit.  Unlike hunt_runs this keeps every test,
-- including an unsaved draft and a test without hits.  It stores the
-- question and measured summary, never the bulk access-log rows.
CREATE TABLE IF NOT EXISTS hunt_tests (
    id INTEGER PRIMARY KEY,
    pattern_id TEXT NOT NULL DEFAULT '',
    pattern_version INTEGER NOT NULL DEFAULT 0,
    rule_hash TEXT NOT NULL,
    rule_json TEXT NOT NULL,
    dsl TEXT NOT NULL DEFAULT '',
    tested_at TEXT NOT NULL,
    index_fingerprint TEXT NOT NULL DEFAULT '',
    hits INTEGER NOT NULL DEFAULT 0,
    ok_hits INTEGER NOT NULL DEFAULT 0,
    clients INTEGER NOT NULL DEFAULT 0,
    ok_clients INTEGER NOT NULL DEFAULT 0,
    uris INTEGER NOT NULL DEFAULT 0,
    first_epoch INTEGER,
    last_epoch INTEGER,
    tz INTEGER NOT NULL DEFAULT 0,
    truncated INTEGER NOT NULL DEFAULT 0,
    coverage_json TEXT NOT NULL DEFAULT '{}',
    batch_id TEXT NOT NULL DEFAULT '',
    legacy INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_hunt_tests_pattern
    ON hunt_tests(pattern_id, tested_at DESC, id DESC);
CREATE TABLE IF NOT EXISTS hunt_applications (
    id INTEGER PRIMARY KEY,
    test_id INTEGER NOT NULL,
    pattern_id TEXT NOT NULL,
    pattern_version INTEGER NOT NULL,
    rule_hash TEXT NOT NULL,
    applied_at TEXT NOT NULL,
    idempotency_key TEXT UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS hunt_application_clusters (
    id INTEGER PRIMARY KEY,
    application_id INTEGER NOT NULL,
    cluster_key TEXT NOT NULL,
    client TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT '',
    uri_pattern TEXT NOT NULL DEFAULT '',
    status_class TEXT NOT NULL DEFAULT '',
    requests INTEGER NOT NULL DEFAULT 0,
    ok_hits INTEGER NOT NULL DEFAULT 0,
    first_epoch INTEGER,
    last_epoch INTEGER,
    evidence_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE(application_id, cluster_key)
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
-- Analyst-owned access-log work survives rebuilding the derived log index.
-- A saved query is the reproducible question; a clip is a snapshot of the
-- exact request the analyst chose, including its source-line reference.
CREATE TABLE IF NOT EXISTS access_saved_queries (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    query TEXT NOT NULL DEFAULT '{}',
    created TEXT NOT NULL,
    updated TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS access_clips (
    id INTEGER PRIMARY KEY,
    request_key TEXT UNIQUE NOT NULL,
    snapshot TEXT NOT NULL DEFAULT '{}',
    note TEXT NOT NULL DEFAULT '',
    added TEXT NOT NULL
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
    "findings": [
        ("rule_id", "TEXT NOT NULL DEFAULT ''"),
        ("engine", "TEXT NOT NULL DEFAULT ''"),
        ("seen_run", "INTEGER NOT NULL DEFAULT 0"),
    ],
    "jobs": [("run_id", "TEXT NOT NULL DEFAULT ''")],
    "cms_installs": [("version_source", "TEXT NOT NULL DEFAULT ''")],
    "cms_items": [("version_source", "TEXT NOT NULL DEFAULT ''")],
    "db_accounts": [
        ("last_login", "TEXT NOT NULL DEFAULT ''"),
        ("blocked", "INTEGER NOT NULL DEFAULT 0"),
        ("sessions", "INTEGER NOT NULL DEFAULT 0"),
    ],
    "db_dumps": [
        ("kind", "TEXT NOT NULL DEFAULT 'export'"),
        ("intelligence", "TEXT NOT NULL DEFAULT '{}'"),
    ],
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
# 5: findings learn engine + seen_run so a completed re-scan can RETIRE the
#    rows it did not reproduce (a payload that moved, a file that is gone)
#    instead of leaving them standing as current facts beside their
#    replacements. Existing rows get their engine mapped from source (and
#    rule_id where source alone is ambiguous) so they become retirable;
#    rows nothing can claim stay engine='' and are never retired.
# 6: jobs started by one analysis request share run_id, so the interface and
#    exports can describe runs rather than a flat row-id stream.
# 7: structured IOC provenance makes generated indicators reversible, and
#    triage_events records the analyst's decision history.
# 8: saved access-log searches and clipped requests are analyst-owned case
#    records, separate from the rebuildable bulk index.
# 9: SQL dumps gain a bounded CMS-intelligence snapshot for WordPress and
#     Joomla.  Sensitive raw credentials and full content stay in evidence.
# 10: Pattern Hunt keeps immutable draft-test audits and the analyst's
#     selected cluster applications separately from generated findings.
CASE_SCHEMA_VERSION = 10

# A version marker is the fast path, not proof by itself. A process can be
# interrupted between stamping a development/pre-release schema and adding a
# later table, and a copied database can carry the marker without the complete
# structure. These are the current sentinels whose absence is safe to repair
# with the idempotent upgrade.
_CURRENT_SCHEMA_TABLES = {
    "ioc_sources", "triage_events", "access_saved_queries", "access_clips",
    "hunt_tests", "hunt_applications", "hunt_application_clusters",
}


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


def _has_current_schema(conn):
    """Read-only proof that the version marker and its sentinel tables agree."""
    if _stored_version(conn) != CASE_SCHEMA_VERSION:
        return False
    placeholders = ",".join("?" for _ in _CURRENT_SCHEMA_TABLES)
    rows = conn.execute(
        f"SELECT name FROM sqlite_master WHERE type = 'table' "
        f"AND name IN ({placeholders})", tuple(_CURRENT_SCHEMA_TABLES))
    return {row[0] for row in rows} == _CURRENT_SCHEMA_TABLES


def _upgrade(conn):
    """Create the schema and bring data corrections along -- the ONLY path on
    which a connection writes before the caller wants anything."""
    previous_version = _stored_version(conn)
    conn.executescript(SCHEMA)
    for table, columns in _ADDED_COLUMNS.items():
        have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        for name, decl in columns:
            if name not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
    # This index names a column added in schema 6. Creating it inside SCHEMA
    # would run before ALTER TABLE on a schema-5 case and abort the whole
    # upgrade with "no such column: run_id".
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_run ON jobs(run_id, id)")
    # Scanner sightings were filed as LOW before INFO existed. Re-grading them
    # here (rather than only on the next re-index) means a case that is
    # already open stops drowning in them without having to be re-analysed.
    # Idempotent, and it touches nothing the analyst decided: the triage
    # state, the note and the finding's identity are untouched.
    conn.execute(
        "UPDATE findings SET severity = ? "
        "WHERE source = 'logs' AND rule LIKE 'Scanner tool User-Agent%' "
        "AND severity != ?", (SEV_INFO, SEV_INFO))
    # Rows from before the engine column get their owner mapped from what is
    # already on them, so the FIRST completed re-scan after the upgrade can
    # retire the ones it does not reproduce. Idempotent (only empty engines
    # are touched), and deliberately incomplete: `logs` with an empty rule_id
    # is either a hunt finding or older than the rule_id column, and a row
    # nothing can claim must stay unmanaged rather than be retired by the
    # wrong engine's run. Nothing is retired BY this upgrade itself: no
    # `engine_done:` marks exist yet, so every row stays live until an
    # engine completes a run.
    conn.execute("UPDATE findings SET engine = 'webshell' "
                 "WHERE engine = '' AND source = 'webshell'")
    conn.execute("UPDATE findings SET engine = 'yarascan' "
                 "WHERE engine = '' AND source = 'yara'")
    conn.execute("UPDATE findings SET engine = 'sqldump' "
                 "WHERE engine = '' AND source = 'sqldb'")
    conn.execute("UPDATE findings SET engine = 'errorlog' "
                 "WHERE engine = '' AND source = 'errorlog'")
    conn.execute("UPDATE findings SET engine = 'logindex' "
                 "WHERE engine = '' AND source = 'logs' "
                 "AND rule_id LIKE 'logs.%'")
    conn.execute("UPDATE findings SET engine = 'sigmascan' "
                 "WHERE engine = '' AND source = 'logs' "
                 "AND rule_id != '' AND rule_id NOT LIKE 'logs.%'")
    if previous_version < 10:
        # hunt_runs retained only the latest summary per textual pattern.
        # Preserve those rows as explicitly legacy audits rather than making
        # a schema upgrade look as though the analyst never ran them.
        for row in conn.execute(
                "SELECT id, pattern, label, ran_at, hits, ok_hits, clients, "
                "ok_clients, uris, first_epoch, last_epoch, tz FROM hunt_runs"):
            rule = {"client_match": "any", "requests": [{"clauses": [{
                "field": "uri", "operator": "wildcard",
                "values": [row[1]],
            }]}]}
            encoded = json.dumps(rule, ensure_ascii=False, sort_keys=True,
                                 separators=(",", ":"))
            digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            conn.execute(
                "INSERT INTO hunt_tests(pattern_id, pattern_version, rule_hash,"
                " rule_json, dsl, tested_at, hits, ok_hits, clients, ok_clients,"
                " uris, first_epoch, last_epoch, tz, coverage_json, legacy) "
                "SELECT '',0,?,?,?,?,?,?,?,?,?,?,?,?,?,1 "
                "WHERE NOT EXISTS (SELECT 1 FROM hunt_tests "
                "WHERE legacy=1 AND tested_at=? AND rule_hash=?)",
                (digest, encoded, row[1], row[3], row[4], row[5], row[6],
                 row[7], row[8], row[9], row[10], row[11], row[12], "{}",
                 row[3], digest))
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
    `webroot-copy/images/x.phtml` -- no longer absolute, so the loop
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

    if not _has_current_schema(conn):
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


# A findings row is LIVE while its engine's last COMPLETED run reproduced it
# (or while no run of its engine has completed at all -- an engine that has
# not looked cannot retire anything). The predicate binds to the alias `f`
# and needs RETIRE_JOIN beside it; both live here so every reader of the
# findings table applies the same definition of "current", or the dashboard
# and the work list quietly count different things.
RETIRE_JOIN = ("LEFT JOIN meta done ON done.key = 'engine_done:' || f.engine")
LIVE_PREDICATE = ("(done.value IS NULL "
                  "OR f.seen_run >= CAST(done.value AS INTEGER))")


def begin_run(conn, engine):
    """Hand out this scan's run number -- one global monotonic counter.

    A COUNTER, NOT THE CLOCK. now() is second-resolution and a small re-scan
    finishes inside one second, so a timestamp comparison marks nothing and
    a test against the broken behaviour could not fail. The counter is
    global across engines, which makes every run number unique to the one
    engine that drew it; committed immediately so a later rollback in the
    engine cannot hand the same number out twice."""
    row = conn.execute(
        "INSERT INTO meta (key, value) VALUES ('scan_seq', '1') "
        "ON CONFLICT(key) DO UPDATE SET "
        "value = CAST(value AS INTEGER) + 1 "
        "RETURNING CAST(value AS INTEGER)").fetchone()
    conn.commit()
    return int(row[0])


def complete_run(conn, engine, run):
    """Record that this engine's run saw everything it was going to see.

    Retirement is nothing but this mark: rows of the engine whose seen_run
    is older stop counting as current. A CANCELLED run must never call this
    -- half a webroot's real findings would grey out. The engines therefore
    call it only on the path where their loop ran to the end."""
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (f"engine_done:{engine}", str(int(run))))
    conn.commit()


def upsert_finding(conn, source, severity, rule, artifact_kind, artifact,
                   line=None, evidence="", rule_id="", engine="", run=0):
    """Insert a finding or refresh last_seen -- triage state is never reset.

    `rule_id`, `engine` and `seen_run` are stored but NOT fingerprinted. The
    fingerprint is what keeps a decision attached to a finding across
    re-scans, so a new field in it would silently orphan every decision an
    analyst has already made. `engine`/`run` tie the row to the scan that
    saw it (see begin_run); callers without a managed run -- hunts -- leave
    them at their defaults and their rows are never retired."""
    fp = fingerprint(source, rule, artifact, line)
    ts = now()
    conn.execute(
        """INSERT INTO findings (fingerprint, source, severity, rule, rule_id,
               artifact_kind, artifact, line, evidence, created, last_seen,
               engine, seen_run)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(fingerprint) DO UPDATE SET
               severity=excluded.severity, evidence=excluded.evidence,
               rule_id=excluded.rule_id, last_seen=excluded.last_seen,
               engine=excluded.engine, seen_run=excluded.seen_run""",
        (fp, source, int(severity), rule, str(rule_id or ""), artifact_kind,
         artifact, line, evidence, ts, ts, str(engine or ""), int(run or 0)))
    return fp


def _norm(path):
    return str(path).replace("\\", "/").rstrip("/")


def _resolved_norm(path):
    """Canonical spelling of an existing local path, including NTFS aliases."""
    try:
        candidate = Path(path)
        return _norm(candidate.resolve(strict=True)) if candidate.is_absolute() else None
    except (OSError, ValueError, RuntimeError):
        return None


def _relative_spelling(roots, norm):
    low = norm.lower()
    for root in roots:
        if low == root.lower():
            return norm.rsplit("/", 1)[-1]
        if low.startswith(root.lower() + "/"):
            return norm[len(root) + 1:]
    return None


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
    `webroot-copy/images/shell.phtml` -- where `webroot-copy` is
    what the ANALYST called a directory on their own machine. Handed to
    anyone else that path matches nothing: the web server calls the file
    `/images/shell.phtml`, and so does every other view in this tool. Two
    answers to one question, and the one that leaves the machine was the
    wrong one.

    Telling two webroots apart is a real need and this was the wrong place
    for it: an indicator has to be what the other side can look for. The
    distinction survives in the SHA-256 beside it and in the edge between
    them, which is where a difference between two files belongs.

    The common case is pure string work. On a mismatch, resolve existing
    local paths as well: Windows may register a short 8.3 root but return a
    long path from the file browser. Offline/unavailable evidence keeps its
    original spelling. If no root matches, the value is handed back UNCHANGED
    -- an absolute path is better than an invented relative one."""
    norm = _norm(path)
    relative = _relative_spelling(roots, norm)
    if relative is not None:
        return relative
    resolved = _resolved_norm(path)
    if resolved is not None:
        canonical_roots = sorted(filter(None, (_resolved_norm(root) for root in roots)),
                                 key=len, reverse=True)
        relative = _relative_spelling(canonical_roots, resolved)
        if relative is not None:
            return relative
    return str(path)


def case_relative_path(conn, path):
    """`relative_to_evidence` for a single path, roots read from the case."""
    return relative_to_evidence(evidence_roots(conn), path)


def absolute_from_evidence(roots, value):
    """The inverse of `relative_to_evidence`: where does `images/shell.php`
    actually lie? Tries every root, longest first -- the same precedence the
    forward direction uses -- and answers only with a file that EXISTS,
    because the caller wants to open it, not to guess.

    Returns None when no root holds the file. That is a real answer: an
    indicator names what stood on the compromised server, and the copy in
    the evidence may be partial."""
    rel = _norm(value).lstrip("/")
    if not rel:
        return None
    for root in roots:
        candidate = Path(root) / rel
        if candidate.is_file():
            return str(candidate)
    # A value no root ever matched went into the box as the absolute path
    # it was (see relative_to_evidence's last line) -- honour that reading
    # too before giving up. ONLY the absolute reading: a relative value
    # resolved against the server's working directory would answer with a
    # file that has nothing to do with the case.
    as_is = Path(str(value))
    if as_is.is_absolute() and as_is.is_file():
        return str(as_is)
    return None


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
