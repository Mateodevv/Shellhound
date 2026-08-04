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
CREATE TABLE IF NOT EXISTS cms_installs (
    id INTEGER PRIMARY KEY,
    root TEXT UNIQUE NOT NULL,
    cms TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    -- Die Datei, AUS DER die Version gelesen wurde (wp-includes/version.php
    -- bzw. libraries/.../version.php). Ohne sie ist die Versionsangabe nicht
    -- nachprüfbar -- und eine Angabe, die man nicht prüfen kann, gehört in
    -- keinen Bericht.
    version_source TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS cms_items (
    id INTEGER PRIMARY KEY,
    install_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    slug TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    -- Wo die Extension LIEGT (Verzeichnis oder Einzeldatei) ...
    path TEXT NOT NULL DEFAULT '',
    -- ... und woraus die Version stammt: Manifest-XML, style.css,
    -- Plugin-Header. Leer, wenn keine Version zu finden war.
    version_source TEXT NOT NULL DEFAULT ''
);
-- KORREKTUREN DES ANALYSTEN, GETRENNT VON DER MESSUNG.
-- cms_items/cms_installs sind abgeleitet: jede Analyse löscht und schreibt
-- sie neu. Eine von Hand gesetzte Version ist das Gegenteil davon -- sie ist
-- eine Aussage des Analysten und darf durch eine Re-Analyse nicht
-- verschwinden. Deshalb steht sie in einer eigenen Tabelle und wird beim
-- Lesen über die gemessene Version gelegt; der Messwert bleibt daneben
-- sichtbar, damit die Korrektur nachvollziehbar ist.
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
    -- export = ein echter Datenbank-Export (mysqldump/phpMyAdmin).
    -- schema = eine mit einer Erweiterung AUSGELIEFERTE SQL-Datei
    --          (install/uninstall/updates). Sie enthält keine Daten und
    --          keinen Export-Kopf; als Datenbank-Evidence ist sie wertlos
    --          und verschüttet in der Ansicht den einen echten Export.
    --          Geprüft wird sie trotzdem: eine manipulierte install.sql
    --          läuft bei der nächsten Installation wieder an.
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
    -- Leer heißt NICHT "nie angemeldet", sondern "der Dump sagt es nicht":
    -- Joomla führt lastvisitDate im Schema, WordPress im Kern gar nicht.
    last_login TEXT NOT NULL DEFAULT '',
    blocked INTEGER NOT NULL DEFAULT 0,
    -- Eine offene Sitzung im Dump: das Konto war zum Zeitpunkt des Exports
    -- angemeldet.
    sessions INTEGER NOT NULL DEFAULT 0
);
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
    "cms_installs": [("version_source", "TEXT NOT NULL DEFAULT ''")],
    "cms_items": [("version_source", "TEXT NOT NULL DEFAULT ''")],
    "db_accounts": [
        ("last_login", "TEXT NOT NULL DEFAULT ''"),
        ("blocked", "INTEGER NOT NULL DEFAULT 0"),
        ("sessions", "INTEGER NOT NULL DEFAULT 0"),
    ],
    "db_dumps": [("kind", "TEXT NOT NULL DEFAULT 'export'")],
}


def _migrate(conn):
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


def connect(case_dir):
    """Open (and if needed create) the case database."""
    path = case_db_path(case_dir)
    conn = sqlite3.connect(str(path), timeout=30)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.executescript(SCHEMA)
    _migrate(conn)
    conn.row_factory = sqlite3.Row
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
                   line=None, evidence=""):
    """Insert a finding or refresh last_seen -- triage state is never reset."""
    fp = fingerprint(source, rule, artifact, line)
    ts = now()
    conn.execute(
        """INSERT INTO findings (fingerprint, source, severity, rule,
               artifact_kind, artifact, line, evidence, created, last_seen)
           VALUES (?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(fingerprint) DO UPDATE SET
               severity=excluded.severity, evidence=excluded.evidence,
               last_seen=excluded.last_seen""",
        (fp, source, int(severity), rule, artifact_kind, artifact, line,
         evidence, ts, ts))
    return fp


def add_ioc(conn, value, ioc_type, tags=(), note="", origin=""):
    """Insert an IOC or merge tags into the existing entry. Existing type and
    note win -- the analyst's correction must never be overwritten by a sync."""
    value = str(value).strip()
    if not value:
        return None
    existing = one(conn, "SELECT * FROM iocs WHERE value = ?", (value,))
    if existing is None:
        conn.execute(
            "INSERT INTO iocs (value, type, note, tags, origin, added) "
            "VALUES (?,?,?,?,?,?)",
            (value, ioc_type, note, json.dumps(sorted(set(tags))), origin, now()))
        return "inserted"
    merged = sorted(set(json.loads(existing["tags"] or "[]")) | set(tags))
    conn.execute("UPDATE iocs SET tags = ? WHERE id = ?",
                 (json.dumps(merged), existing["id"]))
    return "merged"
