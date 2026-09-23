"""Durable backup manifests and content-decision provenance, archived with the case."""
SCHEMA = """
CREATE TABLE IF NOT EXISTS backup_sites (
 id INTEGER PRIMARY KEY, label TEXT NOT NULL, timezone TEXT NOT NULL DEFAULT 'auto'
);
CREATE TABLE IF NOT EXISTS backup_snapshots (
 id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL, evidence_id INTEGER NOT NULL,
 root TEXT NOT NULL, label TEXT NOT NULL, captured_at TEXT NOT NULL DEFAULT '',
 captured_epoch INTEGER, timezone TEXT NOT NULL DEFAULT 'auto',
 completeness TEXT NOT NULL DEFAULT 'unknown', generation TEXT NOT NULL DEFAULT '',
 state TEXT NOT NULL DEFAULT 'new', stats TEXT NOT NULL DEFAULT '{}',
 UNIQUE(evidence_id, root)
);
CREATE TABLE IF NOT EXISTS backup_generations (
 id TEXT PRIMARY KEY, snapshot_id INTEGER NOT NULL, prepared TEXT NOT NULL,
 state TEXT NOT NULL, stats TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS backup_files (
 generation TEXT NOT NULL, relative_path TEXT NOT NULL, artifact TEXT NOT NULL,
 sha256 TEXT NOT NULL DEFAULT '', size INTEGER NOT NULL DEFAULT 0,
 marker TEXT NOT NULL DEFAULT '', modified REAL, created REAL,
 state TEXT NOT NULL, problem TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(generation, relative_path)
);
CREATE INDEX IF NOT EXISTS backup_files_hash ON backup_files(sha256);
CREATE INDEX IF NOT EXISTS backup_files_artifact ON backup_files(artifact);
CREATE TABLE IF NOT EXISTS content_files (
 artifact TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
 marker TEXT NOT NULL, verified_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS content_files_hash ON content_files(sha256);
CREATE TABLE IF NOT EXISTS content_assessments (
 sha256 TEXT PRIMARY KEY, state TEXT NOT NULL, note TEXT NOT NULL,
 classifications TEXT NOT NULL DEFAULT '[]', origin TEXT NOT NULL, updated TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS content_assessment_history (
 id INTEGER PRIMARY KEY, sha256 TEXT NOT NULL, state TEXT NOT NULL, note TEXT NOT NULL,
 classifications TEXT NOT NULL, origin TEXT NOT NULL, at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS content_inheritance (
 artifact TEXT PRIMARY KEY, sha256 TEXT NOT NULL, state TEXT NOT NULL,
 origin TEXT NOT NULL, previous_state TEXT NOT NULL, previous_note TEXT NOT NULL,
 updated TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS content_exceptions (
 artifact TEXT NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY(artifact, sha256)
);
"""
