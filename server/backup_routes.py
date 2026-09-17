"""Case-scoped website backup APIs. Mutations use the case operation fence."""
from fastapi import HTTPException
import os
import itertools
import sqlite3
from pydantic import BaseModel

from server import backups, db, ruleswitch
from pathlib import Path
from server.events import hub
from server.jobs import CaseBusy
from server.engines.fsutil import path_within_any
from server.paths import io_path


def install(app, auth, case_dir_or_404, manager):
    def call(slug, fn, write=False):
        case = case_dir_or_404(slug)
        def run():
            conn = db.connect(case)
            try:
                result = fn(conn)
                if write:
                    conn.commit()
                    hub.publish({'type': 'invalidate', 'scope': 'backups', 'case_slug': slug})
                return result
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
        try:
            if write:
                with manager.case_operation(case):
                    return run()
            return run()
        except CaseBusy as error:
            raise HTTPException(409, str(error)) from None
        except sqlite3.IntegrityError:
            raise HTTPException(409, 'This backup is already registered; edit the existing backup') from None
        except (ValueError, OSError) as error:
            message = str(error) if isinstance(error, ValueError) else 'Evidence could not be read'
            raise HTTPException(400, message) from None

    class Site(BaseModel):
        label: str
        timezone: str = 'auto'

    class Snapshot(BaseModel):
        site_id: int
        evidence_id: int
        root: str = ''
        label: str
        captured_at: str = ''
        timezone: str = 'auto'
        completeness: str = 'unknown'

    class Prepare(BaseModel):
        snapshot_ids: list[int] | None = None

    class RootPreview(BaseModel):
        evidence_id: int
        root: str

    @app.post('/api/cases/{slug}/backups/preview-root', dependencies=[auth])
    def preview_root(slug: str, body: RootPreview):
        def read(conn):
            source = db.one(conn, "SELECT path FROM evidence WHERE id=? AND kind='webroot'", (body.evidence_id,))
            if not source or not path_within_any(body.root, [source['path']]) or not os.path.isdir(io_path(body.root)):
                raise backups.BackupError('Choose an existing website folder inside the registered webroot')
            errors = []
            paths = [os.path.relpath(p, body.root).replace('\\', '/') for p in itertools.islice(backups._walk(body.root, None, errors, max_entries=1000), 6)]
            return {'paths': paths[:5], 'more': len(paths) > 5, 'warning': bool(errors)}
        return call(slug, read)

    @app.get('/api/cases/{slug}/backups', dependencies=[auth])
    def overview(slug: str):
        return call(slug, backups.settings)

    @app.post('/api/cases/{slug}/backups/sites', dependencies=[auth])
    def site_create(slug: str, body: Site):
        return call(slug, lambda conn: {'id': backups.save_site(conn, **body.model_dump())}, True)

    @app.patch('/api/cases/{slug}/backups/sites/{site_id}', dependencies=[auth])
    def site_update(slug: str, site_id: int, body: Site):
        return call(slug, lambda conn: {'id': backups.save_site(conn, site_id=site_id, **body.model_dump())}, True)

    @app.post('/api/cases/{slug}/backups/snapshots', dependencies=[auth])
    def snapshot_create(slug: str, body: Snapshot):
        return call(slug, lambda conn: {'id': backups.save_snapshot(conn, **body.model_dump())}, True)

    @app.patch('/api/cases/{slug}/backups/snapshots/{snapshot_id}', dependencies=[auth])
    def snapshot_update(slug: str, snapshot_id: int, body: Snapshot):
        return call(slug, lambda conn: {'id': backups.save_snapshot(conn, snapshot_id=snapshot_id, **body.model_dump())}, True)

    @app.post('/api/cases/{slug}/backups/prepare', dependencies=[auth])
    def prepare(slug: str, body: Prepare):
        case = case_dir_or_404(slug)
        def validate(conn):
            if body.snapshot_ids is not None and set(body.snapshot_ids) - {s['id'] for s in backups.settings(conn)['snapshots']}:
                raise backups.BackupError('Choose existing backups')
        try:
            with manager.case_operation(case):
                call(slug, validate)
                return {'job': manager.submit(case, 'backup_comparison', lambda ctx: backups.build(case, ctx, body.snapshot_ids))}
        except CaseBusy as error:
            raise HTTPException(409, str(error)) from None

    @app.get('/api/cases/{slug}/backups/compare', dependencies=[auth])
    def compare(slug: str, site_id: int, scope: str = 'suspicious', search: str = '', limit: int = 100, offset: int = 0):
        if scope not in ('suspicious', 'changes', 'all'):
            raise HTTPException(400, 'Choose suspicious, changes or all files')
        muted = ruleswitch.disabled_ids(Path(case_dir_or_404(slug)).parent)
        return call(slug, lambda conn: backups.compare(conn, site_id, scope, search, limit, offset, muted=muted))

    @app.get('/api/cases/{slug}/backups/history', dependencies=[auth])
    def history(slug: str, site_id: int, path: str):
        return call(slug, lambda conn: backups.history(conn, site_id, path))

    @app.get('/api/cases/{slug}/backups/artifact', dependencies=[auth])
    def artifact_history(slug: str, artifact: str):
        def read(conn):
            memberships = backups.grouping(conn)
            member = memberships.get(artifact) or db.one(conn, 'SELECT b.site_id,f.relative_path FROM backup_files f JOIN backup_snapshots b ON b.generation=f.generation WHERE f.artifact=? LIMIT 1', (artifact,))
            return backups.history(conn, member['site_id'], member['relative_path']) if member else {'entries': [], 'path': '', 'site_id': None}
        return call(slug, read)

    class Observation(BaseModel):
        snapshot_id: int
        path: str
        note: str = ''

    @app.post('/api/cases/{slug}/backups/findings', dependencies=[auth])
    def add_observation(slug: str, body: Observation):
        def write(conn):
            snapshot = next((s for s in backups.settings(conn)['snapshots'] if s['id'] == body.snapshot_id), None)
            if not snapshot or not snapshot['available'] or snapshot['state'] not in ('ready', 'partial'):
                raise backups.BackupError('Restore and refresh this backup before selecting evidence')
            item = db.one(conn, 'SELECT * FROM backup_files WHERE generation=? AND relative_path=?', (snapshot['generation'], body.path))
            if not item or not item['sha256'] or backups.hash_file(item['artifact'])['sha256'] != item['sha256']:
                raise backups.BackupError('File content changed or is unavailable; refresh this backup')
            if len(body.note) > 4000:
                raise backups.BackupError('Keep the note within 4,000 characters')
            db.upsert_finding(conn, 'analyst', db.SEV_LOW, 'Backup file selected for investigation', 'file', item['artifact'],
                              evidence=body.note, rule_id='analyst.backup_observation')
            return {'artifact': item['artifact']}
        result = call(slug, write, True)
        hub.publish({'type': 'invalidate', 'scope': 'findings', 'case_slug': slug})
        return result

    @app.get('/api/cases/{slug}/backups/diff', dependencies=[auth])
    def diff(slug: str, left: int, right: int, path: str):
        return call(slug, lambda conn: backups.file_diff(conn, left, right, path))
