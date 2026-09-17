"""Compare preserved website copies without treating either copy as a clean baseline."""
import difflib
import hashlib
import json
import os
import re
import stat
import uuid
from pathlib import Path
from datetime import datetime

from server import db, source_time
from server.engines.fsutil import canonical_file, path_within_any
from server.paths import display_path, io_path

DIFF_BYTES = 1024 * 1024
DIFF_LINES = 12000


class BackupError(ValueError):
    pass


def marker(st):
    return f'{st.st_size}:{st.st_mtime_ns}:{st.st_ctime_ns}:{st.st_ino}'


def hash_file(path, ctx=None):
    """A complete hash only: reject files that change while being read."""
    before = os.stat(io_path(path))
    if not stat.S_ISREG(before.st_mode):
        raise BackupError('Not a regular file')
    digest = hashlib.sha256()
    with open(io_path(path), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            if ctx and ctx.cancelled():
                raise BackupError('Comparison cancelled')
            digest.update(block)
        after = os.fstat(stream.fileno())
    final = os.stat(io_path(path))
    # On Windows Python stat/fstat can expose different ctime semantics.
    # Compare each API with itself, plus content/identity across the handle.
    content = lambda st: (st.st_size, st.st_mtime_ns, st.st_ino)
    if marker(before) != marker(final) or marker(opened) != marker(after) or content(final) != content(after):
        raise BackupError('File changed while being read; refresh this backup')
    return {'sha256': digest.hexdigest(), 'size': final.st_size, 'marker': marker(final),
            'modified': final.st_mtime,
            'created': getattr(final, 'st_birthtime', final.st_ctime if os.name == 'nt' else None)}


def registered(conn, path):
    roots = [r['path'] for r in db.rows(conn, "SELECT path FROM evidence WHERE kind='webroot'")]
    return path_within_any(path, roots)


def remember(conn, path, info):
    inherited = db.one(conn, 'SELECT * FROM content_inheritance WHERE artifact=?', (path,))
    if inherited and inherited['sha256'] != info['sha256']:
        restore_inheritance(conn, inherited, 'Content changed; the previous hash assessment no longer applies')
    conn.execute('INSERT OR REPLACE INTO content_files VALUES (?,?,?,?,?)',
                 (path, info['sha256'], info['size'], info['marker'], db.now()))


def restore_inheritance(conn, inherited, reason):
    """Withdraw only a hash-bound decision; retain the decision and findings audit."""
    from server.artifacts import ART_SQL
    path = inherited['artifact']
    current = db.one(conn, f'WITH art AS ({ART_SQL}) SELECT * FROM art WHERE artifact=?', (path,))
    independent = conn.execute('SELECT 1 FROM content_exceptions WHERE artifact=? AND sha256=?', (path, inherited['sha256'])).fetchone()
    if current and not independent and current['triage'] == inherited['state']:
        state = inherited['previous_state']
        conn.execute('UPDATE findings SET triage=?,triage_note=?,triaged_at=? WHERE artifact=?',
                     (state, inherited['previous_note'], db.now(), path))
        conn.execute("INSERT INTO triage_events(artifact,artifact_kind,from_state,to_state,note,propagated,at) VALUES (?,'file',?,?,?,1,?)",
                     (path, current['triage'], state, reason, db.now()))
        conn.execute('UPDATE ioc_sources SET active=0 WHERE artifact=?', (path,))
        from server.file_classifications import store
        store(conn, path, [], state)
    # This observation describes the old content, not a new detection. Keep it
    # in historical results, with the shared assessment in its separate audit.
    conn.execute("UPDATE findings SET engine='content_assessment',seen_run=0 WHERE artifact=? AND rule_id='analyst.content_assessment'", (path,))
    if not independent and current and current['triage'] == inherited['state']:
        conn.execute("UPDATE findings SET triage='new' WHERE artifact=? AND rule_id='analyst.content_assessment'", (path,))
    db.complete_file(conn, 'content_assessment', path, 1)
    conn.execute('DELETE FROM content_inheritance WHERE artifact=?', (path,))


def settings(conn):
    snapshots = db.rows(conn, 'SELECT b.*,e.path evidence_path,e.kind evidence_kind FROM backup_snapshots b '
                       'LEFT JOIN evidence e ON e.id=b.evidence_id ORDER BY captured_epoch IS NULL,captured_epoch,b.id')
    for row in snapshots:
        row['stats'] = json.loads(row['stats'])
        row['available'] = bool(row['evidence_kind'] == 'webroot' and row['evidence_path']
                                and path_within_any(row['root'], [row['evidence_path']])
                                and os.path.isdir(io_path(row['root'])))
        if not row['available']:
            row['state'] = 'unavailable'
    return {'sites': db.rows(conn, 'SELECT * FROM backup_sites ORDER BY label,id'), 'snapshots': snapshots}


def save_site(conn, label, timezone='auto', site_id=None):
    label = str(label).strip()
    if not label or len(label) > 120:
        raise BackupError('Give the website a name of up to 120 characters')
    timezone = source_time.validate(timezone)
    if site_id is not None:
        if not conn.execute('UPDATE backup_sites SET label=?,timezone=? WHERE id=?', (label, timezone, site_id)).rowcount:
            raise BackupError('Website no longer exists')
        return site_id
    return conn.execute('INSERT INTO backup_sites(label,timezone) VALUES (?,?)', (label, timezone)).lastrowid


def save_snapshot(conn, *, site_id, evidence_id, root, label, captured_at='', timezone='auto', completeness='unknown', snapshot_id=None):
    site = db.one(conn, 'SELECT * FROM backup_sites WHERE id=?', (site_id,))
    evidence = db.one(conn, "SELECT * FROM evidence WHERE id=? AND kind='webroot'", (evidence_id,))
    if not site or not evidence:
        raise BackupError('Choose a website and a registered webroot')
    root = display_path(os.path.abspath(root or evidence['path']))
    if not path_within_any(root, [evidence['path']]) or not os.path.isdir(io_path(root)):
        raise BackupError('Choose an existing website folder inside the registered webroot')
    if completeness not in ('complete', 'partial', 'unknown'):
        raise BackupError('Choose complete, partial or unknown coverage')
    label = str(label).strip()
    if not label or len(label) > 120:
        raise BackupError('Give the backup a name of up to 120 characters')
    timezone = source_time.validate(timezone)
    if timezone == 'auto':
        timezone = site['timezone']
    captured_at = captured_at.strip()
    if captured_at:
        try:
            if len(captured_at) > 80:
                raise ValueError()
            datetime.fromisoformat(captured_at.replace('Z', '+00:00'))
        except ValueError:
            raise BackupError('Use an ISO date such as 2026-09-17T12:00:00, or leave it blank') from None
    epoch = source_time.example(captured_at, timezone)['epoch'] if captured_at else None
    for other in db.rows(conn, 'SELECT * FROM backup_snapshots WHERE id != ?', (snapshot_id or 0,)):
        if path_within_any(root, [other['root']]) or path_within_any(other['root'], [root]):
            raise BackupError('This folder overlaps another backup. Choose distinct website roots')
    values = (site_id, evidence_id, root, label, captured_at, epoch, timezone, completeness)
    if snapshot_id:
        old = db.one(conn, 'SELECT * FROM backup_snapshots WHERE id=?', (snapshot_id,))
        if not old:
            raise BackupError('Backup no longer exists')
        conn.execute('UPDATE backup_snapshots SET site_id=?,evidence_id=?,root=?,label=?,captured_at=?,captured_epoch=?,timezone=?,completeness=?,'
                     "generation=CASE WHEN root=? THEN generation ELSE '' END,state=CASE WHEN root=? THEN state ELSE 'new' END WHERE id=?",
                     values + (root, root, snapshot_id))
        return snapshot_id
    return conn.execute('INSERT INTO backup_snapshots(site_id,evidence_id,root,label,captured_at,captured_epoch,timezone,completeness) '
                        'VALUES (?,?,?,?,?,?,?,?)', values).lastrowid


def _walk(root, ctx, errors, max_entries=None):
    """Logical paths retained; cycles and escapes cannot enlarge evidence scope."""
    pending = [(root, frozenset())]
    visited = 0
    while pending:
        directory, parents = pending.pop()
        if ctx and ctx.cancelled():
            raise BackupError('Comparison cancelled')
        identity = canonical_file(directory)
        if identity in parents:
            errors.append((directory, 'Directory link cycle'))
            continue
        try:
            with os.scandir(io_path(directory)) as entries:
                for entry in entries:
                    visited += 1
                    if max_entries is not None and visited > max_entries:
                        errors.append((root, 'Preview stopped at its entry limit'))
                        return
                    path = display_path(entry.path)
                    try:
                        if not path_within_any(path, [root]):
                            errors.append((path, 'Link leaves the evidence root'))
                        elif entry.is_dir():
                            pending.append((path, parents | {identity}))
                        elif entry.is_file():
                            yield path
                        else:
                            errors.append((path, 'Not a readable regular file'))
                    except OSError:
                        errors.append((path, 'Cannot inspect entry'))
        except OSError:
            errors.append((directory, 'Cannot enumerate folder'))


def build(case_dir, ctx=None, snapshot_ids=None):
    conn = db.connect(case_dir)
    try:
        seed_ioc_assessments(conn)
        conn.commit()
        snapshots = settings(conn)['snapshots']
        if snapshot_ids is not None:
            wanted = set(snapshot_ids)
            if wanted - {s['id'] for s in snapshots}:
                raise BackupError('Choose existing backups')
            snapshots = [s for s in snapshots if s['id'] in wanted]
        total, failed, incomplete = 0, 0, False
        for index, snapshot in enumerate(snapshots):
            sid, root, generation = snapshot['id'], snapshot['root'], uuid.uuid4().hex
            if not snapshot['available']:
                failed += 1
                continue
            conn.execute("UPDATE backup_snapshots SET state='indexing' WHERE id=?", (sid,))
            conn.execute('INSERT INTO backup_generations VALUES (?,?,?,?,?)', (generation, sid, db.now(), 'building', '{}'))
            conn.commit()
            count, byte_count, problems, discovery = 0, 0, 0, []
            try:
                for path in _walk(root, ctx, discovery):
                    rel = os.path.relpath(path, root).replace('\\', '/')
                    if ctx:
                        ctx.phase_progress(index / max(1, len(snapshots)), f'Preparing backup {index + 1}/{len(snapshots)}: {count:,} files', 'hashing', count, None)
                    try:
                        info = hash_file(path, ctx)
                        state, problem = 'ready', ''
                    except (OSError, BackupError):
                        if ctx and ctx.cancelled():
                            raise BackupError('Comparison cancelled')
                        info = dict(sha256='', size=0, marker='', modified=None, created=None)
                        state, problem = 'unavailable', 'Cannot hash this file; retry the backup'
                        problems += 1
                        if ctx:
                            ctx.detailed_skip(path, problem, category='file', root=root)
                    conn.execute('INSERT INTO backup_files VALUES (?,?,?,?,?,?,?,?,?,?)',
                                 (generation, rel, path, info['sha256'], info['size'], info['marker'], info['modified'], info['created'], state, problem))
                    count += 1
                    byte_count += info['size']
                    if count % 100 == 0:
                        conn.commit()
                if ctx and ctx.cancelled():
                    raise BackupError('Comparison cancelled')
                for path, reason in discovery:
                    if ctx:
                        ctx.detailed_skip(path, reason, category='discovery', root=root)
                stats = {'files': count, 'bytes': byte_count, 'unavailable': problems, 'discovery_errors': len(discovery), 'prepared': db.now()}
                # Enumeration failures cannot support claims that another file is absent.
                if discovery:
                    raise BackupError('Some folders could not be read; the previous comparison is retained')
                state = 'partial' if problems else 'ready'
                incomplete = incomplete or bool(problems)
                conn.execute('UPDATE backup_generations SET state=?,stats=? WHERE id=?', (state, json.dumps(stats), generation))
                conn.execute('UPDATE backup_snapshots SET generation=?,state=?,stats=? WHERE id=?', (generation, state, json.dumps(stats), sid))
                for item in db.rows(conn, "SELECT * FROM backup_files WHERE generation=? AND sha256!=''", (generation,)):
                    remember(conn, item['artifact'], item)
                conn.commit()
                total += count
            except (OSError, BackupError) as error:
                conn.rollback()
                problem = str(error) if isinstance(error, BackupError) else 'Evidence could not be read; check access and retry'
                conn.execute("UPDATE backup_snapshots SET state='stale',stats=json_set(stats,'$.error',?) WHERE id=?", (problem, sid))
                conn.execute("UPDATE backup_generations SET state='failed' WHERE id=?", (generation,))
                conn.commit()
                if ctx and ctx.cancelled():
                    return {'files': total, 'partial': True, 'cancelled': True}
                failed += 1
        # All registered webroots participate in case-wide hash decisions, including ungrouped copies.
        content_result = {'applied': [], 'conflicts': []}
        if conn.execute('SELECT 1 FROM content_assessments LIMIT 1').fetchone():
            index_content(conn, ctx)
            content_result = inherit_all(conn, ctx)
            conn.commit()
        return {'files': total, 'failed_sources': failed, 'partial': bool(failed) or incomplete, 'content_assessment': content_result}
    except BackupError:
        if ctx and ctx.cancelled():
            conn.rollback()
            return {'partial': True, 'cancelled': True}
        raise
    finally:
        conn.close()


def index_content(conn, ctx=None):
    seen = set()
    for root in db.rows(conn, "SELECT path FROM evidence WHERE kind='webroot'"):
        errors = []
        for path in _walk(root['path'], ctx, errors):
            identity = canonical_file(path)
            if identity in seen:
                continue
            seen.add(identity)
            if ctx:
                ctx.phase_progress(0, f'Checking identical content: {len(seen):,} files', 'hashing', len(seen), None)
            try:
                remember(conn, path, hash_file(path, ctx))
                if ctx and len(seen) % 100 == 0:
                    conn.commit()
            except (OSError, BackupError):
                if ctx and ctx.cancelled():
                    raise
                if ctx:
                    ctx.detailed_skip(path, 'Cannot verify file content; retry preparation', category='file', root=root['path'])
        for path, reason in errors:
            if ctx:
                ctx.detailed_skip(path, reason, category='discovery', root=root['path'])
    conn.execute('INSERT OR REPLACE INTO meta(key,value) VALUES (?,?)', ('content_inventory_sources', source_signature(conn)))


def source_signature(conn):
    return json.dumps(db.rows(conn, "SELECT id,path FROM evidence WHERE kind='webroot' ORDER BY id"), sort_keys=True)


def seed_ioc_assessments(conn):
    """Only explicit analyst IOC assessments, never legacy/default malicious badges."""
    for item in db.rows(conn, "SELECT a.*,i.type,i.value FROM ioc_assessments a JOIN iocs i ON i.id=a.ioc_id "
                       "WHERE i.type IN ('file','hash') ORDER BY a.id"):
        digest = item['value'].lower()
        if not re.fullmatch('[0-9a-f]{64}', digest):
            continue
        origin = f"ioc:{item['ioc_id']}:assessment:{item['id']}"
        if conn.execute('SELECT 1 FROM content_assessment_history WHERE origin=?', (origin,)).fetchone():
            continue
        state = {'malicious': 'confirmed', 'benign': 'dismissed'}.get(item['state'], 'new')
        values = (digest, state, item['reason'], 'null', origin, item['created'])
        previous = db.one(conn, 'SELECT updated FROM content_assessments WHERE sha256=?', (digest,))
        if not previous or previous['updated'] <= item['created']:
            conn.execute('INSERT OR REPLACE INTO content_assessments VALUES (?,?,?,?,?,?)', values)
        conn.execute('INSERT INTO content_assessment_history(sha256,state,note,classifications,origin,at) VALUES (?,?,?,?,?,?)', values)


def assessment(conn, digest):
    row = db.one(conn, 'SELECT * FROM content_assessments WHERE sha256=?', (digest,))
    if row:
        row['classifications'] = json.loads(row['classifications'])
    return row


def assess_content(conn, artifact, state, note='', classifications=None):
    if state not in ('confirmed', 'dismissed', 'new'):
        return None
    if not registered(conn, artifact):
        raise BackupError('The file is outside the registered webroots')
    try:
        info = hash_file(artifact)
    except OSError:
        raise BackupError('Cannot verify the file content; restore the source before sharing its assessment') from None
    remember(conn, artifact, info)
    digest = info['sha256']
    scanned = db.one(conn, "SELECT value FROM meta WHERE key='webshell_hashes'")
    old_digest = json.loads(scanned['value'] or '{}').get(artifact) if scanned else None
    if old_digest and old_digest != digest:
        raise BackupError('The file changed since its scan. Analyze it again before sharing a content assessment')
    if classifications is None:
        from server.file_classifications import current
        classifications = current(conn, artifact, db.rows(conn, 'SELECT * FROM findings WHERE artifact=?', (artifact,)))
    values = (digest, state, note or '', json.dumps(classifications), artifact, db.now())
    conn.execute('INSERT OR REPLACE INTO content_assessments VALUES (?,?,?,?,?,?)', values)
    conn.execute('INSERT INTO content_assessment_history(sha256,state,note,classifications,origin,at) VALUES (?,?,?,?,?,?)', values)
    conn.execute('DELETE FROM content_exceptions WHERE artifact=? AND sha256=?', (artifact, digest))
    from server.artifacts import ART_SQL
    current = db.one(conn, f'WITH art AS ({ART_SQL}) SELECT * FROM art WHERE artifact=?', (artifact,))
    prior = db.one(conn, 'SELECT * FROM content_inheritance WHERE artifact=?', (artifact,))
    conn.execute('INSERT OR REPLACE INTO content_inheritance VALUES (?,?,?,?,?,?,?)',
                 (artifact, digest, state, artifact, prior['previous_state'] if prior else 'new',
                  prior['previous_note'] if prior else (current or {}).get('triage_note', ''), db.now()))
    return digest


def inherit_all(conn, ctx=None):
    from server.artifacts import ART_SQL
    from server.file_classifications import store
    states = {r['artifact']: r for r in db.rows(conn, f'WITH art AS ({ART_SQL}) SELECT * FROM art')}
    applied, conflicts = [], []
    for row in db.rows(conn, 'SELECT f.*,a.state decision,a.note,a.classifications,a.origin FROM content_files f JOIN content_assessments a ON a.sha256=f.sha256'):
        path, digest, desired = row['artifact'], row['sha256'], row['decision']
        if not registered(conn, path) or conn.execute('SELECT 1 FROM content_exceptions WHERE artifact=? AND sha256=?', (path, digest)).fetchone():
            continue
        try:
            fresh = hash_file(path, ctx)
        except (OSError, BackupError):
            if ctx and ctx.cancelled():
                raise
            continue
        if fresh['sha256'] != digest:
            remember(conn, path, fresh)
            continue
        old = states.get(path)
        previous = db.one(conn, 'SELECT * FROM content_inheritance WHERE artifact=?', (path,))
        if old and old['triage'] in ('confirmed', 'dismissed') and old['triage'] == desired and not previous:
            # Agreement is not provenance: never turn an independent decision into
            # one a future shared assessment is allowed to overwrite.
            continue
        if old and old['triage'] in ('confirmed', 'dismissed') and old['triage'] != desired and not (previous and previous['sha256'] == digest and previous['state'] == old['triage']):
            conflicts.append(path)
            continue
        if path == row['origin']:
            continue
        if desired == 'new':
            if previous:
                restore_inheritance(conn, previous, 'Shared content assessment withdrawn')
                applied.append(path)
            continue
        if not old and desired != 'confirmed':
            continue
        if not old:
            db.upsert_finding(conn, 'analyst', db.SEV_HIGH, 'Identical content assessed malicious in this case', 'file', path,
                              evidence='Inherited content assessment; not an independent scanner detection.', rule_id='analyst.content_assessment', engine='content_assessment', run=1)
        elif desired == 'confirmed':
            conn.execute("UPDATE findings SET seen_run=1 WHERE artifact=? AND engine='content_assessment'", (path,))
        before = old['triage'] if old else 'new'
        if desired == 'confirmed' and row['classifications'] != 'null':
            store(conn, path, json.loads(row['classifications']), desired)
        if before != desired or not previous:
            conn.execute('UPDATE findings SET triage=?,triaged_at=? WHERE artifact=?', (desired, db.now(), path))
            conn.execute('INSERT INTO triage_events(artifact,artifact_kind,from_state,to_state,note,propagated,at) VALUES (?,\'file\',?,?,?,1,?)',
                         (path, before, desired, 'Identical SHA-256 content assessment: ' + row['note'], db.now()))
            conn.execute('INSERT OR REPLACE INTO content_inheritance VALUES (?,?,?,?,?,?,?)',
                         (path, digest, desired, row['origin'], previous['previous_state'] if previous else before,
                          previous['previous_note'] if previous else (old or {}).get('triage_note', ''), db.now()))
            if desired == 'confirmed':
                from server.ioc import model as ioc_model
                path_id = db.add_ioc(conn, db.case_relative_path(conn, path), 'path', origin='Inherited content assessment', context=path, path_context='system')
                hash_id = db.add_ioc(conn, digest, 'hash', origin='Verified identical content')
                for ioc_id, role in ((path_id, 'direct'), (hash_id, 'hash')):
                    conn.execute('INSERT INTO ioc_sources(ioc_id,artifact,role,active,added) VALUES (?,?,?,1,?) '
                                 'ON CONFLICT(ioc_id,artifact,role) DO UPDATE SET active=1', (ioc_id, path, role, db.now()))
                db.link_iocs(conn, hash_id, path_id, 'hash-of')
                ioc_model.collect_file(conn, path, digest, hash_id, path_id)
            elif before == 'confirmed':
                conn.execute('UPDATE ioc_sources SET active=0 WHERE artifact=?', (path,))
            applied.append(path)
    return {'applied': applied, 'conflicts': conflicts}


def grouping(conn):
    """Logical review units, while retaining source artifacts for chronology and provenance."""
    rows = db.rows(conn, 'SELECT f.artifact,f.sha256,f.relative_path,b.site_id,b.id snapshot_id,b.label,b.state '
                   'FROM backup_files f JOIN backup_snapshots b ON b.generation=f.generation '
                   "JOIN evidence e ON e.id=b.evidence_id WHERE f.sha256!='' AND b.state IN ('ready','partial')")
    allowed = {s['id'] for s in settings(conn)['snapshots'] if s['available']}
    members = {r['artifact']: {**r, 'key': json.dumps([r['site_id'], r['relative_path'], r['sha256']])} for r in rows if r['snapshot_id'] in allowed}
    identities = {canonical_file(path): entry for path, entry in members.items()}
    for item in db.rows(conn, "SELECT DISTINCT artifact FROM findings WHERE artifact_kind='file'"):
        if item['artifact'] not in members:
            member = identities.get(canonical_file(item['artifact']))
            if member:
                members[item['artifact']] = member
    return members


def group_rows(conn, rows):
    members = grouping(conn)
    occurrences = {}
    for member in members.values():
        occurrences.setdefault(member['key'], set()).add(member['snapshot_id'])
    grouped = {}
    for row in rows:
        membership = members.get(row['artifact']) if row['artifact_kind'] == 'file' else None
        key = membership['key'] if membership else row['artifact']
        grouped.setdefault(key, []).append(row)
    result = []
    for key, copies in grouped.items():
        copies.sort(key=lambda r: (r['worst'], r['artifact']))
        row = dict(copies[0])
        row['backup_members'] = [r['artifact'] for r in copies]
        row['backup_count'] = len(occurrences.get(key, ()))
        row['version_key'] = key
        decisions = {r['triage'] for r in copies}
        row['review_conflict'] = 'confirmed' in decisions and 'dismissed' in decisions
        row['triage'] = 'new' if row['review_conflict'] or 'new' in decisions else 'reviewed' if 'reviewed' in decisions else row['triage']
        row['worst'] = min(r['worst'] for r in copies)
        result.append(row)
    return result


def history(conn, site_id, relative_path, *, states=None, snapshots=None):
    from server.artifacts import ART_SQL
    if states is None:
        states = {r['artifact']: r for r in db.rows(conn, f'WITH art AS ({ART_SQL}) SELECT * FROM art')}
    if snapshots is None:
        snapshots = [s for s in settings(conn)['snapshots'] if s['site_id'] == site_id]
    entries = []
    for snapshot in snapshots:
        file = db.one(conn, 'SELECT * FROM backup_files WHERE generation=? AND relative_path=?', (snapshot['generation'], relative_path))
        entry = {'snapshot': snapshot, 'file': file, 'status': 'not_present' if snapshot['generation'] and snapshot['state'] in ('ready', 'partial') else 'unknown'}
        if file:
            current = states.get(file['artifact'])
            entry.update(status=file['state'], finding=current, assessment=assessment(conn, file['sha256']),
                         inheritance=db.one(conn, 'SELECT * FROM content_inheritance WHERE artifact=? AND sha256=?', (file['artifact'], file['sha256'])))
            try:
                entry['available'] = snapshot['available'] and marker(os.stat(io_path(file['artifact']))) == file['marker']
            except OSError:
                entry['available'] = False
            entry['stale'] = not entry['available'] or snapshot['state'] not in ('ready', 'partial')
            if entry['stale']:
                entry['finding'] = None
                entry['inheritance'] = None
            evidence = db.one(conn, 'SELECT scanned_at,stats FROM evidence WHERE id=?', (snapshot['evidence_id'],))
            attempt = json.loads(evidence['stats'] or '{}').get('last_attempt', {}) if evidence else {}
            from server.analysis import skip_outcomes
            skipped = False
            for skipped_row in db.rows(conn, "SELECT s.*,j.run_id FROM job_skips s JOIN jobs j ON j.id=s.job_id WHERE s.path=? AND j.kind IN ('webshell','yara')", (file['artifact'],)):
                if attempt.get('run_id') and skipped_row['run_id'] != attempt['run_id']:
                    continue
                if skip_outcomes(conn, skipped_row['job_id']).get(skipped_row['ordinal'], {}).get('status') != 'resolved':
                    skipped = True
            complete = evidence and evidence['scanned_at'] and attempt.get('status', 'complete') in ('complete', 'complete_with_warnings')
            entry['scan_state'] = 'detections' if current and current['findings'] else 'not_analyzed' if skipped or not complete else 'no_detections'
        entries.append(entry)
    return {'path': relative_path, 'site_id': site_id, 'entries': entries}


def compare(conn, site_id, scope='suspicious', search='', limit=100, offset=0, muted=()):
    from server.artifacts import art_sql, MUTED_CLAUSE
    snapshots = [s for s in settings(conn)['snapshots'] if s['site_id'] == site_id]
    generations = [s['generation'] for s in snapshots if s['generation']]
    if not generations:
        return {'snapshots': snapshots, 'rows': [], 'total': 0, 'prepared': False}
    marks = ','.join('?' * len(generations))
    conn.create_function('casefold', 1, lambda text: str(text).casefold(), deterministic=True)
    prefix = f'''WITH art AS ({art_sql(muted)}), paths AS (
        SELECT f.relative_path path,
          MAX(CASE WHEN art.worst<3 AND art.triage!='dismissed' AND {MUTED_CLAUSE} THEN 1 ELSE 0 END) suspicious,
          (COUNT(DISTINCT NULLIF(f.sha256,''))>1 OR COUNT(*)!=? OR MIN(f.sha256)='') changed
        FROM backup_files f LEFT JOIN art ON art.artifact=f.artifact
        WHERE f.generation IN ({marks}) AND instr(casefold(f.relative_path),?)>0
        GROUP BY f.relative_path)'''
    condition = 'suspicious=1' if scope == 'suspicious' else 'changed=1' if scope == 'changes' else '1=1'
    values = [len(snapshots), *generations, search.casefold()]
    total = db.one(conn, prefix + ' SELECT COUNT(*) n FROM paths WHERE ' + condition, values)['n']
    selected = db.rows(conn, prefix + ' SELECT * FROM paths WHERE ' + condition + ' ORDER BY suspicious DESC,path LIMIT ? OFFSET ?',
                       values + [min(max(limit, 1), 200), max(0, offset)])
    states = {r['artifact']: r for r in db.rows(conn, f'WITH art AS ({art_sql(muted)}) SELECT * FROM art')}
    return {'snapshots': snapshots, 'prepared': True, 'total': total,
            'rows': [{**history(conn, site_id, row['path'], states=states, snapshots=snapshots),
                      'suspicious': bool(row['suspicious']), 'changed': bool(row['changed'])} for row in selected]}


def file_diff(conn, left, right, relative_path):
    snapshots = [db.one(conn, 'SELECT * FROM backup_snapshots WHERE id=?', (sid,)) for sid in (left, right)]
    if any(s is None for s in snapshots) or snapshots[0]['site_id'] != snapshots[1]['site_id']:
        raise BackupError('Choose two backups of the same website')
    sides = []
    for snapshot in snapshots:
        if snapshot['state'] not in ('ready', 'partial') or not registered(conn, snapshot['root']) or not os.path.isdir(io_path(snapshot['root'])):
            raise BackupError('This comparison is stale; prepare the backups again')
        row = db.one(conn, 'SELECT * FROM backup_files WHERE generation=? AND relative_path=?', (snapshot['generation'], relative_path))
        if not row:
            sides.append({'label': snapshot['label'], 'missing': True, 'lines': []})
            continue
        if snapshot['state'] not in ('ready', 'partial') or not registered(conn, row['artifact']):
            raise BackupError('This comparison is stale; prepare the backups again')
        try:
            info = hash_file(row['artifact'])
        except OSError:
            raise BackupError('Evidence is unavailable; historical hashes remain in the backup history') from None
        if not row['sha256'] or info['sha256'] != row['sha256']:
            raise BackupError('File content changed; refresh this backup before viewing the difference')
        side = {'label': snapshot['label'], 'artifact': row['artifact'], 'sha256': row['sha256'], 'size': row['size'], 'lines': []}
        if row['size'] > DIFF_BYTES:
            side['limited'] = 'File exceeds the 1 MiB text comparison limit'
        else:
            with open(io_path(row['artifact']), 'rb') as stream:
                data = stream.read(DIFF_BYTES + 1)
            if hashlib.sha256(data).hexdigest() != row['sha256']:
                raise BackupError('File changed during comparison; refresh the backup')
            try:
                text = data.decode('utf-8-sig')
                if '\0' in text:
                    raise UnicodeError()
                side['lines'] = text.splitlines()
                if len(side['lines']) > DIFF_LINES:
                    side['limited'] = 'File exceeds the 12,000-line comparison limit'
                    side['lines'] = []
            except UnicodeError:
                side['limited'] = 'Binary or non-UTF-8 content; compare hashes and original files'
        sides.append(side)
    lines = []
    if not any(s.get('limited') for s in sides):
        # Bounded unified diff, with source line numbers in each hunk header.
        for line in difflib.unified_diff(sides[0]['lines'], sides[1]['lines'], fromfile=sides[0]['label'], tofile=sides[1]['label'], n=3):
            lines.append(line)
            if len(lines) == DIFF_LINES:
                break
    return {'sides': [{k: v for k, v in s.items() if k != 'lines'} for s in sides], 'lines': lines, 'truncated': len(lines) == DIFF_LINES}
