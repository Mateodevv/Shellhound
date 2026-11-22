"""Opt-in case matching; saved reads never contact OpenCTI or evidence files."""
import ipaddress
import json
import re
import threading
from urllib.parse import quote, urlsplit

from server import db, ruleswitch, settings, workspace
from server.artifacts import MUTED_CLAUSE, art_sql
from server.integrations.opencti import service
from server.integrations.opencti.client import OpenCTIClient, OpenCTIError

_locks = [threading.Lock() for _ in range(64)]


def _lock(case_dir, destination, reference, kind, value):
    return _locks[hash((str(case_dir.resolve()), destination, reference, kind, value)) % len(_locks)]


def _current(root, case_dir, destination, reference, only_new=False):
    config = settings.opencti_config(root)
    return (service._destination(config) == destination and _reference(case_dir) == reference
            and (not only_new or config.get('auto_match') is True))


def _config(root, expected_url=None):
    config = dict(settings.opencti_config(root))
    if not config.get('url') or not config.get('token'):
        raise ValueError('Configure the OpenCTI URL and integration token first.')
    if expected_url is not None and config['url'] != expected_url:
        raise ValueError('The OpenCTI destination changed. Review the connection and check again.')
    return config


def authority(root, expected_url=None):
    return service._destination(_config(root, expected_url))


def _key(kind, value):
    if kind == 'ip' and isinstance(value, str) and '%' not in value:
        try:
            return kind, str(ipaddress.ip_address(value))
        except ValueError:
            pass
    elif kind == 'hash' and isinstance(value, str) and re.fullmatch(r'[0-9a-fA-F]{64}', value):
        return kind, value.lower()
    raise ValueError('Only IP addresses and SHA-256 hashes can be checked.')


def _reference(case_dir):
    return (workspace._read_identity(case_dir).get('reference') or '').strip()


def _safe_result(payload, kind, value, config):
    if (not isinstance(payload, dict) or type(payload.get('known')) is not bool or
            type(payload.get('truncated')) is not bool or not isinstance(payload.get('cases'), list) or
            (not payload.get('known') and bool(payload.get('cases'))) or
            not isinstance(payload.get('checked_at'), str)):
        raise OpenCTIError('OpenCTI returned an invalid matching response.', code='invalid_response')
    # Imported case databases are untrusted; build links only from the current host.
    url = config.get('url', '')
    parsed = urlsplit(url)
    valid = (parsed.scheme == 'https' and parsed.hostname and not parsed.username and
             not parsed.password and not parsed.query and not parsed.fragment and
             '\\' not in url and not any(c.isspace() or ord(c) < 32 for c in url))
    cases = []
    for case in payload.get('cases', []):
        if (not isinstance(case, dict) or not isinstance(case.get('id'), str) or
                not re.fullmatch(r'[A-Za-z0-9_-]{1,200}', case['id']) or
                not isinstance(case.get('name'), str)):
            raise OpenCTIError('OpenCTI returned an invalid matching response.', code='invalid_response')
        cases.append({'id': case['id'], 'name': str(case.get('name') or ''),
                      'url': url.rstrip('/') + '/dashboard/id/' + quote(case['id'], safe='') if valid else None})
    return {'kind': kind, 'value': value, 'known': bool(payload.get('known')),
            'cases': cases, 'truncated': bool(payload.get('truncated')),
            'checked_at': payload.get('checked_at', '')}


def _save(case_dir, destination, reference, result):
    conn = db.connect(case_dir)
    try:
        snapshot = {key: result[key] for key in ('known', 'truncated', 'checked_at')}
        snapshot['cases'] = [{'id': case['id'], 'name': case['name']} for case in result['cases']]
        conn.execute('INSERT OR REPLACE INTO opencti_case_matches VALUES (?,?,?,?,?)',
                     (destination, reference, result['kind'], result['value'], json.dumps(snapshot)))
        conn.commit()
    finally:
        conn.close()


def _lookup(client, config, case_dir, destination, reference, kind, value, current):
    payload = client.case_matches(kind, value, exclude_reference=reference)
    result = _safe_result({**payload, 'checked_at': db.now()}, kind, value, config)
    if not current():
        raise ValueError('OpenCTI connection, automatic matching, or case reference changed during the check.')
    _save(case_dir, destination, reference, result)
    return result


def lookup(root, case_dir, kind, value, *, expected_url=None):
    kind, value = _key(kind, value)
    config = _config(root, expected_url)
    destination, reference = service._destination(config), _reference(case_dir)
    with _lock(case_dir, destination, reference, kind, value):
        current = lambda: _current(root, case_dir, destination, reference)
        if not current():
            raise ValueError('OpenCTI connection or case reference changed during the check. Start a new check.')
        return _lookup(OpenCTIClient(config), config, case_dir, destination, reference, kind, value, current)


def saved(root, case_dir, kind, value):
    kind, value = _key(kind, value)
    config = settings.opencti_config(root)
    if not config.get('url') or not config.get('token'):
        return None
    conn = db.connect(case_dir)
    try:
        row = db.one(conn, 'SELECT payload FROM opencti_case_matches WHERE authority=? AND case_reference=? AND kind=? AND value=?',
                     (service._destination(config), _reference(case_dir), kind, value))
    finally:
        conn.close()
    if not row:
        return None
    return _read_result(row['payload'], kind, value, config)


def _read_result(payload, kind, value, config):
    try:
        return _safe_result(json.loads(payload), kind, value, config)
    except (ValueError, TypeError, AttributeError, OpenCTIError):
        return None


def _candidates(root, case_dir, *, cache_scope=None):
    conn = db.connect(case_dir)
    try:
        disabled = ruleswitch.disabled_ids(root)
        art = art_sql(disabled)
        eligible = f"SELECT artifact, artifact_kind FROM art WHERE {MUTED_CLAUSE} AND triage != 'dismissed' AND findings > 0"
        rows = db.rows(conn, f"""WITH art AS ({art}), eligible AS ({eligible}),
            latest_skip AS (SELECT s.path, MAX(s.job_id) AS job_id FROM job_skips s
                            JOIN eligible e ON e.artifact=s.path AND e.artifact_kind='file' WHERE s.category='file' GROUP BY s.path),
            active_skip AS (SELECT DISTINCT s.path FROM skipped s JOIN eligible e ON e.artifact=s.path
                            WHERE e.artifact_kind='file' AND s.source='webshell'),
            required AS (SELECT f.artifact, f.engine, MAX(f.seen_run) AS seen_run
                         FROM eligible e JOIN findings f ON f.artifact=e.artifact AND e.artifact_kind='file'
                         {db.RETIRE_JOIN} WHERE {db.LIVE_PREDICATE}
                         AND f.engine IN ('webshell','yarascan') GROUP BY f.artifact, f.engine)
            SELECT e.artifact, e.artifact_kind, required.engine AS required_engine,
                   required.seen_run, r.engine, r.run, r.sha256, r.marker,
                   c.sha256 AS indexed_hash, c.marker AS indexed_marker,
                   a.path IS NOT NULL AS skipped,
                   (s.job_id IS NOT NULL AND s.job_id >= COALESCE(r.job_id, 0)) AS later_skip
            FROM eligible e LEFT JOIN required ON required.artifact=e.artifact
            LEFT JOIN file_scan_receipts r ON r.artifact=e.artifact AND r.engine IN ('webshell','yarascan')
            LEFT JOIN content_files c ON c.artifact=e.artifact
            LEFT JOIN latest_skip s ON s.path=e.artifact
            LEFT JOIN active_skip a ON a.path=e.artifact""")
        files = {}
        keys, missing = set(), 0
        observations = db.rows(conn, f"""WITH art AS ({art}), eligible AS ({eligible})
            SELECT o.snapshot FROM log_observations o JOIN findings f ON f.fingerprint=o.finding_fingerprint
            JOIN eligible e ON e.artifact=f.artifact {db.RETIRE_JOIN}
            WHERE {db.LIVE_PREDICATE} AND f.triage != 'dismissed'
            AND (f.rule_id = '' OR f.triage != 'new' OR f.rule_id NOT IN ({','.join('?' for _ in disabled) or "''"}))""", tuple(disabled))
        for observation in observations:
            try:
                keys.add(_key('ip', json.loads(observation['snapshot']).get('ip')))
            except (ValueError, TypeError, AttributeError):
                pass
        for row in rows:
            artifact = row['artifact']
            if row['artifact_kind'] == 'client':
                try:
                    keys.add(_key('ip', artifact))
                except ValueError:
                    pass
            elif row['artifact_kind'] == 'file':
                files.setdefault(artifact, []).append(row)
        for evidence in files.values():
            required = {r['required_engine'] for r in evidence if r['required_engine']}
            proven, hashes, invalid = set(), set(), False
            for row in evidence:
                if not row['engine'] or row['skipped'] or row['later_skip']:
                    continue
                try:
                    digest = _key('hash', row['sha256'])
                except ValueError:
                    invalid = True
                    continue
                if not row['marker'] or (row['indexed_hash'] and
                        (row['indexed_hash'] != row['sha256'] or row['indexed_marker'] != row['marker'])):
                    invalid = True
                    continue
                hashes.add(digest)
                # A newer scan may have recorded clean replacement bytes before retiring this finding.
                if row['engine'] == row['required_engine'] and row['run'] == row['seen_run']:
                    proven.add(row['engine'])
            if not invalid and len(hashes) == 1 and required <= proven:
                keys.update(hashes)
            else:
                missing += 1
        cached = set()
        if cache_scope:
            destination, reference, config = cache_scope
            for row in db.rows(conn, 'SELECT kind,value,payload FROM opencti_case_matches WHERE authority=? AND case_reference=?',
                               (destination, reference)):
                key = (row['kind'], row['value'])
                if key in keys and _read_result(row['payload'], *key, config) is not None:
                    cached.add(key)
        return sorted(keys), missing, cached
    finally:
        conn.close()


def scan(root, case_dir, ctx, *, expected_authority, only_new=False):
    config = _config(root)
    destination = service._destination(config)
    if destination != expected_authority:
        raise ValueError('OpenCTI connection changed while the check was queued. Start a new check.')
    if only_new and config.get('auto_match') is not True:
        raise ValueError('Automatic OpenCTI matching is not enabled.')
    reference = _reference(case_dir)
    client = None
    candidates, missing, cached = _candidates(root, case_dir, cache_scope=(destination, reference, config) if only_new else None)
    stats = {'total': len(candidates), 'checked': 0, 'known': 0, 'linked': 0,
             'failed': 0, 'skipped': len(cached), 'missing_hashes': missing, 'partial': False, 'cancelled': False, 'reason': '',
             'linked_values': []}
    if ctx.cancelled() or not _current(root, case_dir, destination, reference, only_new):
        stats['cancelled'] = bool(ctx.cancelled())
        stats['partial'] = True
        stats['reason'] = 'OpenCTI connection, automatic matching, or case reference changed.'
        return stats
    for kind, value in (key for key in candidates if key not in cached):
        if ctx.cancelled():
            stats['cancelled'] = True
            break
        if not _current(root, case_dir, destination, reference, only_new):
            stats['partial'] = True
            stats['reason'] = 'OpenCTI connection or case reference changed. Start a new check.'
            break
        try:
            lock = _lock(case_dir, destination, reference, kind, value)
            while not lock.acquire(timeout=0.1):
                if ctx.cancelled() or not _current(root, case_dir, destination, reference, only_new):
                    raise ValueError('Matching stopped while waiting for another check.')
            try:
                if ctx.cancelled() or not _current(root, case_dir, destination, reference, only_new):
                    raise ValueError('Matching stopped before the check.')
                if only_new and saved(root, case_dir, kind, value) is not None:
                    stats['skipped'] += 1
                    continue
                if client is None:
                    client = OpenCTIClient(config)
                result = _lookup(client, config, case_dir, destination, reference, kind, value,
                                 lambda: _current(root, case_dir, destination, reference, only_new) and not ctx.cancelled())
            finally:
                lock.release()
            stats['checked'] += 1
            stats['known'] += int(result['known'])
            if result['cases']:
                stats['linked'] += 1
                if len(stats['linked_values']) < 20:
                    stats['linked_values'].append({'kind': kind, 'value': value})
        except ValueError:
            stats['cancelled'] = bool(ctx.cancelled())
            stats['partial'] = True
            stats['reason'] = 'OpenCTI connection, automatic matching, or case reference changed.'
            break
        except OpenCTIError as exc:
            stats['failed'] += 1
            stats['reason'] = {
                'authentication': 'OpenCTI rejected the integration token. Check the connection settings.',
                'permission': 'The OpenCTI token lacks permission to check matches.',
                'timeout': 'OpenCTI did not respond. Check the connection and try again.',
                'connection': 'OpenCTI could not be reached. Check the connection and try again.',
                'rate_limit': 'OpenCTI rate limit reached. Try again later.',
            }.get(exc.code, 'OpenCTI could not complete the check. Check the connection and platform compatibility.')
            break
        ctx.progress((stats['checked'] + stats['failed']) / max(1, stats['total']), 'Checking OpenCTI matches')
    stats['partial'] = bool(stats['partial'] or stats['cancelled'] or stats['failed'] or missing)
    return stats
