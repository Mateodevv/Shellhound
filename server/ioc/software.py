"""Case software collection. Inventory presence is not an analyst assessment."""
import hashlib
import json
from server import db


def properties(row):
    try:
        context = json.loads(row.get('context') or '{}')
    except (ValueError, TypeError):
        context = {}
    return {'name': row['value'], **{key: context[key] for key in ('version', 'vendor') if isinstance(context, dict) and isinstance(context.get(key), str) and context.get(key)}}


def collect(conn, name, version='', vendor='', category='CMS', origin='CMS inventory'):
    version = '' if version in ('(unknown)', 'unknown', None) else str(version).strip()
    context = json.dumps({'version': version, 'vendor': vendor, 'category': category}, sort_keys=True)
    return db.add_ioc(conn, name, 'software', context=context, origin=origin)


def sync_inventory(conn):
    overrides = {(r['scope'], r['key']): r['version'] for r in db.rows(conn, 'SELECT * FROM cms_version_overrides')}
    for row in db.rows(conn, 'SELECT * FROM cms_installs'):
        version = overrides.get(('install', row['root']), row['version'])
        key = 'software-import:' + hashlib.sha256(json.dumps([row['root'], row['cms'], version]).encode()).hexdigest()
        if conn.execute('SELECT 1 FROM meta WHERE key=?', (key,)).fetchone():
            continue
        identifier = collect(conn, row['cms'], version)
        from server.ioc.model import observe
        observe(conn, identifier, 'software-inventory', source_ref=row['root'], local_path=row['root'], detail='CMS')
        conn.execute('INSERT INTO meta(key,value) VALUES (?,?)', (key, '1'))


def migrate_profile(conn, profile):
    for item in profile.get('software') or []:
        key = 'profile-software:' + hashlib.sha256(json.dumps(item, sort_keys=True).encode()).hexdigest()
        if conn.execute('SELECT 1 FROM meta WHERE key=?', (key,)).fetchone():
            continue
        collect(conn, item['name'], item.get('version', ''), origin='Case profile')
        conn.execute('INSERT INTO meta(key,value) VALUES (?,?)', (key, '1'))
    for item in profile.get('vulnerabilities') or []:
        key = 'profile-cve:' + hashlib.sha256(json.dumps(item, sort_keys=True).encode()).hexdigest()
        if conn.execute('SELECT 1 FROM meta WHERE key=?', (key,)).fetchone():
            continue
        import re
        kind = 'vulnerability' if re.fullmatch(r'CVE-\d{4}-\d{4,}', item['name'], re.I) else 'other'
        db.add_ioc(conn, item['name'], kind, note='\n'.join(filter(None, [item.get('status'), item.get('description')])), origin='Case profile')
        conn.execute('INSERT INTO meta(key,value) VALUES (?,?)', (key, '1'))
