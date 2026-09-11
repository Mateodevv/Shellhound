"""Explicit, case-local file classifications retained with artifact decisions."""
import json

LABELS = {
    'webshell': 'Webshell', 'dropper': 'Dropper', 'backdoor': 'Backdoor',
    'seo-spam': 'SEO-Spam', 'malware': 'Malware', 'phishing': 'Phishing',
    'injected-code': 'Injected code', 'modified-file': 'Modified file',
}
PREFIX = 'artifact-classifications:'


def validate(values):
    if not isinstance(values, list) or any(value not in LABELS for value in values):
        raise ValueError('Unknown file classification')
    return [value for value in LABELS if value in values]


def all_saved(conn):
    return {row[0][len(PREFIX):]: json.loads(row[1]) for row in conn.execute(
        'SELECT key,value FROM meta WHERE key LIKE ?', (PREFIX + '%',))}


def saved(conn, artifact):
    row = conn.execute('SELECT value FROM meta WHERE key=?', (PREFIX + artifact,)).fetchone()
    return json.loads(row[0]) if row else None


def current(conn, artifact, findings):
    explicit = saved(conn, artifact)
    if explicit is not None:
        return explicit
    for finding in findings:
        if finding.get('source') == 'analyst' and finding.get('rule_id') == 'analyst.file_review':
            value = {'Analyst classified the file as a webshell.': 'webshell',
                     'Analyst classified the file as a malware sample.': 'malware'}.get(finding.get('evidence'))
            if value:
                return [value]
    rows = conn.execute('SELECT DISTINCT f.classification FROM ioc_files f JOIN ioc_sources s '
                        'ON s.ioc_id=f.ioc_id WHERE s.artifact=? AND s.active=1 AND f.verified_at!=\'\'', (artifact,))
    values = [row[0] for row in rows if row[0] in LABELS]
    return validate(values) if values else None


def store(conn, artifact, values, state):
    from server import db
    values = validate(values)
    previous = saved(conn, artifact)
    conn.execute('INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)',
                 (PREFIX + artifact, json.dumps(values)))
    if previous != values:
        summary = ', '.join(LABELS[value] for value in values) or 'None'
        conn.execute('INSERT INTO triage_events (artifact,artifact_kind,from_state,to_state,note,propagated,at) '
                     'VALUES (?,\'file\',?,?,?,0,?)',
                     (artifact, state, state, 'File classifications: ' + summary, db.now()))


def for_iocs(conn):
    """Apply explicit classes only along active file provenance; requester IPs keep their own labels."""
    explicit = all_saved(conn)
    out = {}
    for ioc_id, artifact in conn.execute("SELECT DISTINCT s.ioc_id,s.artifact FROM ioc_sources s "
            "JOIN findings f ON f.artifact=s.artifact WHERE s.active=1 AND s.role IN ('hash','direct') "
            "AND f.artifact_kind='file' AND f.triage='confirmed'"):
        if artifact in explicit:
            out.setdefault(ioc_id, set()).update(explicit[artifact])
    return {key: [value for value in LABELS if value in values] for key, values in out.items()}
