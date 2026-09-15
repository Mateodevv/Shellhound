"""Offline training data. Files contain text markers, never executable malware."""
import os
from server import db, file_classifications, workspace as workspaces
from server.engines import logindex


def generate(workspace):
    case = workspaces.create_case(workspace, 'Training case', notes=(
        'SYNTHETIC TRAINING DATA. Review the pending findings, inspect file content, '
        'follow client traces and run Pattern Hunt. The files are inert placeholders. '
        'One file and one client are already confirmed to demonstrate the timeline.'))
    evidence = case / 'training-evidence'
    webroot = evidence / 'webroot'
    (webroot / 'uploads').mkdir(parents=True)
    files = [('uploads/training-shell.php', 'webshell', 'confirmed'),
             ('uploads/training-dropper.php', 'dropper', 'new'),
             ('index.html', 'modified-file', 'dismissed')]
    for relative, classification, state in files:
        path = webroot / relative
        path.write_text('SHELLHOUND SYNTHETIC TRAINING FILE\n'
                        f'Simulated classification: {classification}\n'
                        'This inert text file does not execute code.\n', encoding='utf-8')
        os.utime(path, (1788825600, 1788825600))
    log = evidence / 'access.log'
    rows = []
    for hour, minute, ip, method, uri, status in [
        (8, 0, '203.0.113.80', 'GET', '/', 200),
        (9, 0, '192.0.2.14', 'GET', '/administrator/', 200),
        (9, 0, '192.0.2.14', 'GET', '/plugins/editors/jce/jce.xml', 200),
        (9, 1, '192.0.2.14', 'POST', '/index.php?option=com_jce', 200),
        (9, 2, '192.0.2.14', 'POST', '/uploads/training-shell.php', 200),
        (9, 4, '192.0.2.14', 'GET', '/uploads/training-shell.php', 200),
        (10, 0, '198.51.100.28', 'GET', '/uploads/training-dropper.php', 200),
        (10, 3, '198.51.100.28', 'POST', '/wp-login.php', 403),
        (11, 0, '203.0.113.80', 'GET', '/', 200),
    ]:
        rows.append(f'{ip} - - [08/Sep/2026:{hour:02d}:{minute:02d}:00 +0000] "{method} {uri} HTTP/1.1" {status} 128 "-" "Synthetic training client"\n')
    log.write_text(''.join(rows), encoding='utf-8')
    conn = db.connect(case)
    try:
        for kind, path in [('webroot', webroot), ('access_logs', log)]:
            conn.execute('INSERT INTO evidence(kind,path,label,added) VALUES (?,?,?,?)',
                         (kind, str(path), 'Synthetic training evidence', db.now()))
        for relative, classification, state in files:
            path = str(webroot / relative)
            db.upsert_finding(conn, 'webshell' if classification != 'modified-file' else 'analyst',
                              db.SEV_HIGH, 'Training: simulated ' + classification, 'file', path,
                              line=2, evidence='Inert training marker; classify this sample for practice.',
                              rule_id='training.' + classification)
            file_classifications.store(conn, path, [classification], state)
            conn.execute('UPDATE findings SET triage=?,triaged_at=? WHERE artifact=?', (state, db.now(), path))
        for ip, state in [('192.0.2.14', 'confirmed'), ('198.51.100.28', 'new')]:
            db.upsert_finding(conn, 'analyst', db.SEV_HIGH, 'Training: simulated suspicious client',
                              'client', ip, evidence='Synthetic access-log requests. Inspect the trace before deciding.',
                              rule_id='training.client')
            conn.execute('UPDATE findings SET triage=?,triaged_at=? WHERE artifact=?', (state, db.now(), ip))
        db.add_ioc(conn, '192.0.2.14', 'ip', note='Synthetic training client', origin='Training case')
        conn.commit()
    finally:
        conn.close()
    logindex.build(case, [str(log)])
    return case
