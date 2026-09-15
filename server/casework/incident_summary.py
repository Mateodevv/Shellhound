"""Dashboard counts from current confirmed evidence, never file-copy times."""
import ipaddress
from server import db, file_classifications
from server.artifacts import ART_SQL


def summarize(case_dir, chain):
    conn = db.connect(case_dir)
    try:
        artifacts = db.rows(conn, f"WITH art AS ({ART_SQL}) SELECT artifact, artifact_kind FROM art WHERE triage='confirmed' AND findings > 0")
        ips = set()
        malware = set()
        for item in artifacts:
            if item['artifact_kind'] == 'client':
                try:
                    ips.add(str(ipaddress.ip_address(item['artifact'])))
                except ValueError:
                    pass
            elif item['artifact_kind'] == 'file':
                findings = db.rows(conn, f"SELECT f.* FROM findings f {db.RETIRE_JOIN} WHERE f.artifact=? AND f.triage='confirmed' AND ({db.LIVE_PREDICATE})", (item['artifact'],))
                classes = file_classifications.current(conn, item['artifact'], findings)
                if classes is None:
                    classes = ['webshell'] if any(f['source'] == 'webshell' for f in findings) else []
                if set(classes) & {'webshell', 'malware', 'backdoor', 'dropper'}:
                    malware.add(item['artifact'])
    finally:
        conn.close()
    # Only recorded activity attached to confirmed artifacts with current
    # evidence provenance. Filesystem metadata and account creation guesses
    # are deliberately excluded. Confirmed clients cover their request span.
    confirmed = {item['artifact'] for item in artifacts}
    events = [e for e in chain.get('events', [])
              if e.get('artifact') in confirmed and e.get('first_sign_selectable')
              and e.get('first_sign_basis') in ('request', 'hunt_match', 'log_observation')
              and (e.get('first_sign_eligible') or
                   (e.get('artifact_kind') == 'client' and e.get('kind') in ('erstkontakt', 'letzter-zugriff')))
              and isinstance(e.get('epoch'), (int, float))]
    times = [e['epoch'] for e in events]
    # Hunt clusters and successful file requests can carry a precise end
    # separately from the first evidence anchor.
    times.extend(e['activity_last_epoch'] for e in events if e.get('activity_last_epoch') is not None)
    return {'first_action': min(times) if times else None,
            'last_action': max(times) if times else None,
            'attacker_ips': len(ips), 'malware_files': len(malware)}
