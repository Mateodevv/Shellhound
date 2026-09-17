"""Dashboard facts and the exact Findings groups that support their counts."""
import ipaddress
from collections import defaultdict

from server import db, file_classifications
from server.artifacts import MUTED_CLAUSE, art_sql


SUMMARY_GROUPS = frozenset({'ips', 'malware_files'})
MALWARE_CLASSES = frozenset({'webshell', 'malware', 'backdoor', 'dropper'})


def summary_groups(conn, muted=()):
    """Current visible artifacts, using the same decision fold as Findings.

    Explicit file classifications, including an empty list, outrank scanner
    suggestions. Historical confirmations remain in Findings but cannot add
    to a summary of what current evidence reports.
    """
    artifacts = db.rows(conn, f"""
        WITH art AS ({art_sql(muted)})
        SELECT artifact, artifact_kind, triage FROM art
        WHERE findings > 0 AND triage IN ('confirmed', 'new', 'reviewed')
              AND {MUTED_CLAUSE}
    """)
    by_file = defaultdict(list)
    if any(item['artifact_kind'] == 'file' for item in artifacts):
        for finding in db.rows(conn, f"SELECT f.* FROM findings f {db.RETIRE_JOIN} "
                                    f"WHERE f.artifact_kind='file' AND {db.LIVE_PREDICATE}"):
            by_file[finding['artifact']].append(finding)
    groups = {key: [] for key in SUMMARY_GROUPS}
    for item in artifacts:
        if item['artifact_kind'] == 'client':
            try:
                identity = str(ipaddress.ip_address(item['artifact']))
            except ValueError:
                continue
            groups['ips'].append({**item, 'identity': identity})
        elif item['artifact_kind'] == 'file':
            findings = by_file[item['artifact']]
            classes = file_classifications.current(conn, item['artifact'], findings)
            if classes is None:
                classes = ['webshell'] if any(f['source'] == 'webshell' for f in findings) else []
            if MALWARE_CLASSES.intersection(classes):
                groups['malware_files'].append({**item, 'identity': item['artifact']})
    return groups


def group_artifacts(conn, group, muted=()):
    """All supporting artifacts; an unknown URL group deliberately matches none."""
    if group not in SUMMARY_GROUPS:
        return set()
    return {item['artifact'] for item in summary_groups(conn, muted)[group]}


def summarize(case_dir, chain, muted=()):
    conn = db.connect(case_dir)
    try:
        groups = summary_groups(conn, muted)
        confirmed = {row['artifact'] for row in db.rows(conn, f"""
            WITH art AS ({art_sql(muted)})
            SELECT artifact FROM art WHERE triage='confirmed' AND findings > 0
        """)}
    finally:
        conn.close()

    def decisions(group):
        return (sum(item['triage'] == 'confirmed' for item in groups[group]),
                sum(item['triage'] != 'confirmed' for item in groups[group]))

    confirmed_ips, pending_ips = decisions('ips')
    malware, pending_malware = decisions('malware_files')
    # Preserve the older unique-address field; the dashboard's new linked-IP
    # counts describe Findings artifacts so each card opens its exact set.
    unique_ips = {item['identity'] for item in groups['ips'] if item['triage'] == 'confirmed'}
    # Only recorded activity attached to confirmed artifacts with current
    # evidence provenance. File-copy times and account creation guesses are
    # not observed incident activity.
    events = [e for e in chain.get('events', [])
              if e.get('artifact') in confirmed and e.get('first_sign_selectable')
              and e.get('first_sign_basis') in ('request', 'hunt_match', 'log_observation')
              and (e.get('first_sign_eligible') or
                   e.get('kind') == 'hunt-match' or e.get('activity_boundary') == 'last_ok' or
                   (e.get('artifact_kind') == 'client' and e.get('kind') in ('erstkontakt', 'letzter-zugriff')))
              and isinstance(e.get('epoch'), (int, float))]
    times = [e['epoch'] for e in events]
    times.extend(e['activity_last_epoch'] for e in events
                 if isinstance(e.get('activity_last_epoch'), (int, float)))
    last_action = max(times) if times else None
    # Never focus a cluster's first request while displaying its last time.
    # Current chains supply explicit end events; older callers may not.
    anchors = sorted(e['id'] for e in events if e.get('id') and e['epoch'] == last_action)
    return {'first_action': min(times) if times else None,
            'last_action': last_action,
            'last_action_event_id': anchors[0] if anchors else None,
            'attacker_ips': len(unique_ips), 'confirmed_ips': confirmed_ips,
            'pending_ips': pending_ips,
            'malware_files': malware, 'pending_malware_files': pending_malware}
