"""Dashboard facts and the exact Findings groups that support their counts."""
import ipaddress
from collections import defaultdict

from server import db, file_classifications
from server.artifacts import art_sql, grouped_review_artifacts


SUMMARY_GROUPS = frozenset({'ips', 'malware_files'})
MALWARE_CLASSES = frozenset({'webshell', 'malware', 'backdoor', 'dropper'})


def review_summary(conn, muted=()):
    """Dashboard work counts use exactly the logical units shown in Findings."""
    artifacts = db.rows(conn, f'WITH art AS ({art_sql(muted)}) SELECT * FROM art')
    visible = [row for row in grouped_review_artifacts(conn, artifacts) if row['review_visible']]

    def count(rows, field):
        totals = defaultdict(int)
        for row in rows:
            totals[row[field]] += 1
        return dict(totals)

    confirmed = [row for row in visible if row['triage'] == 'confirmed']
    outstanding = [row for row in visible if row['triage'] != 'dismissed']
    kind_order = {'file': 0, 'table': 1, 'dump': 2}

    def preview(rows, decided_only=False):
        # Balance entity kinds without filling every slot with copies of one
        # site version. The ordering preserves the existing dashboard preview.
        ranked = []
        ranks = defaultdict(int)
        for row in sorted(rows, key=lambda item: (item['worst'], item['artifact'].lower(), item['artifact'])):
            priority = 0 if row['triage'] == 'confirmed' else 1
            partition = row['artifact_kind'] if decided_only else (priority, row['worst'], row['artifact_kind'])
            ranks[partition] += 1
            key = ((ranks[partition], kind_order.get(row['artifact_kind'], 3), row['worst'], row['artifact'].lower())
                   if decided_only else (priority, row['worst'], ranks[partition],
                                         kind_order.get(row['artifact_kind'], 3), row['artifact'].lower(), row['artifact']))
            fields = ('artifact', 'artifact_kind', 'worst') if decided_only else ('artifact', 'artifact_kind', 'worst', 'triage')
            ranked.append((key, {field: row[field] for field in fields}))
        return [row for _, row in sorted(ranked, key=lambda item: item[0])[:6]]

    return {'severity': count(outstanding, 'worst'), 'triage': count(visible, 'triage'),
            'confirmed_kinds': count(confirmed, 'artifact_kind'),
            'confirmed_severity': count(confirmed, 'worst'),
            'confirmed_artifacts': preview(confirmed, True),
            'notable_artifacts': preview(outstanding),
            # A disagreement requires review but does not retract an existing
            # independent confirmation of compromise in one of the copies.
            'has_confirmed_findings': any(row['triage'] == 'confirmed' for row in artifacts)}


def summary_groups(conn, muted=()):
    """Current visible artifacts, using the same decision fold as Findings.

    Explicit file classifications, including an empty list, outrank scanner
    suggestions. Historical confirmations remain in Findings but cannot add
    to a summary of what current evidence reports.
    """
    artifacts = db.rows(conn, f'WITH art AS ({art_sql(muted)}) SELECT * FROM art')
    by_artifact = {row['artifact']: row for row in artifacts}
    by_file = defaultdict(list)
    if any(item['artifact_kind'] == 'file' for item in artifacts):
        for finding in db.rows(conn, f"SELECT f.* FROM findings f {db.RETIRE_JOIN} "
                                    f"WHERE f.artifact_kind='file' AND {db.LIVE_PREDICATE}"):
            by_file[finding['artifact']].append(finding)
    groups = {key: [] for key in SUMMARY_GROUPS}
    for item in grouped_review_artifacts(conn, artifacts):
        if item['triage'] == 'dismissed' or not item['review_visible']:
            continue
        candidates = [by_artifact[name] for name in item['backup_members']
                      if by_artifact[name]['findings'] > 0 and by_artifact[name]['triage'] != 'dismissed'
                      and (by_artifact[name]['active'] > 0 or by_artifact[name]['triage'] != 'new')]
        if not candidates:
            continue
        if item['artifact_kind'] == 'client':
            try:
                identity = str(ipaddress.ip_address(item['artifact']))
            except ValueError:
                continue
            groups['ips'].append({**item, 'identity': identity,
                                  'supporting_artifacts': [row['artifact'] for row in candidates]})
        elif item['artifact_kind'] == 'file':
            supporting = []
            for candidate in candidates:
                findings = by_file[candidate['artifact']]
                classes = file_classifications.current(conn, candidate['artifact'], findings)
                if classes is None:
                    classes = ['webshell'] if any(f['source'] == 'webshell' for f in findings) else []
                if MALWARE_CLASSES.intersection(classes):
                    supporting.append(candidate['artifact'])
            if supporting:
                groups['malware_files'].append({**item, 'identity': item['version_key'],
                                              'supporting_artifacts': supporting})
    return groups


def group_artifacts(conn, group, muted=()):
    """All supporting artifacts; an unknown URL group deliberately matches none."""
    if group not in SUMMARY_GROUPS:
        return set()
    return {artifact for item in summary_groups(conn, muted)[group]
            for artifact in item['supporting_artifacts']}


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
