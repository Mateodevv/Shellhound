"""Public IOC labels derived from case facts and explicit tag choices."""
import json
import re
from server.file_classifications import LABELS, for_iocs

TECHNICAL = {"analyst", "finding", "confirmed", "hunt", "actor", "derived"}
CLASSIFICATIONS = LABELS


def classification_label(value):
    value = str(value or "").strip()
    key = re.sub(r"[ _]+", "-", value.lower())
    return CLASSIFICATIONS.get(key, value)


def finding_classification(findings):
    """Use explicit scanner categories/names, never infer a class from payload text."""
    findings = list(findings)
    for finding in findings:
        if re.search(r'\bseo[ _-]*spam\b', str(finding.get('rule', '')), re.I) or finding.get('source') in ('seo', 'seo-spam'):
            return 'seo-spam'
    if any(f.get('source') == 'webshell' for f in findings):
        return 'webshell'
    return ''


def preserve_imported_labels(conn):
    """Seed provenance for previously imported labels once; no external access."""
    from server import db
    if conn.execute("SELECT 1 FROM meta WHERE key='ioc-label-origins-v1'").fetchone():
        return
    for row in db.rows(conn, "SELECT i.id,i.source_uid,l.payload FROM iocs i JOIN opencti_lookups l ON l.ioc_id=i.id"):
        labels = []
        for entity in json.loads(row['payload']).get('entities', []):
            for label in entity.get('labels') or []:
                value = label.get('value') if isinstance(label, dict) else label
                if isinstance(value, str) and value.strip():
                    labels.append(value.strip())
        record_choices(conn, row, labels, 'opencti')
    conn.execute("INSERT INTO meta(key,value) VALUES('ioc-label-origins-v1','1')")


def record_choices(conn, row, values, origin):
    key = f"ioc-tag-choices:{row['id']}:{row['source_uid']}"
    saved = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    choices = json.loads(saved[0]) if saved else {}
    for value in values:
        folded = value.casefold()
        # Importing knowledge preserves an explicit local addition/removal.
        if origin == "opencti" and choices.get(folded, {}).get("origin") in ("manual", "removed"):
            continue
        choices[folded] = {"value": value, "origin": origin}
    conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", (key, json.dumps(choices)))


def apply_labels(conn, rows):
    """Keep provenance markers internal; expose the same labels to UI and exports.

    Deriving labels on read also covers existing cases and withdrawn evidence,
    without replaying analyses, uploading anything or guessing file identity.
    """
    from server import db
    generated = {}
    classifications = for_iocs(conn)
    classification_names = {value.casefold() for value in LABELS.values()} | set(LABELS)
    hunt_links = {r[0] for r in conn.execute("""SELECT e.link_id FROM ioc_relationship_evidence e
        JOIN ioc_observations o ON o.id=e.observation_id
        WHERE o.kind='pattern-hunt' AND o.active=1""")}
    for link in db.ioc_links(conn):
        if (link['id'] in hunt_links and link['src_type'] == 'ip' and link['dst_type'] == 'vulnerability'
                and re.fullmatch(r'CVE-\d{4}-\d{4,}', link['dst_value'], re.I)):
            generated.setdefault(link['src_id'], []).append(link['dst_value'].upper())
    choices = {r['key']: json.loads(r['value']) for r in db.rows(conn,
        "SELECT key,value FROM meta WHERE key LIKE 'ioc-tag-choices:%'")}
    for row in rows:
        tags = json.loads(row.get('tags') or '[]')
        explicit = choices.get(f"ioc-tag-choices:{row['id']}:{row.get('source_uid', '')}", {})
        labels = {tag.casefold(): tag for tag in tags if tag.casefold() not in TECHNICAL}
        if row['id'] in classifications:
            labels = {key: value for key, value in labels.items() if key not in classification_names}
            for value in classifications[row['id']]:
                labels[LABELS[value].casefold()] = LABELS[value]
            if row.get('file') is not None:
                row['file']['classifications'] = classifications[row['id']]
                row['file']['classification'] = next(iter(classifications[row['id']]), '')
        for tag in generated.get(row['id'], []):
            labels[tag.casefold()] = tag
        if (row.get('file') or {}).get('classification'):
            label = classification_label(row['file']['classification'])
            labels[label.casefold()] = label
        for key, choice in explicit.items():
            if choice['origin'] == 'removed':
                labels.pop(key, None)
            elif choice['origin'] == 'opencti':
                # Match the casing retained by the case's import union.
                labels.setdefault(key, next((tag for tag in tags if tag.casefold() == key), choice['value']))
            else:
                labels[key] = choice['value']
        row['tags'] = json.dumps(sorted(labels.values(), key=str.casefold), ensure_ascii=False)
    return rows
