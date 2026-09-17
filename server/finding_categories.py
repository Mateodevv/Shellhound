"""Shared finding groups for the dashboard and the artifact work list.

An artifact belongs to the category of its leading observation: current rows
first, then severity, line and ID. Supporting detections stay attached to it.
"""
from server import db
from server.artifacts import art_sql


CATEGORY_ORDER = (
    "webshell", "obfuscation", "htaccess", "yara", "db_injected",
    "db_markup", "shell_access", "bruteforce", "probes", "errorlog",
    "scanner", "log_observation", "other",
)

# Ordered, case-sensitive substring matches, preserving the Findings taxonomy.
CATEGORY_RULES = (
    ("webshell", "Obfuscation decode chain", "obfuscation"),
    ("webshell", "Hex/octal string obfuscation", "obfuscation"),
    ("webshell", "chr() concatenation", "obfuscation"),
    ("webshell", "goto-based control-flow", "obfuscation"),
    ("webshell", ".htaccess", "htaccess"),
    ("webshell", "", "webshell"),
    ("sqldb", "Inline <script>", "db_markup"),
    ("sqldb", "Injected <iframe>", "db_markup"),
    ("sqldb", "document.write", "db_markup"),
    ("sqldb", "", "db_injected"),
    ("logs", "upload/cache directory", "shell_access"),
    ("logs", "CMS extension directory", "shell_access"),
    ("logs", "brute-force", "bruteforce"),
    ("logs", "login POST flood", "bruteforce"),
    ("logs", "Scanner tool User-Agent", "scanner"),
    ("logs", "SQL injection", "probes"),
    ("logs", "Path traversal", "probes"),
    ("analyst", "Manual file review", "webshell"),
    ("yara", "", "yara"),
    ("errorlog", "", "errorlog"),
    ("log_observation", "", "log_observation"),
)


def _literal(value):
    """Quote our static category definitions, never user query parameters."""
    return "'" + value.replace("'", "''") + "'"


def categorized_art_sql(muted=()):
    conditions = []
    for source, needle, category in CATEGORY_RULES:
        test = f"lead.source = {_literal(source)}"
        if needle:
            test += f" AND instr(lead.rule, {_literal(needle)}) > 0"
        conditions.append(f"WHEN {test} THEN {_literal(category)}")
    category = "CASE " + " ".join(conditions) + " ELSE 'other' END"
    return f"""
        WITH leaders AS (
            SELECT f.artifact, f.rule, f.source,
                   ROW_NUMBER() OVER (
                       PARTITION BY f.artifact
                       ORDER BY CASE WHEN {db.LIVE_PREDICATE} THEN 0 ELSE 1 END,
                                f.severity, f.line, f.id
                   ) AS position
            FROM findings f {db.RETIRE_JOIN}
        )
        SELECT art.*, {category} AS category,
               lead.rule AS lead_rule, lead.source AS lead_source
        FROM ({art_sql(muted)}) art
        JOIN leaders lead ON lead.artifact = art.artifact AND lead.position = 1
    """


def top_findings(conn, muted=()):
    """Three whole-case categories counted in the same review units as Findings."""
    from server.artifacts import grouped_review_artifacts
    from server.log_evidence import artifact_label
    rows = grouped_review_artifacts(conn, db.rows(
        conn, f'WITH art AS ({categorized_art_sql(muted)}) SELECT * FROM art'))
    informational = sum(row['triage'] != 'dismissed' and row['review_visible']
                        and row['worst'] == 3 and row['triage'] != 'confirmed' for row in rows)
    hidden = sum(row['triage'] != 'dismissed' and not row['review_visible'] for row in rows)
    categories = {}
    for row in rows:
        if (row['triage'] == 'dismissed' or not row['review_visible']
                or (row['worst'] == 3 and row['triage'] != 'confirmed')):
            continue
        categories.setdefault(row['category'], []).append(row)
    groups = []
    for category, members in categories.items():
        example = min(members, key=lambda row: (row['triage'] != 'confirmed', row['worst'],
                                               row['artifact'].lower(), row['artifact']))
        kinds = {}
        for row in members:
            kinds[row['artifact_kind']] = kinds.get(row['artifact_kind'], 0) + 1
        display_name = artifact_label(conn, example['artifact']) if example['artifact_kind'] == 'log_observation' else ''
        groups.append({
            'category': category, 'worst': min(row['worst'] for row in members),
            'confirmed': sum(row['triage'] == 'confirmed' for row in members),
            'awaiting_review': sum(row['triage'] in ('new', 'reviewed') for row in members),
            'historical': sum(row['findings'] == 0 and row['retired'] > 0 for row in members),
            'kinds': kinds,
            'example': {'artifact': example['artifact'], 'artifact_kind': example['artifact_kind'],
                        'rule': example['lead_rule'], 'source': example['lead_source'], 'display_name': display_name},
        })
    order = {category: index for index, category in enumerate(CATEGORY_ORDER)}
    groups.sort(key=lambda group: (not group['confirmed'], group['worst'], order.get(group['category'], 99)))
    return {'groups': groups[:3], 'total_groups': len(groups),
            'informational': informational, 'hidden': hidden}
