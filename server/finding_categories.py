"""Shared finding groups for the dashboard and the artifact work list.

An artifact belongs to the category of its leading observation: current rows
first, then severity, line and ID. Supporting detections stay attached to it.
"""
from server import db
from server.artifacts import MUTED_CLAUSE, art_sql


CATEGORY_ORDER = (
    "webshell", "obfuscation", "htaccess", "yara", "db_injected",
    "db_markup", "shell_access", "bruteforce", "probes", "errorlog",
    "scanner", "other",
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
    """Three whole-case groups, with bounded output even for large cases."""
    # An analyst's confirmation outranks an informational rule's severity.
    eligible = f"triage != 'dismissed' AND {MUTED_CLAUSE}"
    summary = conn.execute(f"""
        WITH art AS ({art_sql(muted)})
        SELECT COALESCE(SUM(CASE WHEN {eligible} AND worst = 3
                                    AND triage != 'confirmed' THEN 1 ELSE 0 END), 0)
                   AS informational,
               COALESCE(SUM(CASE WHEN triage != 'dismissed' AND NOT {MUTED_CLAUSE}
                                    THEN 1 ELSE 0 END), 0) AS hidden
        FROM art
    """).fetchone()
    order = "CASE category " + " ".join(
        f"WHEN {_literal(category)} THEN {index}"
        for index, category in enumerate(CATEGORY_ORDER)
    ) + " ELSE 99 END"
    rows = db.rows(conn, f"""
        WITH art AS ({categorized_art_sql(muted)}), eligible AS (
            SELECT * FROM art
            WHERE {eligible} AND (worst < 3 OR triage = 'confirmed')
        ), grouped AS (
            SELECT category, MIN(worst) AS worst,
                   SUM(triage = 'confirmed') AS confirmed,
                   SUM(triage IN ('new', 'reviewed')) AS awaiting_review,
                   SUM(findings = 0 AND retired > 0) AS historical,
                   SUM(artifact_kind = 'file') AS files,
                   SUM(artifact_kind = 'client') AS clients,
                   SUM(artifact_kind = 'table') AS tables,
                   SUM(artifact_kind = 'dump') AS dumps
            FROM eligible GROUP BY category
        ), examples AS (
            SELECT *, ROW_NUMBER() OVER (
                PARTITION BY category
                ORDER BY CASE triage WHEN 'confirmed' THEN 0 ELSE 1 END,
                         worst, lower(artifact), artifact
            ) AS position FROM eligible
        )
        SELECT grouped.*, example.artifact, example.artifact_kind,
               example.lead_rule AS rule, example.lead_source AS source,
               COUNT(*) OVER () AS total_groups
        FROM grouped JOIN examples example USING (category)
        WHERE example.position = 1
        ORDER BY CASE WHEN grouped.confirmed > 0 THEN 0 ELSE 1 END,
                 grouped.worst, {order}
        LIMIT 3
    """)
    groups = []
    for row in rows:
        groups.append({
            "category": row["category"], "worst": row["worst"],
            "confirmed": row["confirmed"], "awaiting_review": row["awaiting_review"],
            "historical": row["historical"],
            "kinds": {kind: row[column] for kind, column in (
                ("file", "files"), ("client", "clients"), ("table", "tables"),
                ("dump", "dumps")) if row[column]},
            "example": {key: row[key] for key in ("artifact", "artifact_kind", "rule", "source")},
        })
    return {"groups": groups, "total_groups": rows[0]["total_groups"] if rows else 0,
            "informational": summary["informational"], "hidden": summary["hidden"]}
