# server/engines/sqldump.py
"""CMS database-dump analysis: injected code + account inventory.

Ported from legacy core/sqldump.py (streaming tokenizer) and
modules/sql_analyzer.py (rules + account extraction). A dump is streamed
statement by statement -- a 1 GB mysqldump is parsed once, and everything the
Database view shows (accounts, tables, findings) lands in case.db.
"""
import os
import re
from collections import namedtuple

from server import db
from server.engines.fsutil import iter_target_files, open_text_auto

_STREAM_CHUNK = 1 << 20

SQL_EXTS = (".sql", ".sql.gz", ".sql.bz2")

# `#` belongs in the character class: Joomla extensions ship their SQL with
# the placeholder prefix `#__`. Without it neither of the two rules matches,
# and injected code in a manipulated install.sql would be invisible to the
# scanner -- in exactly the file that runs again on the next installation.
INSERT_RE = re.compile(
    r"INSERT\s+(?:IGNORE\s+)?INTO\s+`?(?P<table>[A-Za-z0-9_$#]+)`?\s*"
    r"(?:\((?P<cols>[^)]*)\))?\s+VALUES",
    re.IGNORECASE)
CREATE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?`?(?P<table>[A-Za-z0-9_$#]+)`?\s*\(",
    re.IGNORECASE)
_COL_RE = re.compile(r"^\s*`(?P<name>[^`]+)`\s+(?P<type>[A-Za-z]+)")
_NOT_A_COLUMN = re.compile(
    r"^\s*(PRIMARY\s+KEY|UNIQUE|KEY|INDEX|FULLTEXT|SPATIAL|CONSTRAINT|FOREIGN\s+KEY|CHECK)\b",
    re.IGNORECASE)

# --- code-in-data signatures ------------------------------------------------
# HIGH: executable/obfuscated code has no business in a data column.
# MEDIUM: markup that CAN be legitimate stored content.
RULES = [
    (0, "PHP open tag in database value",
     re.compile(r"<\?php|<\?=")),
    (0, "eval/assert on decoded or request input",
     re.compile(r"(?i)\b(eval|assert)\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_)")),
    (0, "Obfuscation decode chain",
     re.compile(r"(?i)(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(\s*(base64_decode|gzinflate|str_rot13|['\"])")),
    (0, "Command execution call in database value",
     re.compile(r"(?i)\b(system|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(")),
    (0, "create_function / dynamic callback",
     re.compile(r"(?i)create_function\s*\(")),
    (1, "Inline <script> in database value",
     re.compile(r"(?i)<script[\s>]")),
    (1, "Injected <iframe> in database value",
     re.compile(r"(?i)<iframe[\s>]")),
    (1, "document.write (script injection)",
     re.compile(r"(?i)document\s*\.\s*write\s*\(")),
]

# --- export or shipped schema file? -----------------------------------------
# A webroot contains dozens of .sql files that are NOT database exports: every
# Joomla extension brings install/uninstall/updates along. They have no export
# header, no data and no accounts -- in the database view they bury the one
# real export.
#
# The most reliable difference sits in the content: in schema files Joomla
# writes the PLACEHOLDER PREFIX `#__`, which the installer only replaces with
# the real table prefix. In a mysqldump it never occurs. The path
# (.../<extension>/sql/...) supports this but does not decide on its own --
# someone can put a real export there.
_PREFIX_PLACEHOLDER = "#__"
_SCHEMA_DIR_RE = re.compile(r"(?i)[\\/]sql[\\/]")
_SCHEMA_NAME_RE = re.compile(
    r"(?i)^(install|uninstall|schema|updates?)\b|^\d+[\d.]*\.sql$")


def classify_dump(path, meta, placeholder_seen, data_rows):
    """'export' or 'schema'. When in doubt 'export': wrongly classifying a
    file as incidental would hide real evidence, the other way round it
    merely stands in the wrong place."""
    if any(meta.get(k) for k in ("tool", "database", "server", "created")):
        return "export"
    if placeholder_seen:
        return "schema"
    name = os.path.basename(path)
    if _SCHEMA_DIR_RE.search(path) and _SCHEMA_NAME_RE.match(name):
        return "schema"
    if not data_rows:
        # Only CREATE/DROP, not a single data row -- an export without data
        # is possible but rare; an installation script is exactly that.
        return "schema"
    return "export"


_WP_SUFFIXES = ("options", "posts", "postmeta", "usermeta", "users", "comments")
_JOOMLA_SUFFIXES = ("extensions", "content", "user_usergroup_map", "usergroups",
                    "session", "assets", "menu")

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DATETIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}")

_META_PATTERNS = (
    ("tool", re.compile(r"^--\s*(phpMyAdmin SQL Dump|MySQL dump|MariaDB dump)", re.I)),
    ("tool_version", re.compile(r"^--\s*(?:version|Version)\s+(\S+)")),
    ("server", re.compile(r"^--\s*Server[- ]?[Vv]ersion:?\s*(.+?)\s*$")),
    ("database", re.compile(r"^--\s*(?:Datenbank|Database|Current Database):\s*`?([^`\s]+)`?")),
    ("created", re.compile(r"^--\s*(?:Erstellungszeit|Generation Time|Dump completed on):\s*(.+?)\s*$")),
    ("host", re.compile(r"^--\s*Host:\s*(.+?)\s*$")),
)


# --- streaming tokenizer (ported verbatim) ----------------------------------

def _decode(token):
    t = token.strip()
    if t.upper() == "NULL" or t == "":
        return None
    if len(t) >= 2 and t[0] == "'" and t[-1] == "'":
        inner = t[1:-1]
        return (inner.replace("\\'", "'").replace("''", "'").replace('\\"', '"')
                     .replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t")
                     .replace("\\\\", "\\"))
    return t


def iter_statements(fh, chunk_size=_STREAM_CHUNK):
    """Yield complete SQL statements, tracking quote state so a `;` inside a
    value (post content, a webshell payload) never cuts a statement in half."""
    buf = []
    in_str = escape = False
    while True:
        chunk = fh.read(chunk_size)
        if not chunk:
            break
        start = 0
        for i, c in enumerate(chunk):
            if escape:
                escape = False
            elif in_str:
                if c == "\\":
                    escape = True
                elif c == "'":
                    in_str = False
            elif c == "'":
                in_str = True
            elif c == ";":
                buf.append(chunk[start:i + 1])
                yield "".join(buf)
                buf, start = [], i + 1
        buf.append(chunk[start:])
    tail = "".join(buf).strip()
    if tail:
        yield tail


def split_rows(values_text):
    """Parse the VALUES portion of an INSERT into rows of decoded values.
    Quote/escape-aware, nesting-aware; returns [] on malformed input."""
    rows, cur, row = [], [], None
    in_str = False
    depth = 0
    i, n = 0, len(values_text)
    while i < n:
        c = values_text[i]
        if in_str:
            if c == "\\":
                cur.append(c)
                if i + 1 < n:
                    cur.append(values_text[i + 1]); i += 2; continue
                i += 1; continue
            if c == "'":
                if i + 1 < n and values_text[i + 1] == "'":
                    cur.append("''"); i += 2; continue
                in_str = False; cur.append(c); i += 1; continue
            cur.append(c); i += 1; continue
        if depth == 0:
            if c == "(":
                depth = 1; row = []; cur = []
            elif c == ";":
                break
            i += 1; continue
        if c == "'":
            in_str = True; cur.append(c)
        elif c == ",":
            row.append(_decode("".join(cur))); cur = []
        elif c == "(":
            depth += 1; cur.append(c)
        elif c == ")":
            depth -= 1
            if depth == 0:
                row.append(_decode("".join(cur)))
                rows.append(row); row = None; cur = []
            else:
                cur.append(c)
        else:
            cur.append(c)
        i += 1
    return rows


def parse_create(stmt):
    m = CREATE_RE.search(stmt)
    if m is None:
        return None
    body = stmt[m.end():]
    cols = []
    depth, start = 0, 0
    for i, c in enumerate(body):
        if c == "(":
            depth += 1
        elif c == ")":
            if depth == 0:
                break
            depth -= 1
        elif c == "," and depth == 0:
            cols.append(body[start:i])
            start = i + 1
    else:
        i = len(body)
    cols.append(body[start:i])
    out = []
    for chunk in cols:
        if _NOT_A_COLUMN.match(chunk):
            continue
        cm = _COL_RE.match(chunk)
        if cm:
            out.append((cm.group("name"), cm.group("type").lower()))
    return (m.group("table"), out) if out else None


def insert_columns(stmt_match):
    raw = stmt_match.group("cols")
    if not raw:
        return []
    return [c.strip().strip("`").strip() for c in raw.split(",") if c.strip()]


def dump_meta(fh, max_lines=80):
    out = {k: "" for k, _ in _META_PATTERNS}
    for i, line in enumerate(fh):
        if i >= max_lines:
            break
        if not line.startswith("--"):
            continue
        for key, rx in _META_PATTERNS:
            if out[key]:
                continue
            m = rx.match(line)
            if m:
                out[key] = m.group(1).strip()
    return out


# --- account extraction -----------------------------------------------------

def _suffix(table):
    low = table.lower()
    for s in ("user_usergroup_map", "usergroups"):
        if low.endswith(s):
            return s
    return low.rsplit("_", 1)[-1]


def _is_email(v):
    return isinstance(v, str) and bool(_EMAIL_RE.match(v.strip()))


def _is_datetime(v):
    return isinstance(v, str) and bool(_DATETIME_RE.match(v.strip()))


def _looks_wordpress(row):
    return len(row) >= 7 and _is_email(row[4]) and _is_datetime(row[6])


def _first(pred, row):
    return next((v for v in row if pred(v)), None)


def _hash_type(pw):
    if not isinstance(pw, str):
        return "-"
    if pw.startswith(("$2y$", "$2a$", "$2b$")):
        return "bcrypt"
    if pw.startswith("$P$") or pw.startswith("$H$"):
        return "phpass"
    if pw.startswith("$wp$"):
        return "wp-hash"
    if pw.startswith("$argon"):
        return "argon2"
    if re.fullmatch(r"[0-9a-fA-F]{32}", pw or ""):
        return "md5 (weak!)"
    return "other" if pw else "-"


# A timestamp the CMS writes for "never". MySQL has no NULL idiom for this
# but a zero date -- whoever reads it as a date takes an admin who never
# signed in for one from 1899.
_NEVER = ("", "-", "0000-00-00 00:00:00", "0000-00-00", "1970-01-01 00:00:00")


def _clean_stamp(value):
    text = str(value or "").strip()
    return "" if text in _NEVER else text


def _extract_users(table, rows, cms):
    """(uid, login, email, registered, hash, last_login, blocked).

    Last login and block status only exist where the CMS carries them: Joomla
    has both fixed in its schema (lastvisitDate, block), WordPress core has no
    last login at all -- there it comes, if at all, from the usermeta of a
    plugin and is added later. What is missing stays empty; a guessed
    timestamp would be worse than none."""
    users = []
    for row in rows:
        if len(row) < 4:
            continue
        uid = str(row[0]).strip() if row[0] is not None else "?"
        last, blocked = "", 0
        if cms == "WordPress" and _looks_wordpress(row):
            login, pw, email, reg = row[1], row[2], row[4], row[6]
            # user_status: barely used in core, but when set, meant as a
            # block.
            if len(row) > 8:
                try:
                    blocked = 1 if int(str(row[8]).strip() or 0) else 0
                except ValueError:
                    blocked = 0
        elif cms == "Joomla" and len(row) >= 5:
            login = row[2]
            email = row[3]
            pw = row[4]
            # Fixed column order: 5 block, 7 registerDate, 8 lastvisitDate.
            if len(row) >= 9:
                try:
                    blocked = 1 if int(str(row[5]).strip() or 0) else 0
                except ValueError:
                    blocked = 0
                reg = row[7]
                last = _clean_stamp(row[8])
            else:
                reg = _first(_is_datetime, row)
        else:
            email = _first(_is_email, row)
            reg = _first(_is_datetime, row)
            login = row[1] if len(row) > 1 else uid
            pw = _first(lambda v: isinstance(v, str) and v.startswith("$"), row)
        users.append((uid, str(login or "?"), str(email or "-"),
                      _clean_stamp(reg) or "-", _hash_type(pw), last, blocked))
    return users


# WordPress does not carry the last login in core. What exists sits in
# usermeta -- either as a plugin field or as an active session. Both are a
# statement: "was last here" resp. "is signed in RIGHT NOW".
_LAST_LOGIN_KEYS = ("last_login", "wfls-last-login", "last_activity",
                    "wp_last_login", "_last_login")


def _wp_user_meta_signals(rows):
    """user_id -> {"last": str, "sessions": int} from the usermeta table."""
    out = {}
    for row in rows:
        if len(row) < 4:
            continue
        uid = str(row[1]).strip()
        key = str(row[2] or "").strip().lower()
        value = str(row[3] or "")
        entry = out.setdefault(uid, {"last": "", "sessions": 0})
        if key.endswith("session_tokens") and value.strip():
            entry["sessions"] = 1
        elif any(key.endswith(k) for k in _LAST_LOGIN_KEYS):
            stamp = _clean_stamp(value)
            if stamp.isdigit():          # Unix time, as plugins write it
                from datetime import datetime as _dt
                try:
                    stamp = _dt.fromtimestamp(int(stamp)).isoformat(sep=" ",
                                                                   timespec="seconds")
                except (ValueError, OSError, OverflowError):
                    stamp = ""
            if stamp > entry["last"]:
                entry["last"] = stamp
    return out


def _wp_admin_ids(rows):
    ids = set()
    for row in rows:
        if len(row) < 4:
            continue
        meta_key, meta_value = str(row[2] or ""), str(row[3] or "")
        if meta_key.endswith("capabilities") and '"administrator"' in meta_value:
            ids.add(str(row[1]).strip())
    return ids


def _joomla_super_ids(rows):
    ids = set()
    for row in rows:
        if len(row) >= 2 and str(row[1]).strip() == "8":
            ids.add(str(row[0]).strip())
    return ids


def _detect_cms(tables):
    suffixes = {_suffix(t) for t in tables}
    cms = set()
    if suffixes & set(_WP_SUFFIXES) and ("usermeta" in suffixes or "options" in suffixes):
        cms.add("WordPress")
    if suffixes & set(_JOOMLA_SUFFIXES):
        cms.add("Joomla")
    return cms


def _excerpt(text, start, end, radius=70, max_len=200):
    """Show what MATCHED, not the first N chars of a whole article column."""
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    out = ("…" if lo else "") + text[lo:hi] + ("…" if hi < len(text) else "")
    out = out.replace("\n", " ").replace("\r", " ")
    return out[:max_len]


# --- the engine -------------------------------------------------------------

_Account = namedtuple(
    "_Account",
    "cms table uid login email registered hash_type admin last_login blocked sessions")


def scan(case_dir, targets, ctx=None):
    """Analyze every dump under `targets`; write findings, accounts, table
    inventory and dump metadata into case.db. Returns a stats dict."""
    files = []
    for target in targets:
        for p in iter_target_files(target):
            if p.lower().endswith(SQL_EXTS):
                files.append(p)
    files = list(dict.fromkeys(files))
    stats = {"dumps": 0, "schema_files": 0, "findings": 0, "accounts": 0,
             "admins": 0, "tables": 0, "rows": 0, "skipped": 0}
    total_size = sum(os.path.getsize(p) for p in files if os.path.isfile(p)) or 1

    conn = db.connect(case_dir)
    try:
        done = 0
        for path in files:
            if ctx is not None and ctx.cancelled():
                break
            abs_path = os.path.abspath(path)
            try:
                size = os.path.getsize(path)
            except OSError:
                size = 0
            try:
                result = _scan_dump(path, size, total_size, done, ctx)
            except (OSError, EOFError, MemoryError) as e:
                conn.execute(
                    "INSERT INTO skipped (source, path, reason) VALUES (?,?,?)",
                    ("sqldb", abs_path, f"read/parse error: {e}"))
                stats["skipped"] += 1
                done += size
                continue
            done += size

            import json as _json
            cms_label = ", ".join(sorted(result["cms"])) or ""
            conn.execute("DELETE FROM db_dumps WHERE path = ?", (abs_path,))
            cur = conn.execute(
                "INSERT INTO db_dumps (path, meta, statements, size, cms, kind) "
                "VALUES (?,?,?,?,?,?)",
                (abs_path, _json.dumps(result["meta"]), result["statements"],
                 size, cms_label, result["kind"]))
            dump_id = cur.lastrowid
            conn.execute("DELETE FROM db_tables WHERE dump_id = ?", (dump_id,))
            conn.execute("DELETE FROM db_accounts WHERE dump_id = ?", (dump_id,))
            for name, t in sorted(result["tables"].items()):
                conn.execute(
                    "INSERT INTO db_tables (dump_id, name, columns, rows, bytes,"
                    " col_list) VALUES (?,?,?,?,?,?)",
                    (dump_id, name, len(t["columns"]), t["rows"], t["bytes"],
                     ", ".join(t["columns"])))
                stats["tables"] += 1
                stats["rows"] += t["rows"]
            for acc in result["accounts"]:
                conn.execute(
                    "INSERT INTO db_accounts (dump_id, cms, tbl, user_id, login,"
                    " email, registered, hash_type, admin, last_login, blocked,"
                    " sessions) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (dump_id, acc.cms, acc.table, acc.uid, acc.login, acc.email,
                     acc.registered, acc.hash_type, int(acc.admin),
                     acc.last_login, int(acc.blocked), int(acc.sessions)))
                stats["accounts"] += 1
                if acc.admin:
                    stats["admins"] += 1
            for sev, rule, table, row_no, evidence in result["findings"]:
                db.upsert_finding(conn, "sqldb", sev, rule, "table", table,
                                  line=row_no, evidence=evidence)
                stats["findings"] += 1
            if result["kind"] == "schema":
                stats["schema_files"] += 1
            else:
                stats["dumps"] += 1
            conn.commit()
        conn.commit()
    finally:
        conn.close()
    return stats


def _scan_dump(path, size, total_size, done_before, ctx):
    """One streaming pass over one dump."""
    tables_seen = []
    wp_admin_ids, joomla_super_ids = set(), set()
    wp_meta = {}                 # user_id -> last login / active session
    placeholder_seen = False     # `#__` -> a shipped schema file
    data_rows = 0
    user_tables = []
    row_offsets = {}
    inv = {}
    findings = []
    statements = 0
    name = os.path.basename(path)
    read_bytes = 0

    with open_text_auto(path) as f:
        meta = dump_meta(f)

    with open_text_auto(path) as f:
        for stmt in iter_statements(f):
            statements += 1
            read_bytes += len(stmt)
            if ctx is not None and statements % 200 == 0:
                if ctx.cancelled():
                    break
                frac = (done_before + min(size, read_bytes)) / total_size
                ctx.progress(0.02 + frac * 0.93,
                             f"{name}: {statements:,} statements, "
                             f"{sum(t['rows'] for t in inv.values()):,} rows")
            if not placeholder_seen and _PREFIX_PLACEHOLDER in stmt:
                placeholder_seen = True
            created = parse_create(stmt)
            if created:
                tname, cols = created
                entry = inv.setdefault(tname, _blank_table())
                entry["columns"] = [c for c, _t in cols]
                continue
            m = INSERT_RE.search(stmt)
            if m is None:
                continue
            table = m.group("table")
            rows = split_rows(stmt[m.end():])
            entry = inv.setdefault(table, _blank_table())
            entry["rows"] += len(rows)
            entry["bytes"] += len(stmt)
            data_rows += len(rows)
            if not entry["columns"]:
                named = insert_columns(m)
                if named:
                    entry["columns"] = named
                elif rows:
                    entry["columns"] = [f"col{i + 1}" for i in range(len(rows[0]))]
            if not rows:
                continue
            tables_seen.append(table)
            base = row_offsets.get(table, 0)
            row_offsets[table] = base + len(rows)
            suf = _suffix(table)
            for ridx, row in enumerate(rows):
                for col in row:
                    if not isinstance(col, str) or len(col) < 4:
                        continue
                    for sev, rule, rx in RULES:
                        hit = rx.search(col)
                        if hit:
                            findings.append((sev, rule, table, base + ridx + 1,
                                             _excerpt(col, *hit.span())))
                            break        # one finding per column is enough
            if suf == "users":
                user_tables.append((table, rows))
            elif suf == "usermeta":
                wp_admin_ids |= _wp_admin_ids(rows)
                for uid, sig in _wp_user_meta_signals(rows).items():
                    entry = wp_meta.setdefault(uid, {"last": "", "sessions": 0})
                    entry["sessions"] = max(entry["sessions"], sig["sessions"])
                    if sig["last"] > entry["last"]:
                        entry["last"] = sig["last"]
            elif suf == "user_usergroup_map":
                joomla_super_ids |= _joomla_super_ids(rows)

    cms = _detect_cms(tables_seen)
    cms_single = ("WordPress" if "WordPress" in cms
                  else "Joomla" if "Joomla" in cms else None)
    accounts = []
    for table, rows in user_tables:
        tbl_cms = cms_single or ("WordPress" if _suffix(table) == "users"
                                 and any(_looks_wordpress(r) for r in rows)
                                 else "Joomla")
        for uid, login, email, reg, htype, last, blocked in _extract_users(
                table, rows, tbl_cms):
            admin = (uid in wp_admin_ids) or (uid in joomla_super_ids)
            # Do NOT call this `meta`: in this function that is the header
            # data of the dump, which appears further down in the return
            # value.
            signals = wp_meta.get(uid, {})
            accounts.append(_Account(tbl_cms, table, uid, login, email, reg,
                                     htype, admin,
                                     last or signals.get("last", ""),
                                     blocked, signals.get("sessions", 0)))

    return {"meta": meta, "tables": inv, "statements": statements,
            "findings": findings, "accounts": accounts, "cms": cms,
            "kind": classify_dump(path, meta, placeholder_seen, data_rows)}


def _blank_table():
    return {"columns": [], "rows": 0, "bytes": 0}
