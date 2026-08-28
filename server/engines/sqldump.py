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

from server import cmsintelligence, db, ruleswitch
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
# ANCHORED AT THE START OF THE STATEMENT. Unanchored it also found the words
# inside a VALUE -- a wp_options row holding a schema backup, a post about SQL,
# an attacker staging DDL -- and the whole INSERT was then read as a CREATE:
# its rows vanished from the inventory without ever being scanned, and a table
# that exists nowhere in the database appeared instead.
CREATE_RE = re.compile(
    r"^(?:\s*(?:--[^\n]*\n|\#[^\n]*\n|/\*.*?\*/))*\s*"
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
    r"`?(?P<table>[A-Za-z0-9_$#]+)`?\s*\(",
    re.IGNORECASE | re.DOTALL)
_COL_RE = re.compile(r"^\s*`(?P<name>[^`]+)`\s+(?P<type>[A-Za-z]+)")
_NOT_A_COLUMN = re.compile(
    r"^\s*(PRIMARY\s+KEY|UNIQUE|KEY|INDEX|FULLTEXT|SPATIAL|CONSTRAINT|FOREIGN\s+KEY|CHECK)\b",
    re.IGNORECASE)

# --- code-in-data signatures ------------------------------------------------
# HIGH: executable/obfuscated code has no business in a data column.
# MEDIUM: markup that CAN be legitimate stored content.
RULES = [
    ("sqldb.php_tag", 0, "PHP open tag in database value",
     re.compile(r"<\?php|<\?=")),
    ("sqldb.eval_input", 0, "eval/assert on decoded or request input",
     re.compile(r"(?i)\b(eval|assert)\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_)")),
    ("sqldb.obfuscation", 0, "Obfuscation decode chain",
     re.compile(r"(?i)(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(\s*(base64_decode|gzinflate|str_rot13|['\"])")),
    ("sqldb.cmd_call", 0, "Command execution call in database value",
     re.compile(r"(?i)\b(system|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(")),
    ("sqldb.create_function", 0, "create_function / dynamic callback",
     re.compile(r"(?i)create_function\s*\(")),
    ("sqldb.script", 1, "Inline <script> in database value",
     re.compile(r"(?i)<script[\s>]")),
    ("sqldb.iframe", 1, "Injected <iframe> in database value",
     re.compile(r"(?i)<iframe[\s>]")),
    ("sqldb.document_write", 1, "document.write (script injection)",
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

# The CMS this toolkit knows in DETAIL are WordPress and Joomla -- their
# account tables are read by column position, because their schemas are
# fixed and documented. Everything below is the other half of the answer:
# recognising that a dump belongs to some OTHER CMS, and finding its accounts
# anyway.
#
# Naming the CMS is worth doing on its own: "Drupal export, 1 user table, 3
# admins" is a usable sentence, and it stops the Database view from calling a
# TYPO3 dump "unknown" as if nothing could be read from it.
_CMS_MARKERS = {
    "Drupal": ("users_field_data", "node_field_data", "watchdog",
               "config", "key_value"),
    "TYPO3": ("be_users", "fe_users", "sys_log", "tt_content", "sys_template"),
    "Magento": ("admin_user", "catalog_product_entity", "sales_order",
                "core_config_data"),
    "PrestaShop": ("employee", "ps_employee", "customer", "configuration"),
    "Contao": ("tl_user", "tl_member", "tl_page", "tl_content"),
}

# Tables that hold accounts in the CMS above. Checked by suffix, so a
# `t3_be_users` or `drupal8_users_field_data` is found too.
_USER_TABLE_NAMES = (
    "users", "user", "be_users", "fe_users", "users_field_data",
    "admin_user", "employee", "tl_user", "tl_member", "customer",
    "customer_entity", "accounts", "members",
)

# A table nobody named that still holds accounts. Recognised by its COLUMNS,
# which is the only signal left when the schema is unknown -- and a better
# one than the name: a table called `wp_users` with no e-mail column is not
# an account table, and one called `kunden` with login/email/password is.
_LOGIN_COLS = ("login", "username", "user_name", "user_login", "name",
               "handle", "nick", "account")
_EMAIL_COLS = ("email", "mail", "e_mail", "user_email", "emailaddress")
_PASS_COLS = ("password", "passwd", "pass", "user_pass", "pwd", "hash",
              "password_hash")


def _looks_like_user_table(columns):
    """True when the COLUMNS say accounts, whatever the table is called.

    All three are required. Two would match half the tables in a shop
    database -- an `orders` table has a name and an e-mail on it too, and
    filling the account list with customers of a webshop would bury the one
    planted administrator."""
    low = {str(c).strip().strip("`").lower() for c in columns or ()}
    if not low:
        return False

    def has(candidates):
        return any(c == cand or c.endswith("_" + cand)
                   for c in low for cand in candidates)

    return has(_LOGIN_COLS) and has(_EMAIL_COLS) and has(_PASS_COLS)


def _is_user_table(table, columns):
    suffix = _suffix(table)
    low = str(table).lower().strip("`")
    if suffix in _USER_TABLE_NAMES or any(
            low.endswith(name) for name in _USER_TABLE_NAMES):
        return True
    return _looks_like_user_table(columns)


def _column_index(columns, candidates):
    """Where a column of this kind sits, or None. Exact match first, then a
    suffix match -- `user_email` counts as an e-mail column, `email_verified`
    does not."""
    low = [str(c).strip().strip("`").lower() for c in columns or ()]
    for i, name in enumerate(low):
        if name in candidates:
            return i
    for i, name in enumerate(low):
        if any(name.endswith("_" + cand) for cand in candidates):
            return i
    return None


_REG_COLS = ("registered", "created", "created_at", "crdate", "user_registered",
             "registerdate", "date_add", "regdate", "dateadd")
_LAST_COLS = ("last_login", "lastvisitdate", "lastlogin", "last_access",
              "lastvisit", "last_seen", "date_upd", "access")
_BLOCK_COLS = ("block", "blocked", "disable", "disabled", "banned", "deleted",
               "active", "status", "user_status")
_ID_COLS = ("id", "uid", "user_id", "userid", "id_employee", "entity_id")


def _extract_users_by_columns(rows, columns):
    """Accounts from a table whose SCHEMA is unknown, read by column name.

    This is what makes an unknown CMS usable rather than merely named. What
    cannot be located stays empty -- a guessed timestamp would be worse than
    none, the same rule the WordPress and Joomla readers follow."""
    idx = {
        "id": _column_index(columns, _ID_COLS),
        "login": _column_index(columns, _LOGIN_COLS),
        "email": _column_index(columns, _EMAIL_COLS),
        "pass": _column_index(columns, _PASS_COLS),
        "reg": _column_index(columns, _REG_COLS),
        "last": _column_index(columns, _LAST_COLS),
        "block": _column_index(columns, _BLOCK_COLS),
    }

    def at(row, key):
        i = idx[key]
        return row[i] if i is not None and i < len(row) else None

    users = []
    for row in rows:
        if len(row) < 2:
            continue
        uid = at(row, "id")
        login = at(row, "login")
        email = at(row, "email")
        if not login and not email:
            continue
        blocked = 0
        raw_block = at(row, "block")
        if raw_block is not None:
            try:
                flag = int(str(raw_block).strip() or 0)
                # `active`/`status` mean the OPPOSITE of `blocked`. Reading
                # them the same way would report every live account as
                # locked -- and an account list that lies about who can log
                # in is worse than one without the column.
                name = [str(c).lower() for c in (columns or [])]
                col = name[idx["block"]] if idx["block"] is not None else ""
                blocked = (0 if flag else 1) if col.endswith(
                    ("active", "status")) else (1 if flag else 0)
            except ValueError:
                blocked = 0
        users.append((
            str(uid).strip() if uid is not None else "?",
            str(login or email or "?"),
            str(email or "-"),
            _stamp_or_blank(at(row, "reg")) or "-",
            _hash_type(at(row, "pass")),
            _stamp_or_blank(at(row, "last")),
            blocked,
        ))
    return users


def _stamp_or_blank(value):
    """A timestamp, or nothing.

    Column NAMES are a guess when the schema is unknown -- a `access` column
    is a date in Drupal and could be a permission flag somewhere else. So the
    VALUE decides: what does not read as a date is dropped rather than shown
    as one. An account list that presents `1` as a login date is worse than
    one with the column empty."""
    text = _clean_stamp(value)
    return text if _is_datetime(text) else ""

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
        return _unescape(t[1:-1])
    return t


_SQL_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "b": "\b",
                "Z": "\x1a"}


def _unescape(inner):
    """MySQL's backslash escapes, read LEFT TO RIGHT.

    A chain of `.replace()` calls cannot do this. In a dump `\\\\` is ONE
    literal backslash, so `'C:\\\\new'` means `C:\\new` -- backslash, then the
    letter n. Replacing the `\\n` sequence first consumed the second backslash
    and produced a line break before the `\\\\` rule ever looked at it, and the
    value in the report was then not the value in the database.

    One pass, each escape decided once, so no rule can eat another's input."""
    out, i = [], 0
    while i < len(inner):
        char = inner[i]
        if char == "\\" and i + 1 < len(inner):
            nxt = inner[i + 1]
            # An unknown escape is the character itself -- that is what MySQL
            # does, and inventing a meaning for it would be worse.
            out.append(_SQL_ESCAPES.get(nxt, nxt))
            i += 2
            continue
        if char == "'" and i + 1 < len(inner) and inner[i + 1] == "'":
            out.append("'")
            i += 2
            continue
        out.append(char)
        i += 1
    return "".join(out)


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


def _flag(value):
    """A tinyint column as 0/1. Anything unreadable is 0 -- claiming an
    account is blocked when the column could not be read would be a statement
    the data does not support."""
    try:
        return 1 if int(str(value).strip() or 0) else 0
    except (TypeError, ValueError):
        return 0


# Joomla 1.x/2.5 kept the permission on the account itself. 25 is Super
# Administrator, 24 Administrator; the `usertype` column spells the same
# thing out. From 3.0 the answer moved to #__user_usergroup_map, which is
# where `_joomla_super_ids` reads it.
_JOOMLA_LEGACY_ADMIN_GIDS = {"24", "25"}
_JOOMLA_LEGACY_ADMIN_TYPES = {"administrator", "super administrator"}


def _joomla_legacy_admin(row, index_of):
    """Is this 1.x account an administrator? False when the columns that
    would say so are not in this dump."""
    gid = index_of.get("gid")
    if gid is not None and gid < len(row):
        if str(row[gid]).strip() in _JOOMLA_LEGACY_ADMIN_GIDS:
            return True
    usertype = index_of.get("usertype")
    if usertype is not None and usertype < len(row):
        return str(row[usertype]).strip().lower() in _JOOMLA_LEGACY_ADMIN_TYPES
    return False


def _extract_users(table, rows, cms, columns=()):
    """(uid, login, email, registered, hash, last_login, blocked, admin).

    Last login and block status only exist where the CMS carries them: Joomla
    has both fixed in its schema (lastvisitDate, block), WordPress core has no
    last login at all -- there it comes, if at all, from the usermeta of a
    plugin and is added later. What is missing stays empty; a guessed
    timestamp would be worse than none."""
    index_of = {str(name).strip().strip("`").lower(): i
                for i, name in enumerate(columns or ())}
    users = []
    for row in rows:
        if len(row) < 4:
            continue

        def at(name, fallback):
            """The value of a named column, or the fallback when this dump
            gave no CREATE TABLE to read the names from."""
            i = index_of.get(name)
            return row[i] if i is not None and i < len(row) else fallback

        uid = str(row[0]).strip() if row[0] is not None else "?"
        last, blocked, admin = "", 0, False
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
            login = at("username", row[2])
            email = at("email", row[3])
            pw = at("password", row[4])
            # BY NAME WHERE THE NAMES ARE KNOWN. The fixed positions below
            # are Joomla 3.x and later; version 1.x and 2.5 carry `usertype`
            # and `gid` between the password and the dates, which pushes both
            # of them two columns along. Read positionally, a 1.5 export
            # reported the sendEmail flag as the registration date and the
            # group id as the last login -- and the chronology then dropped
            # the account entirely, because "1" is not a timestamp.
            if columns:
                reg = at("registerdate", None)
                last = _clean_stamp(at("lastvisitdate", None))
                blocked = _flag(at("block", None))
            elif len(row) >= 9:
                blocked = _flag(row[5])
                reg = row[7]
                last = _clean_stamp(row[8])
            else:
                reg = _first(_is_datetime, row)
            # Joomla 1.x/2.5 kept the permission on the ACCOUNT. From 3.0 it
            # lives in the group map, and only that was ever read -- so on a
            # 1.5 export, which has no such table, the Super Administrator
            # came back as an ordinary user and the case reported no admins
            # at all. Old installations are disproportionately the
            # compromised ones.
            admin = _joomla_legacy_admin(row, index_of)
        else:
            email = _first(_is_email, row)
            reg = _first(_is_datetime, row)
            login = row[1] if len(row) > 1 else uid
            pw = _first(lambda v: isinstance(v, str) and v.startswith("$"), row)
        users.append((uid, str(login or "?"), str(email or "-"),
                      _clean_stamp(reg) or "-", _hash_type(pw), last, blocked,
                      admin))
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
    lowered = {str(t).lower().strip("`") for t in tables}
    cms = set()
    if suffixes & set(_WP_SUFFIXES) and ("usermeta" in suffixes or "options" in suffixes):
        cms.add("WordPress")
    # TWO markers for Joomla as well, not one. A single one was enough until
    # a TYPO3 dump arrived: `tt_content` ends in `content`, so every TYPO3
    # export was also announced as Joomla. One shared table name is a
    # coincidence -- `content`, `session` and `menu` are words half the
    # schemas in the world use.
    if len(suffixes & set(_JOOMLA_SUFFIXES)) >= 2:
        cms.add("Joomla")
    # The others are NAMED, not parsed in detail: two of their marker tables
    # have to be there. One is a coincidence -- plenty of schemas have a
    # `config` or a `customer` table.
    for name, markers in _CMS_MARKERS.items():
        hits = sum(1 for m in markers
                   if m in suffixes or any(t.endswith(m) for t in lowered))
        if hits >= 2:
            cms.add(name)
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


def _with_source(conn, rule, table, row_no, evidence, dump_name):
    """`evidence`, with every dump this finding has been seen in named.

    Two dumps holding the same table, the same row number and the same rule
    produce ONE finding -- the fingerprint is source|rule|artifact|line, and
    widening it would orphan every triage decision already made. Without this
    the second dump silently overwrote the first one's evidence and the case
    reported one compromised host where there were two.
    """
    tag = f"dump: {dump_name}"
    fp = db.fingerprint("sqldb", rule, table, row_no)
    row = db.one(conn, "SELECT evidence FROM findings WHERE fingerprint = ?",
                 (fp,))
    seen = [part for part in str(row["evidence"] if row else "").split(" · ")
            if part.startswith("dump: ")]
    if tag not in seen:
        seen.append(tag)
    return (evidence + " · " + ", ".join(seen))[:400]


def scan(case_dir, targets, ctx=None, workspace=None):
    """Analyze every dump under `targets`; write findings, accounts, table
    inventory and dump metadata into case.db. Returns a stats dict."""
    files = []
    for target in targets:
        for p in iter_target_files(target):
            if p.lower().endswith(SQL_EXTS):
                files.append(p)
    files = list(dict.fromkeys(files))
    off = ruleswitch.disabled_ids(workspace) if workspace else set()
    stats = {"dumps": 0, "schema_files": 0, "findings": 0, "accounts": 0,
             "admins": 0, "tables": 0, "rows": 0, "skipped": 0}
    total_size = sum(os.path.getsize(p) for p in files if os.path.isfile(p)) or 1

    conn = db.connect(case_dir)
    try:
        run = db.begin_run(conn, "sqldump")
        cancelled = False
        done = 0
        for path in files:
            if ctx is not None and ctx.cancelled():
                cancelled = True
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
            # THE OLD ROWS BELONG TO THE OLD ID. Deleting the children by the
            # id the INSERT has just handed out misses them entirely -- it
            # only appeared to work because SQLite reuses the rowid when the
            # deleted row was the last one. With a second dump in the case the
            # id is not reused, the old accounts stay behind orphaned, and the
            # chronology -- which does not join db_dumps -- then read the same
            # account twice.
            for old in conn.execute("SELECT id FROM db_dumps WHERE path = ?",
                                    (abs_path,)).fetchall():
                conn.execute("DELETE FROM db_tables WHERE dump_id = ?",
                             (old["id"],))
                conn.execute("DELETE FROM db_accounts WHERE dump_id = ?",
                             (old["id"],))
            conn.execute("DELETE FROM db_dumps WHERE path = ?", (abs_path,))
            cur = conn.execute(
                "INSERT INTO db_dumps (path, meta, statements, size, cms, "
                "intelligence, kind) VALUES (?,?,?,?,?,?,?)",
                (abs_path, _json.dumps(result["meta"]), result["statements"],
                 size, cms_label,
                 _json.dumps(result["intelligence"], ensure_ascii=False,
                             separators=(",", ":")),
                 result["kind"]))
            dump_id = cur.lastrowid
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
            for rid, sev, rule, table, row_no, evidence in result["findings"]:
                if rid in off:
                    continue
                # WHICH DUMP THIS CAME OUT OF. The fingerprint is
                # source|rule|artifact|line and deliberately stays that way --
                # widening it would orphan every decision an analyst has
                # already made. The consequence is that the same table, row
                # and rule in two dumps is ONE finding, so the evidence has to
                # name every dump it was seen in; otherwise the second host
                # silently overwrites the first and the case reports one
                # compromise where there were two.
                db.upsert_finding(conn, "sqldb", sev, rule, "table", table,
                                  line=row_no,
                                  evidence=_with_source(
                                      conn, rule, table, row_no, evidence,
                                      os.path.basename(abs_path)),
                                  rule_id=rid, engine="sqldump", run=run)
                stats["findings"] += 1
            if result["kind"] == "schema":
                stats["schema_files"] += 1
            else:
                stats["dumps"] += 1
            conn.commit()
        conn.commit()
        # Only a run that read every dump may retire what it did not
        # reproduce; a cancelled one has no opinion about the rest.
        if not cancelled:
            db.complete_run(conn, "sqldump", run)
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
    intelligence = cmsintelligence.Collector()
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
            # The placeholder marks a SHIPPED SCHEMA, where table names read
            # `#__users` because the installer fills the prefix in later. It
            # is a statement about the NAME -- looking for it anywhere in the
            # text filed a real export as a template as soon as one row
            # happened to mention `#__content`, which any CMS documentation
            # table does.
            if not placeholder_seen:
                named = CREATE_RE.search(stmt) or INSERT_RE.search(stmt)
                if named and _PREFIX_PLACEHOLDER in named.group("table"):
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
            intelligence.collect(table, entry["columns"], rows, row_offset=base)
            for ridx, row in enumerate(rows):
                for col in row:
                    if not isinstance(col, str) or len(col) < 4:
                        continue
                    for rid, sev, rule, rx in RULES:
                        hit = rx.search(col)
                        if hit:
                            findings.append((rid, sev, rule, table,
                                             base + ridx + 1,
                                             _excerpt(col, *hit.span())))
                            break        # one finding per column is enough
            if _is_user_table(table, entry["columns"]):
                user_tables.append((table, rows, list(entry["columns"])))
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
    for table, rows, columns in user_tables:
        # WordPress and Joomla are read by column POSITION, because their
        # schemas are fixed. Anything else -- a known-but-not-parsed CMS or
        # none at all -- is read by column NAME, which is the only signal
        # left when the schema is unknown.
        if cms_single in ("WordPress", "Joomla"):
            tbl_cms = cms_single
        elif _suffix(table) == "users" and any(_looks_wordpress(r) for r in rows):
            tbl_cms = "WordPress"
        else:
            tbl_cms = ""
        if tbl_cms:
            extracted = _extract_users(table, rows, tbl_cms, columns)
        else:
            extracted = [row + (False,)
                         for row in _extract_users_by_columns(rows, columns)]
            tbl_cms = ", ".join(sorted(cms)) or "unknown"
        for uid, login, email, reg, htype, last, blocked, own in extracted:
            # Three sources, because three Joomla generations answer it in
            # three places: WordPress in usermeta, Joomla 3+ in the group
            # map, Joomla 1.x/2.5 on the account row itself.
            admin = own or (uid in wp_admin_ids) or (uid in joomla_super_ids)
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
            "intelligence": intelligence.finish(cms),
            "kind": classify_dump(path, meta, placeholder_seen, data_rows)}


def _blank_table():
    return {"columns": [], "rows": 0, "bytes": 0}
