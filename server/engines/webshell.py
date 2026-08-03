# server/engines/webshell.py
"""Static webshell scanner (ported from legacy modules/webshell_scanner.py).

The rules were tuned against real Joomla incident data; the single most
effective discriminator is the CMS bootstrap guard (_JEXEC / ABSPATH): a PHP
file in a writable upload directory is only flagged when the guard is ABSENT
and the file has an executable surface. Ported rule-for-rule.
"""
import os
import re

from server import db
from server.engines.fsutil import get_files_recursive, sha256_of

PHP_EXTS = {".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar", ".inc"}
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".webp"}

UPLOAD_SEG_RE = re.compile(
    r"(?i)(^|[/\\])(images|tmp|cache|media|files|assets|upload|uploads"
    r"|wp-content[/\\]uploads|wp-content[/\\]cache)[/\\]")

EXCLUDE_PATH_RE = re.compile(
    r"(?i)("
    r"(^|[/\\])tmp[/\\]install_[^/\\]+[/\\]"
    r"|[/\\]media[/\\](system|vendor|legacy|templates|editors|com_\w+|mod_\w+|plg_\w+)[/\\]"
    r")")

CMS_GUARD_RE = re.compile(
    rb"(?i)(_JEXEC|JPATH_PLATFORM|defined\(\s*['\"]_JEXEC|\bABSPATH\b|\bWPINC\b|restricted access)")

EXEC_SURFACE_RE = re.compile(
    rb"(?i)("
    rb"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\b|\$GLOBALS\b|php://input"
    rb"|\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec"
    rb"|create_function|call_user_func(_array)?|preg_replace|extract|unserialize)\s*\("
    rb"|\b(base64_decode|gzinflate|gzuncompress|str_rot13|convert_uudecode|hex2bin)\s*\("
    rb"|\b(file_put_contents|fwrite|fputs|move_uploaded_file|copy|rename|unlink|chmod)\s*\("
    rb"|\b(include|include_once|require|require_once)\s*[\(\s]*\$"
    rb"|\$\w+\s*\("
    rb"|\bcurl_exec\s*\(|\bfsockopen\s*\("
    rb")")

INERT_STUB_BYTES = 4096

DOUBLE_EXT_RE = re.compile(
    r"(?i)\.(jpe?g|png|gif|bmp|ico|pdf|txt|zip|xml)\.(php\d?|phtml|phar|inc)$")

# (severity, rule name, regex) applied line-by-line. 0=HIGH 1=MEDIUM.
CONTENT_RULES = [
    (0, "eval/assert on decoded or request input",
     re.compile(r"(?i)\b(eval|assert)\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|strrev|\$_(POST|GET|REQUEST|COOKIE))")),
    (0, "Variable function called on request input",
     re.compile(r"\$\w+\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)")),
    (0, "Command execution on request input",
     re.compile(r"(?i)(shell_exec|passthru|proc_open|popen|pcntl_exec|system|exec)\s*\(\s*[^;]{0,40}\$_(POST|GET|REQUEST|COOKIE|SERVER)")),
    (0, "preg_replace with /e modifier (code execution)",
     re.compile(r"(?i)preg_replace\s*\(\s*(['\"]).*?[/#~|!%@][a-zA-Z]*e[a-zA-Z]*\1")),
    (0, "create_function / callback on request input",
     re.compile(r"(?i)(create_function\s*\(\s*['\"]|call_user_func(_array)?\s*\(\s*\$_)")),
    (0, "File dropper writing request input to disk",
     re.compile(r"(?i)(move_uploaded_file|file_put_contents|fwrite)\s*\(.{0,80}\$_(POST|GET|REQUEST|FILES)")),
    (1, "Obfuscation decode chain",
     re.compile(r"(?i)(base64_decode\s*\(\s*(str_rot13|strrev|gzinflate|gzuncompress)|gzinflate\s*\(\s*(base64_decode|str_rot13)|str_rot13\s*\(\s*base64_decode)")),
    (1, "Hex/octal string obfuscation",
     re.compile(r"((\\x[0-9a-fA-F]{2}|\\[0-7]{3})){10,}")),
    (1, "chr() concatenation obfuscation",
     re.compile(r"(?i)(chr\s*\(\s*\d+\s*\)\s*\.\s*){5,}")),
    (1, "goto-based control-flow obfuscation",
     re.compile(r"(?i)\bgoto\s+\w{1,20}\s*;")),
    (1, "Standalone command-execution shell",
     re.compile(r"(?i)\b(shell_exec|passthru|proc_open|pcntl_exec)\s*\(")),
]

HTACCESS_RULES = [
    (0, ".htaccess maps non-PHP extension to PHP handler",
     re.compile(r"(?i)(AddHandler|AddType|SetHandler)[^\n]*(php|x-httpd)")),
    (0, ".htaccess auto_prepend/append_file backdoor",
     re.compile(r"(?i)auto_(prepend|append)_file")),
]

MAX_CONTENT_SCAN_BYTES = 5 * 1024 * 1024
GUARD_SNIFF_BYTES = 4096


def in_upload_dir(path_str):
    return bool(UPLOAD_SEG_RE.search(path_str)) and not EXCLUDE_PATH_RE.search(path_str)


def _truncate(text, limit=160):
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + "…"


def _scan_lines(text, rules):
    for line_num, line in enumerate(text.splitlines(), 1):
        for severity, name, rx in rules:
            if rx.search(line):
                yield severity, name, line_num, _truncate(line)


def scan_file(file_path):
    """Scan one file. Returns (findings, skip_reason, inert) where findings is
    [(severity, rule, line, evidence)]."""
    abs_path = os.path.abspath(file_path)
    base_name = os.path.basename(file_path).lower()
    ext = os.path.splitext(base_name)[1]
    findings = []

    is_php = ext in PHP_EXTS
    is_image = ext in IMAGE_EXTS
    is_htaccess = base_name == ".htaccess"

    if DOUBLE_EXT_RE.search(base_name):
        findings.append((0, "Double extension disguise (e.g. logo.jpg.php)",
                         None, base_name))

    if not (is_php or is_image or is_htaccess):
        return findings, None, None

    try:
        size = os.path.getsize(file_path)
    except OSError as e:
        if is_php and in_upload_dir(abs_path):
            findings.append((0, "Unguarded-location PHP could not be read",
                             None, base_name))
        return findings, f"read error: {e}", None

    if size > MAX_CONTENT_SCAN_BYTES:
        if is_php and in_upload_dir(abs_path):
            findings.append((0, "PHP in writable upload directory (too large to inspect)",
                             None, base_name))
        return findings, f"too large for content scan ({size} bytes)", None

    try:
        with open(file_path, "rb") as f:
            raw = f.read()
    except OSError as e:
        if is_php and in_upload_dir(abs_path):
            findings.append((0, "Unguarded-location PHP could not be read",
                             None, base_name))
        return findings, f"read error: {e}", None

    if is_image:
        if b"<?php" in raw or b"<?=" in raw:
            findings.append((0, "PHP code hidden inside image file", None,
                             f"'<?php' tag found in {ext} file"))
        return findings, None, None

    text = raw.decode("utf-8", errors="replace")

    if is_htaccess:
        findings.extend(_scan_lines(text, HTACCESS_RULES))
        return findings, None, None

    findings.extend(_scan_lines(text, CONTENT_RULES))

    if in_upload_dir(abs_path) and not CMS_GUARD_RE.search(raw[:GUARD_SNIFF_BYTES]):
        if EXEC_SURFACE_RE.search(raw):
            findings.append((0, "Unguarded PHP in writable upload directory "
                                "(executable, no _JEXEC/ABSPATH)", None, base_name))
        else:
            reason = (f"no executable surface ({len(raw)} bytes"
                      + (", likely a directory stub)" if len(raw) <= INERT_STUB_BYTES
                         else ")"))
            return findings, None, (abs_path, reason)

    return findings, None, None


def scan(case_dir, targets, ctx=None):
    """Scan every file under `targets`; write findings straight into case.db.
    Flagged files are hashed (SHA-256) so the IOC box can carry both path and
    hash without a second pass."""
    stats = {"scanned": 0, "findings": 0, "flagged_files": 0, "inert": 0,
             "skipped": 0}
    files = []
    for target in targets:
        if os.path.isfile(target):
            files.append(target)
        else:
            files.extend(get_files_recursive(target))
    total = len(files) or 1

    conn = db.connect(case_dir)
    try:
        conn.execute("DELETE FROM inert_php")
        conn.execute("DELETE FROM skipped WHERE source = 'webshell'")
        flagged = set()
        for i, file_path in enumerate(files):
            if ctx is not None and i % 200 == 0:
                if ctx.cancelled():
                    break
                ctx.progress(0.02 + (i / total) * 0.93,
                             f"{i:,}/{total:,} Dateien — {stats['findings']} Findings")
            stats["scanned"] += 1
            findings, skip_reason, inert = scan_file(file_path)
            abs_path = os.path.abspath(file_path)
            for severity, rule, line, evidence in findings:
                db.upsert_finding(conn, "webshell", severity, rule, "file",
                                  abs_path, line=line, evidence=evidence)
                stats["findings"] += 1
                flagged.add(abs_path)
            if inert:
                conn.execute("INSERT INTO inert_php (path, reason) VALUES (?,?)",
                             inert)
                stats["inert"] += 1
            if skip_reason:
                conn.execute(
                    "INSERT INTO skipped (source, path, reason) VALUES (?,?,?)",
                    ("webshell", abs_path, skip_reason))
                stats["skipped"] += 1
            if i % 500 == 0:
                conn.commit()
        stats["flagged_files"] = len(flagged)

        # Hash the flagged set now -- it is small, and "path + hash" is what a
        # hand-off list needs. Stored as IOC-ready facts on the finding rows.
        if ctx is not None:
            ctx.progress(0.96, f"Hashe {len(flagged)} auffällige Datei(en)…")
        hashes = {}
        for path in flagged:
            digest = sha256_of(path)
            if digest:
                hashes[path] = digest
        if hashes:
            import json as _json
            conn.execute("INSERT OR REPLACE INTO meta VALUES ('webshell_hashes', ?)",
                         (_json.dumps(hashes),))
        conn.commit()
    finally:
        conn.close()
    return stats
