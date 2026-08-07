# server/engines/webshell.py
"""Static webshell scanner.

The rules were tuned against real Joomla incident data; the single most
effective discriminator is the CMS bootstrap guard (_JEXEC / ABSPATH): a PHP
file in a writable upload directory is only flagged when the guard is ABSENT
and the file has an executable surface.

THE CONTENT RULES ARE YARA NOW (`server/rules_bundled/`). What is left in
this file is everything YARA cannot express, and the split is not arbitrary:

  * A rule about a file's CONTENT is a YARA rule. That is what YARA is.
  * A rule about its LOCATION, its NAME, or the fact that it could not be
    read at all is not -- YARA is handed bytes and never learns where they
    came from. Those stay here.

So `Double extension disguise` and `Unguarded PHP in writable upload
directory` are Python, and every pattern that looks INSIDE a file is a
bundled YARA rule the analyst can read and switch off.

The names the findings carry are unchanged across that move, because they
are part of the triage fingerprint: a decision somebody made about a file
last week still applies to it today.
"""
import json
import os
import re

from server import bundled_rules, db, ruleswitch
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

MAX_CONTENT_SCAN_BYTES = 5 * 1024 * 1024
GUARD_SNIFF_BYTES = 4096


def _site_path(abs_path, root):
    """The file as the SERVER sees it: `/` plus its path below the webroot.

    Without a root the absolute path is all there is -- that is the old
    behaviour and it stays for callers that scan a loose file, but everything
    above the webroot is the analyst's business and must not decide anything.
    """
    if not root:
        return abs_path
    target = str(abs_path).replace("\\", "/")
    base = os.path.abspath(str(root)).replace("\\", "/").rstrip("/")
    if base and target.lower().startswith(base.lower() + "/"):
        return "/" + target[len(base) + 1:]
    return abs_path


def in_upload_dir(path_str):
    return bool(UPLOAD_SEG_RE.search(path_str)) and not EXCLUDE_PATH_RE.search(path_str)


def _truncate(text, limit=160):
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + "…"


def _line_index(raw):
    """Byte offset -> line number, and the line's bounds. Built ONCE per
    file: a match carries an offset, and every finding needs the line it sits
    on plus that line's text as evidence."""
    starts = [0]
    for i, byte in enumerate(raw):
        if byte == 0x0A:
            starts.append(i + 1)
    return starts


def _at_offset(raw, starts, offset):
    """(line number, the line) for a byte offset."""
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= offset:
            lo = mid
        else:
            hi = mid - 1
    begin = starts[lo]
    end = raw.find(b"\n", begin)
    line = raw[begin:end if end >= 0 else len(raw)]
    return lo + 1, line.decode("utf-8", errors="replace")


def _yara_findings(raw, kind):
    """Run the bundled rules of one kind over a file's bytes.

    Yields (rule_id, severity, name, line, evidence) -- the same shape the
    regex tables produced, and deliberately so: everything downstream, up to
    and including the triage fingerprint, must not notice the change.

    ONE FINDING PER RULE PER LINE, like before. YARA reports every instance
    of a string; a rule that matches four times on one line used to produce
    one finding, not four."""
    matches = bundled_rules.compiled(kind).match(data=raw)
    if not matches:
        return
    starts = _line_index(raw)
    seen = set()
    out = []
    for match in matches:
        meta = match.meta
        rule_id = meta.get("id")
        if not rule_id:
            continue
        severity = bundled_rules.severity_of(meta.get("severity"))
        name = meta.get("name") or match.rule
        for string_match in match.strings:
            for instance in string_match.instances:
                line_no, line = _at_offset(raw, starts, instance.offset)
                if (rule_id, line_no) in seen:
                    continue
                seen.add((rule_id, line_no))
                out.append((rule_id, severity, name, line_no,
                            _truncate(line)))
    # By line, so a file reads top to bottom like it used to.
    out.sort(key=lambda row: (row[3], row[0]))
    yield from out


def scan_file(file_path, root=None):
    """Scan one file. Returns (findings, skip_reason, inert) where findings is
    [(rule_id, severity, rule, line, evidence)].

    `root` is the registered webroot. WITHOUT IT THE LOCATION RULES READ THE
    ANALYST'S OWN DISK: `in_upload_dir` walked the absolute path, so evidence
    unpacked below a folder called `files`, `uploads` or `media` turned every
    unguarded PHP file on the site into a HIGH finding about a "writable
    upload directory" that exists on no server. What decides has to be the
    path INSIDE the webroot, which is the only part that describes the site.

    Every finding carries the id of the rule that produced it, so `scan` can
    drop the ones this workspace has switched off in one place instead of
    each rule having to remember to ask."""
    abs_path = os.path.abspath(file_path)
    site_path = _site_path(abs_path, root)
    base_name = os.path.basename(file_path).lower()
    ext = os.path.splitext(base_name)[1]
    findings = []

    is_php = ext in PHP_EXTS
    is_image = ext in IMAGE_EXTS
    is_htaccess = base_name == ".htaccess"

    if DOUBLE_EXT_RE.search(base_name):
        findings.append(("webshell.double_ext", 0,
                         "Double extension disguise (e.g. logo.jpg.php)",
                         None, base_name))

    if not (is_php or is_image or is_htaccess):
        return findings, None, None

    try:
        size = os.path.getsize(file_path)
    except OSError as e:
        if is_php and in_upload_dir(site_path):
            findings.append(("webshell.unreadable", 0,
                             "Unguarded-location PHP could not be read",
                             None, base_name))
        return findings, f"read error: {e}", None

    if size > MAX_CONTENT_SCAN_BYTES:
        if is_php and in_upload_dir(site_path):
            findings.append(("webshell.too_large", 0,
                             "PHP in writable upload directory (too large to inspect)",
                             None, base_name))
        return findings, f"too large for content scan ({size} bytes)", None

    try:
        with open(file_path, "rb") as f:
            raw = f.read()
    except OSError as e:
        if is_php and in_upload_dir(site_path):
            findings.append(("webshell.unreadable", 0,
                             "Unguarded-location PHP could not be read",
                             None, base_name))
        return findings, f"read error: {e}", None

    if is_image:
        # `<?PHP` and `<?Php` open PHP just as `<?php` does -- the language
        # does not care about the case and neither may the check. A shell
        # hidden in an image only had to shout to get past it.
        if b"<?php" in raw.lower() or b"<?=" in raw:
            findings.append(("webshell.php_in_image", 0,
                             "PHP code hidden inside image file", None,
                             f"'<?php' tag found in {ext} file"))
        return findings, None, None

    text = raw.decode("utf-8", errors="replace")

    if is_htaccess:
        findings.extend(_yara_findings(raw, "htaccess"))
        return findings, None, None

    findings.extend(_yara_findings(raw, "content"))

    if in_upload_dir(site_path) and not CMS_GUARD_RE.search(raw[:GUARD_SNIFF_BYTES]):
        if EXEC_SURFACE_RE.search(raw):
            findings.append(("webshell.upload_php", 0,
                             "Unguarded PHP in writable upload directory "
                             "(executable, no _JEXEC/ABSPATH)", None, base_name))
        else:
            reason = (f"no executable surface ({len(raw)} bytes"
                      + (", likely a directory stub)" if len(raw) <= INERT_STUB_BYTES
                         else ")"))
            return findings, None, (abs_path, reason)

    return findings, None, None


def scan(case_dir, targets, ctx=None, workspace=None):
    """Scan every file under `targets`; write findings straight into case.db.
    Flagged files are hashed (SHA-256) so the IOC box can carry both path and
    hash without a second pass."""
    stats = {"scanned": 0, "findings": 0, "flagged_files": 0, "inert": 0,
             "skipped": 0}
    # Read ONCE. The answer cannot change mid-run, and a settings read per
    # line of every file in a webroot is a different kind of tool.
    off = ruleswitch.disabled_ids(workspace) if workspace else set()
    # Each file remembers WHICH TARGET it came out of: the location rules
    # need the path below that root, not the one on this machine.
    files = []
    for target in targets:
        if os.path.isfile(target):
            files.append((target, os.path.dirname(target)))
        else:
            files.extend((f, target) for f in get_files_recursive(target))
    total = len(files) or 1

    conn = db.connect(case_dir)
    try:
        conn.execute("DELETE FROM inert_php")
        conn.execute("DELETE FROM skipped WHERE source = 'webshell'")
        flagged = set()
        for i, (file_path, root) in enumerate(files):
            if ctx is not None and i % 200 == 0:
                if ctx.cancelled():
                    break
                ctx.progress(0.02 + (i / total) * 0.93,
                             f"{i:,}/{total:,} files — "
                             f"{stats['findings']} findings")
            stats["scanned"] += 1
            findings, skip_reason, inert = scan_file(file_path, root)
            abs_path = os.path.abspath(file_path)
            for rule_id, severity, rule, line, evidence in findings:
                if rule_id in off:
                    continue
                db.upsert_finding(conn, "webshell", severity, rule, "file",
                                  abs_path, line=line, evidence=evidence,
                                  rule_id=rule_id)
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
            ctx.progress(0.96, f"Hashing {len(flagged)} conspicuous file(s)…")
        hashes = {}
        for path in flagged:
            digest = sha256_of(path)
            if digest:
                hashes[path] = digest
        # Written UNCONDITIONALLY, empty result included: these hashes are a
        # measurement of THIS run. Keeping the previous map when a re-scan
        # flags nothing would hand a confirmation the digest of a file that is
        # no longer there -- a hash in the IOC box that nothing measured.
        conn.execute("INSERT OR REPLACE INTO meta VALUES ('webshell_hashes', ?)",
                     (json.dumps(hashes),))
        conn.commit()
    finally:
        conn.close()
    return stats
