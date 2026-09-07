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
import codecs
import json
import os
import re
import stat

import yara

from server import bundled_rules, db, ruleswitch
from server.paths import display_path, io_path
from server.engines.fsutil import (
    ScanProgress, canonical_file, discover_scan_files, record_skip, sha256_of,
)
from server.engines.scan_limits import scan_byte_limit, size_skip_reason

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

# AN EXECUTABLE EXTENSION THAT IS NOT THE LAST ONE. `mod_mime` dispatches
# on ANY extension present in a name, so `up.php.json` is served as PHP --
# which is exactly why an exploit that appends its own suffix writes it in
# that shape. The content rules never saw such a file, because whether to
# open it at all was decided on the SUFFIX alone.
#
# Only the gate, not a finding. Measured on a compromised Joomla webroot:
# 3 of 1744 files carry an executable extension anywhere but at the end,
# all three are 32-byte checksum sidecars, and opening them produced zero
# new findings and no measurable runtime. What it buys is that a file the
# server runs as PHP is read as PHP.
EXEC_EXT_ANYWHERE_RE = re.compile(r"(?i)\.(php\d?|phtml|phar|inc)(\.|$)")

MAX_CONTENT_SCAN_BYTES = 5 * 1024 * 1024
GUARD_SNIFF_BYTES = 4096


def _short_tag_in_source(raw, window=48, need=0.9):
    """Is there a `<?=` here that is actually PHP rather than three bytes of
    pixel data that happen to line up?

    PHP is TEXT. A shell smuggled into an image is source code sitting inside
    the file, so the bytes after the tag read as code -- letters, spaces,
    brackets. A coincidence in compressed data is followed by more compressed
    data. That is the whole distinction, and it is one the entropy makes for
    us rather than one this function has to guess at.

    Deliberately NOT a check for specific functions: naming them would turn
    this into a list a shell can be written around, and the point of the rule
    is that PHP has no business in an image at all.
    """
    start = 0
    while True:
        i = raw.find(b"<?=", start)
        if i < 0:
            return False
        tail = raw[i + 3:i + 3 + window]
        if tail:
            readable = sum(1 for b in tail
                           if 32 <= b < 127 or b in (9, 10, 13))
            if readable / len(tail) >= need:
                return True
        start = i + 3


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


def _match_locations(raw, matches):
    """Index actual matches, not every newline in a potentially large file."""
    offsets = sorted({instance.offset
                      for match in matches if match.meta.get("id")
                      for string_match in match.strings
                      for instance in string_match.instances})
    locations = {}
    line_no, begin, previous = 1, 0, 0
    for offset in offsets:
        newlines = raw.count(b"\n", previous, offset)
        if newlines:
            line_no += newlines
            begin = raw.rfind(b"\n", previous, offset) + 1
        locations[offset] = (line_no, begin)
        previous = offset
    return locations


def _line_snippet(raw, begin, limit=160):
    """Keep strip/truncation semantics without copying or decoding a whole line.

    Incremental decoding also handles UTF-8 split at a chunk boundary. Long
    leading/trailing whitespace costs a bounded pass, not a large allocation.
    """
    end = raw.find(b"\n", begin)
    if end < 0:
        end = len(raw)
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    prefix = ""
    started = False
    consumed = last_nonspace = 0
    for offset in range(begin, end, 4096):
        stop = min(offset + 4096, end)
        text = decoder.decode(raw[offset:stop], final=stop == end)
        if not started:
            text = text.lstrip()
            if not text:
                continue
            started = True
        if len(prefix) < limit:
            prefix += text[:limit - len(prefix)]
        nonspace = text.rstrip()
        if nonspace:
            last_nonspace = consumed + len(nonspace)
            if last_nonspace > limit:
                return prefix + "…"
        consumed += len(text)
    return prefix[:last_nonspace]


def _yara_findings(raw, kind):
    """Run the bundled rules of one kind over a file's bytes.

    Yields (rule_id, severity, name, line, evidence) -- the same shape the
    regex tables produced, and deliberately so: everything downstream, up to
    and including the triage fingerprint, must not notice the change.

    ONE FINDING PER RULE PER LINE, like before. YARA reports every instance
    of a string; a rule that matches four times on one line used to produce
    one finding, not four."""
    matches = bundled_rules.compiled(kind).match(data=raw, timeout=20)
    if not matches:
        return
    locations = _match_locations(raw, matches)
    snippets = {}
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
                line_no, begin = locations[instance.offset]
                if (rule_id, line_no) in seen:
                    continue
                seen.add((rule_id, line_no))
                if line_no not in snippets:
                    snippets[line_no] = _line_snippet(raw, begin)
                out.append((rule_id, severity, name, line_no,
                            snippets[line_no]))
    # By line, so a file reads top to bottom like it used to.
    out.sort(key=lambda row: (row[3], row[0]))
    yield from out


def scan_file(file_path, root=None, *, max_bytes=None):
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
    limit = scan_byte_limit(MAX_CONTENT_SCAN_BYTES, max_bytes)
    abs_path = os.path.abspath(display_path(file_path))
    site_path = _site_path(abs_path, root)
    base_name = os.path.basename(file_path).lower()
    ext = os.path.splitext(base_name)[1]
    findings = []

    is_php = ext in PHP_EXTS or bool(EXEC_EXT_ANYWHERE_RE.search(base_name))
    is_image = ext in IMAGE_EXTS
    is_htaccess = base_name == ".htaccess"

    if DOUBLE_EXT_RE.search(base_name):
        findings.append(("webshell.double_ext", 0,
                         "Double extension disguise (e.g. logo.jpg.php)",
                         None, base_name))

    try:
        file_stat = os.stat(io_path(file_path))
        if not stat.S_ISREG(file_stat.st_mode):
            return findings, "file is no longer a regular file", None
    except OSError as e:
        if is_php and in_upload_dir(site_path):
            findings.append(("webshell.unreadable", 0,
                             "Unguarded-location PHP could not be read",
                             None, base_name))
        return findings, f"read error: {e}", None

    if not (is_php or is_image or is_htaccess):
        return findings, None, None

    size = file_stat.st_size
    if size > limit:
        if is_php and in_upload_dir(site_path):
            findings.append(("webshell.too_large", 0,
                             "PHP in writable upload directory (too large to inspect)",
                             None, base_name))
        return findings, size_skip_reason("webshell", size, limit), None

    try:
        with open(io_path(file_path), "rb") as f:
            raw = f.read(limit + 1)
    except OSError as e:
        if is_php and in_upload_dir(site_path):
            findings.append(("webshell.unreadable", 0,
                             "Unguarded-location PHP could not be read",
                             None, base_name))
        return findings, f"read error: {e}", None

    if len(raw) > limit:
        return findings, "file grew beyond the content scan size limit", None

    if is_image:
        # `<?PHP` and `<?Php` open PHP just as `<?php` does -- the language
        # does not care about the case and neither may the check. A shell
        # hidden in an image only had to shout to get past it.
        #
        # `<?=` IS THREE BYTES, AND THAT IS THE WHOLE PROBLEM. In compressed
        # pixel data any given three-byte sequence turns up about once per
        # 16 MB, so on a real Joomla webroot this rule announced "PHP code
        # hidden inside image file" -- at HIGH -- about a 1.4 MB photograph
        # whose only `<?=` sat at byte 374243 between `54 8a` and `3d 79`.
        # Measured over that site's 79 images: zero contained `<?php`, one
        # contained `<?=`, and it was the false one. `<?php` is five bytes
        # and coincidence there is negligible, so only the short tag needs
        # the second question: is what follows it SOURCE?
        if b"<?php" in raw.lower() or _short_tag_in_source(raw):
            findings.append(("webshell.php_in_image", 0,
                             "PHP code hidden inside image file", None,
                             f"'<?php' tag found in {ext} file"))
        return findings, None, None

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


def scan(case_dir, targets, ctx=None, workspace=None, authoritative=True,
         file_targets=None):
    """Scan every file under `targets`; write findings straight into case.db.
    Flagged files are hashed (SHA-256) so the IOC box can carry both path and
    hash without a second pass."""
    stats = {"scanned": 0, "findings": 0, "flagged_files": 0, "inert": 0,
             "skipped": 0, "file_skips": 0}
    # Read ONCE. The answer cannot change mid-run, and a settings read per
    # line of every file in a webroot is a different kind of tool.
    off = ruleswitch.disabled_ids(workspace) if workspace else set()
    # Each file remembers WHICH TARGET it came out of: the location rules
    # need the path below that root, not the one on this machine.
    progress = ScanProgress(ctx)
    limits = {canonical_file(entry["path"]): scan_byte_limit(
        MAX_CONTENT_SCAN_BYTES, entry["max_bytes"])
        for entry in (file_targets or []) if "max_bytes" in entry}
    files = discover_scan_files(targets, progress, stats, file_targets)
    total = len(files)
    retry = file_targets is not None
    if progress.cancelled():
        return stats
    progress.update(0.02, f"0/{total:,} files — 0 findings", "scanning", 0, total,
                    force=True)

    conn = db.connect(case_dir)
    try:
        run = db.begin_run(conn, "webshell")
        # Keep derived state until its file has been read successfully. A
        # cancelled run must not erase facts about the files it never reached.
        inert_rows = db.rows(conn, "SELECT id, path FROM inert_php")
        skip_rows = db.rows(conn, "SELECT id, path FROM skipped WHERE source = 'webshell'")
        row = db.one(conn, "SELECT value FROM meta WHERE key = 'webshell_hashes'")
        try:
            hashes = json.loads(row["value"] if row else "{}")
            if not isinstance(hashes, dict):
                hashes = {}
        except (TypeError, ValueError):
            hashes = {}
        inert_by_path, skips_by_path, hashes_by_path = {}, {}, {}
        for row in inert_rows:
            inert_by_path.setdefault(canonical_file(row["path"]), []).append(row["id"])
        for row in skip_rows:
            skips_by_path.setdefault(canonical_file(row["path"]), []).append(row["id"])
        for path in hashes:
            hashes_by_path.setdefault(canonical_file(path), []).append(path)
        flagged = set()
        for i, (file_path, root) in enumerate(files):
            if progress.cancelled():
                break
            progress.update(0.02 + (i / max(total, 1)) * 0.93,
                            f"{i:,}/{total:,} files — {stats['findings']} findings",
                            "scanning", i, total)
            stats["scanned"] += 1
            try:
                limit = limits.get(canonical_file(file_path))
                if limit is None:
                    findings, skip_reason, inert = scan_file(file_path, root)
                else:
                    findings, skip_reason, inert = scan_file(file_path, root, max_bytes=limit)
            except yara.TimeoutError:
                findings, skip_reason, inert = [], "content scan timed out after 20 seconds", None
            except MemoryError:
                findings, skip_reason, inert = [], (
                    "not enough memory to scan this file; close other applications "
                    "and retry, or inspect it with a tool for larger files"), None
            abs_path = os.path.abspath(display_path(file_path))
            identity = canonical_file(abs_path)
            conn.executemany("DELETE FROM skipped WHERE id = ?",
                             ((row_id,) for row_id in skips_by_path.pop(identity, [])))
            if skip_reason:
                db.protect_file(conn, "webshell", abs_path, run)
            else:
                conn.executemany("DELETE FROM inert_php WHERE id = ?",
                                 ((row_id,) for row_id in inert_by_path.pop(identity, [])))
                for path in hashes_by_path.pop(identity, []):
                    hashes.pop(path, None)
            file_flagged = False
            for rule_id, severity, rule, line, evidence in findings:
                if rule_id in off:
                    continue
                db.upsert_finding(conn, "webshell", severity, rule, "file",
                                  abs_path, line=line, evidence=evidence,
                                  rule_id=rule_id, engine="webshell", run=run)
                stats["findings"] += 1
                flagged.add(abs_path)
                file_flagged = True
            if inert:
                conn.execute("INSERT INTO inert_php (path, reason) VALUES (?,?)",
                             inert)
                stats["inert"] += 1
            if skip_reason:
                record_skip(ctx, abs_path, skip_reason, root=root)
                conn.execute(
                    "INSERT INTO skipped (source, path, reason) VALUES (?,?,?)",
                    ("webshell", abs_path, skip_reason))
                stats["skipped"] += 1
                stats["file_skips"] += 1
            else:
                if file_flagged:
                    digest = sha256_of(abs_path)
                    if digest:
                        hashes[abs_path] = digest
                if retry:
                    db.complete_file(conn, "webshell", abs_path, run)
            if retry or i % 500 == 0:
                conn.execute("INSERT OR REPLACE INTO meta VALUES ('webshell_hashes', ?)",
                             (json.dumps(hashes),))
                conn.commit()
            if retry:
                callback = getattr(ctx, "file_result", None)
                if callback is not None:
                    callback(abs_path, root, "skipped" if skip_reason else "resolved",
                             reason=skip_reason or "")
        stats["flagged_files"] = len(flagged)
        progress.update(0.98, "Saving scan results…", "finalizing",
                        stats["scanned"], total, force=True)
        complete = not progress.cancelled() and not stats.get("partial")
        if authoritative and not retry and complete:
            discovered = {canonical_file(path) for path, _root in files}
            # A complete traversal also accounts for files removed since the
            # previous scan. Skipped files remain in this set and keep facts.
            for table, by_path in (("inert_php", inert_by_path), ("skipped", skips_by_path)):
                stale = [row_id for key, ids in by_path.items() if key not in discovered
                         for row_id in ids]
                conn.executemany(f"DELETE FROM {table} WHERE id = ?", ((i,) for i in stale))
            hashes = {path: digest for path, digest in hashes.items()
                      if canonical_file(path) in discovered}
        conn.execute("INSERT OR REPLACE INTO meta VALUES ('webshell_hashes', ?)",
                     (json.dumps(hashes),))
        conn.commit()
        # Only a run that saw every file may retire what it did not
        # reproduce; a cancelled one has no opinion about the rest.
        if authoritative and not retry and complete:
            db.complete_file_scan(conn, "webshell", run)
    finally:
        conn.close()
    return stats
