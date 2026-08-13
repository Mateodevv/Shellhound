# server/engines/errorlog.py
"""The error log: the file that names the shell the access log never saw.

Until now these files were RECOGNISED AND SKIPPED -- correctly, because they
are not access logs and feeding them to that parser would have produced
garbage. But skipping them threw away the second most useful log on the
server.

WHY IT MATTERS: a PHP fatal or warning names an absolute path and a line
number. That is a file the interpreter actually EXECUTED. It catches what the
access log structurally cannot:

  * a shell run from cron or the CLI, which never produced a request line;
  * an include chain -- the error names the file that was pulled in, not the
    one that was requested;
  * a shell that crashed on its own broken payload, which is how half of
    them announce themselves.

WHAT IS AND IS NOT CLAIMED: an error naming a file is not evidence that the
file is malicious -- legitimate code throws warnings all day. It is evidence
that the path EXISTED and was EXECUTED at that time. Findings from here are
therefore LOW on their own; they earn their weight by landing on the same
artifact as something else. That is exactly what artifact-level triage is
for.

A LOGGED PATH IS WRITTEN ONLY WHEN THE FILE IS PRESENT in the copy. `_resolver`
matches the server-side path against the registered webroot by TAIL and then
requires `os.path.isfile`. An error log mentions every file on the server, and
a case must not fill up with findings about paths that have nothing to do with
the webroot at hand. What cannot be placed is counted, not dropped.

THE PRICE OF THAT, SAID OUT LOUD: a file deleted before the copy was taken
produces NOTHING. The docstring and docs/rules.md both used to advertise that
case as the engine's strongest -- "the log still names it, and the webroot can
no longer make that statement" -- and it was never implemented; `isfile` says
no and the path lands in `unresolved`. The restraint above and that promise
cannot both hold.

It is worth wanting. Nothing else in the toolkit makes that statement: the
webroot diff only sees files a reference CMS release contains, so a dropped
and then deleted shell in an upload directory is invisible to it as well. What
it needs is a way to PLACE a path without being able to open it, and the cheap
version is wrong -- accepting a path because its parent directory exists in
the copy was measured at 99 false resolutions out of 102 against neighbouring
sites on the same host, each one asserting that somebody else's file had run
here. Learning the server-side prefix from the paths that did resolve scores 0
of those 102, but its noise floor on a real month-long error log from a site
that was updated between the incident and the copy is unmeasured, because no
such log has been available. Until it is, this engine says less rather than
more.
"""
import os
import re
from datetime import datetime, timezone

from server import db, ruleswitch
from server.engines.fsutil import is_scannable_text, open_text_auto

# Apache:  [Fri Jun 26 05:19:59.123456 2026] [php:error] [pid 123] [client 1.2.3.4:5] PHP Fatal error: ...
# Nginx:   2026/06/30 11:52:26 [error] 1234#0: *5 FastCGI sent in stderr: "PHP message: ..."
_APACHE_RE = re.compile(
    r"^\[(?P<time>\w{3} \w{3} [ \d]?\d \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\]\s*"
    r"(?:\[(?P<module>[^\]]*)\]\s*)?"
    r"(?:\[pid[^\]]*\]\s*)?"
    # `[client 1.2.3.4:41234]` but also `[client [2001:db8::1]:41234]` --
    # the bracketed IPv6 form has to be consumed as a whole, or the group
    # stops at the INNER bracket and hands back half an address.
    r"(?:\[client (?P<client>\[[^\]]*\][^\]]*|[^\]]*)\]\s*)?"
    r"(?P<message>.*)$")
_NGINX_RE = re.compile(
    r"^(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] "
    r"\d+#\d+:\s*(?P<message>.*)$")

# `in /path/file.php on line 42` -- the form PHP writes for every error.
# Deliberately anchored on `in `: matching a bare path would pick up every
# quoted filename in a message, and a finding on the wrong file is worse
# than a missed one.
# THE PATH DOES NOT END AT THE EXECUTABLE EXTENSION. It used to: the capture
# stopped at `.php`, so a fatal naming `/var/www/up.php.json` was read as
# `/var/www/up.php`.
#
# That is not a miss, it is a false statement, and the ordinary case is the
# bad one. An exploit that appends its own suffix picks a plausible stem, so
# `up.php` frequently EXISTS beside `up.php.json` -- and then the resolver
# finds it and the engine writes a finding onto an innocent file, whose
# evidence names a path the log never contained, printed next to the quoted
# log line that contradicts it. The line number was dropped too, because the
# `:3` no longer followed the capture, so the finding pointed at no line.
#
# `(?:\.[A-Za-z0-9_-]+)*` takes whatever follows. The class deliberately
# excludes `:` and whitespace, so `up.php.json:3` still yields its line and
# `x.php, referer: ...` still stops at the comma.
_PATH_RE = re.compile(
    r"\bin\s+(?P<path>(?:[A-Za-z]:)?[/\\][^\s:,()]+\.(?:php|phtml|inc|phar)"
    r"(?:\.[A-Za-z0-9_-]+)*)"
    r"(?:\s+on line\s+(?P<line1>\d+)|:(?P<line2>\d+))?",
    re.IGNORECASE)

# The kinds of message worth a finding at all. A deprecation notice about a
# core file is noise; a fatal, a parse error or an include that failed is a
# statement about what ran.
_INTERESTING = re.compile(
    r"(?i)\b(PHP (Fatal|Parse|Warning|Notice|Deprecated)|"
    r"Uncaught|require(_once)?\(\)|include(_once)?\(\)|"
    r"allowed memory size|maximum execution time)")

_HARD = re.compile(r"(?i)\b(fatal|parse error|uncaught)\b")

# Apache writes `[client 1.2.3.4:41234]` for IPv4 and
# `[client [2001:db8::1]:41234]` for IPv6. The port has to go and the address
# has to survive -- a naive split on ":" would cut an IPv6 address in half.
_CLIENT_V6_RE = re.compile(r"^\[(?P<ip>[0-9a-fA-F:]+)\]")


def _client_ip(raw):
    raw = (raw or "").strip()
    if not raw:
        return ""
    m = _CLIENT_V6_RE.match(raw)
    if m:
        return m.group("ip")
    if raw.count(":") == 1:              # IPv4 with a port
        return raw.split(":", 1)[0]
    return raw.split(" ", 1)[0]

MAX_LINES_PER_FILE = 2_000_000
_EVIDENCE_CAP = 300


def looks_like_error_log(file_path):
    """True if the first non-empty line matches one of the two shapes. Same
    sniff the log index uses to skip these files -- one definition, so the
    two can never disagree about what an error log is."""
    try:
        with open_text_auto(file_path) as fh:
            for line in fh:
                if line.strip():
                    return bool(_APACHE_RE.match(line) or _NGINX_RE.match(line))
    except (OSError, EOFError, ValueError):
        pass
    return False


_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def parse_time(raw):
    """Naive local seconds, or None.

    Naive on purpose, and read the SAME WAY as every other time in this
    toolkit: the wall clock of the log, converted as if it were UTC. An
    error log carries no zone, and the chronology compares times as they
    stand rather than inventing one -- doing anything else here would make
    an error-log time incomparable with an access-log time."""
    raw = (raw or "").strip()
    try:
        if "/" in raw:                       # nginx: 2026/06/30 11:52:26
            dt = datetime.strptime(raw[:19], "%Y/%m/%d %H:%M:%S")
        else:                                # apache: Fri Jun 26 05:19:59 2026
            parts = raw.split()
            if len(parts) < 5:
                return None
            month = _MONTHS.get(parts[1])
            if month is None:
                return None
            clock = parts[3].split(".")[0]
            dt = datetime(int(parts[4]), month, int(parts[2]),
                          *(int(p) for p in clock.split(":")))
        return int(dt.replace(tzinfo=timezone.utc).timestamp())
    except (ValueError, TypeError, IndexError):
        return None


def parse_line(line):
    """{time, message, client} or None."""
    m = _APACHE_RE.match(line)
    if m:
        return {"time": m.group("time"), "message": m.group("message") or "",
                "client": _client_ip(m.group("client"))}
    m = _NGINX_RE.match(line)
    if m:
        return {"time": m.group("time"), "message": m.group("message") or "",
                "client": ""}
    return None


def paths_in(message):
    """Every PHP file the message names, with its line number when there is
    one. A stack trace names several; all of them ran."""
    out = []
    for m in _PATH_RE.finditer(message or ""):
        line = m.group("line1") or m.group("line2")
        out.append((m.group("path"), int(line) if line else None))
    return out


def _real_path(candidate):
    """The path as the FILESYSTEM spells it.

    The lookup is done in lower case because a log line and a copied webroot
    need not agree on capitalisation; what is stored afterwards has to be the
    real name, or nothing else in the case will match it."""
    resolved = os.path.realpath(candidate)
    return os.path.abspath(resolved if os.path.isfile(resolved) else candidate)


def _norm(path):
    return str(path or "").replace("\\", "/").rstrip("/").lower()


def _resolver(conn):
    """Map a path from the log onto a registered evidence file.

    An error log names every file on the SERVER; the case holds a COPY under
    a different root. Matching by tail is what bridges the two -- and it is
    also the guard that keeps unrelated paths out: what does not sit under a
    registered root is not written."""
    roots = []
    for row in db.rows(conn, "SELECT path FROM evidence WHERE kind = 'webroot'"):
        root = _norm(row["path"])
        if root:
            roots.append((root, str(row["path"]).replace("\\", "/").rstrip("/")))
    if not roots:
        return None

    def resolve(logged):
        low = _norm(logged)
        for root_low, root_raw in roots:
            # The server path and the copy share a tail: /var/www/html/x.php
            # under a copy at D:/case/webroot becomes D:/case/webroot/x.php.
            parts = low.split("/")
            for i in range(len(parts)):
                tail = "/".join(parts[i:])
                if not tail:
                    continue
                candidate = f"{root_low}/{tail}"
                if not os.path.isfile(candidate):
                    continue
                # THE ARTIFACT MUST BE SPELLED AS THE FILE IS. `tail` comes
                # out of the lower-cased path, so returning it built a second,
                # lower-cased identity for a file the webshell scanner had
                # already recorded in its real spelling -- two artifacts for
                # one file, and a triage decision on one covering neither the
                # other nor the export. On a case-sensitive filesystem the
                # lookup above fails outright and the finding is lost.
                return _real_path(candidate)
        return None
    return resolve


def scan(case_dir, targets, ctx=None, workspace=None):
    """Read every error log under `targets`; write findings on the FILE
    artifacts they name."""
    stats = {"files": 0, "lines": 0, "matched": 0, "findings": 0,
             "unresolved": 0, "skipped": 0}
    off = ruleswitch.disabled_ids(workspace) if workspace else set()
    files = []
    for target in targets:
        if os.path.isfile(target):
            files.append(target)
        elif os.path.isdir(target):
            from server.engines.fsutil import get_files_recursive
            files.extend(get_files_recursive(target))
    logs = [f for f in files
            if is_scannable_text(f) and looks_like_error_log(f)]

    conn = db.connect(case_dir)
    try:
        run = db.begin_run(conn, "errorlog")
        cancelled = False
        if not logs:
            # A COMPLETE run that found no error log among the targets. It
            # completes so its verdict counts: findings from an error log
            # that has since left the evidence stop being current instead of
            # promising files no log names any more.
            db.complete_run(conn, "errorlog", run)
            return stats
        resolve = _resolver(conn)
        if resolve is None:
            # No webroot registered: every path would be unresolvable, and a
            # case full of findings about paths nobody can open helps no one.
            # NOT completed -- this run skipped its work rather than doing
            # it, so it has no opinion about the rows of earlier runs.
            stats["skipped"] = len(logs)
            return stats

        # artifact -> what the log says about it. Collected first so one file
        # named in 400 lines becomes ONE finding with a count, not 400.
        seen = {}
        for n, path in enumerate(logs):
            if ctx is not None and ctx.cancelled():
                cancelled = True
                break
            if ctx is not None:
                ctx.progress(0.05 + 0.85 * (n / max(1, len(logs))),
                             f"{os.path.basename(path)}: reading error log…")
            stats["files"] += 1
            try:
                with open_text_auto(path) as fh:
                    for i, line in enumerate(fh):
                        if i > MAX_LINES_PER_FILE:
                            break
                        stats["lines"] += 1
                        entry = parse_line(line)
                        if entry is None or not _INTERESTING.search(entry["message"]):
                            continue
                        hits = paths_in(entry["message"])
                        if not hits:
                            continue
                        stats["matched"] += 1
                        when = parse_time(entry["time"])
                        hard = bool(_HARD.search(entry["message"]))
                        for logged, line_no in hits:
                            artifact = resolve(logged)
                            if artifact is None:
                                stats["unresolved"] += 1
                                continue
                            agg = seen.setdefault(artifact, {
                                "n": 0, "line": line_no, "first": when,
                                "last": when, "hard": False,
                                "example": entry["message"].strip()[:_EVIDENCE_CAP],
                                "logged": logged})
                            agg["n"] += 1
                            agg["hard"] = agg["hard"] or hard
                            if line_no and not agg["line"]:
                                agg["line"] = line_no
                            if when:
                                agg["first"] = min(agg["first"] or when, when)
                                agg["last"] = max(agg["last"] or when, when)
                            if hard and "Fatal" not in agg["example"]:
                                agg["example"] = entry["message"].strip()[:_EVIDENCE_CAP]
            except (OSError, EOFError, ValueError) as e:
                conn.execute(
                    "INSERT INTO skipped (source, path, reason) VALUES (?,?,?)",
                    ("errorlog", os.path.abspath(path), f"read error: {e}"))
                stats["skipped"] += 1
                continue

        for artifact, agg in seen.items():
            # LOW on its own, MEDIUM for a fatal or parse error. Neither is a
            # verdict about the file: it is proof that this path existed and
            # ran. The weight comes from landing on the same artifact as
            # something else -- which is what artifact triage is for.
            # Two rules, not one: "the interpreter died in this file" and
            # "the interpreter complained about this file" are different
            # statements, and an analyst may want only the first.
            rule_id = ("errorlog.hard" if agg["hard"] else "errorlog.soft")
            if rule_id in off:
                continue
            severity = db.SEV_MEDIUM if agg["hard"] else db.SEV_LOW
            rule = ("PHP error names this file (fatal/parse)" if agg["hard"]
                    else "PHP error names this file")
            db.upsert_finding(
                conn, "errorlog", severity, rule, "file", artifact,
                line=agg["line"],
                evidence=(f"{agg['n']}× in the error log as {agg['logged']}"
                          f" · {agg['example']}")[:400],
                rule_id=rule_id, engine="errorlog", run=run)
            stats["findings"] += 1
        conn.commit()
        if not cancelled:
            db.complete_run(conn, "errorlog", run)
    finally:
        conn.close()
    return stats
