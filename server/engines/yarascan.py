# server/engines/yarascan.py
"""The analyst's OWN rules over the webroot.

The 33 rules this toolkit ships are mine. They were tuned against real Joomla
incident data and they are opinionated -- which is useful right up to the
moment somebody arrives with a rule set of their own, from their CERT, their
vendor feed, or the last incident they worked. YARA is the format that
already exists for that, so this engine adds no dialect: point it at `.yar`
files and it reports what they match.

THE RULES BELONG TO THE WORKSPACE, not to the case (`<workspace>/yara/`) --
the same decision as the pattern library, for the same reason: knowledge
about what to look for grows across cases, while a case only records what it
found.

YARA IS NO LONGER OPTIONAL. It used to be, while it only ran rules the
analyst brought themselves. The web shell content rules are YARA now
(`server/rules_bundled/`), so a missing package would mean thirteen
detections quietly not running -- and a scanner that silently finds less is
worse than one that refuses to start. The "is YARA even installed" branches
that used to be here are gone with it.

A BROKEN RULE FILE MUST NOT COST THE SCAN. One file that does not compile is
reported by name and skipped; the rest still run. An analyst who pastes a
half-finished rule at 23:00 should lose that rule, not the run.
"""
import os
import re

from server import db, settings as settingslib
from server.engines.fsutil import get_files_recursive

import yara

RULES_DIR = "yara"
RULE_SUFFIXES = (".yar", ".yara")

# A YARA rule carries no severity -- it is a matching language, not a triage
# system. `meta: severity = "high"` is honoured when the author bothered;
# everything else lands at MEDIUM, which is what "somebody's rule matched"
# honestly is until a human looks.
_SEVERITY = {"high": db.SEV_HIGH, "critical": db.SEV_HIGH,
             "medium": db.SEV_MEDIUM, "warning": db.SEV_MEDIUM,
             "low": db.SEV_LOW, "info": db.SEV_INFO}
_DEFAULT_SEVERITY = db.SEV_MEDIUM

# Same ceiling as the webshell content scan: above it the file is reported as
# unchecked rather than silently passed over.
MAX_SCAN_BYTES = 5 * 1024 * 1024
_MATCH_CAP = 20           # per file -- a greedy rule must not flood the case


def rules_dir(workspace):
    return os.path.join(str(workspace), RULES_DIR)


def rule_file_names(workspace):
    """Every rule file in the workspace, switched off ones included."""
    directory = rules_dir(workspace)
    if not os.path.isdir(directory):
        return []
    return sorted(n for n in os.listdir(directory)
                  if n.lower().endswith(RULE_SUFFIXES))


def rule_files(workspace, include_disabled=False):
    """The files a scan will actually compile."""
    directory = rules_dir(workspace)
    off = set() if include_disabled else settingslib.yara_disabled(workspace)
    return [os.path.join(directory, n) for n in rule_file_names(workspace)
            if n not in off]


# --- rule files as things the analyst edits -----------------------------
#
# The name arrives from the browser and becomes a PATH. Everything below
# treats it as hostile: one flat directory, one allowed shape, and the
# resolved path is checked to still sit inside the rules directory before
# anything is written. A local single-seat tool is not a reason to hand out
# a write-anywhere endpoint.

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# `rule Foo`, `private rule Foo`, `global private rule Foo` -- and NOT the
# word "rule" inside a comment or a string, which is what a bare count of
# "rule " used to pick up.
_RULE_DECL = re.compile(
    r"^[ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+([A-Za-z_]\w*)",
    re.M)


class RuleError(ValueError):
    """An input the analyst has to correct. Carries a catalogue key so the
    route can answer in the language of the request."""

    def __init__(self, message, key=""):
        super().__init__(message)
        self.key = key


def rule_names_in(text):
    return _RULE_DECL.findall(text or "")


def _safe_path(workspace, name):
    name = str(name or "").strip()
    if not name.lower().endswith(RULE_SUFFIXES):
        name += ".yar"
    if ".." in name or not _NAME_RE.match(name):
        raise RuleError(
            "A rule file name may hold letters, digits, dot, dash and "
            "underscore only.", "err.yaraName")
    directory = os.path.abspath(rules_dir(workspace))
    full = os.path.abspath(os.path.join(directory, name))
    if os.path.dirname(full) != directory:
        # Unreachable through _NAME_RE; kept because the day somebody
        # loosens that regex, this is the check that still holds.
        raise RuleError("Outside the rules directory.", "err.yaraName")
    return name, full


def validate(text):
    """Compile a rule file on its own. Returns the rule names it declares."""
    names = rule_names_in(text)
    try:
        yara.compile(source=text or "")
    except Exception as e:                  # yara.SyntaxError and friends
        raise RuleError(str(e)[:300], "err.yaraCompile") from e
    return names, True


def list_rules(workspace):
    """Every rule file with what the interface needs to show it."""
    off = settingslib.yara_disabled(workspace)
    directory = rules_dir(workspace)
    out = []
    for name in rule_file_names(workspace):
        full = os.path.join(directory, name)
        entry = {"name": name, "enabled": name not in off,
                 "rules": [], "error": "", "bytes": 0}
        try:
            entry["bytes"] = os.path.getsize(full)
            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as e:
            entry["error"] = str(e)[:200]
            out.append(entry)
            continue
        entry["rules"] = rule_names_in(text)
        try:
            yara.compile(source=text)
        except Exception as e:
            entry["error"] = str(e)[:200]
        out.append(entry)
    return out


def read_rule(workspace, name):
    _, full = _safe_path(workspace, name)
    try:
        with open(full, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError as e:
        raise RuleError("No such rule file.", "err.yaraUnknown") from e


def write_rule(workspace, name, text):
    """Create or replace a rule file. Compiles first: a file that does not
    compile is one the next scan reports as skipped, and finding that out at
    save time is cheaper than finding it out mid-case."""
    name, full = _safe_path(workspace, name)
    names, compiled = validate(text)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    tmp = full + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text if text.endswith("\n") else text + "\n")
    os.replace(tmp, full)
    return {"name": name, "rules": names, "compiled": compiled,
            "enabled": name not in settingslib.yara_disabled(workspace)}


def delete_rule(workspace, name):
    name, full = _safe_path(workspace, name)
    try:
        os.remove(full)
    except OSError as e:
        raise RuleError("No such rule file.", "err.yaraUnknown") from e
    # A file that is gone must not stay on the off-list, or a later file of
    # the same name would arrive switched off for no visible reason.
    off = settingslib.yara_disabled(workspace)
    if name in off:
        settingslib.set_yara_disabled(workspace, off - {name})
    return {"name": name, "removed": 1}


def set_rule_enabled(workspace, name, enabled):
    name, full = _safe_path(workspace, name)
    if not os.path.isfile(full):
        raise RuleError("No such rule file.", "err.yaraUnknown")
    off = settingslib.yara_disabled(workspace)
    off = (off - {name}) if enabled else (off | {name})
    settingslib.set_yara_disabled(workspace, off)
    return {"name": name, "enabled": bool(enabled)}


def status(workspace):
    """What the interface needs to know: what runs, and out of what.

    Two silences still look alike and must not be confused: no rules placed
    at all, versus rules that are all switched off."""
    all_names = rule_file_names(workspace)
    off = settingslib.yara_disabled(workspace)
    compiled, broken, count = _compile(workspace)
    enabled = [n for n in all_names if n not in off]
    return {"available": True,
            # The two silences the interface must not confuse: no rules at
            # all, versus rules that are all switched off.
            "reason": ("norules" if not all_names
                       else "alloff" if not enabled else ""),
            "dir": rules_dir(workspace),
            "files": enabled,
            "disabled": sorted(off & set(all_names)),
            "rules": count, "broken": broken,
            "ready": compiled is not None}


def _compile(workspace):
    """(compiled, broken, rule_count). Compiles each file ON ITS OWN so that
    one syntax error costs one file instead of the whole set."""
    sources, broken = {}, []
    for path in rule_files(workspace):
        name = os.path.basename(path)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            yara.compile(source=text)          # does it stand on its own?
            sources[name] = text
        except Exception as e:                 # yara.Error, OSError, SyntaxError
            broken.append({"file": name, "error": str(e)[:200]})
    if not sources:
        return None, broken, 0
    try:
        compiled = yara.compile(sources=sources)
    except Exception as e:                     # pragma: no cover - defensive
        return None, broken + [{"file": "(combined)", "error": str(e)[:200]}], 0
    # Declarations, not occurrences of the word: a bare count of "rule "
    # also picks it up out of comments and string literals.
    count = sum(len(rule_names_in(text)) for text in sources.values())
    return compiled, broken, count


def _severity_of(match):
    raw = str((getattr(match, "meta", None) or {}).get("severity", "")).lower()
    return _SEVERITY.get(raw, _DEFAULT_SEVERITY)


def _evidence(match):
    """What matched, in a form a report can carry: the first few string
    identifiers and the offset they hit at. Never the matched BYTES -- a
    rule can match on a credential, and the evidence line travels into the
    case archive."""
    parts = []
    for s in (getattr(match, "strings", None) or [])[:4]:
        ident = getattr(s, "identifier", None)
        instances = getattr(s, "instances", None) or []
        offset = getattr(instances[0], "offset", None) if instances else None
        if ident is None:                      # yara-python < 4.3 tuple form
            try:
                offset, ident = s[0], s[1]
            except (TypeError, IndexError):
                continue
        parts.append(f"{ident}@{offset}" if offset is not None else str(ident))
    tags = ", ".join(getattr(match, "tags", None) or [])
    out = f"{match.rule}"
    if tags:
        out += f" [{tags}]"
    if parts:
        out += ": " + ", ".join(parts)
    return out[:400]


def scan(case_dir, targets, workspace=None, ctx=None):
    """Run every rule in the workspace over every file under `targets`.

    Findings land on the FILE artifact, like the webshell scan -- so triage,
    propagation and IOC collection carry on unchanged instead of opening a
    second work list.
    """
    stats = {"scanned": 0, "findings": 0, "flagged_files": 0, "rules": 0,
             "skipped": 0, "broken_rules": 0, "available": True}
    if workspace is None:
        return stats

    compiled, broken, rule_count = _compile(workspace)
    stats["rules"] = rule_count
    stats["broken_rules"] = len(broken)
    if broken:
        stats["broken"] = [b["file"] for b in broken]
    if compiled is None:
        # NOT A CLEAN SCAN -- a scan that could not run. Without this the
        # broken rules lived only in the job stats, so a workspace whose rule
        # files all fail to compile looked, in the case itself, exactly like a
        # workspace where YARA found nothing.
        conn = db.connect(case_dir)
        try:
            for entry in broken:
                conn.execute(
                    "INSERT INTO skipped (source, path, reason) VALUES (?,?,?)",
                    ("yara", entry["file"],
                     f"rule file does not compile: {entry.get('error', '')}"[:400]))
            conn.commit()
        finally:
            conn.close()
        return stats

    files = []
    for target in targets:
        if os.path.isfile(target):
            files.append(target)
        else:
            files.extend(get_files_recursive(target))
    total = len(files) or 1

    conn = db.connect(case_dir)
    try:
        run = db.begin_run(conn, "yarascan")
        cancelled = False
        conn.execute("DELETE FROM skipped WHERE source = 'yara'")
        # One line per broken rule file, in the same place every other
        # unchecked thing goes: a rule that did not run is not a rule that
        # found nothing.
        for entry in broken:
            conn.execute(
                "INSERT INTO skipped (source, path, reason) VALUES (?,?,?)",
                ("yara", entry["file"], f"rule did not compile: {entry['error']}"))
        flagged = set()
        for i, file_path in enumerate(files):
            if ctx is not None and i % 200 == 0:
                if ctx.cancelled():
                    cancelled = True
                    break
                ctx.progress(0.02 + (i / total) * 0.95,
                             f"{i:,}/{total:,} files — {stats['findings']} findings")
            stats["scanned"] += 1
            abs_path = os.path.abspath(file_path)
            try:
                if os.path.getsize(file_path) > MAX_SCAN_BYTES:
                    conn.execute(
                        "INSERT INTO skipped (source, path, reason) VALUES (?,?,?)",
                        ("yara", abs_path, "too large for a YARA scan"))
                    stats["skipped"] += 1
                    continue
                matches = compiled.match(file_path, timeout=20)
            except Exception as e:             # yara.Error, OSError, TimeoutError
                conn.execute(
                    "INSERT INTO skipped (source, path, reason) VALUES (?,?,?)",
                    ("yara", abs_path, f"scan error: {str(e)[:160]}"))
                stats["skipped"] += 1
                continue
            for match in list(matches)[:_MATCH_CAP]:
                # The analyst's own rules have no catalogue id -- they are
                # managed as FILES and switched off as files. The id column
                # stays empty, which the work list reads as "not mutable
                # from the rule switch", and that is exactly right.
                db.upsert_finding(conn, "yara", _severity_of(match),
                                  f"YARA: {match.rule}", "file", abs_path,
                                  evidence=_evidence(match),
                                  engine="yarascan", run=run)
                stats["findings"] += 1
                flagged.add(abs_path)
            if i % 500 == 0:
                conn.commit()
        stats["flagged_files"] = len(flagged)
        conn.commit()
        # A cancelled run has no opinion about the files it never reached,
        # so only a completed one may retire the rows it did not reproduce.
        # The compile-failure path above never gets here -- a scan that
        # could not run is not a scan that found nothing.
        if not cancelled:
            db.complete_run(conn, "yarascan", run)
    finally:
        conn.close()
    return stats
