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

OPTIONAL, LIKE THE GEOIP DATABASE. Without `yara-python` installed nothing
here runs and everything else works unchanged; the status says which of the
two it is, so "no YARA findings" is never ambiguous between "the rules found
nothing" and "there was no YARA".

A BROKEN RULE FILE MUST NOT COST THE SCAN. One file that does not compile is
reported by name and skipped; the rest still run. An analyst who pastes a
half-finished rule at 23:00 should lose that rule, not the run.
"""
import os

from server import db
from server.engines.fsutil import get_files_recursive

try:                                  # optional, exactly like maxminddb
    import yara
except ImportError:                   # pragma: no cover - depends on the host
    yara = None

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


def rule_files(workspace):
    directory = rules_dir(workspace)
    if not os.path.isdir(directory):
        return []
    out = []
    for name in sorted(os.listdir(directory)):
        if name.lower().endswith(RULE_SUFFIXES):
            out.append(os.path.join(directory, name))
    return out


def status(workspace):
    """What the interface needs to know: is this possible, and out of what.

    Distinguishes the two silences that look alike -- no YARA installed
    versus no rules placed."""
    files = rule_files(workspace)
    if yara is None:
        return {"available": False, "reason": "package",
                "dir": rules_dir(workspace), "files": [], "rules": 0,
                "broken": []}
    compiled, broken, count = _compile(workspace)
    return {"available": True, "reason": "" if files else "norules",
            "dir": rules_dir(workspace),
            "files": [os.path.basename(f) for f in files],
            "rules": count, "broken": broken,
            "ready": compiled is not None}


def _compile(workspace):
    """(compiled, broken, rule_count). Compiles each file ON ITS OWN so that
    one syntax error costs one file instead of the whole set."""
    if yara is None:
        return None, [], 0
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
    count = sum(text.count("rule ") for text in sources.values())
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
             "skipped": 0, "broken_rules": 0, "available": yara is not None}
    if yara is None or workspace is None:
        return stats

    compiled, broken, rule_count = _compile(workspace)
    stats["rules"] = rule_count
    stats["broken_rules"] = len(broken)
    if broken:
        stats["broken"] = [b["file"] for b in broken]
    if compiled is None:
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
                db.upsert_finding(conn, "yara", _severity_of(match),
                                  f"YARA: {match.rule}", "file", abs_path,
                                  evidence=_evidence(match))
                stats["findings"] += 1
                flagged.add(abs_path)
            if i % 500 == 0:
                conn.commit()
        stats["flagged_files"] = len(flagged)
        conn.commit()
    finally:
        conn.close()
    return stats
