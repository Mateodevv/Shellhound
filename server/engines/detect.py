# server/engines/detect.py
"""Point the toolkit at ONE folder and let it propose the evidence inside.

Ported from legacy core/detect.py: candidates are RANKED AND EXPLAINED, never
chosen -- structural facts only (a CMS is its shipped directories, a log dir
is lines that parse, a dump is the statements it begins with).
"""
import os
from pathlib import Path

from server.engines import accesslog
from server.engines.fsutil import open_text_auto
from server.i18n import t

MAX_DEPTH = 5
MAX_DIRS = 4000
SNIFF_BYTES = 8192
SNIFF_LINES = 40

CMS_MARKERS = {
    "joomla": [
        ("configuration.php", "file", 2),
        ("administrator", "dir", 3),
        ("libraries/src", "dir", 4),
        ("libraries/joomla", "dir", 4),
        ("components/com_content", "dir", 3),
        ("templates", "dir", 1),
        ("media/system", "dir", 2),
    ],
    "wordpress": [
        ("wp-config.php", "file", 2),
        ("wp-includes", "dir", 4),
        ("wp-content", "dir", 4),
        ("wp-admin", "dir", 3),
        ("wp-load.php", "file", 2),
        ("wp-content/plugins", "dir", 2),
    ],
    # NAMED, not inventoried. These do not get a CMS inventory -- their
    # extension layouts are each a project of their own -- but recognising
    # the webroot is most of the value: it tells the analyst the folder IS
    # the web directory, which is the question this scan answers.
    "drupal": [
        ("core/lib/Drupal.php", "file", 4),
        ("sites/default", "dir", 3),
        ("modules", "dir", 2),
        ("themes", "dir", 1),
        ("index.php", "file", 1),
    ],
    "typo3": [
        ("typo3", "dir", 4),
        ("typo3conf", "dir", 4),
        ("typo3temp", "dir", 3),
        ("fileadmin", "dir", 2),
    ],
    "magento": [
        ("app/etc/env.php", "file", 4),
        ("pub/static", "dir", 3),
        ("vendor/magento", "dir", 4),
        ("bin/magento", "file", 2),
    ],
    "prestashop": [
        ("config/settings.inc.php", "file", 4),
        ("classes/Shop.php", "file", 3),
        ("modules", "dir", 1),
        ("themes", "dir", 1),
    ],
}
CMS_LABEL = {"joomla": "Joomla", "wordpress": "WordPress",
             "drupal": "Drupal", "typo3": "TYPO3", "magento": "Magento",
             "prestashop": "PrestaShop"}
CMS_MIN_SCORE = 6

DUMP_SUFFIXES = (".sql", ".sql.gz", ".sql.bz2", ".dump", ".sql.xz")
DUMP_MARKERS = ("CREATE TABLE", "INSERT INTO", "MySQL dump", "MariaDB dump",
                "PostgreSQL database dump", "DROP TABLE", "LOCK TABLES")
LOG_SUFFIXES = (".log", ".gz", ".bz2", ".txt", "")


def _looks_like_dump(path, lang="en"):
    try:
        with open_text_auto(path) as f:
            head = f.read(SNIFF_BYTES)
    except (OSError, EOFError, ValueError):
        return False, ""
    hits = [m for m in DUMP_MARKERS if m.lower() in head.lower()]
    if not hits:
        return False, ""
    return True, t(lang, "detect.contains") + " " + ", ".join(hits[:3])


def _log_score(directory, files):
    parsed = sampled = 0
    example = ""
    for name in files[:12]:
        path = directory / name
        try:
            if path.stat().st_size == 0:
                continue
        except OSError:
            continue
        sampled += 1
        try:
            with open_text_auto(path) as f:
                for i, line in enumerate(f):
                    if i >= SNIFF_LINES:
                        break
                    if accesslog.parse_line(line.rstrip("\n")):
                        parsed += 1
                        if not example:
                            example = name
        except (OSError, EOFError, ValueError):
            continue
    return parsed, sampled, example


def _cms_score(directory, entries):
    names = {e.lower() for e in entries}
    best = (None, 0, [])
    for cms, markers in CMS_MARKERS.items():
        score, matched = 0, []
        for marker, kind, weight in markers:
            if "/" in marker:
                target = directory / marker
                if target.is_dir() if kind == "dir" else target.is_file():
                    score += weight
                    matched.append(marker)
                continue
            if marker.lower() in names:
                target = directory / marker
                if target.is_dir() if kind == "dir" else target.is_file():
                    score += weight
                    matched.append(marker)
        if score > best[1]:
            best = (cms, score, matched)
    return best


def scan(folder, lang="en"):
    """{"candidates": {kind: [...]}, "scanned": n, "truncated": bool, ...}"""
    root = Path(str(folder or "")).expanduser()
    out = {"candidates": {"webroot": [], "access_logs": [], "sql_dump": []},
           "scanned": 0, "truncated": False, "root": str(root), "error": ""}
    if not str(folder or "").strip():
        out["error"] = t(lang, "err.noFolder")
        return out
    if not root.is_dir():
        out["error"] = f"{root} is not a directory"
        return out

    seen_dirs = 0
    truncated = False
    log_dirs = {}
    layout = {}
    for current, dirnames, filenames in os.walk(root):
        here = Path(current)
        try:
            depth = len(here.relative_to(root).parts)
        except ValueError:
            depth = 0
        if depth >= MAX_DEPTH:
            dirnames[:] = []
        seen_dirs += 1
        if seen_dirs > MAX_DIRS:
            truncated = True
            dirnames[:] = []
            continue

        entries = list(dirnames) + list(filenames)
        layout[here] = {"subdirs": {here / d for d in dirnames},
                        "files": len(filenames)}

        cms, score, matched = _cms_score(here, entries)
        if cms and score >= CMS_MIN_SCORE:
            php = sum(1 for n in filenames
                      if n.lower().endswith((".php", ".phtml", ".inc")))
            out["candidates"]["webroot"].append({
                "path": str(here), "score": score,
                "why": (t(lang, "detect.cms", cms=CMS_LABEL[cms])
                        + " " + ", ".join(matched[:4])
                        + (" · " + t(lang, "detect.phpHere", n=php) if php else "")),
                "kind": cms,
            })
            dirnames[:] = []
            continue

        logs = [n for n in filenames
                if n.lower().endswith(LOG_SUFFIXES) or ".log" in n.lower()]
        if logs:
            parsed, sampled, example = _log_score(here, sorted(logs))
            if parsed:
                size = 0
                for n in logs:
                    try:
                        size += (here / n).stat().st_size
                    except OSError:
                        pass
                log_dirs[here] = {"files": len(logs), "parsed": parsed,
                                  "sampled": sampled, "size": size,
                                  "example": example}

        for name in filenames:
            low = name.lower()
            if not low.endswith(DUMP_SUFFIXES):
                continue
            path = here / name
            ok, why = _looks_like_dump(path, lang)
            if not ok:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            out["candidates"]["sql_dump"].append({
                "path": str(path), "score": size,
                "why": f"{size:,} bytes — {why}", "kind": "dump",
            })

    # Fold nested log directories into their topmost log-only parent.
    changed = True
    while changed:
        changed = False
        for parent in sorted(layout, key=lambda p: -len(p.parts)):
            subs = layout[parent]["subdirs"]
            if not subs or not subs.issubset(set(log_dirs)):
                continue
            if layout[parent]["files"] and parent not in log_dirs:
                continue
            merged = log_dirs.setdefault(
                parent, {"files": 0, "parsed": 0, "sampled": 0, "size": 0,
                         "example": "", "nested": 0})
            for child in list(subs):
                mine = log_dirs.pop(child)
                merged["files"] += mine["files"]
                merged["parsed"] += mine["parsed"]
                merged["sampled"] += mine["sampled"]
                merged["size"] += mine["size"]
                merged["nested"] = merged.get("nested", 0) + 1 + mine.get("nested", 0)
                merged["example"] = merged["example"] or mine["example"]
            changed = True
            break

    for here, s in log_dirs.items():
        out["candidates"]["access_logs"].append({
            "path": str(here), "score": s["parsed"] * 10 + s["files"],
            "why": (t(lang, "detect.logFiles", n=s["files"], bytes=f"{s['size']:,}")
                    + (" " + t(lang, "detect.inDirs", n=s["nested"] + 1)
                       if s.get("nested") else "")
                    + " — " + t(lang, "detect.logParsed",
                                 parsed=s["parsed"],
                                 sampled=s["sampled"] * SNIFF_LINES,
                                 example=s["example"])),
            "kind": "logs",
        })

    for kind in out["candidates"]:
        out["candidates"][kind].sort(key=lambda c: -c["score"])
    out["scanned"] = seen_dirs
    out["truncated"] = truncated
    return out
