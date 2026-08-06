# server/patterns.py
"""The pattern library: URL paths the analyst knows belong to an exploit.

THE LIBRARY HAS TWO HALVES, AND WHICH HALF A PATTERN CAME FROM IS PART OF
WHAT IT MEANS.

  * BUNDLED patterns ship inside the package (`patterns_bundled.json`).
    They are the same on every installation of a given version, which is what
    makes them citable: "SHELLHOUND 0.2.0 ships this pattern" is a statement
    a reader can verify. They are read-only for exactly that reason -- an
    entry that could be edited while keeping its id and its CVE would make
    the same identifier mean different things on two machines.

  * OWN patterns live in the WORKSPACE, NOT IN THE CASE. Created once, a
    pattern is available in every further case -- the knowledge of what to
    look for grows across cases, while the individual case only records what
    it found.

An analyst who does not want a bundled pattern switches it OFF rather than
deleting it: it lives in the package, so a delete would only last until the
next start. The off-switch is stored per workspace, by id.

The workspace file is JSON, not a database: the library should be readable,
extendable by hand, copyable to another team and placeable in a repository.
It is at the same time the exchange format -- import and export are the same
file. The export carries the analyst's OWN patterns only; the bundled ones
travel with the tool, and exporting them would land as duplicates on the
other side.

WHAT A HIT PROVES, for either half: that a request was made. Not that it
succeeded. The status code decides, and reporting that is the hunt's job.
"""
import json
import uuid
from datetime import datetime
from pathlib import Path

LIBRARY_FILE = "hunt_patterns.json"

# Shipped alongside the code, so `pip install` carries it -- see the
# package-data entry in pyproject.toml.
BUNDLED_FILE = Path(__file__).resolve().parent / "patterns_bundled.json"

# A pattern without substance hits everything: "/" or "*" would collect
# every line of the log and report it as a find.
MIN_PATTERN_LENGTH = 3


class PatternError(ValueError):
    """An input the analyst has to correct.

    It carries a catalogue KEY next to its English message. The route turns
    it into the language of the request; `import_text` recognises a known
    pattern by the key rather than by a substring of the text -- a check
    against wording breaks the moment the wording is translated."""

    def __init__(self, message, key=""):
        super().__init__(message)
        self.key = key


def library_path(workspace):
    return Path(workspace) / LIBRARY_FILE


def _read(workspace):
    """The raw workspace file. A broken file does not raise -- it must never
    be the reason the interface no longer opens."""
    try:
        data = json.loads(library_path(workspace).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if isinstance(data, list):          # the oldest form: a bare list
        return {"patterns": data}
    return data if isinstance(data, dict) else {}


def bundled():
    """The patterns that ship with this version. Read from the package on
    every call rather than cached at import: the cost is one small file, and
    a cache would hand a stale set to a long-running process after an
    upgrade-in-place."""
    try:
        data = json.loads(BUNDLED_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # A missing or broken bundled file costs the bundled patterns and
        # nothing else. The analyst's own library still opens.
        return []
    out = []
    for row in data.get("patterns", []) if isinstance(data, dict) else []:
        if not isinstance(row, dict) or not str(row.get("pattern", "")).strip():
            continue
        out.append({
            "id": str(row.get("id") or ""),
            "pattern": str(row["pattern"]).strip(),
            "label": str(row.get("label") or "").strip(),
            "note": str(row.get("note") or "").strip(),
            "about": str(row.get("about") or "").strip(),
            "added": "",
            "source": "bundled",
        })
    return [p for p in out if p["id"]]


def disabled_ids(workspace):
    """Bundled ids this workspace has switched off."""
    raw = _read(workspace).get("disabled", [])
    return {str(i) for i in raw} if isinstance(raw, list) else set()


def load(workspace):
    """The analyst's OWN patterns. Not the bundled ones -- see `library`."""
    out = []
    for row in _read(workspace).get("patterns", []) or []:
        if not isinstance(row, dict) or not str(row.get("pattern", "")).strip():
            continue
        out.append({
            "id": str(row.get("id") or uuid.uuid4().hex[:12]),
            "pattern": str(row["pattern"]).strip(),
            "label": str(row.get("label") or "").strip(),
            "note": str(row.get("note") or "").strip(),
            "added": str(row.get("added") or ""),
            "source": "own",
        })
    return out


def library(workspace, include_disabled=False):
    """What the hunt runs: the enabled bundled patterns, then the analyst's
    own. Bundled first because they are the same everywhere and therefore the
    part a reader of the report can check."""
    off = disabled_ids(workspace)
    rows = []
    for entry in bundled():
        if entry["id"] in off:
            if not include_disabled:
                continue
            entry = {**entry, "enabled": False}
        else:
            entry = {**entry, "enabled": True}
        rows.append(entry)
    return rows + [{**p, "enabled": True} for p in load(workspace)]


def find(workspace, pattern_id):
    for entry in library(workspace, include_disabled=True):
        if entry["id"] == pattern_id:
            return entry
    return None


def save(workspace, patterns, disabled=None):
    path = library_path(workspace)
    path.parent.mkdir(parents=True, exist_ok=True)
    if disabled is None:
        disabled = disabled_ids(workspace)
    # `source` is derived, not stored: it says which half of the library an
    # entry came from, and everything in this file came from the same half.
    body = {"patterns": [{k: v for k, v in p.items()
                          if k not in ("source", "enabled")}
                         for p in patterns],
            "disabled": sorted(disabled)}
    payload = json.dumps(body, indent=2, ensure_ascii=False)
    # Write beside it first, then replace: a crash in the middle of writing
    # must not halve the library.
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(payload + "\n", encoding="utf-8")
    tmp.replace(path)
    return patterns


def set_enabled(workspace, pattern_id, enabled):
    """Switch a bundled pattern off or on for this workspace."""
    ids = {p["id"] for p in bundled()}
    if pattern_id not in ids:
        raise PatternError("Not a bundled pattern.", "err.patternUnknown")
    off = disabled_ids(workspace)
    off.discard(pattern_id) if enabled else off.add(pattern_id)
    save(workspace, load(workspace), off)
    return {"id": pattern_id, "enabled": bool(enabled)}


def _validate(pattern):
    pattern = str(pattern or "").strip()
    if len(pattern.replace("*", "")) < MIN_PATTERN_LENGTH:
        raise PatternError(
            f"The pattern is too unspecific — at least "
            f"{MIN_PATTERN_LENGTH} characters besides wildcards.",
            "err.patternTooShort")
    return pattern


def add(workspace, pattern, label="", note=""):
    pattern = _validate(pattern)
    patterns = load(workspace)
    # Checked against BOTH halves, including switched-off bundled entries: a
    # copy of something the tool already ships would run twice and be
    # reported twice, and switching the bundled one back on later would then
    # silently duplicate every hit.
    for existing in library(workspace, include_disabled=True):
        if existing["pattern"].lower() == pattern.lower():
            raise PatternError("This pattern is already in the library.",
                               "err.patternKnown")
    entry = {"id": uuid.uuid4().hex[:12], "pattern": pattern,
             "label": str(label or "").strip(), "note": str(note or "").strip(),
             "added": datetime.now().isoformat(timespec="seconds")}
    patterns.append(entry)
    save(workspace, patterns)
    return {**entry, "source": "own", "enabled": True}


def update(workspace, pattern_id, pattern=None, label=None, note=None):
    if any(p["id"] == pattern_id for p in bundled()):
        # Editing it would keep the id and the CVE while changing what they
        # point at, so the same identifier would mean two things on two
        # machines. Switch it off and add your own instead.
        raise PatternError(
            "A bundled pattern cannot be edited. Switch it off and add your "
            "own version.", "err.patternBundled")
    patterns = load(workspace)
    for entry in patterns:
        if entry["id"] != pattern_id:
            continue
        if pattern is not None:
            entry["pattern"] = _validate(pattern)
        if label is not None:
            entry["label"] = str(label).strip()
        if note is not None:
            entry["note"] = str(note).strip()
        save(workspace, patterns)
        return entry
    raise PatternError("Unknown pattern.", "err.patternUnknown")


def remove(workspace, pattern_id):
    """Delete an own pattern; switch off a bundled one.

    A bundled pattern cannot be deleted -- it lives in the package, so the
    delete would last until the next start and then quietly undo itself.
    Switching it off is the honest version of the same intent, and it is
    reversible, which deleting a shipped pattern should be."""
    if any(p["id"] == pattern_id for p in bundled()):
        set_enabled(workspace, pattern_id, False)
        return {"removed": 0, "disabled": 1}
    patterns = load(workspace)
    kept = [p for p in patterns if p["id"] != pattern_id]
    save(workspace, kept)
    return {"removed": len(patterns) - len(kept), "disabled": 0}


def import_text(workspace, text):
    """Read in a list: either JSON (as the export writes it) or one line per
    pattern, optionally `pattern | label`. Known patterns are skipped, not
    duplicated."""
    text = str(text or "").strip()
    if not text:
        return {"added": 0, "skipped": 0, "invalid": 0}
    rows = []
    if text.lstrip().startswith(("[", "{")):
        try:
            data = json.loads(text)
        except ValueError as e:
            raise PatternError(f"not valid JSON: {e}", "err.patternJson") from e
        if isinstance(data, dict):
            data = data.get("patterns", [])
        for row in data if isinstance(data, list) else []:
            if isinstance(row, str):
                rows.append((row, "", ""))
            elif isinstance(row, dict):
                rows.append((row.get("pattern", ""), row.get("label", ""),
                             row.get("note", "")))
    else:
        for line in text.splitlines():
            line = line.strip()
            # `#` starts a comment -- a shared list should be allowed to
            # explain where its patterns come from.
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|", 2)]
            rows.append((parts[0], parts[1] if len(parts) > 1 else "",
                         parts[2] if len(parts) > 2 else ""))

    added = skipped = invalid = 0
    for pattern, label, note in rows:
        try:
            add(workspace, pattern, label, note)
            added += 1
        except PatternError as e:
            if e.key == "err.patternKnown":
                skipped += 1
            else:
                invalid += 1
    return {"added": added, "skipped": skipped, "invalid": invalid}


def export_text(workspace):
    """The analyst's OWN patterns as JSON -- the same form `import_text`
    reads.

    Deliberately without the bundled ones. They travel with the tool, so a
    colleague who imports this file already has them; including them would
    land as duplicates that `add` then rejects one by one, and the import
    would report a pile of skips that says nothing."""
    own = [{k: v for k, v in p.items() if k != "source"}
           for p in load(workspace)]
    return json.dumps({"patterns": own}, indent=2, ensure_ascii=False) + "\n"
