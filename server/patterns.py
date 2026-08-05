# server/patterns.py
"""The pattern library: URL paths the analyst knows belong to an exploit.

IT LIVES IN THE WORKSPACE, NOT IN THE CASE. Created once, a pattern is
available in every further case -- the knowledge of what to look for grows
across cases, while the individual case only records what it found.

As a JSON file next to the cases, not as a database: the library should be
readable, extendable by hand, copyable to another team and placeable in a
repository. It is at the same time the exchange format -- import and export
are the same file.
"""
import json
import uuid
from datetime import datetime
from pathlib import Path

LIBRARY_FILE = "hunt_patterns.json"

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


def load(workspace):
    """The library. A broken file does not raise -- it must never be the
    reason the interface no longer opens."""
    path = library_path(workspace)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, list):
        data = data.get("patterns", []) if isinstance(data, dict) else []
    out = []
    for row in data:
        if not isinstance(row, dict) or not str(row.get("pattern", "")).strip():
            continue
        out.append({
            "id": str(row.get("id") or uuid.uuid4().hex[:12]),
            "pattern": str(row["pattern"]).strip(),
            "label": str(row.get("label") or "").strip(),
            "note": str(row.get("note") or "").strip(),
            "added": str(row.get("added") or ""),
        })
    return out


def save(workspace, patterns):
    path = library_path(workspace)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"patterns": patterns}, indent=2, ensure_ascii=False)
    # Write beside it first, then replace: a crash in the middle of writing
    # must not halve the library.
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(payload + "\n", encoding="utf-8")
    tmp.replace(path)
    return patterns


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
    for existing in patterns:
        if existing["pattern"].lower() == pattern.lower():
            raise PatternError("This pattern is already in the library.",
                               "err.patternKnown")
    entry = {"id": uuid.uuid4().hex[:12], "pattern": pattern,
             "label": str(label or "").strip(), "note": str(note or "").strip(),
             "added": datetime.now().isoformat(timespec="seconds")}
    patterns.append(entry)
    save(workspace, patterns)
    return entry


def update(workspace, pattern_id, pattern=None, label=None, note=None):
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
    patterns = load(workspace)
    kept = [p for p in patterns if p["id"] != pattern_id]
    save(workspace, kept)
    return len(patterns) - len(kept)


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
    """The library as JSON -- the same form `import_text` reads."""
    return json.dumps({"patterns": load(workspace)}, indent=2,
                      ensure_ascii=False) + "\n"
