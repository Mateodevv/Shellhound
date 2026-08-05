# server/patterns.py
"""Die Muster-Bibliothek: URL-Pfade, von denen der Analyst weiß, dass sie zu
einem Exploit gehören.

SIE LEBT IM WORKSPACE, NICHT IM FALL. Einmal angelegt, steht ein Muster in
jedem weiteren Fall zur Verfügung -- das Wissen darüber, wonach man sucht,
wächst über Fälle hinweg, während der einzelne Fall nur festhält, was er
gefunden hat.

Als JSON-Datei neben den Fällen, nicht als Datenbank: die Bibliothek soll man
lesen, von Hand ergänzen, in ein anderes Team kopieren und in ein Repository
legen können. Sie ist zugleich das Austauschformat -- Import und Export sind
dieselbe Datei.
"""
import json
import uuid
from datetime import datetime
from pathlib import Path

LIBRARY_FILE = "hunt_patterns.json"

# Ein Muster ohne Substanz trifft alles: "/" oder "*" würde jede Zeile des
# Logs einsammeln und als Fund ausgeben.
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
    """Die Bibliothek. Eine kaputte Datei wirft nicht -- sie darf nie der
    Grund sein, dass die Oberfläche nicht mehr aufgeht."""
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
    # Erst daneben schreiben, dann ersetzen: ein Absturz mitten im Schreiben
    # darf die Bibliothek nicht halbieren.
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
    """Eine Liste einlesen: entweder JSON (wie der Export) oder eine Zeile je
    Muster, optional `muster | label`. Bekannte Muster werden übersprungen,
    nicht verdoppelt."""
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
            # `#` leitet einen Kommentar ein -- eine geteilte Liste soll
            # erklären dürfen, woher ihre Muster stammen.
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
    """Die Bibliothek als JSON -- dieselbe Form, die `import_text` liest."""
    return json.dumps({"patterns": load(workspace)}, indent=2,
                      ensure_ascii=False) + "\n"
