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

from server import huntrules

LIBRARY_FILE = "hunt_patterns.json"
LIBRARY_SCHEMA = 2

# Shipped alongside the code, so `pip install` carries it -- see the
# package-data entry in pyproject.toml.
BUNDLED_FILE = Path(__file__).resolve().parent / "patterns_bundled.json"

# A pattern without substance hits everything: "/" or "*" would collect
# every line of the log and report it as a find.
MIN_PATTERN_LENGTH = 3

# How several paths in one entry are combined -- OVER CLIENTS, not over a
# single request. A URI cannot be two paths at once, so ANDing them per
# request would be nonsense; ANDing them per client is the sentence an
# analyst actually wants: "this address fetched the exploit path AND the
# thing it dropped".
MATCH_ANY = "any"          # a client that hit at least one of them
MATCH_ALL = "all"          # only clients that hit every one of them
MATCH_MODES = (MATCH_ANY, MATCH_ALL)

# More than a handful in one entry stops being a rule and becomes a query.
MAX_PATHS = 8

# Request predicates are intentionally a small second stage after the URL
# pre-filter. They are useful for endpoints shared with legitimate traffic,
# but an unbounded list would turn one hunt into an arbitrary SQL workload.
MAX_REQUEST_VALUES = 8


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
        if not isinstance(row, dict):
            continue
        entry = _normalise(row)
        if entry and entry["id"]:
            out.append({**entry, "added": "", "source": "bundled"})
    return out


def disabled_ids(workspace):
    """Bundled ids this workspace has switched off."""
    raw = _read(workspace).get("disabled", [])
    return {str(i) for i in raw} if isinstance(raw, list) else set()


# A pattern entry has FOUR fields and optional request conditions. The fields
# are what a report needs: the paths, what it is called, which advisory it
# belongs to, and what a hit proves. Earlier versions called them
# label/note/about; `_normalise` still reads those, because a workspace file
# outlives a rename.
def _request_values(raw, key, upper=False):
    value = raw.get(key, []) if isinstance(raw, dict) else []
    if isinstance(value, str):
        value = [value]
    out = []
    for item in value if isinstance(value, list) else []:
        item = str(item or "").strip()
        if upper:
            item = item.upper()
        if item and item.lower() not in {v.lower() for v in out}:
            out.append(item)
    return out


def _normalise_request(value):
    return {"methods": _request_values(value, "methods", upper=True),
            "user_agents": _request_values(value, "user_agents")}


def _normalise(row):
    """One stored entry in the current shape, whatever shape it was in."""
    raw = row.get("patterns")
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        raw = [row.get("pattern", "")]
    mode = str(row.get("match") or MATCH_ANY).lower()
    paths = [str(p).strip() for p in raw if str(p or "").strip()]
    try:
        rule = huntrules.normalise_rule(row.get("rule")) \
            if row.get("rule") else huntrules.legacy_rule(
                paths, mode, row.get("request"))
    except huntrules.RuleError:
        return None
    legacy = huntrules.legacy_projection(rule)
    name = str(row.get("name") or row.get("label") or "").strip()
    cve = str(row.get("cve") or row.get("note") or "").strip()
    description = str(row.get("description") or row.get("about")
                      or "").strip()
    stamp = str(row.get("updated_at") or row.get("added") or "")
    technology = str(row.get("technology") or "").lower()
    if technology not in huntrules.TECHNOLOGIES:
        technology = huntrules.suggest_technology(
            name, cve, description, *legacy["patterns"])
    try:
        version = max(1, int(row.get("version") or 1))
    except (TypeError, ValueError):
        version = 1
    entry = {
        "id": str(row.get("id") or uuid.uuid4().hex[:12]),
        **legacy,
        "rule": rule,
        "rule_hash": huntrules.rule_hash(rule),
        "dsl": huntrules.to_dsl(rule),
        "technology": technology,
        "name": name,
        "cve": cve,
        "description": description,
        "added": str(row.get("added") or ""),
        "created_at": str(row.get("created_at") or row.get("added") or stamp),
        "updated_at": stamp,
        "version": version,
        "archived": bool(row.get("archived", False)),
        "own_enabled": bool(row.get("own_enabled", True)),
        "derived_from": row.get("derived_from") \
            if isinstance(row.get("derived_from"), dict) else None,
    }
    history = row.get("history")
    entry["history"] = history if isinstance(history, list) and history \
        else [_snapshot(entry)]
    return entry


def load(workspace, include_archived=True):
    """The analyst's OWN patterns. Not the bundled ones -- see `library`."""
    out = []
    for row in _read(workspace).get("patterns", []) or []:
        if not isinstance(row, dict):
            continue
        entry = _normalise(row)
        if entry and (include_archived or not entry["archived"]):
            out.append({**entry, "source": "own"})
    return out


def library(workspace, include_disabled=False, include_archived=False):
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
    own = []
    for pattern in load(workspace, include_archived=True):
        enabled = pattern["own_enabled"] and not pattern["archived"]
        if pattern["archived"] and not include_archived:
            continue
        if not enabled and not include_disabled:
            continue
        own.append({**pattern, "enabled": enabled})
    return rows + own


def find(workspace, pattern_id):
    for entry in library(workspace, include_disabled=True,
                         include_archived=True):
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
    body = {"schema": LIBRARY_SCHEMA,
            "patterns": [{k: v for k, v in p.items()
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
    """Switch a bundled or own pattern off or on for this workspace."""
    ids = {p["id"] for p in bundled()}
    if pattern_id in ids:
        off = disabled_ids(workspace)
        off.discard(pattern_id) if enabled else off.add(pattern_id)
        save(workspace, load(workspace), off)
        return {"id": pattern_id, "enabled": bool(enabled)}
    own = load(workspace)
    for entry in own:
        if entry["id"] == pattern_id:
            entry["own_enabled"] = bool(enabled)
            save(workspace, own)
            return {"id": pattern_id, "enabled": bool(enabled)}
    raise PatternError("Unknown pattern.", "err.patternUnknown")


def _validate_one(pattern):
    pattern = str(pattern or "").strip()
    if len(pattern.replace("*", "")) < MIN_PATTERN_LENGTH:
        raise PatternError(
            f"The pattern is too unspecific — at least "
            f"{MIN_PATTERN_LENGTH} characters besides wildcards.",
            "err.patternTooShort")
    return pattern


def _validate(paths):
    """One or more paths, each substantial, no duplicates inside the entry."""
    if isinstance(paths, str):
        paths = [paths]
    out = []
    for raw in paths or []:
        value = _validate_one(raw)
        if value.lower() not in {p.lower() for p in out}:
            out.append(value)
    if not out:
        raise PatternError("A pattern needs at least one path.",
                           "err.patternEmpty")
    if len(out) > MAX_PATHS:
        raise PatternError(
            f"At most {MAX_PATHS} paths in one pattern — beyond that it stops "
            f"being a rule and becomes a query.", "err.patternTooMany")
    return out


def _mode(value):
    value = str(value or MATCH_ANY).lower()
    if value not in MATCH_MODES:
        raise PatternError("Unknown combination.", "err.patternMatchMode")
    return value


def _validate_request(value):
    request = _normalise_request(value)
    if len(request["methods"]) > MAX_REQUEST_VALUES:
        raise PatternError(
            f"At most {MAX_REQUEST_VALUES} HTTP methods in one pattern.",
            "err.patternTooManyConditions")
    if len(request["user_agents"]) > MAX_REQUEST_VALUES:
        raise PatternError(
            f"At most {MAX_REQUEST_VALUES} user-agent patterns in one pattern.",
            "err.patternTooManyConditions")
    for method in request["methods"]:
        if not method.replace("-", "").isalpha():
            raise PatternError("Invalid HTTP method.",
                               "err.patternRequestCondition")
    for agent in request["user_agents"]:
        _validate_one(agent)
    return request


def validate_hypothesis(patterns_in, match=MATCH_ANY):
    """Validate an unsaved hunt with the same rules as a library entry.

    Previewing something that cannot be stored is confusing, and accepting an
    unbounded list here would let one request trigger an arbitrary number of
    index passes.  Keep that boundary in this module, beside the library's
    canonical validation.
    """
    return _validate(patterns_in), _mode(match)


def _signature(entry):
    """The canonical rule, independent from display metadata and order."""
    rule = entry.get("rule") or huntrules.legacy_rule(
        entry.get("patterns"), entry.get("match"), entry.get("request"))
    return huntrules.rule_hash(rule)


def _snapshot(entry):
    return {key: entry.get(key) for key in (
        "version", "technology", "name", "cve", "description", "rule",
        "created_at", "updated_at", "archived", "own_enabled",
        "derived_from",
    )}


def _stamp():
    return datetime.now().isoformat(timespec="seconds")


def add(workspace, patterns_in, name="", cve="", description="",
        match=MATCH_ANY, request=None, *, rule=None, technology="",
        derived_from=None):
    try:
        canonical = (huntrules.normalise_rule(rule) if rule is not None
                     else huntrules.legacy_rule(
                         _validate(patterns_in), _mode(match),
                         _validate_request(request)))
    except huntrules.RuleError as exc:
        raise PatternError(str(exc), exc.key) from exc
    legacy = huntrules.legacy_projection(canonical)
    technology = str(technology or "").lower()
    if technology not in huntrules.TECHNOLOGIES:
        technology = huntrules.suggest_technology(
            name, cve, description, *legacy["patterns"])
    stamp = _stamp()
    entry = {"id": uuid.uuid4().hex[:12], **legacy, "rule": canonical,
             "rule_hash": huntrules.rule_hash(canonical),
             "dsl": huntrules.to_dsl(canonical),
             "technology": technology,
             "name": str(name or "").strip(), "cve": str(cve or "").strip(),
             "description": str(description or "").strip(),
             "added": stamp, "created_at": stamp, "updated_at": stamp,
             "version": 1, "archived": False, "own_enabled": True,
             "derived_from": derived_from if isinstance(derived_from, dict)
             else None, "history": []}
    entry["history"] = [_snapshot(entry)]
    # Checked against BOTH halves, including switched-off bundled entries: a
    # copy of something the tool already ships would run twice and be
    # reported twice, and switching the bundled one back on later would then
    # silently duplicate every hit.
    sig = _signature(entry)
    for existing in library(workspace, include_disabled=True,
                            include_archived=True):
        if _signature(existing) == sig:
            raise PatternError("This pattern is already in the library.",
                               "err.patternKnown")
    stored = load(workspace, include_archived=True)
    stored.append(entry)
    save(workspace, stored)
    return {**entry, "source": "own", "enabled": True}


def update(workspace, pattern_id, patterns_in=None, name=None, cve=None,
           description=None, match=None, request=None, *, rule=None,
           technology=None, expected_version=None, archived=None):
    if any(p["id"] == pattern_id for p in bundled()):
        # Editing it would keep the id and the CVE while changing what they
        # point at, so the same identifier would mean two things on two
        # machines. Switch it off and add your own instead.
        raise PatternError(
            "A bundled pattern cannot be edited. Switch it off and add your "
            "own version.", "err.patternBundled")
    patterns = load(workspace, include_archived=True)
    for entry in patterns:
        if entry["id"] != pattern_id:
            continue
        if expected_version is not None and int(expected_version) != entry["version"]:
            raise PatternError("Pattern version conflict.",
                               "err.patternVersionConflict")
        try:
            if rule is not None:
                entry["rule"] = huntrules.normalise_rule(rule)
            elif patterns_in is not None or match is not None or request is not None:
                entry["rule"] = huntrules.legacy_rule(
                    patterns_in if patterns_in is not None else entry["patterns"],
                    match if match is not None else entry["match"],
                    request if request is not None else entry["request"])
        except huntrules.RuleError as exc:
            raise PatternError(str(exc), exc.key) from exc
        entry.update(huntrules.legacy_projection(entry["rule"]))
        entry["rule_hash"] = huntrules.rule_hash(entry["rule"])
        entry["dsl"] = huntrules.to_dsl(entry["rule"])
        # THE SAME CHECK add() MAKES. It refuses a copy of something already
        # in the library because the pattern would then run twice and be
        # reported twice -- and editing an entry into that copy has exactly
        # the same effect. Checked against BOTH halves and against every
        # OTHER entry, so saving an unchanged pattern stays allowed.
        sig = _signature(entry)
        parent_id = (entry.get("derived_from") or {}).get("id")
        for other in library(workspace, include_disabled=True,
                             include_archived=True):
            if other["id"] not in (pattern_id, parent_id) \
                    and _signature(other) == sig:
                raise PatternError("This pattern is already in the library.",
                                   "err.patternKnown")
        if name is not None:
            entry["name"] = str(name).strip()
        if cve is not None:
            entry["cve"] = str(cve).strip()
        if description is not None:
            entry["description"] = str(description).strip()
        if technology is not None:
            value = str(technology).lower()
            if value not in huntrules.TECHNOLOGIES:
                raise PatternError("Unknown technology.", "err.patternTechnology")
            entry["technology"] = value
        if archived is not None:
            entry["archived"] = bool(archived)
            if archived:
                entry["own_enabled"] = False
        entry["version"] += 1
        entry["updated_at"] = _stamp()
        entry.setdefault("history", []).append(_snapshot(entry))
        save(workspace, patterns)
        return {**entry, "source": "own",
                "enabled": entry["own_enabled"] and not entry["archived"]}
    raise PatternError("Unknown pattern.", "err.patternUnknown")


def remove(workspace, pattern_id):
    """Archive an own pattern; switch off a bundled one.

    A bundled pattern cannot be deleted -- it lives in the package, so the
    delete would last until the next start and then quietly undo itself.
    Switching it off is the honest version of the same intent, and it is
    reversible, which deleting a shipped pattern should be."""
    if any(p["id"] == pattern_id for p in bundled()):
        set_enabled(workspace, pattern_id, False)
        return {"removed": 0, "disabled": 1}
    patterns = load(workspace, include_archived=True)
    for entry in patterns:
        if entry["id"] == pattern_id:
            if not entry["archived"]:
                entry["archived"] = True
                entry["own_enabled"] = False
                entry["version"] += 1
                entry["updated_at"] = _stamp()
                entry.setdefault("history", []).append(_snapshot(entry))
                save(workspace, patterns)
                return {"removed": 1, "disabled": 0, "archived": 1}
            return {"removed": 0, "disabled": 0, "archived": 0}
    return {"removed": 0, "disabled": 0, "archived": 0}


def versions(workspace, pattern_id):
    entry = find(workspace, pattern_id)
    if not entry:
        raise PatternError("Unknown pattern.", "err.patternUnknown")
    if entry["source"] == "bundled":
        return [_snapshot(entry)]
    return list(entry.get("history") or [_snapshot(entry)])


def restore(workspace, pattern_id, version, expected_version=None):
    entry = find(workspace, pattern_id)
    if not entry or entry["source"] != "own":
        raise PatternError("Unknown own pattern.", "err.patternUnknown")
    wanted = next((row for row in versions(workspace, pattern_id)
                   if int(row.get("version") or 0) == int(version)), None)
    if not wanted:
        raise PatternError("Unknown pattern version.", "err.patternVersion")
    return update(
        workspace, pattern_id, name=wanted.get("name"), cve=wanted.get("cve"),
        description=wanted.get("description"), rule=wanted.get("rule"),
        technology=wanted.get("technology"),
        expected_version=expected_version,
        archived=bool(wanted.get("archived", False)))


def clone(workspace, pattern_id, *, disable_original=False, rule=None,
          name=None, cve=None, description=None, technology=None):
    source = find(workspace, pattern_id)
    if not source:
        raise PatternError("Unknown pattern.", "err.patternUnknown")
    # A variant intentionally starts equal to its source and is edited next;
    # bypass the duplicate guard only for this explicit provenance-aware path.
    stamp = _stamp()
    try:
        canonical = huntrules.normalise_rule(
            source["rule"] if rule is None else rule)
    except huntrules.RuleError as exc:
        raise PatternError(str(exc), exc.key) from exc
    value_technology = str(source["technology"] if technology is None
                           else technology).lower()
    if value_technology not in huntrules.TECHNOLOGIES:
        raise PatternError("Unknown technology.", "err.patternTechnology")
    legacy = huntrules.legacy_projection(canonical)
    entry = {"id": uuid.uuid4().hex[:12], **legacy, "rule": canonical,
             "rule_hash": huntrules.rule_hash(canonical),
             "dsl": huntrules.to_dsl(canonical),
             "technology": value_technology,
             "name": (f"{source['name']} — variant".strip(" —")
                      if name is None else str(name).strip()),
             "cve": source["cve"] if cve is None else str(cve).strip(),
             "description": (source["description"] if description is None
                             else str(description).strip()),
             "added": stamp, "created_at": stamp, "updated_at": stamp,
             "version": 1, "archived": False, "own_enabled": True,
             "derived_from": {"id": source["id"],
                              "version": source.get("version", 1),
                              "source": source["source"]}, "history": []}
    entry["history"] = [_snapshot(entry)]
    customised = any(value is not None for value in (
        rule, name, cve, description, technology))
    if customised:
        sig = _signature(entry)
        for existing in library(workspace, include_disabled=True,
                                include_archived=True):
            if existing["id"] != source["id"] and _signature(existing) == sig:
                raise PatternError("This pattern is already in the library.",
                                   "err.patternKnown")
    stored = load(workspace, include_archived=True)
    stored.append(entry)
    save(workspace, stored)
    if disable_original:
        set_enabled(workspace, source["id"], False)
    return {**entry, "source": "own", "enabled": True}


def import_text(workspace, text):
    """Read in a list: either JSON (as the export writes it) or one line per
    pattern, optionally `pattern | label | note`. Known patterns are skipped,
    not duplicated. Only the JSON form carries a description."""
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
                rows.append({"patterns": [row]})
            elif isinstance(row, dict):
                paths = row.get("patterns") or row.get("pattern") or ""
                rows.append({
                    "patterns": paths,
                    "name": row.get("name") or row.get("label") or "",
                    "cve": row.get("cve") or row.get("note") or "",
                    "description": row.get("description") or row.get("about") or "",
                    "match": row.get("match") or MATCH_ANY,
                    "request": row.get("request") or {},
                    "rule": row.get("rule"),
                    "technology": row.get("technology") or "",
                    "derived_from": row.get("derived_from"),
                })
    else:
        for line in text.splitlines():
            line = line.strip()
            # `#` starts a comment -- a shared list should be allowed to
            # explain where its patterns come from.
            if not line or line.startswith("#"):
                continue
            # The line form stops at three fields. A description is prose and
            # would run into the separator; whoever wants one exports JSON,
            # which is what the export writes anyway.
            parts = [p.strip() for p in line.split("|", 2)]
            rows.append({"patterns": [parts[0]],
                         "name": parts[1] if len(parts) > 1 else "",
                         "cve": parts[2] if len(parts) > 2 else ""})

    added = skipped = invalid = 0
    for row in rows:
        try:
            add(workspace, row.get("patterns") or [], row.get("name") or "",
                row.get("cve") or "", row.get("description") or "",
                row.get("match") or MATCH_ANY, row.get("request") or {},
                rule=row.get("rule"), technology=row.get("technology") or "",
                derived_from=row.get("derived_from"))
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
    own = [{k: v for k, v in p.items() if k not in ("source", "enabled")}
           for p in load(workspace, include_archived=True)]
    return json.dumps({"schema": LIBRARY_SCHEMA, "patterns": own}, indent=2,
                      ensure_ascii=False) + "\n"
