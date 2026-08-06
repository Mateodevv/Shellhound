# server/rules.py
"""What rules there are -- read out of the engines, not kept beside them.

EVERY ENTRY HERE IS DERIVED. The id, the severity and the wording of a rule
live next to the rule that implements it; this module imports the engines and
reports what it finds. A hand-maintained catalogue would be a second list to
keep in sync, and the way that fails is silent: the rule gets renamed, the
catalogue does not, and the off-switch quietly stops matching anything.

The content rules are YARA and are read out of `server/rules_bundled/`; the
database and log rules are still tables in their engines. The two exceptions
are the rules that come from neither -- the structural web shell rules, which
depend on a file's location or name rather than on a pattern, and the two
error-log rules. Those are named here explicitly, and `tests/test_rules.py`
checks that the set matches the ids the engines actually emit.

The analyst's own YARA files are NOT in here. They are managed as files, with
their own switch, because a file is what a vendor feed hands over -- see
`server/engines/yarascan.py`.
"""
from __future__ import annotations

from server import bundled_rules as bundled, db, ruleswitch
from server.engines import logindex, sqldump

# Rules that do not come from a regex table. Their ids appear in the engine
# beside the `findings.append` that emits them; the test keeps the two sides
# honest.
_STRUCTURAL = [
    ("webshell.upload_php", db.SEV_HIGH,
     "Unguarded PHP in writable upload directory"),
    ("webshell.double_ext", db.SEV_HIGH, "Double extension disguise"),
    ("webshell.php_in_image", db.SEV_HIGH, "PHP code hidden inside image file"),
    ("webshell.unreadable", db.SEV_HIGH,
     "Unguarded-location PHP could not be read"),
    ("webshell.too_large", db.SEV_HIGH,
     "PHP in writable upload directory (too large to inspect)"),
]

_ERRORLOG = [
    ("errorlog.hard", db.SEV_MEDIUM,
     "PHP error names this file (fatal/parse)"),
    ("errorlog.soft", db.SEV_LOW, "PHP error names this file"),
]

# Which engine an id belongs to, for grouping in the interface. The prefix
# already says it; this only turns it into a label the UI can order by.
ENGINES = ("webshell", "sqldb", "logs", "errorlog")


def _from_table(table):
    return [(rid, sev, name) for rid, sev, name, _rx in table]


def _patterns_from(table):
    """The regex a table rule matches with, so the interface can show what a
    rule actually does. The bundled rules answer this with their YARA
    source; these answer it with the pattern."""
    return {rid: rx.pattern for rid, _sev, _name, rx in table}


def catalogue():
    """Every built-in rule: id, engine, severity, name.

    Ordered by engine and then by severity, which is the order the reference
    in `docs/rules.md` uses -- an analyst looking for a rule to switch off
    should find it in the same place in both."""
    rows = []
    rows += _STRUCTURAL
    rows += [(e["id"], e["severity"], e["name"]) for e in bundled.catalogue()]
    rows += _from_table(sqldump.RULES)
    rows += [(f"logs.{kind}", sev, name)
             for kind, (sev, name) in logindex._ALERT_FINDING.items()]
    rows += _ERRORLOG
    # What a rule is, in the form the analyst can judge it by. A bundled
    # YARA rule carries its own source -- that is the point of the rules
    # being YARA at all: the definition IS the documentation. A rule still
    # written in Python says so instead of pretending otherwise.
    bundled_by_id = bundled.by_id()
    regexes = _patterns_from(sqldump.RULES)
    out = []
    for rid, sev, name in rows:
        entry = bundled_by_id.get(rid)
        if entry:
            fmt, source = "yara", entry["source"]
        elif rid in regexes:
            fmt, source = "regex", regexes[rid]
        else:
            # Location, file name, an unreadable file, an aggregate over the
            # log index. There is no one expression to show, and inventing a
            # readable-looking one would be a lie about what runs.
            fmt, source = "builtin", ""
        out.append({"id": rid, "engine": rid.split(".", 1)[0],
                    "severity": int(sev), "name": name,
                    "format": fmt, "source": source,
                    "what": (entry or {}).get("what", "")})
    order = {name: i for i, name in enumerate(ENGINES)}
    out.sort(key=lambda r: (order.get(r["engine"], 99), r["severity"], r["id"]))
    return out


def public(workspace):
    """The catalogue plus what this workspace has switched off."""
    off = ruleswitch.disabled_ids(workspace)
    rows = [{**r, "enabled": r["id"] not in off} for r in catalogue()]
    return {"rules": rows,
            "disabled": sum(1 for r in rows if not r["enabled"])}


def known_ids():
    return {r["id"] for r in catalogue()}
