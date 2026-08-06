# server/ruleswitch.py
"""Which detection rules are switched on, for this workspace.

DELIBERATELY TINY, and it imports no engine. The engines ask it before they
write a finding, and the catalogue in `server/rules.py` imports the engines to
list what there is -- if the switch lived there too, every engine would import
the module that imports every engine.

WHAT SWITCHING A RULE OFF MEANS, and what it does not:

  * The rule does not run, so it writes nothing on the next analysis.
  * Findings it wrote BEFORE stay where they are, with their triage. A switch
    is not a retraction: an artifact somebody already confirmed does not stop
    being confirmed because the rule that pointed at it was later muted.
  * The setting belongs to the WORKSPACE, not to the case -- like the pattern
    library and the YARA rules. "This rule is noise on the systems I work on"
    is knowledge about the analyst's practice, not about one incident.

An unknown id counts as ENABLED. A rule that is renamed or added by an
upgrade must arrive running; the alternative is a rule that silently does not
fire because a stale off-list happens to name it.
"""
from __future__ import annotations

from server import settings as settingslib


def disabled_ids(workspace) -> set:
    return set(settingslib.load(workspace).get("rules_disabled", []))


def enabled(workspace, rule_id) -> bool:
    return str(rule_id) not in disabled_ids(workspace)


def set_enabled(workspace, rule_id, on) -> dict:
    off = disabled_ids(workspace)
    rule_id = str(rule_id)
    off.discard(rule_id) if on else off.add(rule_id)
    data = settingslib.load(workspace)
    data["rules_disabled"] = sorted(off)
    settingslib.save(workspace, data)
    return {"id": rule_id, "enabled": bool(on)}


def filter_rules(workspace, rules):
    """Keep the entries of an `(id, severity, name, regex)` table that are
    switched on. The engines call this ONCE per scan rather than asking per
    line -- the answer cannot change mid-run, and a settings read per line of
    every file in a webroot is a different kind of tool."""
    off = disabled_ids(workspace)
    return [r for r in rules if r[0] not in off]
