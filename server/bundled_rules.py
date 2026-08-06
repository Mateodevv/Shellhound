# server/bundled_rules.py
"""The YARA rules that ship with the tool.

They live in the package (`server/rules_bundled/*.yar`), not in the
workspace, for the same reason the bundled hunt patterns do: they are
identical on every installation of a version, which is what lets a report
cite one. That is also why they are read-only -- a rule that could be edited
while keeping its id would make the same identifier mean two different things
on two machines. Switch one off instead; the switch stores the id.

WHY THE ANALYST'S OWN RULES ARE NOT LOADED HERE. Those live in
`<workspace>/yara/` and go through `engines/yarascan.py`, which reports them
under their own name with source `yara`. These carry an `id` in their
metadata and report as the rule that id names, with source `webshell` -- so
a decision an analyst made about a file before the rules were translated
still applies to it afterwards. The finding names are unchanged for exactly
that reason: they are part of the triage fingerprint.

THE TWO FILES ARE SEPARATE BECAUSE THE ENGINE DISPATCHES ON FILE TYPE. YARA
cannot see a file name, so "these rules are for .htaccess and those for PHP"
has to live where that is known.
"""
from __future__ import annotations

import re
from pathlib import Path

import yara

from server import db

RULES_DIR = Path(__file__).resolve().parent / "rules_bundled"

# kind -> file. The kind is what the engine asks for.
FILES = {
    "content": "webshell_content.yar",
    "htaccess": "webshell_htaccess.yar",
}

_SEVERITY = {"high": db.SEV_HIGH, "critical": db.SEV_HIGH,
             "medium": db.SEV_MEDIUM, "warning": db.SEV_MEDIUM,
             "low": db.SEV_LOW, "info": db.SEV_INFO}

# `rule Name` up to the matching closing brace. Good enough for files this
# repository owns; it is not a YARA parser and does not pretend to be.
_RULE_START = re.compile(r"^rule[ \t]+([A-Za-z_]\w*)", re.M)

_compiled: dict[str, object] = {}
_sources: dict[str, str] = {}


def source(kind: str) -> str:
    """The whole file, as written. Cached: it ships inside the package and
    cannot change while the process runs."""
    if kind not in _sources:
        _sources[kind] = (RULES_DIR / FILES[kind]).read_text(encoding="utf-8")
    return _sources[kind]


def compiled(kind: str):
    if kind not in _compiled:
        _compiled[kind] = yara.compile(source=source(kind))
    return _compiled[kind]


def severity_of(value) -> int:
    return _SEVERITY.get(str(value or "").lower(), db.SEV_MEDIUM)


def _blocks(text: str):
    """(rule_name, block_text) for every rule in a file."""
    starts = [(m.start(), m.group(1)) for m in _RULE_START.finditer(text)]
    for i, (pos, name) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(text)
        yield name, text[pos:end].rstrip()


def catalogue():
    """Every bundled rule with what the interface and the engine need.

    Read out of the files rather than repeated beside them -- the same
    decision as everywhere else here: a parallel list is a list that drifts.
    """
    out = []
    for kind, filename in FILES.items():
        text = source(kind)
        for name, block in _blocks(text):
            meta = dict(re.findall(r'^\s*(\w+)\s*=\s*"(.*)"\s*$', block, re.M))
            rule_id = meta.get("id", "")
            if not rule_id:
                continue
            out.append({
                "id": rule_id,
                "severity": severity_of(meta.get("severity")),
                "name": meta.get("name") or name,
                "what": meta.get("what", ""),
                "note": " ".join(v for k, v in meta.items()
                                 if k.startswith("note")),
                "kind": kind,
                "file": filename,
                "rule": name,
                "source": block,
            })
    return out


def rule_source(rule_id: str) -> str:
    """One rule as YARA text -- what the analyst reads to decide whether they
    want it. The point of the rules being YARA at all: the definition is
    the documentation."""
    for entry in catalogue():
        if entry["id"] == rule_id:
            return entry["source"]
    return ""


def by_id():
    return {entry["id"]: entry for entry in catalogue()}
