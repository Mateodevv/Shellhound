# server/sigma.py
"""SIGMA rules against the access log index.

SIGMA IS A DESCRIPTION FORMAT, NOT AN ENGINE. A rule says "this field
contains that"; something has to turn it into a query against whatever the
logs actually live in. This module is that something for one log source --
the request table of `logindex.db` -- and nothing else. It is a backend, in
SIGMA's own sense of the word.

WHY SIGMA AND NOT MORE YARA. YARA is handed bytes and answers "is this
pattern in this file". A log line is not a file and the interesting questions
are not about bytes: they are about a FIELD -- this status, that method, a
user agent containing something. SIGMA is the format that already exists for
exactly that, so the log rules are written in it rather than in a dialect
invented here.

WHAT IS DELIBERATELY NOT SUPPORTED, and why refusing beats pretending:

  * AGGREGATIONS (`| count() by ... > 5`). SIGMA has them; they are the
    least standardised part of it, and two of this tool's log rules need
    more than a count -- "a login flood FOLLOWED BY a redirect" is a
    sequence. Those two stay in Python, where they already work.
  * `|re` modifiers, and every field this index does not carry.

A rule that uses any of it is REJECTED AT LOAD with the reason, not loaded
and left to match nothing. A detection rule that silently never fires is the
worst object in a forensic tool: it looks like evidence of absence.
"""
from __future__ import annotations

import re

import yaml

from server import db

# --- what the index actually carries ---------------------------------------
#
# SIGMA field names for a webserver logsource, mapped onto this schema. A
# field that is not here cannot be answered, and a rule that asks for one is
# refused rather than quietly matching nothing.
FIELDS = {
    "c-uri": "uri.text",
    "c-uri-query": "uri.text",
    "cs-uri-stem": "uri.text",
    "c-useragent": "agent.text",
    "cs-method": "req.method",
    "sc-status": "req.status",
    "c-ip": "ip.ip",
    "src_ip": "ip.ip",
}

# The join every compiled rule runs against.
FROM_CLAUSE = (
    "requests req "
    "JOIN strings uri ON uri.id = req.uri "
    "LEFT JOIN strings agent ON agent.id = req.agent "
    "JOIN ips ip ON ip.id = req.ip")

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all"}

LEVELS = {"critical": db.SEV_HIGH, "high": db.SEV_HIGH,
          "medium": db.SEV_MEDIUM, "low": db.SEV_LOW,
          "informational": db.SEV_INFO}


class SigmaError(ValueError):
    """A rule this backend cannot answer. Carries a catalogue key so the
    route can say it in the language of the request."""

    def __init__(self, message, key="err.sigmaUnsupported"):
        super().__init__(message)
        self.key = key


def _escape_like(value):
    """SQLite LIKE with an explicit ESCAPE. Without this a `%` or `_` in a
    rule -- and URLs are full of both -- silently becomes a wildcard."""
    return (str(value).replace("\\", "\\\\")
            .replace("%", "\\%").replace("_", "\\_"))


def _leaf_condition(column, value, modifier):
    """One field/value pair as SQL."""
    if modifier == "contains":
        return f"{column} LIKE ? ESCAPE '\\'", [f"%{_escape_like(value)}%"]
    if modifier == "startswith":
        return f"{column} LIKE ? ESCAPE '\\'", [f"{_escape_like(value)}%"]
    if modifier == "endswith":
        return f"{column} LIKE ? ESCAPE '\\'", [f"%{_escape_like(value)}"]
    # Bare equality. Numbers stay numbers so `sc-status: 200` does not become
    # a string comparison that never matches.
    if isinstance(value, bool):
        raise SigmaError("A boolean is not a value this index can compare.")
    return f"{column} = ?", [value]


def _selection_sql(name, spec):
    """One named selection. A map of field -> value(s); the entries are ANDed
    and the values inside one entry are ORed, which is SIGMA's rule."""
    if not isinstance(spec, dict):
        raise SigmaError(f"Selection '{name}' is not a mapping.")
    parts, params = [], []
    for key, raw in spec.items():
        field, _, mods = str(key).partition("|")
        modifiers = [m for m in mods.split("|") if m]
        unknown = set(modifiers) - SUPPORTED_MODIFIERS
        if unknown:
            raise SigmaError(
                f"Modifier(s) {sorted(unknown)} on '{field}' are not "
                f"supported by this backend.")
        column = FIELDS.get(field)
        if column is None:
            raise SigmaError(
                f"Field '{field}' is not in the log index. Available: "
                f"{', '.join(sorted(FIELDS))}.", "err.sigmaField")
        match_mod = next((m for m in modifiers if m != "all"), "")
        values = raw if isinstance(raw, list) else [raw]
        joiner = " AND " if "all" in modifiers else " OR "
        sub, subparams = [], []
        for value in values:
            sql, ps = _leaf_condition(column, value, match_mod)
            sub.append(sql)
            subparams.extend(ps)
        parts.append("(" + joiner.join(sub) + ")")
        params.extend(subparams)
    if not parts:
        raise SigmaError(f"Selection '{name}' is empty.")
    return "(" + " AND ".join(parts) + ")", params


_TOKEN = re.compile(r"\(|\)|\ball\ of\b|\b1 of\b|\bof\b|\band\b|\bor\b|\bnot\b|[\w*]+")


def _condition_sql(condition, selections):
    """SIGMA's condition mini-language, as far as this backend goes:
    names, and/or/not, parentheses, `all of them`, `1 of them`, and the
    `all of sel*` / `1 of sel*` wildcard forms."""
    tokens = _TOKEN.findall(str(condition or "").strip().lower())
    if not tokens:
        raise SigmaError("The rule has no condition.")

    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take():
        nonlocal pos
        token = peek()
        pos += 1
        return token

    def named(pattern):
        if pattern == "them":
            names = list(selections)
        else:
            rx = re.compile("^" + pattern.replace("*", ".*") + "$")
            names = [n for n in selections if rx.match(n)]
        if not names:
            raise SigmaError(f"'{pattern}' matches no selection.")
        return names

    def primary():
        token = take()
        if token == "(":
            sql, params = expression()
            if take() != ")":
                raise SigmaError("Unbalanced parentheses in the condition.")
            return sql, params
        if token == "not":
            sql, params = primary()
            return f"NOT {sql}", params
        if token in ("all of", "1 of"):
            target = take()
            if target == "of":                    # tokenised as two words
                target = take()
            names = named(target)
            joiner = " AND " if token == "all of" else " OR "
            parts, params = [], []
            for name in names:
                sql, ps = _selection_sql(name, selections[name])
                parts.append(sql)
                params.extend(ps)
            return "(" + joiner.join(parts) + ")", params
        if token not in selections:
            raise SigmaError(f"The condition names '{token}', which is not a "
                             f"selection in this rule.")
        return _selection_sql(token, selections[token])

    def expression():
        sql, params = primary()
        while peek() in ("and", "or"):
            operator = take().upper()
            right, right_params = primary()
            sql = f"({sql} {operator} {right})"
            params.extend(right_params)
        return sql, params

    sql, params = expression()
    if pos != len(tokens):
        raise SigmaError(f"Could not read the whole condition: {condition!r}")
    return sql, params


def compile_rule(text):
    """A SIGMA rule as (metadata, WHERE fragment, parameters).

    Raises SigmaError for anything this backend cannot answer -- see the note
    at the top of the module on why that is not a silent no-match."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise SigmaError(f"not valid YAML: {e}", "err.sigmaYaml") from e
    if not isinstance(doc, dict):
        raise SigmaError("A rule is a YAML mapping.")

    detection = doc.get("detection")
    if not isinstance(detection, dict):
        raise SigmaError("The rule has no `detection` block.")
    condition = detection.get("condition")
    selections = {k: v for k, v in detection.items()
                  if k not in ("condition", "timeframe")}
    if "timeframe" in detection:
        raise SigmaError(
            "`timeframe` needs an aggregation this backend does not do. The "
            "rules that need one stay in the engine.", "err.sigmaAggregate")
    if isinstance(condition, str) and "|" in condition:
        raise SigmaError(
            "Aggregation (`| count() by ...`) is not supported. A rule that "
            "needs one stays in the engine rather than loading here and "
            "matching nothing.", "err.sigmaAggregate")

    where, params = _condition_sql(condition, selections)
    meta = {
        "id": str(doc.get("id") or "").strip(),
        "title": str(doc.get("title") or "").strip(),
        "description": str(doc.get("description") or "").strip(),
        "severity": LEVELS.get(str(doc.get("level") or "").lower(),
                               db.SEV_MEDIUM),
        "level": str(doc.get("level") or ""),
    }
    if not meta["id"]:
        raise SigmaError("The rule has no `id`. The off-switch stores it.")
    if not meta["title"]:
        raise SigmaError("The rule has no `title`. It is the finding text.")
    return meta, where, params


def clients_matching(conn, where, params, limit=5000):
    """Which clients this rule matches, with how often and how many of those
    were answered 2xx.

    The 2xx count is not decoration. Every probe rule in this tool is
    outcome-gated -- a wave of attacks that was refused is a counter on the
    actor, not a finding -- and a SIGMA rule cannot express that itself, so
    the backend always reports it and the caller decides."""
    rows = conn.execute(
        f"SELECT ip.ip AS ip, count(*) AS hits, "
        f"       sum(CASE WHEN req.status BETWEEN 200 AND 299 THEN 1 ELSE 0 END) AS ok_hits, "
        f"       min(req.epoch) AS first_epoch, max(req.epoch) AS last_epoch "
        f"FROM {FROM_CLAUSE} WHERE {where} "
        f"GROUP BY ip.ip ORDER BY hits DESC LIMIT ?",
        list(params) + [limit]).fetchall()
    return [dict(r) for r in rows]


def example_uri(conn, where, params):
    """One URI that triggered it -- what the trace marks red. Without it a
    finding says a rule matched and not what it matched on."""
    row = conn.execute(
        f"SELECT uri.text AS uri FROM {FROM_CLAUSE} WHERE {where} LIMIT 1",
        list(params)).fetchone()
    return row["uri"] if row else ""
