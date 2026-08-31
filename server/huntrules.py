"""Canonical Pattern-Hunt rules.

The visual editor and the optional text representation both end here.  The
module deliberately accepts a small allow-listed language; no part of the
analyst's input is ever treated as SQL or as a regular expression.

A rule contains one or more unordered request predicates.  Clauses inside a
request are ANDed, values inside one clause are ORed, and request predicates
are combined over one client with ``any`` or ``all``.  That preserves the
old, useful statement "this client requested both paths" without pretending
that the requests form an ordered attack sequence.
"""
from __future__ import annotations

import hashlib
import json
import re


FIELDS = (
    "uri", "path", "query", "method", "status",
    "user_agent", "referrer", "host",
)
OPERATORS = ("equals", "contains", "wildcard", "in")
TECHNOLOGIES = ("wordpress", "joomla", "generic", "other")
CLIENT_MATCH = ("any", "all")

MAX_REQUESTS = 8
MAX_CLAUSES = 16
MAX_VALUES = 16
MAX_VALUE_LENGTH = 2048
MIN_PATTERN_LENGTH = 3

_STATUS = re.compile(r"^[1-5](?:xx|\d{2})$", re.I)
_METHOD = re.compile(r"^[A-Z][A-Z0-9_-]{0,31}$")


class RuleError(ValueError):
    def __init__(self, message: str, key: str = "err.patternRule"):
        super().__init__(message)
        self.key = key


def _values(raw, *, upper=False):
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        raise RuleError("Clause values must be a list.")
    out = []
    for item in raw:
        value = str(item or "").strip()
        if upper:
            value = value.upper()
        if not value:
            continue
        if len(value) > MAX_VALUE_LENGTH:
            raise RuleError("A rule value is too long.")
        if any(ord(char) < 32 and char not in "\t" for char in value):
            raise RuleError("A rule value contains control characters.")
        if value.lower() not in {known.lower() for known in out}:
            out.append(value)
    if not out:
        raise RuleError("A clause needs at least one value.")
    if len(out) > MAX_VALUES:
        raise RuleError(f"At most {MAX_VALUES} values are allowed per clause.")
    return out


def normalise_clause(raw):
    if not isinstance(raw, dict):
        raise RuleError("A rule clause must be an object.")
    field = str(raw.get("field") or "").strip().lower()
    operator = str(raw.get("operator") or "").strip().lower()
    if field not in FIELDS:
        raise RuleError("Unknown rule field.")
    if operator not in OPERATORS:
        raise RuleError("Unknown rule operator.")
    if field in ("method", "status") and operator not in ("in", "equals"):
        raise RuleError(f"{field} only supports equals or in.")
    values = _values(raw.get("values"), upper=field == "method")
    if field == "method" and any(not _METHOD.fullmatch(value) for value in values):
        raise RuleError("Invalid HTTP method.")
    if field == "status":
        values = [value.lower() for value in values]
        if any(not _STATUS.fullmatch(value) for value in values):
            raise RuleError("Status must be an exact code or a class such as 2xx.")
    if field in ("uri", "path", "query", "user_agent", "referrer", "host"):
        for value in values:
            substance = value.replace("*", "").replace("?", "")
            if operator != "equals" and len(substance) < MIN_PATTERN_LENGTH:
                raise RuleError(
                    "A text pattern needs at least three characters besides wildcards.",
                    "err.patternTooShort",
                )
    return {"field": field, "operator": operator, "values": values}


def normalise_rule(raw):
    if not isinstance(raw, dict):
        raise RuleError("A hunt rule must be an object.")
    client_match = str(raw.get("client_match") or "any").strip().lower()
    if client_match not in CLIENT_MATCH:
        raise RuleError("Unknown request combination.", "err.patternMatchMode")
    requests = raw.get("requests")
    if not isinstance(requests, list) or not requests:
        raise RuleError("A hunt rule needs at least one request.", "err.patternEmpty")
    if len(requests) > MAX_REQUESTS:
        raise RuleError(f"At most {MAX_REQUESTS} request steps are allowed.")
    clean_requests = []
    for request in requests:
        if not isinstance(request, dict):
            raise RuleError("A request step must be an object.")
        clauses = request.get("clauses")
        if not isinstance(clauses, list) or not clauses:
            raise RuleError("A request step needs at least one clause.")
        if len(clauses) > MAX_CLAUSES:
            raise RuleError(f"At most {MAX_CLAUSES} clauses are allowed per request.")
        clean = []
        for clause in clauses:
            item = normalise_clause(clause)
            signature = (item["field"], item["operator"],
                         tuple(value.lower() for value in item["values"]))
            if signature not in {
                    (old["field"], old["operator"],
                     tuple(value.lower() for value in old["values"]))
                    for old in clean}:
                clean.append(item)
        clean_requests.append({"clauses": clean})
    return {"client_match": client_match, "requests": clean_requests}


def legacy_rule(patterns, match="any", request=None):
    """Lift the v1 path + request-filter shape into the canonical model."""
    if isinstance(patterns, str):
        patterns = [patterns]
    request = request if isinstance(request, dict) else {}
    methods = request.get("methods") or []
    agents = request.get("user_agents") or []
    steps = []
    for pattern in patterns or []:
        clauses = [{"field": "uri", "operator": "wildcard",
                    "values": [str(pattern)]}]
        if methods:
            clauses.append({"field": "method", "operator": "in",
                            "values": methods})
        if agents:
            clauses.append({"field": "user_agent", "operator": "wildcard",
                            "values": agents})
        steps.append({"clauses": clauses})
    return normalise_rule({"client_match": match, "requests": steps})


def legacy_projection(rule):
    """Return the old fields used by older clients and reports.

    Full v2 rules cannot be represented perfectly.  Their URI-like clauses
    are still returned as readable pattern labels while the canonical rule
    remains authoritative.
    """
    rule = normalise_rule(rule)
    paths, common_methods, common_agents = [], None, None
    for request in rule["requests"]:
        methods, agents = [], []
        for clause in request["clauses"]:
            if clause["field"] in ("uri", "path", "query"):
                paths.extend(clause["values"])
            elif clause["field"] == "method":
                methods.extend(clause["values"])
            elif clause["field"] == "user_agent":
                agents.extend(clause["values"])
        common_methods = methods if common_methods is None else [
            value for value in common_methods if value in methods]
        common_agents = agents if common_agents is None else [
            value for value in common_agents if value in agents]
    return {
        "patterns": paths or ["(structured request rule)"],
        "match": rule["client_match"],
        "request": {"methods": common_methods or [],
                    "user_agents": common_agents or []},
    }


def rule_hash(rule):
    clean = normalise_rule(rule)
    canonical_requests = []
    for request in clean["requests"]:
        clauses = [{**clause, "values": sorted(
            clause["values"], key=str.lower)} for clause in request["clauses"]]
        clauses.sort(key=lambda clause: (
            clause["field"], clause["operator"],
            tuple(value.lower() for value in clause["values"])))
        canonical_requests.append({"clauses": clauses})
    canonical_requests.sort(key=lambda request: json.dumps(
        request, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    canonical = {"client_match": clean["client_match"],
                 "requests": canonical_requests}
    payload = json.dumps(canonical, ensure_ascii=False,
                         sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def to_dsl(rule):
    rule = normalise_rule(rule)
    lines = [f"client {rule['client_match']}"]
    for request in rule["requests"]:
        lines.append("request")
        for clause in request["clauses"]:
            encoded = json.dumps(clause["values"], ensure_ascii=False)
            lines.append(f"  {clause['field']} {clause['operator']} {encoded}")
        lines.append("end")
    return "\n".join(lines)


def parse_dsl(text):
    lines = [line.strip() for line in str(text or "").splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    if not lines:
        raise RuleError("The rule text is empty.")
    head = lines.pop(0).split()
    if len(head) != 2 or head[0].lower() != "client":
        raise RuleError("The first line must be 'client any' or 'client all'.")
    requests, current = [], None
    for line in lines:
        if line.lower() == "request":
            if current is not None:
                raise RuleError("Close the current request with 'end'.")
            current = {"clauses": []}
            continue
        if line.lower() == "end":
            if current is None:
                raise RuleError("Unexpected 'end'.")
            requests.append(current)
            current = None
            continue
        if current is None:
            raise RuleError("Clauses must be inside a request/end block.")
        parts = line.split(None, 2)
        if len(parts) != 3:
            raise RuleError("A clause needs field, operator and JSON values.")
        try:
            values = json.loads(parts[2])
        except ValueError as exc:
            raise RuleError("Clause values must be valid JSON.") from exc
        current["clauses"].append({"field": parts[0], "operator": parts[1],
                                   "values": values})
    if current is not None:
        raise RuleError("Close the final request with 'end'.")
    return normalise_rule({"client_match": head[1], "requests": requests})


def suggest_technology(*values):
    text = " ".join(str(value or "") for value in values).lower()
    if any(marker in text for marker in (
            "wordpress", "wp-admin", "wp-content", "wp-json", "wp-login")):
        return "wordpress"
    if any(marker in text for marker in (
            "joomla", "/administrator", "option=com_", "task=", "com_jce")):
        return "joomla"
    return "generic"
