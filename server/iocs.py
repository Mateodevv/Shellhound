# server/iocs.py
"""IOC classification, tagging vocabulary and exports (CSV / JSON / STIX 2.1).

Type detection is deterministic string shapes only and always overridable in
the UI. The tag system keeps the legacy discipline: PROVENANCE is written
once at collection (only the caller knows it), KIND restates the rule that
produced a finding, OBSERVED restates facts the case holds.
"""
import csv
import io
import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone

IOC_TYPES = ("ip", "hash", "url", "domain", "email", "path", "user", "other")

# provenance
TAG_ANALYST = "analyst"
TAG_FINDING = "finding"
TAG_CONFIRMED = "confirmed"
TAG_HUNT = "hunt"
TAG_ACTOR = "actor"
TAG_DERIVED = "derived"
# kind
TAG_WEBSHELL = "webshell"
TAG_INJECTED = "injected-code"
TAG_MODIFIED = "modified-file"
TAG_ACCOUNT = "account"
# observed
TAG_SCANNER = "scanner"
TAG_BRUTE = "brute-force"
TAG_SUCCESS = "successful"
TAG_THREATLIST = "threat-list"

TAGS = (TAG_ANALYST, TAG_FINDING, TAG_CONFIRMED, TAG_HUNT, TAG_ACTOR,
        TAG_DERIVED, TAG_WEBSHELL, TAG_INJECTED, TAG_MODIFIED, TAG_ACCOUNT,
        TAG_SCANNER, TAG_BRUTE, TAG_SUCCESS, TAG_THREATLIST)

_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
_URL_RE = re.compile(r"^https?://", re.I)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
_FILENAME_RE = re.compile(r"^[\w.\- ()\[\]{}@#%+~!$]{1,255}\.[A-Za-z0-9]{1,12}$")

# Hosts inside a finding's evidence: an injected <script src="//evil.test/x.js">
# names an attacker-controlled domain worth keeping.
HOST_RE = re.compile(r"(?:https?:)?//([A-Za-z0-9][A-Za-z0-9.\-]{1,250}\.[A-Za-z]{2,24})")


def classify(value):
    v = str(value).strip()
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if _HASH_RE.match(v):
        return "hash"
    if _URL_RE.match(v):
        return "url"
    if _EMAIL_RE.match(v):
        return "email"
    if "/" in v or "\\" in v:
        return "path"
    if _FILENAME_RE.match(v):
        return "path"
    if _DOMAIN_RE.match(v):
        return "domain"
    return "other"


# --- exports ----------------------------------------------------------------

def to_csv(iocs):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["Value", "Type", "Tags", "Note", "Origin", "Added"])
    for i in iocs:
        value = str(i["value"])
        # formula-injection guard, same rule as the legacy reports
        if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
            value = "'" + value
        w.writerow([value, i["type"], " ".join(json.loads(i["tags"] or "[]")),
                    i["note"], i["origin"], i["added"]])
    return buf.getvalue()


def to_json(iocs, case_name=""):
    return json.dumps({
        "case": case_name,
        "exported": datetime.now(timezone.utc).isoformat(),
        "iocs": [{"value": i["value"], "type": i["type"],
                  "tags": json.loads(i["tags"] or "[]"),
                  "note": i["note"], "origin": i["origin"], "added": i["added"]}
                 for i in iocs],
    }, indent=2, ensure_ascii=False)


_STIX_HASH_KIND = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}


def _stix_pattern(value, ioc_type):
    esc = str(value).replace("\\", "\\\\").replace("'", "\\'")
    if ioc_type == "ip":
        try:
            v = ipaddress.ip_address(str(value))
            obj = "ipv6-addr" if v.version == 6 else "ipv4-addr"
        except ValueError:
            obj = "ipv4-addr"
        return f"[{obj}:value = '{esc}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{esc}']"
    if ioc_type == "url":
        return f"[url:value = '{esc}']"
    if ioc_type == "email":
        return f"[email-addr:value = '{esc}']"
    if ioc_type == "hash":
        kind = _STIX_HASH_KIND.get(len(str(value)), "SHA-256")
        return f"[file:hashes.'{kind}' = '{esc}']"
    if ioc_type == "path":
        name = str(value).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        esc_name = name.replace("\\", "\\\\").replace("'", "\\'")
        return f"[file:name = '{esc_name}']"
    return None


def to_stix(iocs, case_name=""):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objects = []
    for i in iocs:
        pattern = _stix_pattern(i["value"], i["type"])
        if pattern is None:
            continue
        tags = json.loads(i["tags"] or "[]")
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": f"{i['type']}: {i['value']}",
            "description": (i["note"] or i["origin"] or ""),
            "labels": tags or ["indicator"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
        })
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}",
              "objects": objects}
    return json.dumps(bundle, indent=2, ensure_ascii=False)
