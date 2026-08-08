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

# How two indicators belong together (see ioc_links in db.py). Every kind
# stands here with BOTH reading directions: an edge is the same fact at its
# two ends, but not the same sentence -- at the hash it reads "is the SHA-256
# of /wp-content/…", at the path "has the SHA-256 6b2f…".
LINK_HASH_OF = "hash-of"
LINK_REQUESTED = "requested"
LINK_HOST_IN = "host-in"
LINK_ACCOUNT_OF = "account-of"

# (forward, back) -- how the edge reads from each of its two ends.
#
# These travel into CSV, JSON and STIX exports and are therefore not
# translated: an export is a snapshot for a recipient who cannot ask back,
# and it has to read the same in every case file of a team.
LINK_LABELS = {
    LINK_HASH_OF: ("is the SHA-256 of", "has the SHA-256"),
    LINK_REQUESTED: ("requested", "was requested by"),
    LINK_HOST_IN: ("appears in the code of", "points to"),
    LINK_ACCOUNT_OF: ("is the e-mail of", "has the e-mail"),
}
LINK_KINDS = tuple(LINK_LABELS)

_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
_URL_RE = re.compile(r"^https?://", re.I)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
_FILENAME_RE = re.compile(r"^[\w.\- ()\[\]{}@#%+~!$]{1,255}\.[A-Za-z0-9]{1,12}$")

# Hosts inside a finding's evidence: an injected <script src="//evil.test/x.js">
# names an attacker-controlled domain worth keeping.
HOST_RE = re.compile(r"(?:https?:)?//([A-Za-z0-9][A-Za-z0-9.\-]{1,250}\.[A-Za-z]{2,24})")

# Client addresses inside a finding's evidence, so the UI can offer a trace
# for them. IPv4 is octet-checked; the IPv6 forms deliberately require either
# a full eight groups or a `::` -- the loose form would read the 12:34:56 of
# every log timestamp as an address.
IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
    r"|\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b"
    r"|\b(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:[0-9A-Fa-f]{1,4})?\b")


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

def actor_tags(actor, brute_threshold):
    """What a client's own measurements say about it, as tags.

    ITS OWN FUNCTION BECAUSE TWO PLACES DECIDED THIS AND DRIFTED APART. The
    engine gates its "possible successful brute-force" alert on `admin_ok` --
    a 2xx on the CMS backend, which an unauthenticated session does not get.
    It used to gate on `login_redirects` and stopped, because Joomla answers
    EVERY login POST with a redirect, right credentials or wrong: a plain
    POST-Redirect-GET that proves nothing. The collector kept the old gate,
    so a client the case no longer accused still went into the box tagged
    "successful" -- and a tag on an indicator leaves the machine with it.

    Takes a mapping, so it can be asked about a shape rather than a case.
    """
    tags = [TAG_ACTOR]
    if (actor.get("scanner_uas") or "[]") != "[]":
        tags.append(TAG_SCANNER)
    if int(actor.get("login_posts") or 0) >= brute_threshold:
        tags.append(TAG_BRUTE)
    # THE SAME THREE CONDITIONS THE ENGINE USES, and it took two goes to get
    # here. Pulling the decision out of the endpoint fixed the gate that had
    # drifted (`login_redirects`) and left this one WIDER than the alert
    # beside it: `admin_ok` alone, no flood. So an operator who never
    # attracted a finding still went into the box tagged "successful" -- and
    # a tag on an indicator leaves the machine in the CSV, the JSON and the
    # STIX bundle, where nobody can see which gate produced it.
    #
    # The burst is the third: signing in every working morning for nine weeks
    # crosses a plain count, and reaches nothing inside any one day.
    if (int(actor.get("login_posts") or 0) >= brute_threshold
            and int(actor.get("login_burst") or 0) >= brute_threshold
            and int(actor.get("admin_ok") or 0) > 0):
        tags.append(TAG_SUCCESS)
    return tags


def _by_ioc(links):
    """Edges by indicator id, both ends, each in the fitting reading
    direction.

    An export is a snapshot: the recipient cannot ask back at which end the
    relationship sits."""
    out = {}
    for link in links or ():
        forward, back = LINK_LABELS.get(link["kind"], (link["kind"],) * 2)
        out.setdefault(link["src_id"], []).append(
            (forward, link["dst_value"], link["dst_type"], link["note"]))
        out.setdefault(link["dst_id"], []).append(
            (back, link["src_value"], link["src_type"], link["note"]))
    return out


def to_csv(iocs, links=()):
    by_ioc = _by_ioc(links)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["Value", "Type", "Tags", "Note", "Origin", "Added", "Related"])
    for i in iocs:
        value = str(i["value"])
        # formula-injection guard, same rule as the legacy reports
        if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
            value = "'" + value
        related = "; ".join(
            f"{label} {other}" for label, other, _t, _n in by_ioc.get(i["id"], ()))
        w.writerow([value, i["type"], " ".join(json.loads(i["tags"] or "[]")),
                    i["note"], i["origin"], i["added"], related])
    return buf.getvalue()


_TAIL = (", encoded as Unix seconds; clock_offsets names corrections set by "
         "the analyst.")


def _chain_note(chain):
    """One sentence naming the frame the exported timestamps are in.

    English and measured, like everything else that is stored or exported:
    the reader of this file may not be the analyst who made it."""
    if (chain.get("tz_mode") or "log") == "utc":
        return "Times are UTC" + _TAIL
    source = ("Times are naive local times of the respective source "
              "(log server resp. database server)")
    zone = chain.get("zone") or ""
    if zone:
        return f"{source} at {zone}{_TAIL}"
    # More than one offset in the logs. Naming any of them would be wrong for
    # the rest by the difference, so the file says what it has instead.
    offsets = ", ".join(chain.get("tz_offsets") or [])
    return (f"{source}; the logs carry more than one UTC offset"
            + (f" ({offsets})" if offsets else "")
            + ", so none of them labels the whole period -- export in UTC "
              "for a reading that can be compared" + _TAIL)


def to_json(iocs, case_name="", links=(), chain=None):
    by_ioc = _by_ioc(links)
    out = {
        "case": case_name,
        "exported": datetime.now(timezone.utc).isoformat(),
        "iocs": [{"value": i["value"], "type": i["type"],
                  "tags": json.loads(i["tags"] or "[]"),
                  "note": i["note"], "origin": i["origin"], "added": i["added"],
                  "related": [{"relation": label, "value": other, "type": typ,
                               "note": note}
                              for label, other, typ, note
                              in by_ioc.get(i["id"], ())]}
                 for i in iocs],
    }
    # The chronology travels along: the order of the events is the statement
    # that makes up the case, and until now it existed only in the dashboard.
    # `gaps` belongs to it -- what the case does NOT prove is part of the
    # report.
    if chain is not None:
        # WEBROOT-RELATIVE, ALWAYS. The IOC values themselves have been
        # relativised since the box existed; the chronology was added later
        # and carried `artifact` straight through, which put paths like
        # `C:\Cases\2026-05\webroot\...\shell.php` into a file meant to be
        # handed to somebody else. The absolute path is an identity for this
        # machine's interface and has no business in an export.
        def outward(row):
            out_row = {k: v for k, v in row.items() if k != "artifact_rel"}
            if row.get("artifact_rel"):
                out_row["artifact"] = row["artifact_rel"]
            return out_row

        out["chain"] = {
            "span": chain["span"],
            "events": [outward(e) for e in chain["events"]],
            "gaps": chain["gaps"],
            "undated": [outward(u) for u in chain["undated"]],
            "clock_offsets": chain.get("offsets", {}),
            # WHAT FRAME THE NUMBERS ABOVE ARE IN, said out loud. Every
            # timestamp here is a bare integer, so this sentence is the only
            # thing that makes them mean anything -- and it used to be a
            # fixed string describing log mode. Exported in UTC, the file
            # asserted its times were "naive local times of the respective
            # source", which they were not, and nothing in the file
            # contradicted it. A number with the wrong frame is worse than
            # no number: it is quotable.
            "tz_mode": chain.get("tz_mode") or "log",
            "zone": chain.get("zone") or "",
            "tz_offsets": chain.get("tz_offsets") or [],
            "note": _chain_note(chain),
        }
    return json.dumps(out, indent=2, ensure_ascii=False)


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
    if ioc_type == "user":
        # A planted account is exactly what one shares: under the same name
        # it signs in again in the next system.
        return f"[user-account:account_login = '{esc}']"
    if ioc_type == "hash":
        kind = _STIX_HASH_KIND.get(len(str(value)), "SHA-256")
        return f"[file:hashes.'{kind}' = '{esc}']"
    if ioc_type == "path":
        name = str(value).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        esc_name = name.replace("\\", "\\\\").replace("'", "\\'")
        return f"[file:name = '{esc_name}']"
    return None


def to_stix(iocs, case_name="", links=()):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objects = []
    # id of the indicator in the case -> id in the bundle. Only what stands
    # here was actually emitted: for some types there is no STIX pattern, and
    # an edge onto a non-existent object makes the bundle invalid.
    stix_ids = {}
    for i in iocs:
        pattern = _stix_pattern(i["value"], i["type"])
        if pattern is None:
            continue
        tags = json.loads(i["tags"] or "[]")
        stix_ids[i["id"]] = f"indicator--{uuid.uuid4()}"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": stix_ids[i["id"]],
            "created": now,
            "modified": now,
            "name": f"{i['type']}: {i['value']}",
            "description": (i["note"] or i["origin"] or ""),
            "labels": tags or ["indicator"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
        })
    # Without these objects a SIEM receives a handful of unconnected
    # indicators -- and the connection that makes up the case stays behind in
    # our database.
    #
    # relationship_type stays with the generic "related-to": between two
    # Indicators that is the value foreign systems reliably understand. The
    # exact kind stands next to it in the description, where it disturbs
    # nobody on import.
    for link in links or ():
        src, dst = stix_ids.get(link["src_id"]), stix_ids.get(link["dst_id"])
        if not src or not dst:
            continue
        label = LINK_LABELS.get(link["kind"], (link["kind"],) * 2)[0]
        detail = f" ({link['note']})" if link["note"] else ""
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "relationship_type": "related-to",
            "description": f"{link['kind']} — {link['src_value']} "
                           f"{label} {link['dst_value']}{detail}",
            "source_ref": src,
            "target_ref": dst,
        })
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}",
              "objects": objects}
    return json.dumps(bundle, indent=2, ensure_ascii=False)
