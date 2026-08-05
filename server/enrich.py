# server/enrich.py
"""Asking a third party about ONE indicator -- the only enrichment path.

THIS IS THE PART OF SHELLHOUND THAT TALKS TO STRANGERS, and everything about
it is built around limiting that.

WHAT GOES OUT is one value: a SHA-256 to VirusTotal, an IP to AbuseIPDB.
Nothing else -- not the case name, not the path the hash belongs to, not the
other indicators, not a user agent that identifies the case. `_payload_for()`
is the only place a request body is assembled, and it takes a single string.

WHAT THAT STILL COSTS is stated rather than glossed over: sending a hash tells
VirusTotal that somebody holds that file, and an IP tells AbuseIPDB that
somebody is investigating it. On a mandate under an NDA that can itself be
the leak. The analyst confirms it once per workspace (`enrichment_ack`) and
triggers every lookup by hand -- there is no sweep, no background refresh, no
"enrich all".

WHAT COMES BACK IS AN OPINION, NOT A MEASUREMENT. The rest of this toolkit
reports what it measured in the evidence at hand; a reputation score is
somebody else's conclusion about somebody else's data. It is therefore stored
apart from the findings, never touches triage or severity, and is labelled as
foreign in the interface. A file is not a webshell because VirusTotal says
so, and it is not clean because VirusTotal is silent.

The cache is per case: the same hash asked twice costs one request, and the
stored answer carries the time it was fetched -- a verdict from six weeks ago
is a different statement from one fetched this morning.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from server import db, settings

_TIMEOUT = 12
_USER_AGENT = "shellhound"

# Free tiers are small and the limits are per KEY, not per case: four
# requests a minute at VirusTotal, a daily budget at AbuseIPDB. Going over
# them earns a 429 and, repeatedly, a blocked key -- so the throttle sits
# here rather than in the analyst's clicking speed.
#
# The tests turn these down. At the production interval a suite that makes a
# dozen lookups would sit and wait for three minutes, and a test that is
# mostly `sleep` is a test nobody runs.
MIN_INTERVAL = {"virustotal": 15.5, "abuseipdb": 1.0}
_last_call: dict[str, float] = {}
_lock = threading.Lock()


class EnrichError(Exception):
    """A lookup that could not be answered, with a reason a human can act
    on. Never carries the key."""


def _throttle(service):
    """Wait out the per-service interval. Blocks the calling request thread
    on purpose: a lookup is one explicit click, and an answer that arrives a
    few seconds later beats a 429 the analyst has to interpret."""
    with _lock:
        interval = MIN_INTERVAL.get(service, 1.0)
        wait = interval - (time.monotonic() - _last_call.get(service, 0.0))
        if wait > 0:
            time.sleep(min(wait, interval))
        _last_call[service] = time.monotonic()


def _get(url, headers):
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT,
                                               **headers})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        if e.code == 401 or e.code == 403:
            raise EnrichError("key rejected") from e
        if e.code == 404:
            return None                      # not a failure: simply unknown
        if e.code == 429:
            raise EnrichError("rate limit reached") from e
        raise EnrichError(f"HTTP {e.code}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise EnrichError(f"not reachable: {e.__class__.__name__}") from e
    except ValueError as e:
        raise EnrichError("unreadable answer") from e


# --- the two services -------------------------------------------------------
#
# Each takes ONE value and returns a flat dict. The shape is deliberately the
# same for both, so the interface renders one component and the analyst reads
# one kind of card: a verdict number, what it is out of, and a few facts.

def _virustotal(key, sha256):
    data = _get(f"https://www.virustotal.com/api/v3/files/{urllib.parse.quote(sha256)}",
                {"x-apikey": key})
    if data is None:
        return {"known": False}
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    total = sum(int(v or 0) for v in stats.values()) or 0
    names = [n for n in (attrs.get("names") or []) if isinstance(n, str)][:5]
    return {
        "known": True,
        "score": malicious,
        "of": total,
        "suspicious": suspicious,
        "label": attrs.get("popular_threat_classification", {})
                      .get("suggested_threat_label", ""),
        "names": names,
        "first_seen": attrs.get("first_submission_date"),
        "last_analysis": attrs.get("last_analysis_date"),
        "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
    }


def _abuseipdb(key, ip):
    query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    data = _get(f"https://api.abuseipdb.com/api/v2/check?{query}",
                {"Key": key, "Accept": "application/json"})
    if data is None:
        return {"known": False}
    d = data.get("data") or {}
    reports = int(d.get("totalReports") or 0)
    return {
        "known": True,
        "score": int(d.get("abuseConfidenceScore") or 0),
        "of": 100,
        "reports": reports,
        "distinct_reporters": int(d.get("numDistinctUsers") or 0),
        "country": (d.get("countryCode") or "").lower(),
        "isp": d.get("isp") or "",
        "usage": d.get("usageType") or "",
        "domain": d.get("domain") or "",
        "tor": bool(d.get("isTor")),
        "last_reported": d.get("lastReportedAt"),
        "permalink": f"https://www.abuseipdb.com/check/{urllib.parse.quote(ip)}",
    }


_LOOKUPS = {"virustotal": _virustotal, "abuseipdb": _abuseipdb}

# What each service is allowed to be asked about. Enforced, not documented:
# an IP must never be sent to VirusTotal by a caller that mixed up its
# arguments, and a hash must never end up at AbuseIPDB.
_ACCEPTS = {"virustotal": "hash", "abuseipdb": "ip"}


def _payload_for(service, value):
    """The one value that goes out, checked. Anything else is a bug in the
    caller and is refused here rather than sent."""
    value = str(value or "").strip()
    if not value:
        raise EnrichError("nothing to look up")
    kind = _ACCEPTS[service]
    if kind == "hash":
        if len(value) != 64 or any(c not in "0123456789abcdefABCDEF" for c in value):
            raise EnrichError("not a SHA-256")
        return value.lower()
    if kind == "ip":
        import ipaddress
        try:
            ipaddress.ip_address(value)
        except ValueError as e:
            raise EnrichError("not an IP address") from e
        return value
    raise EnrichError("unknown indicator kind")


# --- the cache --------------------------------------------------------------

def cached(conn, service, value):
    row = db.one(conn, "SELECT * FROM enrichment WHERE service = ? AND value = ?",
                 (service, str(value).strip()))
    if row is None:
        return None
    try:
        row["result"] = json.loads(row["payload"] or "{}")
    except ValueError:
        row["result"] = {}
    row.pop("payload", None)
    return row


def all_for(conn, values):
    """Everything already known about these indicators -- one query, so a
    list can show its badges without one request per row."""
    values = [str(v).strip() for v in values if str(v or "").strip()]
    if not values:
        return {}
    out = {}
    for i in range(0, len(values), 400):
        chunk = values[i:i + 400]
        marks = ",".join("?" * len(chunk))
        for row in db.rows(conn, f"SELECT service, value, fetched, payload "
                                 f"FROM enrichment WHERE value IN ({marks})",
                           chunk):
            try:
                result = json.loads(row["payload"] or "{}")
            except ValueError:
                result = {}
            out.setdefault(row["value"], {})[row["service"]] = {
                "fetched": row["fetched"], "result": result}
    return out


def lookup(workspace, case_dir, service, value, refresh=False):
    """Ask one service about one indicator.

    Returns the stored answer when there is one and `refresh` is not set --
    the analyst clicking twice must not cost two requests. The reply always
    carries `fetched`, because a verdict from six weeks ago is a different
    statement from one fetched this morning.
    """
    if service not in _LOOKUPS:
        raise EnrichError(f"unknown service: {service}")
    conf = settings.load(workspace)
    if not conf["enrichment_ack"]:
        raise EnrichError("lookups have not been accepted yet")
    key = conf["keys"].get(service, "")
    if not key:
        raise EnrichError("no API key configured")
    payload = _payload_for(service, value)

    conn = db.connect(case_dir)
    try:
        if not refresh:
            hit = cached(conn, service, payload)
            if hit is not None:
                return {**hit, "cached": True}
    finally:
        conn.close()

    _throttle(service)
    result = _LOOKUPS[service](key, payload)

    # Written AFTER the call and in its own connection: the request can take
    # seconds, and holding a write transaction on the case database across a
    # network round trip is how the interface starts stalling.
    conn = db.connect(case_dir)
    try:
        conn.execute(
            "INSERT INTO enrichment (service, value, kind, fetched, payload) "
            "VALUES (?,?,?,?,?) ON CONFLICT(service, value) DO UPDATE SET "
            "fetched = excluded.fetched, payload = excluded.payload",
            (service, payload, _ACCEPTS[service], db.now(),
             json.dumps(result, ensure_ascii=False)))
        conn.commit()
    finally:
        conn.close()
    return {"service": service, "value": payload, "kind": _ACCEPTS[service],
            "fetched": db.now(), "result": result, "cached": False}
