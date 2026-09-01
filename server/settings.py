# server/settings.py
"""Operator configuration: what the ANALYST set up, not what a case found.

Lives in the workspace (`settings.json`), next to the pattern library and for
the same reason: it is knowledge about how this workstation works, not about
one incident. A case archive therefore never carries it -- handing a colleague
a case must not hand them an API key.

WHAT IS STORED HERE IS A SECRET, AND IT IS STORED IN CLEARTEXT. There is no
key store to hide it in: this is a single-seat tool on a machine where the
analyst already holds every piece of evidence, and a "protection" that
amounts to base64 would only pretend. The file is created readable by its
owner alone where the platform supports it, and that is the honest extent of
it -- said plainly here rather than implied by an encrypted-looking blob.

Keys leave this module in ONE direction only: `for_service()` hands the real
value to the enrichment call. Everything the interface sees comes from
`public()`, which reduces a key to its last four characters -- enough to tell
two keys apart, not enough to use one.
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

SETTINGS_FILE = "settings.json"

# The services that may be asked about an indicator. Each names the ONE thing
# it is allowed to receive -- see server/enrich.py, where that is enforced.
SERVICES = {
    "virustotal": {"sends": "hash", "url": "https://www.virustotal.com"},
    "abuseipdb": {"sends": "ip", "url": "https://www.abuseipdb.com"},
}

_DEFAULTS = {
    # service -> API key. Empty means: not configured, and the interface
    # offers no lookup for it.
    "keys": {name: "" for name in SERVICES},
    # The analyst has read what a lookup sends and accepted it. Until this is
    # true, no request leaves the machine -- the same gate as the GeoIP
    # download, and for the same reason.
    "enrichment_ack": False,
    # YARA rule FILES switched off for this workspace, by file name. Stored
    # here rather than as a marker inside the rule, because the rule file is
    # the analyst's own text and may have come from a vendor feed: switching
    # it off must not edit it.
    "yara_disabled": [],
    # Detection rules switched off for this workspace, by rule id. See
    # server/ruleswitch.py -- an unknown id counts as ENABLED, so a rule an
    # upgrade adds arrives running.
    "rules_disabled": [],
    # One deliberately configured OpenCTI instance per workspace.  The token
    # follows exactly the same honest storage model as the enrichment keys:
    # clear text in the owner-only settings file, never in a case archive and
    # never returned to the browser.
    "opencti": {
        "url": "",
        "token": "",
        "taxii_collection_url": "",
        "author_id": "",
        "author_name": "",
        "default_marking_id": "",
        "default_marking_name": "",
        "verified_at": "",
        "version": "",
        "capabilities": [],
        "markings": [],
        "authors": [],
    },
}


def path(workspace) -> Path:
    return Path(workspace) / SETTINGS_FILE


def load(workspace) -> dict:
    """The settings, with defaults filled in. A broken file never raises --
    it must not be the reason the interface stops opening."""
    out = {"keys": dict(_DEFAULTS["keys"]),
           "enrichment_ack": _DEFAULTS["enrichment_ack"],
           "yara_disabled": [], "rules_disabled": [],
           "opencti": {**_DEFAULTS["opencti"]}}
    try:
        raw = json.loads(path(workspace).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return out
    if not isinstance(raw, dict):
        return out
    keys = raw.get("keys")
    if isinstance(keys, dict):
        for name in SERVICES:
            value = keys.get(name)
            if isinstance(value, str):
                out["keys"][name] = value.strip()
    out["enrichment_ack"] = bool(raw.get("enrichment_ack"))
    opencti = raw.get("opencti")
    if isinstance(opencti, dict):
        for key in ("url", "token", "taxii_collection_url", "author_id",
                    "author_name", "default_marking_id",
                    "default_marking_name", "verified_at", "version"):
            value = opencti.get(key)
            if isinstance(value, str):
                out["opencti"][key] = value.strip()
        for key in ("capabilities", "markings", "authors"):
            value = opencti.get(key)
            if isinstance(value, list):
                out["opencti"][key] = value
    # Anything not understood is dropped on the next write, so every key the
    # file is allowed to carry has to be read back here.
    for key in ("yara_disabled", "rules_disabled"):
        raw_list = raw.get(key)
        if isinstance(raw_list, list):
            out[key] = sorted({str(n) for n in raw_list if str(n).strip()})
    return out


def save(workspace, data) -> dict:
    """Write settings, owner-readable where the platform allows it."""
    target = path(workspace)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".tmp")
    # Beside it first, then replace: a crash mid-write must not leave the
    # workspace with half a settings file.
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                   encoding="utf-8")
    tmp.replace(target)
    try:
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        # Windows and exotic file systems: best effort, and the docstring
        # says so rather than the code pretending it worked.
        pass
    return data


def public(workspace) -> dict:
    """What the interface is allowed to see.

    A KEY NEVER LEAVES THIS FUNCTION IN FULL. The last four characters tell
    the analyst which key is configured; they cannot be used to sign a
    request. `configured` is what the UI actually switches on."""
    data = load(workspace)
    services = {}
    for name, meta in SERVICES.items():
        key = data["keys"].get(name, "")
        services[name] = {
            "configured": bool(key),
            "hint": f"…{key[-4:]}" if len(key) >= 4 else ("…" if key else ""),
            "sends": meta["sends"],
            "url": meta["url"],
        }
    opencti = data["opencti"]
    token = opencti.get("token", "")
    public_opencti = {
        key: value for key, value in opencti.items() if key != "token"
    }
    public_opencti.update({
        "configured": bool(opencti.get("url") and token
                           and opencti.get("taxii_collection_url")),
        "verified": bool(opencti.get("verified_at")),
        "token_hint": f"…{token[-4:]}" if len(token) >= 4
                      else ("…" if token else ""),
    })
    return {"services": services, "enrichment_ack": data["enrichment_ack"],
            "opencti": public_opencti, "path": str(path(workspace))}


def yara_disabled(workspace) -> set:
    """Rule files switched off for this workspace."""
    return set(load(workspace).get("yara_disabled", []))


def set_yara_disabled(workspace, names) -> list:
    data = load(workspace)
    data["yara_disabled"] = sorted({str(n) for n in names if str(n).strip()})
    save(workspace, data)
    return data["yara_disabled"]


def set_key(workspace, service, key) -> dict:
    """Set or clear one key. An empty string clears it -- that is how the
    analyst switches a service off, and it must not be a separate verb."""
    if service not in SERVICES:
        raise ValueError(f"unknown service: {service}")
    data = load(workspace)
    data["keys"][service] = str(key or "").strip()
    save(workspace, data)
    return public(workspace)


def set_ack(workspace, accepted) -> dict:
    """Record that the analyst accepted what a lookup sends out."""
    data = load(workspace)
    data["enrichment_ack"] = bool(accepted)
    save(workspace, data)
    return public(workspace)


def for_service(workspace, service) -> str:
    """The real key -- the only way out of this module. Callers hand it
    straight to the request and never store or log it."""
    return load(workspace)["keys"].get(service, "")


def opencti(workspace) -> dict:
    """The private OpenCTI configuration for the server-side adapter."""
    return dict(load(workspace).get("opencti") or {})


def set_opencti(workspace, values) -> dict:
    """Update connection fields without clearing a token the UI cannot read.

    Sending ``token=None`` retains it; an explicit empty string clears it.
    Any connection-affecting change clears the verification snapshot so the
    integration stays hidden until the operator tests the new endpoint.
    """
    allowed = {"url", "token", "taxii_collection_url", "author_id",
               "author_name", "default_marking_id", "default_marking_name"}
    data = load(workspace)
    current = dict(data.get("opencti") or _DEFAULTS["opencti"])
    connection_changed = False
    for key in allowed:
        if key not in values or values[key] is None:
            continue
        value = str(values[key] or "").strip()
        if current.get(key, "") != value:
            current[key] = value
            if key in {"url", "token", "taxii_collection_url"}:
                connection_changed = True
    if connection_changed:
        current.update(verified_at="", version="", capabilities=[],
                       markings=[], authors=[])
    data["opencti"] = current
    save(workspace, data)
    return public(workspace)["opencti"]


def verify_opencti(workspace, result) -> dict:
    """Persist only the harmless connection catalogue, never a response dump."""
    data = load(workspace)
    current = dict(data.get("opencti") or _DEFAULTS["opencti"])
    for key in ("verified_at", "version", "capabilities", "markings", "authors"):
        current[key] = result.get(key, "" if key in ("verified_at", "version") else [])
    data["opencti"] = current
    save(workspace, data)
    return public(workspace)["opencti"]
