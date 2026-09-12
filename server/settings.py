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

The server adapter receives credentials through `opencti_config()`. Public
settings expose only the token's last four characters. Legacy direct provider
keys are ignored on read and discarded on the next settings write.
"""
from __future__ import annotations

import json
import os
import stat
import threading
import uuid
from urllib.parse import urlsplit
from pathlib import Path

SETTINGS_FILE = "settings.json"
_LOCK = threading.RLock()
_CTI_DEFAULTS = {"url": "", "token": "", "ingester_id": "", "timeout": 30,
                 "sample_uploads": False, "external_file_uploads": False}

# Legacy settings shape, retained as empty slots for older configuration files.
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
}


def path(workspace) -> Path:
    return Path(workspace) / SETTINGS_FILE


def load(workspace) -> dict:
    """The settings, with defaults filled in. A broken file never raises --
    it must not be the reason the interface stops opening."""
    out = {"keys": dict(_DEFAULTS["keys"]),
           "enrichment_ack": _DEFAULTS["enrichment_ack"],
           "yara_disabled": [], "rules_disabled": [], "opencti": dict(_CTI_DEFAULTS)}
    try:
        raw = json.loads(path(workspace).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return out
    if not isinstance(raw, dict):
        return out
    cti = raw.get("opencti")
    if isinstance(cti, dict):
        for key in ("url", "token", "ingester_id"):
            if isinstance(cti.get(key), str):
                out["opencti"][key] = cti[key].strip()
        out["opencti"]["sample_uploads"] = cti.get("sample_uploads") is True
    # Direct provider credentials are retired. Existing cache entries live
    # in case.db and remain readable without retaining or releasing keys.
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
    return {"services": {}, "enrichment_ack": False,
            "opencti": opencti_public(workspace), "path": str(path(workspace))}


def yara_disabled(workspace) -> set:
    """Rule files switched off for this workspace."""
    return set(load(workspace).get("yara_disabled", []))


def set_yara_disabled(workspace, names) -> list:
    with _LOCK:
        data = load(workspace)
        data["yara_disabled"] = sorted({str(n) for n in names if str(n).strip()})
        save(workspace, data)
        return data["yara_disabled"]


def set_key(workspace, service, key) -> dict:
    """Reject writes from callers using the retired provider configuration."""
    raise ValueError("Direct provider keys are retired. Configure OpenCTI instead.")


def set_ack(workspace, accepted) -> dict:
    """Reject the retired global consent flag; OpenCTI actions are explicit."""
    raise ValueError("Direct enrichment is retired. Use OpenCTI instead.")


def for_service(workspace, service) -> str:
    """Never release a retired direct-provider credential."""
    # Legacy keys may remain on disk for backwards compatibility, but are
    # never released to direct enrichment callers in this version.
    return ""


def opencti_config(workspace) -> dict:
    """Server-only credentials. Never put this dictionary in an API response."""
    return dict(load(workspace)["opencti"])


def opencti_public(workspace) -> dict:
    data = opencti_config(workspace)
    token = data.pop("token")
    return {**data, "configured": bool(token and data["url"] and data["ingester_id"]),
            "token_hint": "…" + token[-4:] if len(token) >= 4 else ("…" if token else "")}


def set_opencti(workspace, changes) -> dict:
    """Keep credentials out of URLs and bind a token to its explicit host."""
    unknown = set(changes) - {"url", "token", "ingester_id", "sample_uploads"}
    if unknown:
        raise ValueError("Unsupported OpenCTI setting")
    with _LOCK:
        data = load(workspace)
        current = data["opencti"]
        for key in ("url", "token", "ingester_id"):
            if key in changes and not isinstance(changes[key], str):
                raise ValueError("OpenCTI connection fields must be text")
        if "url" in changes:
            url = changes["url"].strip().rstrip("/")
            try:
                parsed = urlsplit(url)
                port = parsed.port
            except ValueError:
                raise ValueError("OpenCTI URL has an invalid host or port") from None
            if url and (parsed.scheme != "https" or not parsed.hostname or
                        parsed.username or parsed.password or parsed.query or parsed.fragment or
                        "\\" in url or any(c.isspace() or ord(c) < 32 for c in url) or
                        (port is not None and not 1 <= port <= 65535)):
                raise ValueError("OpenCTI requires an HTTPS URL without credentials, query or fragment")
            if url != current["url"]:
                current["token"] = ""
            current["url"] = url
        if "ingester_id" in changes:
            value = changes["ingester_id"].strip()
            if value:
                try:
                    value = str(uuid.UUID(value))
                except ValueError:
                    raise ValueError("TAXII ingester ID must be a UUID") from None
            current["ingester_id"] = value
        if "token" in changes:
            token = changes["token"].strip()
            if len(token) > 4096 or any(not 33 <= ord(c) <= 126 for c in token):
                raise ValueError("Invalid integration token")
            current["token"] = token
        if "sample_uploads" in changes:
            if not isinstance(changes["sample_uploads"], bool):
                raise ValueError("Sample uploads must be enabled explicitly")
            current["sample_uploads"] = changes["sample_uploads"]
        current["external_file_uploads"] = False
        save(workspace, data)
    return opencti_public(workspace)
