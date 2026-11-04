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
settings expose only the token's last four characters. Direct provider keys are kept server-side and used only without configured OpenCTI.
"""
from __future__ import annotations

import json
import os
import stat
import tempfile
import threading
import uuid
from urllib.parse import urlsplit
from pathlib import Path

SETTINGS_FILE = "settings.json"
_LOCK = threading.RLock()
_CTI_DEFAULTS = {"url": "", "token": "", "ingester_id": "", "timeout": 30,
                 "sample_uploads": False, "external_file_uploads": False}

# Direct reputation providers, used only when OpenCTI is not configured.
SERVICES = {
    "virustotal": {"sends": "hash, ip, domain, url", "url": "https://www.virustotal.com"},
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
    "indirect_php": False,
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


class SettingsError(RuntimeError):
    """A safe settings error that contains no file content or credentials."""


def load(workspace, *, for_write=False) -> dict:
    """Fill defaults for readers; never replace unreadable settings on a write."""
    out = {"keys": dict(_DEFAULTS["keys"]),
           "enrichment_ack": _DEFAULTS["enrichment_ack"], "indirect_php": False,
           "yara_disabled": [], "rules_disabled": [], "opencti": dict(_CTI_DEFAULTS)}
    try:
        raw = json.loads(path(workspace).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return out
    except OSError:
        if for_write:
            raise SettingsError("Saved settings could not be read. Check access to settings.json and retry.") from None
        return out
    except ValueError:
        if for_write:
            raise SettingsError("Saved settings.json is invalid. Restore a valid copy before saving changes.") from None
        return out
    if not isinstance(raw, dict):
        if for_write:
            raise SettingsError("Saved settings.json is invalid. Restore a valid copy before saving changes.")
        return out
    if for_write:
        for container, fields in (("keys", SERVICES), ("opencti", ("url", "token", "ingester_id"))):
            if container in raw and (not isinstance(raw[container], dict) or any(
                    field in raw[container] and not isinstance(raw[container][field], str)
                    for field in fields)):
                raise SettingsError("Saved settings.json is invalid. Restore a valid copy before saving changes.")
        # Keep fields written by other versions when changing an unrelated setting.
        out = {**raw, **out}
        out["keys"].update(raw.get("keys", {}))
        out["opencti"].update({key: value for key, value in raw.get("opencti", {}).items()
                               if key not in _CTI_DEFAULTS})
        out["opencti"]["external_file_uploads"] = False
    cti = raw.get("opencti")
    if isinstance(cti, dict):
        for key in ("url", "token", "ingester_id"):
            if isinstance(cti.get(key), str):
                out["opencti"][key] = cti[key].strip()
        out["opencti"]["sample_uploads"] = cti.get("sample_uploads") is True
    keys = raw.get("keys", {})
    if isinstance(keys, dict):
        for name in SERVICES:
            value = keys.get(name)
            if isinstance(value, str):
                out["keys"][name] = value.strip()
    out["enrichment_ack"] = raw.get("enrichment_ack") is True
    out["indirect_php"] = raw.get("indirect_php") is True
    for key in ("yara_disabled", "rules_disabled"):
        raw_list = raw.get(key)
        if isinstance(raw_list, list):
            out[key] = sorted({str(n) for n in raw_list if str(n).strip()})
    return out


def save(workspace, data) -> dict:
    """Replace settings only after a complete, private temporary file is flushed."""
    target = path(workspace)
    tmp = None
    try:
        payload = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=target.parent,
                                         prefix=target.name + ".", suffix=".tmp", delete=False) as stream:
            tmp = Path(stream.name)
            try:
                os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass  # Windows permissions are best effort, as for the settings file.
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        tmp.replace(target)
    except (OSError, TypeError, ValueError):
        raise SettingsError("Settings could not be saved. Existing settings have not been changed.") from None
    finally:
        if tmp is not None:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
    return data


def public(workspace) -> dict:
    """What the interface is allowed to see.

    A KEY NEVER LEAVES THIS FUNCTION IN FULL. The last four characters tell
    the analyst which key is configured; they cannot be used to sign a
    request. `configured` is what the UI actually switches on."""
    data = load(workspace, for_write=True)
    return {"services": {name: {**info, "configured": bool(data["keys"][name]),
            "hint": "…" + data["keys"][name][-4:] if len(data["keys"][name]) > 4 else "…" if data["keys"][name] else ""}
            for name, info in SERVICES.items()}, "enrichment_ack": data["enrichment_ack"],
            "opencti": _public_opencti(data["opencti"]), "indirect_php": data["indirect_php"],
            "path": str(path(workspace))}


def set_indirect_php(workspace, enabled) -> dict:
    with _LOCK:
        data = load(workspace, for_write=True)
        data["indirect_php"] = enabled is True
        save(workspace, data)
    return public(workspace)


def yara_disabled(workspace) -> set:
    """Rule files switched off for this workspace."""
    return set(load(workspace).get("yara_disabled", []))


def set_yara_disabled(workspace, names) -> list:
    with _LOCK:
        data = load(workspace, for_write=True)
        data["yara_disabled"] = sorted({str(n) for n in names if str(n).strip()})
        save(workspace, data)
        return data["yara_disabled"]


def set_key(workspace, service, key) -> dict:
    if service not in SERVICES:
        raise ValueError("Unknown enrichment provider")
    if not isinstance(key, str):
        raise ValueError("API key must be text")
    key = key.strip()
    if len(key) > 4096 or any(not 33 <= ord(c) <= 126 for c in key):
        raise ValueError("Invalid API key")
    from server import diagnostics
    diagnostics.protect_secret(key)
    with _LOCK:
        data = load(workspace, for_write=True)
        data["keys"][service] = key
        save(workspace, data)
    return public(workspace)


def set_ack(workspace, accepted) -> dict:
    with _LOCK:
        data = load(workspace, for_write=True)
        data["enrichment_ack"] = bool(accepted)
        save(workspace, data)
    return public(workspace)


def for_service(workspace, service) -> str:
    if service not in SERVICES:
        return ""
    data = load(workspace, for_write=True)
    if _public_opencti(data["opencti"])["configured"]:
        return ""
    key = data["keys"][service]
    from server import diagnostics
    diagnostics.protect_secret(key)
    return key


def opencti_config(workspace) -> dict:
    """Server-only credentials. Never put this dictionary in an API response."""
    return dict(load(workspace)["opencti"])


def opencti_public(workspace) -> dict:
    return _public_opencti(opencti_config(workspace))


def _public_opencti(data) -> dict:
    token = data["token"]
    visible = {key: data[key] for key in _CTI_DEFAULTS if key != "token"}
    return {**visible, "configured": bool(token and data["url"] and data["ingester_id"]),
            "token_hint": "…" + token[-4:] if len(token) >= 4 else ("…" if token else "")}


def set_opencti(workspace, changes) -> dict:
    """Keep credentials out of URLs and bind a token to its explicit host."""
    unknown = set(changes) - {"url", "token", "ingester_id", "sample_uploads"}
    if unknown:
        raise ValueError("Unsupported OpenCTI setting")
    with _LOCK:
        data = load(workspace, for_write=True)
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
