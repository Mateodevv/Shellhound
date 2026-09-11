"""Validated case context shared with OpenCTI.

``defaults`` and ``list_organizations`` never write. ``normalize`` is for an
explicit case save: it merges a partial profile and resolves (or creates) its
organization. Legacy generated names and identifiers remain supported.
"""
from __future__ import annotations

import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

REGISTRY_FILE = "pseudonyms.json"
MARKINGS = ("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED")
_LOCK = threading.RLock()
_FIELDS = {"organization_id", "organization_name", "pseudonym", "summary", "sectors", "subsectors", "countries", "state", "city",
           "first_seen", "last_seen", "software", "vulnerabilities", "marking"}


def defaults(profile=None):
    """Return a fresh complete shape, including for an unmigrated old case."""
    result = {"organization_id": "", "organization_name": "", "pseudonym": "", "summary": "",
              "subsectors": [], "state": "", "city": "",
              "sectors": [], "countries": [], "first_seen": "", "last_seen": "",
              "software": [], "vulnerabilities": [], "marking": "TLP:AMBER+STRICT"}
    if isinstance(profile, dict):
        result.update({key: value for key, value in profile.items() if key in _FIELDS})
    return result


def _text(value, field, limit=500, required=False):
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    value = value.strip()
    if len(value) > limit or "\x00" in value:
        raise ValueError(f"{field} is too long or contains invalid characters")
    if required and not value:
        raise ValueError(f"{field} is required")
    return value


def _array(value, field, limit=100):
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(f"{field} must be a list with at most {limit} entries")
    return value


def _entry(value, fields, field):
    if not isinstance(value, dict) or set(value) - set(fields):
        raise ValueError(f"{field} contains unsupported fields")
    return value


def _date(value, field):
    value = _text(value, field, 40)
    if not value:
        return value, None
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO date or timestamp") from exc
    return value, date.replace(tzinfo=date.tzinfo or timezone.utc)


def _validated(profile):
    if not isinstance(profile, dict) or set(profile) - _FIELDS:
        raise ValueError("Case profile contains unsupported fields")
    result = defaults(profile)
    for key in ("organization_id", "organization_name", "pseudonym", "city", "state"):
        result[key] = _text(result[key], key, 200)
    result["summary"] = _text(result["summary"], "summary", 10000)
    for field in ("sectors", "countries"):
        result[field] = list(dict.fromkeys(
            _text(v, field, 200, required=True) for v in _array(result[field], field)))
    if any(not re.fullmatch(r"[A-Za-z]{2}", value) for value in result["countries"]):
        raise ValueError("Countries must use two-letter ISO codes, such as DE or AT")
    result["countries"] = list(dict.fromkeys(value.upper() for value in result["countries"]))
    from server.profile_options import geography
    geo = geography()
    if any(value not in {item['code'] for item in geo['countries']} for value in result['countries']):
        raise ValueError('Choose a valid country')
    if result['state'] and (not result['countries'] or result['state'] not in
            {item['code'] for item in geo['states'].get(result['countries'][0], [])}):
        raise ValueError('State must belong to the selected country')
    subsectors = []
    for value in _array(result['subsectors'], 'subsectors'):
        item = _entry(value, ('name', 'sector'), 'subsector')
        name = _text(item.get('name', ''), 'subsector name', 200, required=True)
        sector = _text(item.get('sector', ''), 'parent sector', 200, required=True)
        if sector not in result['sectors']:
            raise ValueError('Select the parent sector for each subsector')
        entry = {'name': name, 'sector': sector}
        if entry not in subsectors:
            subsectors.append(entry)
    result['subsectors'] = subsectors
    result["first_seen"], first = _date(result["first_seen"], "first_seen")
    result["last_seen"], last = _date(result["last_seen"], "last_seen")
    if first and last and first > last:
        raise ValueError("The incident end must not precede its start")
    software = []
    for value in _array(result["software"], "software"):
        item = _entry(value, ("name", "version"), "software")
        software.append({"name": _text(item.get("name", ""), "software name", required=True),
                         "version": _text(item.get("version", ""), "software version", 200)})
    result["software"] = software
    vulnerabilities = []
    for value in _array(result["vulnerabilities"], "vulnerabilities"):
        item = _entry(value, ("name", "status", "description"), "vulnerability")
        status = item.get("status", "suspected")
        if status not in ("confirmed", "suspected"):
            raise ValueError("Vulnerability status must be confirmed or suspected")
        name = _text(item.get("name", ""), "vulnerability name", required=True)
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", name, flags=re.IGNORECASE):
            name = name.upper()
        vulnerabilities.append({"name": name, "status": status,
                                "description": _text(item.get("description", ""),
                                                     "vulnerability description", 10000)})
    result["vulnerabilities"] = vulnerabilities
    if result["marking"] not in MARKINGS:
        raise ValueError("Unknown TLP marking")
    return result


def _organization(value):
    if not isinstance(value, dict) or set(value) != {"id", "name"}:
        raise ValueError("Invalid pseudonym registry entry")
    try:
        identifier = str(uuid.UUID(value["id"]))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Invalid pseudonym identifier") from exc
    name = _text(value['name'], 'Organization name', 200, required=True)
    if any(ord(c) < 32 for c in name):
        raise ValueError('Organization name must be a single line')
    return {"id": identifier, "name": name}


def list_organizations(workspace):
    """Read [{id, name}]; a missing registry is empty, never created on GET."""
    path = Path(workspace) / REGISTRY_FILE
    with _LOCK:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return []
        except (ValueError, OSError) as exc:
            raise ValueError("The organization pseudonym registry cannot be read") from exc
        if not isinstance(data, list):
            raise ValueError("Invalid organization pseudonym registry")
        entries = [_organization(value) for value in data]
        if len({value["id"] for value in entries}) != len(entries):
            raise ValueError("Duplicate organization pseudonym identifier")
        return entries


def _write_organizations(workspace, entries):
    path = Path(workspace) / REGISTRY_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def create_organization(workspace, name=None):
    """Register a chosen name; retain generated names for legacy callers."""
    if name is not None:
        name = _organization({'id': str(uuid.uuid4()), 'name': name})['name']
    with _LOCK:
        entries = list_organizations(workspace)
        if name is not None:
            existing = next((item for item in entries if item['name'].casefold() == name.casefold()), None)
            if existing:
                return existing
        identifier = str(uuid.uuid4())
        item = {"id": identifier, "name": name if name is not None else f"Organization-{uuid.uuid4().hex[:12]}"}
        entries.append(item)
        _write_organizations(workspace, entries)
        return item


def restore_organization(workspace, profile, *, dry_run=False):
    """Register an archived organization, retaining its stable identity."""
    if not profile or not profile.get("organization_id"):
        return
    item = _organization({"id": profile["organization_id"], "name": profile.get("organization_name") or profile.get("pseudonym")})
    with _LOCK:
        entries = list_organizations(workspace)
        existing = next((value for value in entries if value["id"] == item["id"]), None)
        if existing:
            if existing != item:
                raise ValueError("Archived organization pseudonym conflicts with this workspace")
            return
        if not dry_run:
            entries.append(item)
            _write_organizations(workspace, entries)


def validate(profile):
    """Validate a complete archived profile without any filesystem changes."""
    result = _validated(profile)
    if result["organization_id"]:
        _organization({"id": result["organization_id"], "name": result["organization_name"] or result["pseudonym"]})
    elif result["pseudonym"] or result["organization_name"]:
        raise ValueError("An archived organization requires its identifier")
    return result


def normalize(profile, workspace, existing=None):
    """Validate/merge a save payload and resolve its canonical organization.

    Chosen names reuse an existing registry entry or create a new identity.
    Legacy identifier-based saves use the registry name. Omitted keys retain
    existing values; changing a name does not rename another case's identity.
    """
    if not isinstance(profile, dict) or set(profile) - _FIELDS:
        raise ValueError("Case profile contains unsupported fields")
    result = _validated({**defaults(existing), **profile})
    with _LOCK:
        if result['organization_name']:
            # A different chosen name resolves to its own registry entry, so
            # editing one case cannot rename organizations in other cases.
            item = create_organization(workspace, result['organization_name'])
        elif result["organization_id"]:
            item = next((value for value in list_organizations(workspace)
                         if value["id"] == result["organization_id"]), None)
            if item is None:
                raise ValueError("Unknown organization pseudonym")
            # A full form may carry the previous organization's display name
            # while changing its id. Always derive the name from the registry.
        else:
            if profile.get("pseudonym"):
                raise ValueError("Choose an existing organization or generate a pseudonym")
            item = create_organization(workspace)
        result.update(organization_id=item["id"], pseudonym=item["name"])
        if result['organization_name']:
            result['organization_name'] = item['name']
    return result
