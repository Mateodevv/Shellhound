"""Build a reviewable STIX graph without networking or changing a case.

Export only the manually saved profile, IPs with labels, CVEs and hashes.
Previews never read source files or infer malware, indicators or relationships.
"""
import hashlib
import ipaddress
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from server import db
from server.ioc import model as ioc_model
from server.paths import display_path, io_path

MAX_SAMPLE_BYTES = 25 * 1024 * 1024
OBSERVABLE_TYPES = {"ipv4-addr", "ipv6-addr", "file"}
IOC_TYPES = {"ip", "vulnerability", "hash", "file"}
_NS = uuid.UUID("a46ffb21-52b7-5ced-a45e-d75e52701cd4")
_SCO_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
_HASH_TYPES = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
# These are OpenCTI's built-in markings (pycti MarkingDefinition.generate_id).
# Referencing them avoids redefining the server's access-control vocabulary.
MARKINGS = {
    "TLP:CLEAR": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "TLP:GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "TLP:AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "TLP:AMBER+STRICT": "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37",
    "TLP:RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def _id(kind, key):
    return f"{kind}--{uuid.uuid5(_NS, kind + ':' + _json(key))}"

def _sco(kind, properties):
    contributing = dict(properties)
    if kind == "file":
        # STIX 2.1 picks the first available hash in this order for the ID.
        hashes = properties["hashes"]
        key = next(k for k in ("MD5", "SHA-1", "SHA-256") if k in hashes)
        contributing = {"hashes": {key: hashes[key]}}
    return {"type": kind, "spec_version": "2.1",
            "id": f"{kind}--{uuid.uuid5(_SCO_NS, _json(contributing))}", **properties}

def _digest(value):
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()

def _stable(value):
    """Import modification timestamps must not make an unchanged preview dirty."""
    if isinstance(value, dict):
        return {k: _stable(v) for k, v in value.items() if k != "modified"}
    if isinstance(value, list):
        return [_stable(v) for v in value]
    return value

def _timestamp(value, fallback="1970-01-01T00:00:00.000Z", *, naive_utc=False):
    if not value:
        return fallback
    try:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if naive_utc and stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        # Legacy case timestamps are the local machine's time.
        return stamp.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError):
        return fallback

def _normal(path):
    return display_path(str(path)).replace("\\", "/").rstrip("/")

class _Sanitizer:
    def __init__(self, case_dir, evidence):
        self.roots = sorted((_normal(e["path"]) for e in evidence), key=len, reverse=True)
        self.private = sorted(set(self.roots + [_normal(case_dir), _normal(Path(case_dir).parent)]),
                              key=len, reverse=True)

    def text(self, value):
        text = str(value or "")
        for prefix in self.private:
            pattern = re.escape(prefix).replace("/", r"[/\\]")
            text = re.sub(pattern + r"(?=$|[/\\\s'\"),;])", "[local evidence]", text, flags=re.I)
        # Unregistered Windows paths and common local Unix directories must
        # never escape through notes. Relative web paths and URL paths survive.
        text = re.sub(r"(?i)(?<![\w])(?:\\\\\?\\)?[a-z]:[/\\][^\s<>\"']*", "[local path]", text)
        text = re.sub(r"\\\\[^\s<>\"']+", "[local path]", text)
        text = re.sub(r"(?<![:/\w])/(?:Users|home|tmp|private|mnt|Volumes)(?:/[^\s<>\"']*)?",
                      "[local path]", text, flags=re.I)
        text = re.sub(r"(?i)(https?://)[^/@\s]+:[^/@\s]+@", r"\1[credentials removed]@", text)
        text = re.sub(r"(?i)\b(password|passwd|api[_ -]?key|access[_ -]?token|authorization)\s*[:=]\s*[^\s,;]+",
                      r"\1=[redacted]", text)
        return text

def _safe_existing(path, evidence):
    try:
        candidate = Path(io_path(path)).resolve(strict=True)
        if not candidate.is_file():
            return None
    except (OSError, ValueError, RuntimeError):
        return None
    for item in evidence:
        try:
            root = Path(io_path(item["path"])).resolve(strict=True)
            if candidate == root or (root.is_dir() and candidate.is_relative_to(root)):
                return candidate
        except (OSError, ValueError, RuntimeError):
            continue
    return None

def _snapshot(path):
    """One bounded read supplies the digests used by local IOC verification."""
    try:
        with open(io_path(path), "rb") as stream:
            before = os.fstat(stream.fileno())
            if before.st_size > MAX_SAMPLE_BYTES:
                return None, "File exceeds the 25 MiB sample verification limit."
            raw = stream.read(MAX_SAMPLE_BYTES + 1)
            after = os.fstat(stream.fileno())
        current = os.stat(io_path(path))
        # Windows' handle-based fstat and path-based stat disagree about
        # st_ctime (birth time versus change time on some Python versions).
        identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
        if len(raw) > MAX_SAMPLE_BYTES or len(raw) != before.st_size or not (
                identity(before) == identity(after) == identity(current)):
            return None, "File changed during verification; refresh the preview."
        hashes = {}
        for algo, name in (("md5", "MD5"), ("sha1", "SHA-1"), ("sha256", "SHA-256")):
            try:
                hashes[name] = hashlib.new(algo, raw, usedforsecurity=False).hexdigest()
            except (ValueError, TypeError):
                if name == "SHA-256":
                    raise
        answer = {"hashes": hashes, "sha256": hashes["SHA-256"], "size": len(raw)}
        return answer, ""
    except (OSError, ValueError):
        return None, "File is missing or unreadable."


def _observable(row, sanitized):
    value = str(row['value']).strip()
    if value != sanitized:
        raise ValueError('An IOC contains private paths or credentials')
    if row['type'] == 'ip':
        address = ipaddress.ip_address(value)
        return _sco('ipv4-addr' if address.version == 4 else 'ipv6-addr', {'value': str(address)})
    if row['type'] in ('hash', 'file'):
        hashes = (row.get('file') or {}).get('hashes') if row['type'] == 'file' else None
        hashes = hashes or {_HASH_TYPES.get(len(value), ''): value.lower()}
        lengths = {'MD5': 32, 'SHA-1': 40, 'SHA-256': 64}
        if any(name not in lengths or not isinstance(digest, str) or
               not re.fullmatch(r'[a-fA-F0-9]{' + str(lengths[name]) + '}', digest)
               for name, digest in hashes.items()):
            raise ValueError('Invalid file hash')
        return _sco('file', {'hashes': {name: digest.lower() for name, digest in hashes.items()}})
    return None


def build_preview(case_dir, options=None):
    """Build an offline, destination-independent snapshot of explicit export data."""
    from server.workspace import case_info
    options = options or {}
    if set(options) - {'ioc_ids'}:
        raise ValueError('Only IOC selection is supported for OpenCTI transfer')
    conn = db.connect(case_dir)
    try:
        conn.execute('BEGIN')
        rows = ioc_model.enrich_rows(conn, db.rows(conn, 'SELECT * FROM iocs ORDER BY id'))
        evidence = db.rows(conn, 'SELECT path FROM evidence')
    finally:
        conn.close()
    info = case_info(case_dir)
    profile = info.get('profile') or {}
    clean = _Sanitizer(case_dir, evidence)
    reference = str(info.get('reference') or '').strip()
    errors, warnings = [], []
    if not reference or clean.text(reference) != reference:
        errors.append('A valid Case ID is required before transfer.')
    selected = None if options.get('ioc_ids') is None else set(options['ioc_ids'])
    eligible = [row for row in rows if row['type'] in IOC_TYPES]
    if selected is not None and selected - {row['id'] for row in eligible}:
        raise ValueError('Select existing IPs, CVEs or hashes only')
    stamp = _timestamp(info.get('created'))
    modified = datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    marking = MARKINGS[profile.get('marking', 'TLP:AMBER+STRICT')]
    author_id = _id('identity', 'shellhound')
    objects = {}

    def add(obj):
        obj['object_marking_refs'] = [marking]
        previous = objects.get(obj['id'], {})
        if previous.get('labels') or obj.get('labels'):
            obj['labels'] = sorted(set(previous.get('labels', []) + obj.get('labels', [])))
        objects[obj['id']] = {**previous, **obj}
        return obj['id']

    def sdo(kind, key, **fields):
        return {'type': kind, 'spec_version': '2.1', 'id': _id(kind, key),
                'created': stamp, 'modified': modified, 'created_by_ref': author_id, **fields}

    def relation(key, source, target, kind='related-to', description='Case profile context.'):
        return add(sdo('relationship', [reference, key, source, target, kind], relationship_type=kind,
                       source_ref=source, target_ref=target, description=description,
                       x_shellhound_case_reference=reference))

    author = sdo('identity', 'shellhound', name='Shellhound', identity_class='system')
    author.pop('created_by_ref')
    add(author)
    incident = sdo('incident', [reference, 'incident'], name=reference,
                   description=clean.text(profile.get('summary') or ''),
                   x_shellhound_case_reference=reference,
                   external_references=[{'source_name': 'Shellhound', 'external_id': reference}])
    for key in ('first_seen', 'last_seen'):
        if profile.get(key):
            incident[key] = _timestamp(profile[key], naive_utc=True)
    incident_id = add(incident)
    organization = profile.get('organization_name') or profile.get('pseudonym')
    context_id = incident_id
    if organization and profile.get('organization_id'):
        context_id = add(sdo('identity', ['organization', profile['organization_id']],
                             name=clean.text(organization), identity_class='organization'))
        relation('affected-organization', incident_id, context_id, 'targets', 'Manually specified affected organization.')
    sectors = {}
    for value in profile.get('sectors') or []:
        name = clean.text(value)
        sectors[value] = add(sdo('identity', ['sector', name.casefold()], name=name,
                                 identity_class='class', x_opencti_identity_type='Sector'))
        relation(['sector', value], context_id, sectors[value])
    for item in profile.get('subsectors') or []:
        if item['sector'] in sectors:
            name = clean.text(item['name'])
            identifier = add(sdo('identity', ['sector', name.casefold()], name=name,
                                  identity_class='class', x_opencti_identity_type='Sector'))
            relation(['subsector-parent', name, item['sector']], identifier, sectors[item['sector']], 'part-of')
            relation(['subsector', name], context_id, identifier)
    for country in profile.get('countries') or []:
        location = add(sdo('location', ['country', country.casefold()], name=country,
                           country=country.lower(), x_opencti_location_type='Country'))
        relation(['country', country], context_id, location, 'located-at')
    country = next(iter(profile.get('countries') or []), '')
    for field, kind in (('state', 'Administrative-Area'), ('city', 'City')):
        if profile.get(field):
            name = clean.text(profile[field])
            details = {'administrative_area' if field == 'state' else 'city': name}
            if country:
                details['country'] = country.lower()
            identifier = add(sdo('location', [field, country, name.casefold()], name=name,
                                  x_opencti_location_type=kind, **details))
            relation([field, identifier], context_id, identifier, 'located-at')
    for item in profile.get('software') or []:
        identifier = add(_sco('software', {'name': clean.text(item['name']), 'version': clean.text(item.get('version', ''))}))
        relation(['profile-software', identifier], incident_id, identifier)
    for item in profile.get('vulnerabilities') or []:
        if re.fullmatch(r'CVE-\d{4}-\d{4,}', item['name'], re.I):
            name = item['name'].upper()
            identifier = add(sdo('vulnerability', ['vulnerability', name], name=name,
                                  description=clean.text(item.get('description', '')),
                                  external_references=[{'source_name': 'cve', 'external_id': name}]))
            relation(['profile-cve', name], incident_id, identifier,
                     description=clean.text(f"Manually recorded CVE ({item.get('status', 'suspected')}); successful exploitation is not implied. " + item.get('description', '')))
        else:
            warnings.append('A profile vulnerability without a CVE identifier is omitted from transfer.')
    output = []
    for row in eligible:
        chosen = selected is None or row['id'] in selected
        value = clean.text(row['value'])
        row_warnings = []
        obj = None
        try:
            if row['type'] == 'vulnerability':
                if not re.fullmatch(r'CVE-\d{4}-\d{4,}', value, re.I):
                    raise ValueError('Invalid CVE identifier')
                obj = sdo('vulnerability', ['vulnerability', value.upper()], name=value.upper(),
                          external_references=[{'source_name': 'cve', 'external_id': value.upper()}])
            else:
                obj = _observable(row, value)
        except ValueError as exc:
            row_warnings.append(str(exc))
            if chosen:
                errors.append(f'IOC {row["id"]}: {exc}')
        tags = sorted({clean.text(tag).strip() for tag in json.loads(row.get('tags') or '[]') if isinstance(tag, str) and tag.strip()})
        if obj and chosen:
            if tags:
                obj['labels'] = tags
            add(obj)
            relation(['case-observable', obj['id']], incident_id, obj['id'],
                     description='Recorded in this case; this association does not establish maliciousness.')
        entry = {'id': row['id'], 'source_uid': row.get('source_uid'), 'type': row['type'],
                 'value': value, 'selected': chosen, 'tags': tags,
                 'object_ids': [obj['id']] if obj else [], 'warnings': row_warnings}
        entry['fingerprint'] = _digest(_stable([obj, profile]))
        output.append(entry)
    refs = [key for key in objects if key != author_id]
    case_id = add(sdo('x-opencti-case-incident', [reference, 'case'], name=reference,
                      description=clean.text(profile.get('summary') or ''), object_refs=refs,
                      x_shellhound_case_reference=reference,
                      external_references=[{'source_name': 'Shellhound', 'external_id': reference + ':case'}]))
    result = {'model_version': 4, 'case_reference': reference, 'incident_id': incident_id,
              'case_id': case_id, 'objects': list(objects.values()), 'iocs': output,
              'warnings': warnings, 'errors': errors}
    result['fingerprint'] = _digest(_stable(result))
    return result
