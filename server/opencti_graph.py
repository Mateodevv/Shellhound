"""Build a reviewable STIX graph without networking or changing a case.

Only ``resolve_sample`` returns bytes; previews never carry original files or
workstation paths. A hash is an observation, not a malware attribution. Case
assertions live in owned Notes/relationships instead of shared SCO labels.
"""
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from server import db
from server.paths import display_path, io_path

MAX_SAMPLE_BYTES = 25 * 1024 * 1024
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


def _file_classification(finding):
    """Require an explicit live file classification, never a generic verdict."""
    if finding["artifact_kind"] != "file" or finding["triage"] != "confirmed":
        return ""
    if finding["source"] == "webshell":
        return "webshell"
    if finding["source"] == "analyst" and finding.get("rule_id") == "analyst.file_review":
        # The dedicated file-review actions persist these canonical statements.
        # Confirming an ordinary/YARA finding or a previous generic review is
        # insufficient, even if a note or an IOC tag happens to say malware.
        return {
            "Analyst classified the file as a webshell.": "webshell",
            "Analyst classified the file as a malware sample.": "malware",
        }.get(finding.get("evidence"), "")
    return ""


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

    def path(self, value):
        norm = _normal(value)
        for root in self.roots:
            if norm.casefold().startswith(root.casefold() + "/"):
                return self.text(norm[len(root) + 1:])
            if norm.casefold() == root.casefold():
                return "[evidence root]"
        return self.text(norm)

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


def _read_case(case_dir):
    # mode=ro avoids migrations, journal-mode changes and accidentally creating
    # a new case DB. Keep this snapshot consistent while analysis jobs write.
    uri = Path(db.case_db_path(case_dir)).resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("BEGIN")
        links = db.ioc_links(conn)
        source_links = {r["id"]: r for r in db.rows(conn, "SELECT * FROM ioc_links")}
        for link in links:
            link["source_uid"] = source_links[link["id"]].get("source_uid", "")
        return {
            "iocs": db.rows(conn, "SELECT * FROM iocs ORDER BY id"),
            "links": links,
            "sources": db.rows(conn, "SELECT s.* FROM ioc_sources s JOIN iocs i ON i.id=s.ioc_id"),
            "evidence": db.rows(conn, "SELECT * FROM evidence ORDER BY id"),
            "findings": db.rows(conn, "SELECT f.* FROM findings f " + db.RETIRE_JOIN +
                                " WHERE " + db.LIVE_PREDICATE),
        }
    finally:
        conn.close()


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


def _snapshot(path, *, content=False):
    """One bounded read supplies *all* digests and optional upload bytes."""
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
        if content:
            answer["content"] = raw
        return answer, ""
    except (OSError, ValueError):
        return None, "File is missing or unreadable."


def _candidates(row, data, related=None):
    sources = [s["artifact"] for s in data["sources"] if s["ioc_id"] == row["id"] and s["active"]
               and s["role"] in ("direct", "hash")]
    # An explicit hash provenance identifies a root; a shared relative path
    # does not. Never pick the first webroot when two have the same filename.
    if not sources and related:
        sources = [s["artifact"] for s in data["sources"] if s["ioc_id"] == related["id"]
                   and s["active"] and s["role"] in ("direct", "hash")]
    path_row = row if row["type"] == "path" else related
    if not sources and path_row:
        value = str(path_row["value"])
        if Path(value).is_absolute() or re.match(r"^[A-Za-z]:[/\\]", value):
            sources = [value]
        else:
            sources = [str(Path(e["path"]) / value.lstrip("/\\")) for e in data["evidence"]]
    found = {}
    for candidate in sources:
        path = _safe_existing(candidate, data["evidence"])
        if path is not None:
            found[os.path.normcase(str(path))] = path
    return list(found.values())


def _files(data, sanitizer):
    """Associate content only when the current snapshot proves the IOC hash."""
    rows = {r["id"]: r for r in data["iocs"]}
    by_row, warnings, cache = {}, {}, {}
    for row in data["iocs"]:
        if row["type"] not in ("hash", "path"):
            continue
        related = [rows[l["dst_id"]] for l in data["links"] if l["kind"] == "hash-of"
                   and l["src_id"] == row["id"] and rows[l["dst_id"]]["type"] == "path"]
        candidates_by_path = {str(path): path for path_row in (related or [None])
                              for path in _candidates(row, data, path_row)}
        candidates = list(candidates_by_path.values())
        snapshots, problems = [], []
        for path in candidates:
            if str(path) not in cache:
                cache[str(path)] = _snapshot(path)
            snap, reason = cache[str(path)]
            if not snap:
                problems.append(reason)
                continue
            if row["type"] == "hash" and str(row["value"]).lower() not in snap["hashes"].values():
                problems.append("Current file content does not match the collected hash; historical metadata is kept separate.")
                continue
            snapshots.append({**snap, "path": path, "display_path": sanitizer.path(display_path(path))})
        hashes = {s["sha256"] for s in snapshots}
        if len(hashes) > 1:
            problems.append("The relative path matches different files in multiple evidence roots; sample association is ambiguous.")
        elif snapshots:
            by_row[row["id"]] = snapshots
        if not candidates and (related or row["type"] == "path"):
            problems.append("No uniquely associated readable evidence file is available.")
        if problems:
            warnings[row["id"]] = list(dict.fromkeys(problems))
    return by_row, warnings


def _observable(row, sanitized):
    kind, value = row["type"], str(row["value"]).strip()
    if kind not in ("path", "user", "other") and value != sanitized:
        raise ValueError("The value contains private paths or credentials; retained only as sanitized context.")
    if kind == "ip":
        address = ipaddress.ip_address(value)
        return _sco("ipv4-addr" if address.version == 4 else "ipv6-addr", {"value": str(address)})
    if kind == "hash":
        if not re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value):
            raise ValueError("Invalid hash is retained as context.")
        return _sco("file", {"hashes": {_HASH_TYPES[len(value)]: value.lower()}})
    if kind == "domain":
        value = value.rstrip(".").encode("idna").decode("ascii").lower()
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", value):
            raise ValueError("Invalid domain is retained as context.")
        return _sco("domain-name", {"value": value})
    if kind == "email":
        if not re.fullmatch(r"[^@\s]+@[^@\s]+", value):
            raise ValueError("Invalid e-mail address is retained as context.")
        local, domain = value.rsplit("@", 1)
        return _sco("email-addr", {"value": local + "@" + domain.lower()})
    if kind == "url":
        url = urlsplit(value)
        if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password:
            raise ValueError("Invalid URL or embedded credentials; retained as sanitized context.")
        return _sco("url", {"value": sanitized})
    # A username alone is not globally unique. A case-owned context Note
    # deliberately prevents merging two unrelated systems' 'admin' accounts.
    return None


def _pattern(obj):
    esc = lambda v: str(v).replace("\\", "\\\\").replace("'", "\\'")
    if obj["type"] == "file":
        hashes = obj["hashes"]
        algo = next(k for k in ("SHA-256", "SHA-1", "MD5") if k in hashes)
        return f"[file:hashes.'{algo}' = '{esc(hashes[algo])}']"
    if obj["type"] in ("ipv4-addr", "ipv6-addr", "domain-name", "email-addr", "url"):
        return f"[{obj['type']}:value = '{esc(obj['value'])}']"
    return None


def build_preview(case_dir, options=None):
    """Return selected STIX objects plus every review row, including exclusions.

    ``ioc_ids=None`` selects the complete box. Samples and Indicators always
    require explicit IDs; neither follows from a malicious-looking tag.
    ``fingerprint`` covers selection, sanitized content and verified snapshots.
    """
    from server.workspace import case_info
    options = options or {}
    data = _read_case(case_dir)
    info = case_info(case_dir)
    profile = {k: v for k, v in (info.get("profile") or {}).items()
               if k not in set(options.get("exclude_profile_fields") or [])}
    clean = _Sanitizer(case_dir, data["evidence"])
    reference = clean.text(str(info.get("reference") or "").strip())
    errors, warnings = [], []
    if not reference or reference != str(info.get("reference") or "").strip():
        errors.append("A valid Case ID is required before transfer.")
    marking = MARKINGS.get(profile.get("marking", "TLP:AMBER+STRICT"))
    if not marking:
        errors.append("The case marking is not supported.")
        marking = MARKINGS["TLP:AMBER+STRICT"]
    stamp = _timestamp(info.get("created"))
    modified = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    objects, row_objects = {}, {}
    author_id = _id("identity", "shellhound")

    def add(obj):
        obj = dict(obj)
        obj["object_marking_refs"] = [marking]
        objects[obj["id"]] = obj
        return obj["id"]

    def sdo(kind, key, **fields):
        obj = {"type": kind, "spec_version": "2.1", "id": _id(kind, key),
               "created": stamp, "modified": modified, "created_by_ref": author_id, **fields}
        if kind in ("incident", "report", "note", "indicator", "relationship", "malware"):
            obj["x_shellhound_case_reference"] = reference
        return obj

    def relation(key, source, target, kind="related-to", description=""):
        return add(sdo("relationship", [reference, key], relationship_type=kind,
                       source_ref=source, target_ref=target, description=description or kind))

    def note(key, content, refs):
        return add(sdo("note", [reference, key], content=content,
                       object_refs=list(dict.fromkeys(refs)),
                       external_references=[{"source_name": "Shellhound", "external_id": f"{reference}:{key}"}]))

    author = sdo("identity", "shellhound", name="Shellhound", identity_class="system")
    author.pop("created_by_ref")
    add(author)
    incident = sdo("incident", [reference, "incident"], name=reference,
                   description=clean.text(profile.get("summary") or "Shellhound incident investigation"),
                   external_references=[{"source_name": "Shellhound", "external_id": reference}])
    for key in ("first_seen", "last_seen"):
        if profile.get(key):
            incident[key] = _timestamp(profile[key], naive_utc=True)
    incident_id = add(incident)
    report_id = _id("report", [reference, "report"])
    org_id = None
    if profile.get("organization_id") and profile.get("pseudonym"):
        org_id = add(sdo("identity", ["organization", profile["organization_id"]],
                         name=clean.text(profile["pseudonym"]), identity_class="organization"))
        relation("affected-organization", incident_id, org_id, "targets", "Affected pseudonymous organization.")
    for sector in profile.get("sectors") or []:
        sector = clean.text(sector)
        sector_id = add(sdo("identity", ["sector", sector.casefold()], name=sector,
                            identity_class="class", x_opencti_identity_type="Sector"))
        relation(["sector", sector], org_id or incident_id, sector_id, "related-to", "Affected organization's sector.")
    for country in profile.get("countries") or []:
        country = clean.text(country)
        location = sdo("location", ["country", country.casefold()], name=country,
                       country=country.lower(), x_opencti_location_type="Country")
        location_id = add(location)
        relation(["country", country], org_id or incident_id, location_id,
                 "located-at" if org_id else "related-to", "Country of an affected organization.")
    for software in profile.get("software") or []:
        fields = {k: clean.text(software[k]) for k in ("name", "version") if software.get(k)}
        if fields.get("name"):
            soft_id = add(_sco("software", fields))
            relation(["software", fields], incident_id, soft_id, description="Software affected in this case; exploitation is not implied.")
    for index, vulnerability in enumerate(profile.get("vulnerabilities") or []):
        name = clean.text(vulnerability.get("name", ""))
        status = "confirmed" if vulnerability.get("status") == "confirmed" else "suspected"
        description = f"Exploitation {status}: {name}"
        if vulnerability.get("description"):
            description += "\n" + clean.text(vulnerability["description"])
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", name, re.I):
            name = name.upper()
            # OpenCTI deduplicates vulnerabilities by their CVE name.
            vuln_id = add(sdo("vulnerability", ["cve", name], name=name,
                              external_references=[{"source_name": "cve", "external_id": name}]))
            # OpenCTI does not allow Incident -> exploits -> Vulnerability.
            # Keep the exploitation assessment in the owned link and Note.
            relation(["vulnerability", name], incident_id, vuln_id,
                     "related-to", description)
            note(f"vulnerability:{name}", description, [incident_id, vuln_id])
        else:
            note(f"vulnerability:{index}", description, [incident_id])
    if options.get("include_notes") and info.get("notes") and "case_notes" not in (options.get("exclude_profile_fields") or []):
        note("case-notes", clean.text(info["notes"]), [incident_id])

    files, file_warnings = _files(data, clean)
    selected = None if options.get("ioc_ids") is None else set(options["ioc_ids"])
    indicator_ids = set(options.get("indicator_ids") or [])
    sample_ids = set(options.get("sample_ids") or [])
    excluded_links = set(options.get("exclude_relationship_ids") or [])
    excluded_notes = set(options.get("exclude_note_ioc_ids") or [])
    excluded_evidence = set(options.get("exclude_evidence_ioc_ids") or [])
    rows, samples, associations = [], {}, {}
    source_keys = {r["id"]: (r.get("source_uid") or _digest([r["type"], r["value"]])) for r in data["iocs"]}
    confirmed_files = {f["artifact"] for f in data["findings"] if f["artifact_kind"] == "file"
                       and f["triage"] == "confirmed"}
    classifications = {f["artifact"]: _file_classification(f) for f in data["findings"]
                       if f["source"] == "webshell" and _file_classification(f)}
    # An explicit analyst decision supersedes older scan classifications for
    # that occurrence; evidence at a different path remains its own statement.
    classifications.update({f["artifact"]: _file_classification(f) for f in data["findings"]
                            if f["source"] == "analyst" and _file_classification(f)})
    classified_files = {
        kind: {artifact for artifact, classification in classifications.items() if classification == kind}
        for kind in ("webshell", "malware")
    }
    active_confirmed = {s["ioc_id"] for s in data["sources"] if s["active"]
                        and s["role"] in ("direct", "hash") and s["artifact"] in confirmed_files}
    confirmed_hashes = {snapshot["sha256"] for row in data["iocs"]
                        if row["type"] == "hash" and row["id"] in active_confirmed
                        for snapshot in files.get(row["id"], [])}
    active_classified = {
        kind: {s["ioc_id"] for s in data["sources"] if s["active"]
               and s["role"] in ("direct", "hash") and s["artifact"] in artifacts}
        for kind, artifacts in classified_files.items()
    }
    classified_hashes = {
        kind: {snapshot["sha256"] for row in data["iocs"]
               if row["type"] == "hash" and row["id"] in ioc_ids
               for snapshot in files.get(row["id"], [])}
        for kind, ioc_ids in active_classified.items()
    }
    for row in data["iocs"]:
        ioc_id = row["id"]
        source_key = source_keys[ioc_id]
        chosen = selected is None or ioc_id in selected
        value = clean.path(row["value"]) if row["type"] == "path" else clean.text(row["value"])
        row_warnings = list(file_warnings.get(ioc_id, []))
        if value != str(row["value"]):
            row_warnings.append("Local paths or credentials were removed from this value.")
        try:
            observable = _observable(row, value)
        except (ValueError, UnicodeError):
            observable = None
            row_warnings.append("The value is not a valid observable and is retained as case context.")
        verified = files.get(ioc_id, [])
        if verified:
            observable = _sco("file", {"hashes": verified[0]["hashes"], "size": verified[0]["size"]})
        ids = []
        if observable:
            observable["object_marking_refs"] = [marking]
            ids.append(observable["id"])
            if chosen:
                add(observable)
        primary = ids[0] if ids else incident_id
        context = f"Shellhound IOC {ioc_id}: {row['type']} — {value}"
        if ioc_id in active_confirmed:
            context += "\nAssociated file confirmed by the analyst; no malware family is inferred from its name."
        if options.get("include_notes") and ioc_id not in excluded_notes:
            for key in ("origin", "note"):
                if row.get(key):
                    context += f"\n{key.title()}: {clean.text(row[key])}"
        sources = [s for s in data["sources"] if s["ioc_id"] == ioc_id]
        if sources and not any(s["active"] for s in sources):
            context += "\nPrevious confirmation has been withdrawn; this is retained historical context."
            row_warnings.append("Previous confirmation has been withdrawn.")
        if options.get("include_evidence") and ioc_id not in excluded_evidence:
            artifacts = {s["artifact"] for s in sources}
            for f in data["findings"]:
                if f["artifact"] in artifacts:
                    context += "\n" + clean.text(f["rule"]) + ": " + clean.text(f["evidence"])
        context_refs = [incident_id] if row["type"] == "path" else [incident_id, primary]
        context_obj = sdo("note", [reference, f"ioc:{source_key}"], content=context,
                          object_refs=list(dict.fromkeys(context_refs)),
                          external_references=[{"source_name": "Shellhound", "external_id": f"{reference}:ioc:{source_key}"}])
        ids.append(context_obj["id"])
        if chosen:
            add(context_obj)
            if row["type"] == "path" and verified:
                ids.append(note(f"current-file:{source_key}:{verified[0]['sha256']}",
                                f"Current verified bytes at {value}: SHA-256 {verified[0]['sha256']}. "
                                "Historical requests and collected hashes for this path may refer to earlier contents.",
                                [incident_id, context_obj["id"], primary]))
        pattern = _pattern(observable) if observable else None
        if chosen and ioc_id in indicator_ids:
            if pattern:
                indicator_id = add(sdo("indicator", [reference, "indicator", source_key],
                                       name=value, pattern=pattern, pattern_type="stix",
                                       pattern_version="2.1", valid_from=stamp,
                                       description="Explicitly selected by the Shellhound analyst."))
                ids.append(indicator_id)
                relation(["indicator", source_key], indicator_id, primary, "based-on")
            else:
                errors.append(f"IOC {ioc_id} cannot be represented as a STIX Indicator.")
        classification = ""
        if verified and any(ioc_id in active_ids for active_ids in active_classified.values()):
            # Prefer the explicit, more specific webshell classification when
            # multiple confirmed occurrences describe the same verified bytes.
            classification = next((kind for kind in ("webshell", "malware")
                                   if verified[0]["sha256"] in classified_hashes[kind]), "")
        if chosen and classification:
            label = "web shell" if classification == "webshell" else "malware"
            malware_id = add(sdo("malware", [reference, classification, verified[0]["sha256"]],
                                 name=f"Confirmed {label} " + verified[0]["sha256"][:12],
                                 is_family=False,
                                 malware_types=["webshell" if classification == "webshell" else "unknown"],
                                 sample_refs=[primary],
                                 description=f"{label.capitalize()} classification confirmed in this Shellhound case; no family attribution."))
            ids.append(malware_id)
            relation([classification, verified[0]["sha256"]], incident_id, malware_id, "related-to")
        for snapshot in verified:
            sample_id = _digest([reference, "sample", snapshot["sha256"]])
            sample = {"id": sample_id, "display_path": snapshot["display_path"],
                      "sha256": snapshot["sha256"], "size": snapshot["size"],
                      "selected": chosen and sample_id in sample_ids, "available": True,
                      "reason": "", "file_id": observable["id"]}
            if sample_id in samples:
                sample["selected"] = sample["selected"] or samples[sample_id]["selected"]
            samples[sample_id] = sample
        if row["type"] == "path" and not verified:
            sample_id = _digest([reference, "unavailable-sample", ioc_id])
            samples[sample_id] = {"id": sample_id, "display_path": value, "sha256": "", "size": 0,
                                  "selected": False, "available": False,
                                  "reason": " ".join(row_warnings) or "No verified evidence file is available.",
                                  "file_id": ""}
            if sample_id in sample_ids:
                errors.append(f"Sample for IOC {ioc_id} is unavailable.")
        # A path names an occurrence, not immutable content. Historical hash
        # and HTTP request links must never be redirected to today's bytes.
        associations[ioc_id] = primary if observable and row["type"] != "path" else context_obj["id"]
        row_objects[ioc_id] = [observable, context_obj, {"confirmed_classification": classification}]
        rows.append({"id": ioc_id, "source_uid": source_key, "type": row["type"], "value": value, "selected": chosen,
                     "object_ids": ids, "indicator_supported": bool(pattern),
                     "indicator_suggested": bool(row["type"] == "hash" and verified and ioc_id in active_confirmed
                                                 and verified[0]["sha256"] in confirmed_hashes),
                     "warnings": row_warnings})

    edge_rows = []
    selected_ids = {r["id"] for r in rows if r["selected"]}
    for link in data["links"]:
        chosen = link["id"] not in excluded_links and link["src_id"] in selected_ids and link["dst_id"] in selected_ids
        edge_note = clean.text(link["note"]) if options.get("include_notes") else ""
        edge_rows.append({"id": link["id"], "src_id": link["src_id"], "dst_id": link["dst_id"],
                          "kind": link["kind"], "note": edge_note, "selected": chosen})
        if chosen:
            source_key = link.get("source_uid") or _digest([source_keys[link["src_id"]], source_keys[link["dst_id"]], link["kind"]])
            src, dst = associations[link["src_id"]], associations[link["dst_id"]]
            label = f"IOC {link['src_id']} {link['kind']} IOC {link['dst_id']}"
            description = label + ("\n" + edge_note if edge_note else "")
            if link["kind"] in ("hash-of", "requested"):
                description += "\nHistorical collection relationship; it does not identify the path's current file contents or prove execution."
            # 'requested' is evidence of an HTTP request, not 'communicates-with'
            # malware infrastructure. Preserve exact semantics in the Note.
            refs = [incident_id, src, dst]
            if src != dst:
                refs.append(relation(["ioc-link", source_key], src, dst, description=description))
            note(f"ioc-link:{source_key}", description, refs)
    for missing in sample_ids - set(samples):
        errors.append("A selected sample no longer belongs to this preview; refresh before transfer.")
    if selected is not None and selected - {r["id"] for r in rows}:
        errors.append("A selected IOC no longer exists; refresh before transfer.")
    refs = [key for key in objects if key != author_id]
    add(sdo("report", [reference, "report"], name=f"{reference} — Shellhound report",
            description=clean.text(profile.get("summary") or "Selected case observations and their provenance."),
            published=stamp, report_types=["incident"], object_refs=refs,
            external_references=[{"source_name": "Shellhound", "external_id": reference + ":report"}]))
    for row in rows:
        related = [e for e in edge_rows if row["id"] in (e["src_id"], e["dst_id"])]
        row["fingerprint"] = _digest(_stable({"objects": row_objects[row["id"]], "links": related,
                                             "profile": clean.text(_json(profile)),
                                             "indicators": row["id"] in indicator_ids}))
    result = {"case_reference": reference, "incident_id": incident_id, "report_id": report_id,
              "objects": list(objects.values()), "iocs": rows, "relationships": edge_rows,
              "samples": list(samples.values()), "warnings": warnings, "errors": errors}
    result["fingerprint"] = _digest(_stable(result))
    return result


def resolve_sample(case_dir, sample_id, expected_sha256):
    """Resolve an opaque preview ID and return verified bytes, never a live path.

    Result: ``{content: bytes, filename: str, sha256: str, hashes: dict,
    size: int, file_id: str}``. Upload this snapshot directly; reopening a
    filename after verification would reintroduce a time-of-check race.
    """
    from server.workspace import case_info
    if not re.fullmatch(r"[a-f0-9]{64}", str(expected_sha256)):
        raise ValueError("A valid SHA-256 from the reviewed preview is required.")
    reference = str(case_info(case_dir).get("reference") or "").strip()
    if sample_id != _digest([reference, "sample", expected_sha256]):
        raise ValueError("The selected sample does not match this case and preview.")
    data = _read_case(case_dir)
    clean = _Sanitizer(case_dir, data["evidence"])
    files, _ = _files(data, clean)
    for snapshots in files.values():
        for candidate in snapshots:
            if candidate["sha256"] != expected_sha256:
                continue
            snapshot, reason = _snapshot(candidate["path"], content=True)
            if not snapshot or snapshot["sha256"] != expected_sha256:
                raise ValueError(reason or "File changed since the preview; refresh before upload.")
            file_obj = _sco("file", {"hashes": snapshot["hashes"], "size": snapshot["size"]})
            return {**snapshot, "file_id": file_obj["id"],
                    "filename": candidate["display_path"].replace("\\", "/").rsplit("/", 1)[-1]}
    raise ValueError("The selected sample is missing, changed, ambiguous or outside registered evidence.")


def withdrawal_objects(previous, current, reference):
    """Explicitly withdraw disappeared case-owned assertions, never shared data.

    The service must compare against a *full* fresh graph using the previous
    export's disclosure options, so deselection alone is never a withdrawal.
    Append the returned objects to the export and put the withdrawal Note in
    the current Report's object_refs. Previous snapshots are local receipts,
    not arbitrary remote objects.
    """
    live = {obj["id"] for obj in current}
    allowed = {"note", "indicator", "relationship", "malware"}
    owned_author = _id("identity", "shellhound")
    stamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    withdrawn = []
    for obj in previous:
        if obj["id"] in live or obj.get("revoked") or obj.get("x_shellhound_withdrawal") or obj.get("type") not in allowed:
            continue
        if obj.get("created_by_ref") != owned_author or obj.get("x_shellhound_case_reference") != reference:
            continue
        copy = dict(obj)
        copy.update(revoked=True, modified=stamp)
        field = "content" if obj["type"] == "note" else "description"
        copy[field] = str(obj.get(field) or "") + "\nWithdrawn: this statement is no longer supported by the current Shellhound case."
        withdrawn.append(copy)
    if withdrawn:
        ids = sorted(obj["id"] for obj in withdrawn)
        incident_id = _id("incident", [reference, "incident"])
        note = {"type": "note", "spec_version": "2.1", "id": _id("note", [reference, "withdrawal", ids]),
                "created": stamp, "modified": stamp, "created_by_ref": owned_author,
                "x_shellhound_case_reference": reference,
                "x_shellhound_withdrawal": True,
                "content": "Shellhound withdrew earlier case assertions. Shared observables and third-party assessments were retained.",
                "object_refs": [incident_id] + ids,
                "object_marking_refs": withdrawn[0].get("object_marking_refs", [MARKINGS["TLP:AMBER+STRICT"]]),
                "external_references": [{"source_name": "Shellhound", "external_id": reference + ":withdrawal:" + _digest(ids)}]}
        withdrawn.append(note)
    return withdrawn


def reactivate_objects(previous, current):
    """Use a new stable generation when a terminally revoked assertion returns.

    Persist the rewritten objects in the regular mapping receipts. Subsequent
    previews recover the active generation from those receipts; historical
    revoked objects stay revoked and all structured references follow the new
    generation. No external/shared object is assigned a new identifier.
    """
    from datetime import timedelta
    owned = {"note", "indicator", "relationship", "malware"}
    history = {}
    for obj in previous:
        original = obj.get("x_shellhound_original_id", obj["id"])
        history.setdefault(original, []).append(obj)
    remap, rewritten = {}, []
    for obj in current:
        copy = dict(obj)
        if (obj["type"] in owned and obj.get("created_by_ref") == _id("identity", "shellhound")
                and obj.get("x_shellhound_case_reference")):
            prior = history.get(obj["id"], [])
            prior = [p for p in prior if p.get("created_by_ref") == obj["created_by_ref"]
                     and p.get("x_shellhound_case_reference") == obj["x_shellhound_case_reference"]]
            active = [p for p in prior if not p.get("revoked")]
            selected = max(active or prior, key=lambda p: p.get("modified", ""), default=None)
            if selected and selected.get("revoked"):
                key = [obj["id"], selected["id"], _digest(_stable(selected))]
                copy["id"] = _id(obj["type"], ["reactivated", key])
                created = datetime.fromisoformat(selected["modified"].replace("Z", "+00:00")) + timedelta(milliseconds=1)
                copy["created"] = created.isoformat(timespec="milliseconds").replace("+00:00", "Z")
                copy["modified"] = max(copy["modified"], copy["created"])
            elif selected and selected["id"] != obj["id"]:
                copy["id"] = selected["id"]
                copy["created"] = selected["created"]
            if copy["id"] != obj["id"]:
                copy["x_shellhound_original_id"] = obj["id"]
                remap[obj["id"]] = copy["id"]
        rewritten.append(copy)

    def rewrite(value):
        if isinstance(value, dict):
            return {k: (v if k == "x_shellhound_original_id" else rewrite(v)) for k, v in value.items()}
        if isinstance(value, list):
            return [rewrite(v) for v in value]
        return remap.get(value, value) if isinstance(value, str) else value
    return [rewrite(obj) for obj in rewritten]
