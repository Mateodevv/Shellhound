"""Case-owned objects, observations and analyst assertions. No network calls."""
import hashlib
import ipaddress
import json
import re
import uuid
from datetime import datetime


ASSESSMENTS = ("unassessed", "suspicious", "malicious", "benign")
PATH_CONTEXTS = ("unknown", "http-request", "system", "local-evidence")
HASH_NAMES = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
RELATIONS = {
    "hash-of": ({"hash"}, {"path", "file"}),
    "requested": ({"ip"}, {"path", "url"}),
    "host-in": ({"ip", "domain", "url"}, {"path", "file", "other"}),
    "account-of": ({"email"}, {"user"}),
    "located-at": ({"file"}, {"path"}),
    "request-context": ({"ip"}, {"file"}),
    "used": ({"ip"}, {"file"}),
    "executed": ({"ip"}, {"file"}),
    "cve-context": ({"ip", "file", "url", "domain", "user"}, {"vulnerability"}),
    "exploit-attempt": ({"ip", "file", "url"}, {"vulnerability"}),
    "exploitation-confirmed": ({"ip", "file", "url"}, {"vulnerability"}),
}
SCHEMA = """
CREATE TABLE IF NOT EXISTS ioc_files (
    ioc_id INTEGER PRIMARY KEY, hashes TEXT NOT NULL, size INTEGER,
    names TEXT NOT NULL DEFAULT '[]', classification TEXT NOT NULL DEFAULT '',
    classification_reason TEXT NOT NULL DEFAULT '', verified_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS ioc_file_members (
    ioc_id INTEGER NOT NULL, file_id INTEGER NOT NULL, PRIMARY KEY(ioc_id, file_id)
);
CREATE TABLE IF NOT EXISTS ioc_observations (
    id TEXT PRIMARY KEY, ioc_id INTEGER NOT NULL, kind TEXT NOT NULL,
    evidence_id INTEGER, finding_id INTEGER, source_ref TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '', local_path TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL DEFAULT '', last_seen TEXT NOT NULL DEFAULT '',
    count INTEGER, detail TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1,
    created TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ioc_observations_object ON ioc_observations(ioc_id);
CREATE TABLE IF NOT EXISTS ioc_assessments (
    id INTEGER PRIMARY KEY, ioc_id INTEGER NOT NULL, state TEXT NOT NULL,
    reason TEXT NOT NULL, created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ioc_relationship_evidence (
    id TEXT PRIMARY KEY, link_id INTEGER NOT NULL, observation_id TEXT,
    reference TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL DEFAULT '', last_seen TEXT NOT NULL DEFAULT '',
    created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ioc_relationship_events (
    id INTEGER PRIMARY KEY, link_id INTEGER NOT NULL, action TEXT NOT NULL,
    reason TEXT NOT NULL, created TEXT NOT NULL
);
"""


def now():
    return datetime.now().isoformat(timespec="seconds")


def identity(value, kind, context="", path_context="unknown"):
    value = str(value).strip()
    normalized = value
    if kind == "ip":
        try:
            normalized = ipaddress.ip_address(value).compressed
        except ValueError:
            pass  # Legacy invalid values remain editable case context.
    elif kind in ("hash", "file", "vulnerability"):
        normalized = value.lower()
    elif kind == "domain":
        try:
            normalized = value.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            pass
    elif kind == "email" and "@" in value:
        local, domain = value.rsplit("@", 1)
        normalized = local + "@" + domain.lower()
    scope = context if kind in ("path", "user", "other") else ""
    if kind == "path" and path_context != "unknown":
        scope = [context, path_context]
    return json.dumps([kind, normalized, scope],
                      ensure_ascii=False, separators=(",", ":"))


def migrate(conn):
    """Preserve row IDs and source UIDs; never guess missing file metadata."""
    columns = {r[1] for r in conn.execute("PRAGMA table_info(iocs)")}
    if "identity_key" not in columns:
        conn.execute("DROP TRIGGER IF EXISTS delete_ioc_provenance")
        conn.execute("DROP TRIGGER IF EXISTS iocs_source_uid")
        conn.execute("""CREATE TABLE iocs_v13 (
            id INTEGER PRIMARY KEY, value TEXT NOT NULL, type TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '', tags TEXT NOT NULL DEFAULT '[]',
            origin TEXT NOT NULL DEFAULT '', added TEXT NOT NULL,
            source_uid TEXT NOT NULL DEFAULT '', identity_key TEXT NOT NULL DEFAULT '' UNIQUE,
            context TEXT NOT NULL DEFAULT '', path_context TEXT NOT NULL DEFAULT 'unknown',
            assessment TEXT NOT NULL DEFAULT 'unassessed', legacy_warning TEXT NOT NULL DEFAULT ''
        )""")
        used = set()
        for row in conn.execute("SELECT id,value,type,note,tags,origin,added,source_uid FROM iocs").fetchall():
            key = identity(row[1], row[2])
            warning = "Legacy context is unspecified." if row[2] in ("path", "user", "other") else ""
            if key in used:
                key += f":legacy:{row[0]}"
                warning = "Equivalent legacy values retained separately; review before consolidation."
            used.add(key)
            conn.execute("INSERT INTO iocs_v13(id,value,type,note,tags,origin,added,source_uid,identity_key,legacy_warning) "
                         "VALUES(?,?,?,?,?,?,?,?,?,?)", (*row, key, warning))
        conn.execute("DROP TABLE iocs")
        conn.execute("ALTER TABLE iocs_v13 RENAME TO iocs")
    for name, decl in (("origin", "TEXT NOT NULL DEFAULT 'automatic'"),
                       ("active", "INTEGER NOT NULL DEFAULT 1"),
                       ("withdrawal_reason", "TEXT NOT NULL DEFAULT ''")):
        if name not in {r[1] for r in conn.execute("PRAGMA table_info(ioc_links)")}:
            conn.execute(f"ALTER TABLE ioc_links ADD COLUMN {name} {decl}")
    conn.executescript(SCHEMA)
    conn.executescript("""CREATE TRIGGER IF NOT EXISTS iocs_identity AFTER INSERT ON iocs
        WHEN NEW.identity_key='' BEGIN
          UPDATE iocs SET identity_key=json_array(NEW.type,NEW.value,
            CASE WHEN NEW.type IN ('path','user','other') THEN NEW.context ELSE '' END)
          WHERE id=NEW.id;
        END;""")
    # Only explicit hash provenance proves an old file occurrence. Merely
    # sharing a relative path is insufficient, especially across webroots.
    from server import db
    for row in db.rows(conn, "SELECT i.*,s.artifact,s.active AS source_active,s.added AS observed_at FROM iocs i "
                            "JOIN ioc_sources s ON s.ioc_id=i.id WHERE i.type='hash' AND s.role='hash'"):
        digest = row["value"].lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            continue
        file_id = register_file(conn, {"SHA-256": digest}, row["artifact"],
                                hash_id=row["id"], observed_at=row["observed_at"], legacy=True)
        conn.execute("UPDATE iocs SET legacy_warning=? WHERE id=?",
                     ("Historical hash provenance; size and other hashes have not been verified.", file_id))
        conn.execute("UPDATE ioc_sources SET active=? WHERE ioc_id=? AND artifact=?", (row["source_active"], file_id, row["artifact"]))
        conn.execute("UPDATE ioc_observations SET active=? WHERE ioc_id=? AND local_path=?", (row["source_active"], file_id, row["artifact"]))
    for row in db.rows(conn, "SELECT * FROM ioc_links"):
        if not conn.execute("SELECT 1 FROM ioc_relationship_evidence WHERE link_id=?", (row["id"],)).fetchone():
            add_support(conn, row["id"], "Legacy collection relationship", row["note"])


def observe(conn, ioc_id, kind, *, evidence_id=None, finding_id=None, source_ref="",
            path="", local_path="", first_seen="", last_seen="", count=None, detail="", active=True):
    if count is not None and (not isinstance(count, int) or count < 0):
        raise ValueError("Observation count must be non-negative.")
    key = hashlib.sha256(json.dumps([ioc_id, kind, evidence_id, finding_id, source_ref, path, local_path],
                                   separators=(",", ":")).encode()).hexdigest()
    conn.execute("""INSERT INTO ioc_observations
        (id,ioc_id,kind,evidence_id,finding_id,source_ref,path,local_path,first_seen,last_seen,count,detail,active,created)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
        first_seen=CASE WHEN excluded.first_seen='' THEN first_seen WHEN first_seen='' THEN excluded.first_seen
                       ELSE min(first_seen,excluded.first_seen) END,
        last_seen=max(last_seen,excluded.last_seen), count=excluded.count, detail=excluded.detail, active=excluded.active""",
        (key, ioc_id, kind, evidence_id, finding_id, source_ref, path, local_path,
         first_seen or "", last_seen or "", count, detail, int(active), now()))
    return key


def add_support(conn, link_id, reference, detail="", observation_id=None, first_seen="", last_seen=""):
    key = hashlib.sha256(json.dumps([link_id, reference, detail, observation_id, first_seen, last_seen]).encode()).hexdigest()
    conn.execute("INSERT OR IGNORE INTO ioc_relationship_evidence "
                 "(id,link_id,reference,detail,observation_id,first_seen,last_seen,created) VALUES(?,?,?,?,?,?,?,?)",
                 (key, link_id, reference, detail, observation_id, first_seen, last_seen, now()))


def register_file(conn, hashes, artifact="", *, hash_id=None, path_id=None, size=None,
                  classification="", observed_at="", verified=False, legacy=False):
    from server import db
    hashes = {k: str(v).lower() for k, v in hashes.items()}
    for name, digest in hashes.items():
        if HASH_NAMES.get(len(digest)) != name or not re.fullmatch("[0-9a-f]+", digest):
            raise ValueError("Invalid file hash.")
    if "SHA-256" not in hashes:
        raise ValueError("A collected file requires SHA-256; retain standalone digests as hash observations.")
    file_id = db.add_ioc(conn, hashes["SHA-256"], "file", origin="Collected file content")
    old = db.one(conn, "SELECT * FROM ioc_files WHERE ioc_id=?", (file_id,))
    names = json.loads(old["names"]) if old else []
    if artifact:
        name = artifact.replace("\\", "/").rsplit("/", 1)[-1]
        names = sorted(set(names + [name]))
    if old:
        previous = json.loads(old["hashes"])
        if any(k in previous and previous[k] != v for k, v in hashes.items()):
            raise ValueError("Conflicting hashes for the same file identity.")
        hashes = {**previous, **hashes}
    conn.execute("""INSERT INTO ioc_files(ioc_id,hashes,size,names,classification,classification_reason,verified_at)
        VALUES(?,?,?,?,?,?,?) ON CONFLICT(ioc_id) DO UPDATE SET hashes=excluded.hashes,
        size=coalesce(excluded.size,size),names=excluded.names,
        classification=CASE WHEN excluded.classification='' THEN classification ELSE excluded.classification END,
        classification_reason=CASE WHEN excluded.classification='' THEN classification_reason ELSE excluded.classification_reason END,
        verified_at=CASE WHEN excluded.verified_at='' THEN verified_at ELSE excluded.verified_at END""",
        (file_id, json.dumps(hashes), size, json.dumps(names), classification,
         "Explicit file review / confirmed file finding" if classification else "", now() if verified else ""))
    if hash_id:
        conn.execute("INSERT OR IGNORE INTO ioc_file_members VALUES(?,?)", (hash_id, file_id))
    if artifact:
        relative = db.case_relative_path(conn, artifact)
        evidence = next((e for e in db.rows(conn, "SELECT * FROM evidence ORDER BY length(path) DESC")
                         if artifact.replace("\\", "/").casefold().startswith(e["path"].replace("\\", "/").rstrip("/").casefold() + "/")), None)
        observe(conn, file_id, "file-location", evidence_id=evidence["id"] if evidence else None,
                source_ref="legacy-hash" if legacy else "collection", path=relative, local_path=artifact,
                first_seen=observed_at, last_seen=observed_at,
                detail="Recorded file hash; does not prove content at an earlier request time.")
        conn.execute("INSERT INTO ioc_sources(ioc_id,artifact,role,active,added) VALUES(?,?,'hash',1,?) "
                     "ON CONFLICT(ioc_id,artifact,role) DO UPDATE SET active=1", (file_id, artifact, now()))
        if path_id:
            db.link_iocs(conn, file_id, path_id, "located-at", "File content collected at this location.")
    return file_id


def enrich_rows(conn, rows):
    from server import db
    files = {f["ioc_id"]: f for f in db.rows(conn, "SELECT * FROM ioc_files")}
    members = {}
    spans = {o["ioc_id"]: o for o in db.rows(conn, "SELECT ioc_id,min(nullif(first_seen,'')) AS first_seen,"
                                          "max(nullif(last_seen,'')) AS last_seen FROM ioc_observations GROUP BY ioc_id")}
    for m in db.rows(conn, "SELECT * FROM ioc_file_members"):
        members.setdefault(m["ioc_id"], []).append(m["file_id"])
    for row in rows:
        row["first_seen"] = spans.get(row["id"], {}).get("first_seen")
        row["last_seen"] = spans.get(row["id"], {}).get("last_seen")
        row["file_ids"] = members.get(row["id"], [])
        if row["id"] in files:
            f = files[row["id"]]
            row["file"] = {**f, "hashes": json.loads(f["hashes"]), "names": json.loads(f["names"])}
        else:
            row["file"] = None
        row["summary"] = ((", ".join(row["file"]["names"]) or "File content") if row["file"] else
                          row.get("origin", ""))
    return rows


def collect_file(conn, artifact, digest, hash_id, path_id, classification="", findings=()):
    """Attach metadata only if a coherent read matches the recorded hash."""
    from server.opencti_graph import _snapshot
    snapshot, _ = _snapshot(artifact)
    verified = bool(snapshot and snapshot["sha256"] == digest.lower())
    file_id = register_file(conn, snapshot["hashes"] if verified else {"SHA-256": digest}, artifact,
                            hash_id=hash_id, path_id=path_id,
                            size=snapshot["size"] if verified else None,
                            classification=classification if verified else "", verified=verified)
    for finding in findings:
        observe(conn, file_id, "finding", finding_id=finding.get("id"), source_ref=finding.get("fingerprint", ""),
                local_path=artifact, first_seen=finding.get("created", ""), last_seen=finding.get("last_seen", ""),
                detail=finding.get("rule", ""))
    collect_cves(conn, file_id, findings)
    return file_id


def collect_cves(conn, ioc_id, findings):
    """A CVE named by a concrete finding is context, not proof of exploitation."""
    from server import db
    for finding in findings:
        names = set(re.findall(r"\bCVE-\d{4}-\d{4,}\b", finding.get("rule", "") + " " + finding.get("rule_id", ""), re.I))
        for name in sorted(names):
            cve = db.add_ioc(conn, name.upper(), "vulnerability", origin="CVE named by a finding on this specific object")
            db.link_iocs(conn, ioc_id, cve, "cve-context", "Specific finding references this CVE; exploitation is not asserted.")
            link = db.one(conn, "SELECT id FROM ioc_links WHERE src=? AND dst=? AND kind='cve-context'", (ioc_id, cve))
            observation = observe(conn, ioc_id, "finding", finding_id=finding.get("id"),
                                  source_ref=finding.get("fingerprint", ""), detail=finding.get("rule", ""))
            add_support(conn, link["id"], f"Finding {finding.get('id', finding.get('fingerprint', ''))}",
                        finding.get("rule", ""), observation_id=observation)


def verify_file(conn, ioc_id):
    from server import db, opencti_graph as graph
    row = db.one(conn, "SELECT * FROM iocs WHERE id=? AND type='file'", (ioc_id,))
    if not row:
        raise LookupError("File object does not exist.")
    evidence = db.rows(conn, "SELECT * FROM evidence")
    paths = {o["local_path"] for o in db.rows(conn, "SELECT * FROM ioc_observations WHERE ioc_id=?", (ioc_id,)) if o["local_path"]}
    verified, unavailable = 0, 0
    for path in sorted(paths):
        if not graph._safe_existing(path, evidence):
            unavailable += 1
            continue
        snapshot, _ = graph._snapshot(path)
        if not snapshot or snapshot["sha256"] != row["value"]:
            unavailable += 1
            continue
        register_file(conn, snapshot["hashes"], size=snapshot["size"], verified=True)
        verified += 1
    if not verified:
        raise ValueError("No available evidence file matches this content identity. Historical metadata was retained.")
    conn.execute("UPDATE iocs SET legacy_warning='' WHERE id=?", (ioc_id,))
    return {"verified_locations": verified, "unavailable_or_changed_locations": unavailable}


def observations(conn):
    from server import db
    rows = db.rows(conn, "SELECT * FROM ioc_observations ORDER BY created DESC,id")
    live = {r["id"] for r in db.rows(conn, "SELECT f.id FROM findings f " + db.RETIRE_JOIN +
                                    " WHERE (" + db.LIVE_PREDICATE + ") AND f.triage!='dismissed'")}
    sources = {}
    for source in db.rows(conn, "SELECT * FROM ioc_sources"):
        key = (source["ioc_id"], source["artifact"])
        sources[key] = sources.get(key, False) or bool(source["active"])
    for row in rows:
        if row["finding_id"] is not None and row["finding_id"] not in live:
            row["active"] = 0
        if sources.get((row["ioc_id"], row["local_path"])) is False:
            row["active"] = 0
    return rows


def supported_links(conn, links):
    from server import db
    states = {o["id"]: o["active"] for o in observations(conn)}
    supports = {}
    for support in db.rows(conn, "SELECT * FROM ioc_relationship_evidence ORDER BY id"):
        supports.setdefault(support["link_id"], []).append(support)
    out = []
    for link in links:
        evidence = supports.get(link["id"], [])
        if any(e["observation_id"] for e in evidence):
            valid = any(states.get(e["observation_id"], False) if e["observation_id"] else
                        e["reference"] not in ("Automatic collection", "Legacy collection relationship") for e in evidence)
            if not valid:
                continue
        out.append(link)
    return out


def detail(conn, ioc_id):
    from server import db
    row = db.one(conn, "SELECT * FROM iocs WHERE id=?", (ioc_id,))
    if not row:
        raise LookupError("IOC does not exist.")
    enrich_rows(conn, [row])
    row["tags"] = json.loads(row["tags"])
    recorded = [o for o in observations(conn) if o["ioc_id"] == ioc_id]
    # Live source/finding references are read through rather than copied once:
    # withdrawal or retirement is immediately visible without network access.
    findings = db.rows(conn, "SELECT DISTINCT f.*,NOT (" + db.LIVE_PREDICATE + ") AS retired FROM findings f "
                       + db.RETIRE_JOIN + " JOIN ioc_sources s ON s.artifact=f.artifact WHERE s.ioc_id=? ORDER BY f.id", (ioc_id,))
    sources = db.rows(conn, "SELECT * FROM ioc_sources WHERE ioc_id=? ORDER BY id", (ioc_id,))
    links = []
    supported = {l["id"] for l in db.ioc_links(conn)}
    for link in db.rows(conn, "SELECT l.*,s.value AS src_value,s.type AS src_type,d.value AS dst_value,d.type AS dst_type "
                             "FROM ioc_links l JOIN iocs s ON s.id=l.src JOIN iocs d ON d.id=l.dst "
                             "WHERE l.src=? OR l.dst=? ORDER BY l.id", (ioc_id, ioc_id)):
        link["evidence"] = db.rows(conn, "SELECT * FROM ioc_relationship_evidence WHERE link_id=? ORDER BY created,id", (link["id"],))
        link["events"] = db.rows(conn, "SELECT * FROM ioc_relationship_events WHERE link_id=? ORDER BY id", (link["id"],))
        if link["active"] and link["id"] not in supported:
            link["active"] = 0
            link["withdrawal_reason"] = "Supporting observations are no longer active."
        links.append(link)
    return {"object": row, "observations": recorded, "sources": sources, "findings": findings,
            "assessments": db.rows(conn, "SELECT * FROM ioc_assessments WHERE ioc_id=? ORDER BY id DESC", (ioc_id,)),
            "relationships": links, "relationship_types": {k: {"sources": sorted(s), "targets": sorted(t)} for k, (s, t) in RELATIONS.items()}}


def assess(conn, ioc_id, state, reason):
    if state not in ASSESSMENTS or not reason.strip():
        raise ValueError("Choose a valid assessment and provide a reason.")
    if not conn.execute("SELECT 1 FROM iocs WHERE id=?", (ioc_id,)).fetchone():
        raise LookupError("IOC does not exist.")
    conn.execute("UPDATE iocs SET assessment=? WHERE id=?", (state, ioc_id))
    conn.execute("INSERT INTO ioc_assessments(ioc_id,state,reason,created) VALUES(?,?,?,?)",
                 (ioc_id, state, reason.strip(), now()))


def relationship(conn, src, dst, kind, reference, detail="", observation_id=None, first_seen="", last_seen=""):
    from server import db
    source = db.one(conn, "SELECT * FROM iocs WHERE id=?", (src,))
    target = db.one(conn, "SELECT * FROM iocs WHERE id=?", (dst,))
    if not source or not target:
        raise LookupError("Relationship endpoint does not exist.")
    if src == dst or kind not in RELATIONS or source["type"] not in RELATIONS[kind][0] or target["type"] not in RELATIONS[kind][1]:
        raise ValueError("This relationship is not supported for these object types.")
    if not reference.strip():
        raise ValueError("A specific evidence reference is required.")
    if observation_id and not conn.execute("SELECT 1 FROM ioc_observations WHERE id=? AND ioc_id IN (?,?)",
                                           (observation_id, src, dst)).fetchone():
        raise ValueError("The evidence observation must belong to a relationship endpoint.")
    if observation_id and not any(o["id"] == observation_id and o["active"] for o in observations(conn)):
        raise ValueError("The selected evidence observation is no longer active.")
    start = datetime.fromisoformat(first_seen.replace("Z", "+00:00")) if first_seen else None
    end = datetime.fromisoformat(last_seen.replace("Z", "+00:00")) if last_seen else None
    if start and end:
        if bool(start.tzinfo) != bool(end.tzinfo):
            raise ValueError("Use a consistent time zone for the observation range.")
        if end < start:
            raise ValueError("Observation end must not precede its start.")
    current = db.one(conn, "SELECT * FROM ioc_links WHERE src=? AND dst=? AND kind=?", (src, dst, kind))
    if current:
        link_id = current["id"]
        conn.execute("UPDATE ioc_links SET active=1,withdrawal_reason='' WHERE id=?", (link_id,))
    else:
        link_id = conn.execute("INSERT INTO ioc_links(src,dst,kind,note,added,source_uid,origin) VALUES(?,?,?,?,?,?,'manual')",
                               (src, dst, kind, "", now(), uuid.uuid4().hex)).lastrowid
    add_support(conn, link_id, reference.strip(), detail.strip(), observation_id, first_seen, last_seen)
    conn.execute("INSERT INTO ioc_relationship_events(link_id,action,reason,created) VALUES(?,'supported',?,?)",
                 (link_id, reference.strip(), now()))
    return link_id


def withdraw(conn, link_id, reason):
    if not reason.strip():
        raise ValueError("A withdrawal reason is required.")
    if not conn.execute("SELECT 1 FROM ioc_links WHERE id=?", (link_id,)).fetchone():
        raise LookupError("Relationship does not exist.")
    conn.execute("UPDATE ioc_links SET active=0,withdrawal_reason=? WHERE id=?", (reason.strip(), link_id))
    conn.execute("INSERT INTO ioc_relationship_events(link_id,action,reason,created) VALUES(?,'withdrawn',?,?)",
                 (link_id, reason.strip(), now()))
