"""Local profile snapshots for comparing successful exports, never remote reads."""
import json
from server import case_profile, db

FIELDS = ("reference", "summary", "organization_name", "sectors", "subsectors", "countries",
          "state", "city", "first_seen", "last_seen", "marking", "software", "vulnerabilities")


def snapshot(info, options=None):
    profile = case_profile.defaults(info.get("profile"))
    profile["organization_name"] = profile.get("organization_name") or profile.get("pseudonym", "")
    profile["reference"] = info.get("reference", "")
    excluded = set((options or {}).get("exclude_profile_fields") or [])
    if {"pseudonym", "organization_id"} & excluded:
        excluded.add("organization_name")
    # Reference is case identity, not an optional profile field. Marking always
    # applies; excluding its input selects the graph builder's default.
    excluded.discard("reference")
    if "marking" in excluded:
        profile["marking"] = "TLP:AMBER+STRICT"
        excluded.discard("marking")
    values = {}
    for field in FIELDS:
        if field in excluded:
            continue
        value = profile.get(field, "")
        if field == "subsectors":
            lines = [item["sector"] + " → " + item["name"] for item in value]
        elif field == "software":
            lines = [" ".join(filter(None, [item["name"], item.get("version")])) for item in value]
        elif field == "vulnerabilities":
            lines = [" · ".join(filter(None, [item["name"], item.get("status"), item.get("description")])) for item in value]
        else:
            lines = value if isinstance(value, list) else [value]
        values[field] = sorted(set(str(line).strip() for line in lines if str(line).strip()), key=str.casefold)
    return {"version": 1, "values": values}


def compare(case_dir, current, destination, legacy_destination):
    conn = db.connect(case_dir)
    try:
        rows = db.rows(conn, "SELECT id,updated,destination,payload FROM opencti_exports WHERE state='complete' ORDER BY updated DESC,rowid DESC")
    finally:
        conn.close()
    result = {"status": "first_export", "export_id": None, "exported_at": None, "entries": []}
    for row in rows:
        payload = json.loads(row["payload"])
        if payload.get("mapping_destination") != destination and not (
                not payload.get("mapping_destination") and row["destination"] == legacy_destination):
            continue
        result.update(export_id=row["id"], exported_at=row["updated"])
        previous = payload.get("profile_snapshot")
        if not isinstance(previous, dict) or previous.get("version") != 1 or not isinstance(previous.get("values"), dict):
            result["status"] = "unavailable"
            return result
        old, new = previous["values"], current["values"]
        result["entries"] = [{"field": field, "before": old.get(field, []), "after": new.get(field, []),
                              "included": field in new}
                             for field in FIELDS if old.get(field, []) != new.get(field, [])]
        result["status"] = "changed" if result["entries"] else "unchanged"
        return result
    return result
