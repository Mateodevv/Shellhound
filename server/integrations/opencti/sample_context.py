"""Select only reviewed, content-specific context for uploaded file bytes."""


def context_plan(payload, sample):
    file_id = sample["file_id"]
    objects = payload["objects"]
    file = next((o for o in objects if o["id"] == file_id and o["type"] == "file"
                 and (o.get("hashes") or {}).get("SHA-256") == sample["sha256"]), None)
    incident_id = payload["incident_id"]
    def content_target(obj):
        if obj["type"] == "malware":
            return file_id in obj.get("sample_refs", [])
        if obj["type"] == "note":
            refs = set(obj.get("object_refs", []))
            return (file_id in refs and refs <= {file_id, incident_id}
                    and obj.get("x_shellhound_context_kind") != "path" and
                    any(r.get("source_name") == "Shellhound" and
                        any(part in r.get("external_id", "") for part in (":ioc:", ":context:"))
                        for r in obj.get("external_references", [])))
        return obj["type"] == "incident" and obj["id"] == incident_id
    targets = [o["id"] for o in objects if file and not o.get("revoked") and content_target(o)]
    withdrawals = [o["id"] for o in objects if o.get("revoked") and content_target(o)]
    return {"file_id": file_id, "artifact_id": sample["remote_id"], "target_ids": targets,
            "withdraw_ids": withdrawals, "state": "new"}


def legacy_context_plans(previous, current):
    """Retire our old Report-scoped sample edges before creating Case edges.

    Only saved exports for this destination qualify. The client withdraws its
    deterministic source IDs, leaving foreign edges and legacy Reports intact.
    """
    if not current.get("case_id"):
        return []
    plans = {}
    for old in previous:
        if (old.get("case_id") or not old.get("report_id")
                or old.get("mapping_destination") != current.get("mapping_destination")):
            continue
        for sample in old.get("samples", []):
            if not sample.get("remote_id") or sample.get("state") != "complete":
                continue
            entry = context_plan(old, sample)
            key = (old["report_id"], entry["artifact_id"])
            plan = plans.setdefault(key, {**entry, "container_id": old["report_id"],
                                          "target_ids": [], "withdraw_ids": []})
            plan["withdraw_ids"] = list(dict.fromkeys(plan["withdraw_ids"] + entry["target_ids"] + entry["withdraw_ids"]))
    return list(plans.values())
