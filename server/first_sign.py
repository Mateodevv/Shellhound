"""Explainable first-known incident observation and analyst override.

This is a reference to confirmed evidence, never an inferred attack start.
The chronology owns event eligibility; this module owns ranking and the small
case-local analyst choice. No finding or triage decision is changed here.
"""
import json

from server import db


OVERRIDE_KEY = "first_sign_override"
NOTE_LIMIT = 2000
_SNAPSHOT_TEXT_LIMITS = {
    "id": 64, "kind": 80, "title": 500, "detail": 2000, "source": 40,
    "artifact": 4096, "artifact_kind": 40, "artifact_rel": 4096,
    "ip": 100, "first_sign_basis": 40,
}


def _snapshot(event):
    """Bound the retained context; never store a complete log or file body."""
    out = {key: str(event.get(key) or "")[:limit]
           for key, limit in _SNAPSHOT_TEXT_LIMITS.items()}
    if event.get("first_sign_basis") is None:
        out["first_sign_basis"] = None
    for key in ("at", "epoch", "severity"):
        value = event.get(key)
        out[key] = value if isinstance(value, int) and not isinstance(value, bool) else None
    for key in ("first_sign_eligible", "first_sign_selectable"):
        out[key] = bool(event.get(key))
    return out


def _selectable(event):
    epoch = event.get("epoch")
    return (bool(event.get("id") and event.get("artifact")
                 and event.get("first_sign_selectable"))
            and isinstance(epoch, int) and not isinstance(epoch, bool))


def automatic_event(chain_result):
    """Recorded activity outranks evidence-copy metadata, then earliest UTC."""
    candidates = [event for event in chain_result.get("events", [])
                  if _selectable(event) and event.get("first_sign_eligible")]
    if not candidates:
        return None
    return min(candidates, key=lambda event: (
        event.get("first_sign_basis") == "filesystem",
        event["epoch"], event["id"]))


def set_override(conn, chain_result, event_id, note=""):
    """Validate and write inside the caller's case write transaction.

    The caller rebuilds an uncapped chronology while holding BEGIN IMMEDIATE,
    so confirming/removing evidence cannot interleave with selecting it.
    Passing None restores automatic selection. This function never commits.
    """
    if event_id is None:
        conn.execute("DELETE FROM meta WHERE key = ?", (OVERRIDE_KEY,))
        return
    if not isinstance(note, str) or len(note) > NOTE_LIMIT:
        raise ValueError(f"The analyst note must be at most {NOTE_LIMIT} characters.")
    event = next((event for event in chain_result.get("events", [])
                  if event.get("id") == event_id and _selectable(event)), None)
    if event is None:
        raise ValueError("This timeline event is no longer available as a confirmed "
                         "evidence anchor. Refresh the timeline and choose another event.")
    payload = {"event_id": event["id"], "event": _snapshot(event),
               "note": note.strip(), "selected_at": db.now()}
    conn.execute("INSERT INTO meta(key,value) VALUES (?,?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                 (OVERRIDE_KEY, json.dumps(payload, ensure_ascii=False,
                                           separators=(",", ":"))))


def summarize(case_dir, chain_result, conn=None):
    """Summarize an uncapped chronology with an optional persisted override."""
    own_connection = conn is None
    if own_connection:
        conn = db.connect(case_dir)
    try:
        row = db.one(conn, "SELECT value FROM meta WHERE key = ?", (OVERRIDE_KEY,))
    finally:
        if own_connection:
            conn.close()
    override = None
    if row:
        try:
            parsed = json.loads(row["value"])
            override = parsed if isinstance(parsed, dict) else {}
        except (TypeError, ValueError):
            override = {}
    auto = automatic_event(chain_result)
    selected = auto
    out = {"mode": "manual" if override is not None else "automatic",
           "state": "undated", "event": None,
           "automatic_event": _snapshot(auto) if auto else None,
           "note": "", "earlier_candidate": False, "stale_reason": None}
    if override is not None:
        out["note"] = str(override.get("note") or "")[:NOTE_LIMIT]
        selected = next((event for event in chain_result.get("events", [])
                         if event.get("id") == override.get("event_id")
                         and _selectable(event)), None)
        if selected is None:
            saved = override.get("event")
            snapshot = _snapshot(saved) if isinstance(saved, dict) else None
            if snapshot:
                snapshot["first_sign_eligible"] = False
                snapshot["first_sign_selectable"] = False
            out.update(state="stale_override",
                       event=snapshot,
                       stale_reason="The selected evidence is no longer confirmed or its "
                                    "source is unavailable or has changed. Review the choice "
                                    "or restore the automatic suggestion.")
            return out
        out["earlier_candidate"] = bool(auto and auto["id"] != selected["id"]
                                        and auto["epoch"] < selected["epoch"])
    if selected:
        out.update(event=_snapshot(selected),
                   state="metadata_only" if selected.get("first_sign_basis") == "filesystem"
                   else "suggested")
    elif not chain_result.get("confirmed"):
        out["state"] = "no_confirmed"
    return out
