"""Read-only IOC comparison across the open cases of one workspace.

There is deliberately no workspace database. Case isolation is one of the
tool's safety properties, and a central index would become a second source of
truth that can go stale or retain indicators after a case is removed. IOC
tables are small, so reading them on demand is the simpler and more honest
trade-off.

Only entries in the IOC box participate. Findings, raw logs, account tables
and evidence content are never searched across cases.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from pathlib import Path

from server import db, workspace as workspacelib


def match_key(ioc_type: str, value: str) -> tuple[str, str]:
    """A conservative equality key; paths and usernames stay case-sensitive."""
    kind = str(ioc_type or "other").strip().lower()
    text = str(value or "").strip()
    if kind == "ip":
        try:
            text = ipaddress.ip_address(text).compressed
        except ValueError:
            pass
    elif kind in {"hash", "domain", "email"}:
        text = text.lower()
    return kind, text


def _read_iocs(case_dir: Path) -> list[dict]:
    """Read an IOC table without invoking schema upgrades or a write lock."""
    path = db.case_db_path(case_dir).resolve()
    if not path.is_file():
        return []
    conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=0.25)
    conn.row_factory = sqlite3.Row
    try:
        rows = [dict(row) for row in conn.execute(
            "SELECT id, value, type, note, tags, origin, added FROM iocs "
            "ORDER BY id"
        )]
    finally:
        conn.close()
    for row in rows:
        try:
            row["tags"] = json.loads(row.get("tags") or "[]")
        except (TypeError, ValueError):
            row["tags"] = []
    return rows


def _identity(case_dir: Path) -> dict:
    identity = {"slug": case_dir.name, "name": case_dir.name, "reference": ""}
    try:
        raw = json.loads((case_dir / workspacelib.CASE_FILE).read_text(
            encoding="utf-8"
        ))
        identity["name"] = str(raw.get("name") or case_dir.name)
        identity["reference"] = str(raw.get("reference") or "")
    except (OSError, TypeError, ValueError):
        pass
    return identity


def compare(workspace: Path, current_slug: str) -> dict:
    """Return IOC-box entries from other open cases equal to this case's.

    Complexity is O(open cases × indicators). That is intentional while a
    workspace holds tens of small case databases; revisit only if measurements
    show this endpoint becoming slow.
    """
    root = Path(workspace).resolve()
    current = workspacelib.resolve_case(root, current_slug)
    if current is None:
        raise FileNotFoundError(current_slug)

    current_rows = _read_iocs(current)
    wanted = {match_key(row["type"], row["value"]): row for row in current_rows}
    matches: dict[tuple[str, str], list[dict]] = {key: [] for key in wanted}
    scanned = skipped = 0

    if root.is_dir() and wanted:
        for case_dir in sorted(root.iterdir()):
            if (not case_dir.is_dir() or case_dir == current
                    or case_dir.name == workspacelib.ARCHIVE_DIR
                    or not (case_dir / workspacelib.CASE_FILE).is_file()):
                continue
            scanned += 1
            try:
                other_rows = _read_iocs(case_dir)
            except sqlite3.Error:
                skipped += 1
                continue
            identity = _identity(case_dir)
            for row in other_rows:
                key = match_key(row["type"], row["value"])
                if key not in matches:
                    continue
                matches[key].append({
                    **identity,
                    "id": row["id"],
                    "value": row["value"],
                    "type": row["type"],
                    "note": row["note"],
                    "tags": row["tags"],
                    "origin": row["origin"],
                    "added": row["added"],
                })

    entries = []
    for key, row in wanted.items():
        found = sorted(matches[key], key=lambda item: (item["name"], item["slug"]))
        if found:
            entries.append({
                "id": row["id"], "value": row["value"], "type": row["type"],
                "matches": found,
            })
    entries.sort(key=lambda item: (item["type"], item["value"].lower()))
    matched_cases = {match["slug"] for entry in entries for match in entry["matches"]}
    return {
        "entries": entries,
        "matched_iocs": len(entries),
        "matches": sum(len(entry["matches"]) for entry in entries),
        "matched_cases": len(matched_cases),
        "cases_scanned": scanned,
        "cases_skipped": skipped,
    }
