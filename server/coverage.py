# server/coverage.py
"""What the logs do NOT cover -- and whether somebody made it that way.

Attackers clean logs. It is one of the first things done after a successful
intrusion and one of the last things a toolkit looks for, because every view
is built around what IS in the data. This module asks the opposite question:
where is the data missing, and does the shape of the hole look deliberate?

FOUR MEASUREMENTS, ALL FROM WHAT IS ALREADY INDEXED:

  quiet     A hole in the timeline, measured against the log's OWN rhythm --
            not against a fixed threshold. A server with a request every two
            seconds that goes silent for four hours is saying something; a
            server with three requests a day is not.
  truncated The first line of a file is not a parsable record. Rotation cuts
            on line boundaries; a head that starts mid-record means somebody
            removed the beginning.
  stale     The file's mtime is EARLIER than its last entry. A file cannot
            have been written before the last thing written into it; that is
            a copy whose timestamps were forged, or a rewrite that reset it.

WHAT WAS REMOVED, AND WHY IT WAS NOT A THRESHOLD PROBLEM. There used to be a
fourth check here: timestamps stepping BACKWARDS inside one file, read as
"lines were edited, reordered or spliced". It was wrong in principle, not
merely noisy. Apache and Nginx write a log line when a request COMPLETES, and
the timestamp in it is when the request STARTED. A request that took three
seconds is therefore written after a faster one that began later, and its
stamp is lower. On any server with concurrent requests that happens
constantly. The check was measuring normal operation and calling it
tampering, which is the one thing this module must never do.

WHAT IS AND IS NOT CLAIMED. None of these prove tampering. A quiet window can
be a maintenance night, a nightly rotation, a firewall change. A truncated
head can be `head -n`. THAT is why this produces no findings, no severities
and no artifacts: it lands in the GAPS of the chronology, next to the other
things the case cannot prove, and in the evidence view as a coverage note. It
tells the analyst where to point the question, not what the answer is.
"""
from __future__ import annotations

import os
import sqlite3

from server import db
from server.engines import accesslog, logindex
from server.engines.fsutil import open_text_auto
from server.i18n import t

# A hole has to be this many times the log's own median gap before it counts,
# AND at least this long in absolute terms. Both, because on a quiet log the
# median is minutes and every lunch break would qualify, while on a busy one
# a fixed threshold would never fire.
QUIET_FACTOR = 60
QUIET_MIN_SECONDS = 30 * 60
_MAX_QUIET = 6            # reported holes; the biggest ones


def _median(values):
    if not values:
        return 0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2


def quiet_windows(case_dir):
    """Holes in the indexed timeline, measured against the log's own rhythm.

    Runs over the epoch column in order. One pass, and the index is already
    sorted by it -- this is cheap even on a ten-million-line log."""
    conn = logindex._open_ro(case_dir)
    if conn is None:
        return {"windows": [], "median_gap": 0, "checked": False}
    try:
        rows = conn.execute(
            "SELECT DISTINCT epoch FROM requests "
            "WHERE epoch IS NOT NULL AND epoch > 0 ORDER BY epoch").fetchall()
    except sqlite3.Error:
        return {"windows": [], "median_gap": 0, "checked": False}
    finally:
        conn.close()

    stamps = [r[0] for r in rows]
    if len(stamps) < 50:
        # Too little to have a rhythm. Saying "no holes" here would be a
        # statement the data cannot support.
        return {"windows": [], "median_gap": 0, "checked": False}

    gaps = [b - a for a, b in zip(stamps, stamps[1:])]
    median = _median([g for g in gaps if g > 0]) or 1
    threshold = max(QUIET_MIN_SECONDS, median * QUIET_FACTOR)

    windows = []
    for (a, b), gap in zip(zip(stamps, stamps[1:]), gaps):
        if gap >= threshold:
            windows.append({"from": a, "to": b, "seconds": int(gap)})
    windows.sort(key=lambda w: -w["seconds"])
    return {"windows": windows[:_MAX_QUIET], "median_gap": int(median),
            "threshold": int(threshold), "checked": True,
            "total": len(windows)}


def _first_record_line(path):
    """The first non-empty line of the file, and whether it parses."""
    try:
        with open_text_auto(path) as fh:
            for line in fh:
                if line.strip():
                    return line, accesslog.parse_line(line) is not None
    except (OSError, EOFError, ValueError):
        pass
    return None, True          # unreadable is not the same as truncated


def file_anomalies(case_dir):
    """Per indexed source file: a truncated head and a stale mtime. Both are
    properties of the FILE, so they are read from the file and from the index
    side by side."""
    out = []
    conn = logindex._open_ro(case_dir)
    if conn is None:
        return out
    try:
        sources = conn.execute(
            "SELECT id, path, size, mtime FROM sources "
            "WHERE skipped_reason = ''").fetchall()
        for src in sources:
            entry = {"path": src["path"], "name": os.path.basename(src["path"]),
                     "truncated": False, "stale_mtime": False,
                     "last_epoch": None}
            first, parses = _first_record_line(src["path"])
            if first is not None and not parses:
                entry["truncated"] = True

            # The last stamp in THIS file, to compare against its mtime.
            # BY THE FILE, NOT BY ITS NAME: the source used to be an interned
            # basename, so two vhosts each keeping an `access.log` shared one
            # source and this comparison held one file's mtime against the
            # other's newest entry -- and reported forged timestamps on two
            # honestly timestamped files.
            newest = conn.execute(
                "SELECT max(epoch) FROM requests WHERE source = ? "
                "AND epoch IS NOT NULL AND epoch > 0", (src["id"],)).fetchone()
            if newest is not None and newest[0]:
                entry["last_epoch"] = newest[0]
                # Written before the last thing written into it: a file
                # cannot do that on its own.
                if src["mtime"] and src["mtime"] + 60 < entry["last_epoch"]:
                    entry["stale_mtime"] = True
            if entry["truncated"] or entry["stale_mtime"]:
                out.append(entry)
    except sqlite3.Error:
        return out
    finally:
        conn.close()
    return out


def report(case_dir, lang="en", tz_mode="log"):
    """Everything this module measured, plus the sentences for the
    chronology. The sentences are built here so the chain and the evidence
    view can never describe the same hole differently."""
    quiet = quiet_windows(case_dir)
    anomalies = file_anomalies(case_dir)
    notes = []

    from server.chain import iso, local

    for w in quiet["windows"]:
        notes.append(t(lang, "coverage.quiet",
                       hours=f"{w['seconds'] / 3600:.1f}",
                       start=iso(local(w["from"]), 0, tz_mode),
                       end=iso(local(w["to"]), 0, tz_mode)))
    for a in anomalies:
        if a["truncated"]:
            notes.append(t(lang, "coverage.truncated", file=a["name"]))
        if a["stale_mtime"]:
            notes.append(t(lang, "coverage.staleMtime", file=a["name"]))
    return {"quiet": quiet, "files": anomalies, "notes": notes}


def evidence_note(case_dir, lang="en", tz_mode="log"):
    """One line for the evidence view, or ''. Deliberately short: the detail
    belongs where the analyst is reading the story."""
    data = report(case_dir, lang, tz_mode)
    if not data["notes"]:
        return ""
    return t(lang, "coverage.summary", n=len(data["notes"]))
