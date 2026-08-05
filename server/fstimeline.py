# server/fstimeline.py
"""When the webroot was touched -- a LEAD, never a proof.

This toolkit distrusts the mtime, and rightly so: nobody can tell from the
modification time of a COPY whether it came from the original or from the
copying, and an attacker can set it to anything (timestomping). That is why
the chronology is built from the first successful request and never from the
file system, and why nothing in this module ever reaches it.

BUT THE DISTRUST IS ABOUT PROOF, NOT ABOUT VALUE. "These fourteen files were
all written within forty seconds of each other, and one of them is the shell
you already confirmed" is one of the most useful sentences in a webroot
investigation. It does not prove anything; it says where to look next. A
deployment writes hundreds of files in one burst and looks exactly the same
-- which is the point of showing the cluster rather than a verdict about it.

WHAT THIS DELIBERATELY DOES NOT DO:

  * produce findings -- there is nothing here to triage;
  * carry a severity -- a cluster is not more or less bad;
  * enter the chronology -- that stays measured-time only;
  * rank clusters as suspicious -- it orders them by time and marks which
    ones contain something the case already confirmed. The judgement is the
    analyst's.

The one piece of interpretation offered is the tie back to the case: a
cluster that contains a confirmed artifact is worth reading first, because
the OTHER files in it were written in the same minute as something already
known to belong to the incident.
"""
from __future__ import annotations

import os

from server import db
from server.artifacts import ART_SQL

# Files written within this of each other belong to the same burst. A minute
# is long enough to cover an upload of several files over one connection and
# short enough that ordinary editing does not merge into a cluster.
BURST_SECONDS = 60

# A cluster of one file is not a cluster.
MIN_CLUSTER = 2

# Ceilings. A webroot is six figures of files; this reads their metadata
# only, but the ANSWER still has to fit on a screen and in a report.
MAX_FILES = 200_000
MAX_CLUSTERS = 40
MAX_FILES_PER_CLUSTER = 60

# Directories whose churn says nothing about an intrusion: a cache rewrites
# itself constantly and would produce the largest cluster in every case.
_NOISE = ("/cache/", "/tmp/", "/logs/", "/log/", "/sessions/",
          "/wp-content/cache/", "/administrator/cache/")


def _is_noise(path):
    low = path.replace("\\", "/").lower()
    return any(seg in low for seg in _NOISE)


def _roots(conn):
    return [r["path"] for r in db.rows(
        conn, "SELECT path FROM evidence WHERE kind = 'webroot'")]


def _confirmed_files(conn):
    return {r["artifact"] for r in db.rows(
        conn, f"WITH art AS ({ART_SQL}) SELECT artifact FROM art "
              f"WHERE triage = 'confirmed' AND artifact_kind = 'file'")}


def _flagged_files(conn):
    """Everything a rule named, decided or not -- a cluster around an
    undecided finding is exactly as interesting as one around a confirmed
    one, and the analyst has not got there yet."""
    return {r["artifact"] for r in db.rows(
        conn, "SELECT DISTINCT artifact FROM findings "
              "WHERE artifact_kind = 'file'")}


def clusters(case_dir, include_noise=False):
    """Bursts of files written at about the same time.

    Reads metadata only -- no file is opened. On a webroot of 100k files this
    is one stat per file and nothing else."""
    conn = db.connect(case_dir)
    try:
        roots = _roots(conn)
        confirmed = _confirmed_files(conn)
        flagged = _flagged_files(conn)
    finally:
        conn.close()
    if not roots:
        return {"clusters": [], "checked": False, "reason": "nowebroot",
                "files": 0, "truncated": False}

    entries = []
    seen = 0
    truncated = False
    for root in roots:
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                seen += 1
                if seen > MAX_FILES:
                    truncated = True
                    break
                path = os.path.join(dirpath, name)
                if not include_noise and _is_noise(path):
                    continue
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                entries.append((int(st.st_mtime), os.path.abspath(path),
                                st.st_size))
            if truncated:
                break
        if truncated:
            break

    if not entries:
        return {"clusters": [], "checked": False, "reason": "nofiles",
                "files": 0, "truncated": truncated}

    entries.sort()
    out, current = [], [entries[0]]
    for entry in entries[1:]:
        if entry[0] - current[-1][0] <= BURST_SECONDS:
            current.append(entry)
        else:
            out.append(current)
            current = [entry]
    out.append(current)

    result = []
    for group in out:
        if len(group) < MIN_CLUSTER:
            continue
        paths = [g[1] for g in group]
        hits = [p for p in paths if p in confirmed]
        marked = [p for p in paths if p in flagged]
        result.append({
            "from": group[0][0],
            "to": group[-1][0],
            "count": len(group),
            "bytes": sum(g[2] for g in group),
            # The tie back to the case -- the ONE piece of interpretation
            # this module offers. The other files in a cluster were written
            # in the same minute as something already known to belong here.
            "confirmed": len(hits),
            "flagged": len(marked),
            "files": [{"path": p, "confirmed": p in confirmed,
                       "flagged": p in flagged}
                      for p in sorted(paths)[:MAX_FILES_PER_CLUSTER]],
            "truncated": len(paths) > MAX_FILES_PER_CLUSTER,
        })

    # Ordered by TIME, not by a suspicion score. Ranking clusters would be
    # exactly the verdict this module refuses to give; the badge for
    # "contains a confirmed artifact" is what draws the eye instead.
    result.sort(key=lambda c: c["from"])
    if len(result) > MAX_CLUSTERS:
        # Keep the ones tied to the case, then the largest of the rest --
        # and say that it happened.
        tied = [c for c in result if c["confirmed"] or c["flagged"]]
        rest = sorted((c for c in result if c not in tied),
                      key=lambda c: -c["count"])
        result = sorted(tied + rest[:max(0, MAX_CLUSTERS - len(tied))],
                        key=lambda c: c["from"])
        truncated = True

    return {"clusters": result, "checked": True, "reason": "",
            "files": len(entries), "truncated": truncated,
            "burst_seconds": BURST_SECONDS}
