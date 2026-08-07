# server/artifacts.py
"""The artifact: the unit this toolkit decides about.

THE UNIT OF WORK IS THE ARTIFACT, NOT THE SINGLE FINDING.

Eight rules firing on one dropped shell are eight observations about ONE
file, and the analyst decides about the file: is this thing part of the
incident or not? Asking the same question eight times produced eight answers
that could contradict each other and a count that overstated the case ("119
findings" reads like 119 problems; it was 14 files).

Every artifact query in the application starts from `ART_SQL` here rather
than from its own aggregate -- the folding rule (which decision wins when the
rows of one artifact disagree) has to be the same everywhere, or the
dashboard and the findings list quietly count different things.
"""
import os
import re

from server import db

# The aggregate every artifact query starts from. `triage` folds the rows of
# one artifact into one decision -- confirmed wins (one real hit makes the
# artifact real), dismissed only counts when it is unanimous. Legacy cases
# triaged per finding therefore stay readable instead of showing a state
# their rows do not agree on.
# Rule ids are internal strings, but SIGMA ids come from files the analyst
# wrote, so they are held to a shape before they are ever put into SQL. An id
# outside it simply cannot be muted -- which is a visible failure, not a
# silent injection.
_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]+$")


def art_sql(muted=()):
    """The artifact view, optionally knowing which rules are switched off.

    `active` counts the findings on an artifact that came from a rule this
    workspace still runs. A finding whose `rule_id` is empty always counts:
    it is either older than the column or from the analyst's own YARA files,
    which are switched off as FILES and not through this.

    Nothing is filtered here. The column is offered and the WORK LIST decides
    -- because a confirmed artifact must not vanish just because the rule
    that first pointed at it was later muted. That decision is the analyst's,
    and a switch is not a retraction."""
    ids = sorted({i for i in muted if _SAFE_ID.match(str(i))})
    if ids:
        values = ", ".join("'" + i + "'" for i in ids)
        active = (f"SUM(CASE WHEN rule_id = '' OR rule_id NOT IN ({values}) "
                  f"THEN 1 ELSE 0 END)")
    else:
        active = "COUNT(*)"
    return f"""
    SELECT artifact,
           MIN(artifact_kind) AS artifact_kind,
           MIN(severity)      AS worst,
           MIN(source)        AS source,
           COUNT(*)           AS findings,
           {active}           AS active,
           MAX(triaged_at)    AS triaged_at,
           MAX(triage_note)   AS triage_note,
           MAX(last_seen)     AS last_seen,
           CASE
             WHEN SUM(triage = 'confirmed') > 0 THEN 'confirmed'
             WHEN SUM(triage = 'dismissed') = COUNT(*) THEN 'dismissed'
             WHEN SUM(triage = 'reviewed') > 0 THEN 'reviewed'
             ELSE 'new'
           END AS triage
    FROM findings GROUP BY artifact
"""


# The view without any rule switched off. Most callers -- the chronology, the
# exports, the IOC box -- want every artifact regardless: what a case FOUND
# does not change because a rule was later muted.
ART_SQL = art_sql()

# What a muted rule is allowed to hide, as a WHERE fragment: an artifact left
# without a single live finding disappears -- but only while it is still
# UNDECIDED, because a decision belongs to the analyst and muting a rule is
# not a retraction of it.
#
# THE BRACKETS ARE PART OF THE VALUE. This fragment is AND-ed onto the chip
# filters, and SQL binds AND tighter than OR: unbracketed it reads
# `(chips AND active > 0) OR triage != 'new'`, which lets every decided
# artifact past every chip. It lives here, next to the SQL it belongs to,
# rather than as a literal at the call site, so the guard in the test suite
# is testing the string the server actually uses.
MUTED_CLAUSE = "(active > 0 OR triage != 'new')"


def counts(conn):
    """The chip counts -- artifacts, not findings, in every dimension."""
    def group(column):
        return {r[column]: r["n"] for r in db.rows(
            conn, f"WITH art AS ({ART_SQL}) "
                  f"SELECT {column}, count(*) n FROM art GROUP BY {column}")}
    sev = group("worst")
    return {"severity": sev, "triage": group("triage"),
            "source": group("source"),
            "total": sum(sev.values())}


def uri_path(uri):
    """The path part of a URI, lower-cased, without the query."""
    return str(uri or "").split("?", 1)[0].split("#", 1)[0].strip().lower()


def web_path(conn, artifact):
    """The file as it would appear in a URL: the path below the evidence root
    it sits under. Falls back to the file name when no root matches.

    Lower-cased, because the only thing it is ever compared against is
    `uri_path()` -- and a URL is not the file system: the same file arrives as
    /Images/Shell.php and /images/shell.php.
    """
    target = str(artifact).replace("\\", "/")
    best = ""
    for row in db.rows(conn, "SELECT path FROM evidence"):
        root = str(row["path"]).replace("\\", "/").rstrip("/")
        if root and target.lower().startswith(root.lower() + "/") \
                and len(root) > len(best):
            best = root
    rel = target[len(best) + 1:] if best else os.path.basename(target)
    return rel.strip("/").lower()
