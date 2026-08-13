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

    RETIRED ROWS DO NOT COUNT. A row an engine's last completed run did not
    reproduce (see db.LIVE_PREDICATE) describes a payload that moved, a file
    that is gone or a rule that no longer runs -- adding it to `worst`,
    `findings` or the triage fold makes the case assert something a scan no
    longer supports, which is exactly the split issue #7 measured. The rows
    stay in the table and travel out as `retired`, so nothing is deleted and
    the interface can say "no longer reported" instead of silently shrinking.
    An artifact with NO live row keeps its last known aggregate -- a deleted
    shell the analyst confirmed must not fall out of the list, it must stand
    there saying it was not seen again.

    Nothing else is filtered here. The columns are offered and the WORK LIST
    decides -- because a confirmed artifact must not vanish just because the
    rule that first pointed at it was later muted. That decision is the
    analyst's, and a switch is not a retraction."""
    live = db.LIVE_PREDICATE
    ids = sorted({i for i in muted if _SAFE_ID.match(str(i))})
    if ids:
        values = ", ".join("'" + i + "'" for i in ids)
        active = (f"SUM(CASE WHEN {live} AND (rule_id = '' "
                  f"OR rule_id NOT IN ({values})) THEN 1 ELSE 0 END)")
    else:
        active = f"SUM(CASE WHEN {live} THEN 1 ELSE 0 END)"
    return f"""
    SELECT artifact,
           MIN(artifact_kind) AS artifact_kind,
           COALESCE(MIN(CASE WHEN {live} THEN severity END),
                    MIN(severity)) AS worst,
           MIN(source)        AS source,
           SUM(CASE WHEN {live} THEN 1 ELSE 0 END) AS findings,
           SUM(CASE WHEN {live} THEN 0 ELSE 1 END) AS retired,
           {active}           AS active,
           MAX(triaged_at)    AS triaged_at,
           MAX(triage_note)   AS triage_note,
           MAX(last_seen)     AS last_seen,
           CASE
             WHEN SUM(CASE WHEN {live} AND triage = 'confirmed'
                      THEN 1 ELSE 0 END) > 0 THEN 'confirmed'
             WHEN SUM(CASE WHEN {live} THEN 1 ELSE 0 END) > 0
                  AND SUM(CASE WHEN {live} AND triage = 'dismissed'
                          THEN 1 ELSE 0 END)
                      = SUM(CASE WHEN {live} THEN 1 ELSE 0 END)
                  THEN 'dismissed'
             WHEN SUM(CASE WHEN {live} AND triage = 'reviewed'
                      THEN 1 ELSE 0 END) > 0 THEN 'reviewed'
             WHEN SUM(CASE WHEN {live} THEN 1 ELSE 0 END) > 0 THEN 'new'
             WHEN SUM(triage = 'confirmed') > 0 THEN 'confirmed'
             WHEN SUM(triage = 'dismissed') = COUNT(*) THEN 'dismissed'
             WHEN SUM(triage = 'reviewed') > 0 THEN 'reviewed'
             ELSE 'new'
           END AS triage
    FROM findings f {db.RETIRE_JOIN} GROUP BY artifact
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


def uri_targets(uri, rel):
    """Was THIS request aimed at THIS file?

    `rel` is webroot-relative, the URI is absolute from the site root, and
    the two need not share an origin: a site served out of /shop/ turns the
    file `wp-content/x.php` into the request `/shop/wp-content/x.php`.
    Comparing the tail of the URI against the path is what accounts for that.

    A TAIL OF ONE SEGMENT IS NOT A TAIL, IT IS A NAME. For a file sitting
    directly in the webroot the tail is just `/index.php`, and `endswith`
    then also accepts /shop/index.php, /wp-admin/index.php and every other
    index.php on the site. That is the bare name comparison this module says
    elsewhere is no proof, arrived at by accident -- and it put customers who
    browsed the shop into the list of clients that touched a confirmed
    webshell. A single-segment path therefore has to match exactly; the
    deeper the path, the more context its tail carries and the more `endswith`
    is worth.
    """
    rel = str(rel or "").strip("/").lower()
    if not rel:
        return False
    path = uri_path(uri)
    tail = "/" + rel
    return path == tail if "/" not in rel else path.endswith(tail)


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
