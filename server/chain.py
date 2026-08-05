# server/chain.py
"""The chronology of a case: what happened, in which order.

EVERY VIEW ANSWERS "WHAT", NONE ANSWERS "IN WHICH ORDER". That, however, is
exactly the first paragraph of every report, and until now one typed it out
by jumping between Actors, Findings and Database and sorting timestamps in
one's head.

THE CHAIN ORDERS MEASURED FACTS AND CLAIMS NO CAUSE.
"08:12 request for async-upload.php with 2xx, 08:13 first successful
retrieval of kb-media.php" is an observation. "The attacker uploaded the
shell through the upload function" is a conclusion -- and that belongs to
the analyst. A machine that dictates the conclusion of the report is
convenient in every case and wrong in every tenth, and a wrong chain is
worse than none.

Three rules follow from that:
  1. CONFIRMED ARTIFACTS ONLY. The triage decides what belongs to the story,
     not the detection.
  2. MEASURED TIME ONLY. The first 2xx for a file proves it was there; the
     mtime of the copy proves nothing at all, because nobody can tell from it
     whether it comes from the original or from the copying.
  3. GAPS ARE NAMED, NOT BRIDGED.

Both clocks stand there without a zone: the log line in its server time, the
account timestamp in that of the database server. They are compared AS THEY
STAND -- anything else would mean inventing a time zone. The response says
so, lest it get lost in the report.

Its own module rather than a closure inside `create_app`: this is the one
piece of narrative the server writes, it is shared by the `/chain` route and
the JSON export, and it is worth testing on its own.
"""
import json
import os
from datetime import datetime, timezone

from server import db
from server.artifacts import ART_SQL, uri_path, web_path
from server.engines import logindex
from server.i18n import t

EVENT_CAP = 80


def local(epoch, tz=0):
    """Log time as naive local time -- the same one shown everywhere."""
    return None if not epoch else int(epoch) + int(tz or 0)


def iso(value):
    """Naive local time as a readable timestamp, for running text."""
    if not value:
        return "—"
    return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S")


def stamp_to_local(text):
    """'2026-07-08 03:17:00' -> seconds, read naively."""
    raw = str(text or "").strip().replace("T", " ")[:19]
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return int(datetime.strptime(raw, fmt)
                       .replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            continue
    return None


def clock_offsets(conn):
    """The CLOCK OFFSET set by the analyst, per source, in seconds.

    Log server and database server can run different clocks (time zone,
    drifting VM) -- and with "account 03:17, first contact 09:12" a six-hour
    offset can turn the order of the story around. The offset is therefore a
    STATEMENT OF THE ANALYST, stored in the case and reported in the
    chronology -- not something the tool quietly guesses.
    """
    row = db.one(conn, "SELECT value FROM meta WHERE key = 'clock_offsets'")
    try:
        raw = json.loads(row["value"]) if row else {}
    except (ValueError, TypeError):
        raw = {}
    return {"logs": int(raw.get("logs", 0) or 0),
            "dump": int(raw.get("dump", 0) or 0)}


def case_chain(case_dir, lang="en"):
    """The chronology as data -- shared by the route and the exports: what
    the analyst reads in the dashboard has to be the same thing the case
    hands out."""
    conn = db.connect(case_dir)
    try:
        confirmed = db.rows(
            conn, f"WITH art AS ({ART_SQL}) SELECT artifact, artifact_kind,"
                  f" worst, findings, triage_note FROM art "
                  f"WHERE triage = 'confirmed'")
        files = {r["artifact"]: web_path(conn, r["artifact"])
                 for r in confirmed if r["artifact_kind"] == "file"}
        clients = [r["artifact"] for r in confirmed
                   if r["artifact_kind"] == "client"]
        by_artifact = {r["artifact"]: r for r in confirmed}
        accounts = db.rows(
            conn, "SELECT login, registered, admin, last_login, tbl "
                  "FROM db_accounts WHERE registered != ''")
        offsets = clock_offsets(conn)
    finally:
        conn.close()

    off_logs, off_dump = offsets["logs"], offsets["dump"]
    overview = logindex.overview(case_dir) or {}
    span_first = local(overview.get("first_epoch"))
    if span_first is not None:
        span_first += off_logs
    span_last = local(overview.get("last_epoch"))
    if span_last is not None:
        span_last += off_logs
    facts = logindex.chain_facts(
        case_dir,
        leaves=[os.path.basename(p) for p in files.values()],
        ips=clients)

    events, undated, gaps = [], [], []

    # Every log time through ONE funnel, every dump time through the other --
    # that way no single spot can forget the offset.
    def log_at(epoch, tz=0):
        at = local(epoch, tz)
        return None if at is None else at + off_logs

    def dump_at(text):
        at = stamp_to_local(text)
        return None if at is None else at + off_dump

    dated = set()

    def add(at, kind, title, detail, source, artifact="", artifact_kind="",
            ip="", severity=None):
        if at is None:
            return
        dated.add(artifact)
        events.append({"at": at, "kind": kind, "title": title,
                       "detail": detail, "source": source,
                       "artifact": artifact, "artifact_kind": artifact_kind,
                       "ip": ip, "severity": severity})

    # --- confirmed files: when was it there, when was it used ----------
    for artifact, rel in files.items():
        row = by_artifact[artifact]
        name = os.path.basename(rel)
        tail = "/" + rel
        hits = [h for h in facts["files"].get(name, [])
                if uri_path(h["uri"]).endswith(tail)]
        if not hits:
            continue
        tz = max((h["tz"] or 0) for h in hits)
        oks = [h["first_ok"] for h in hits if h["first_ok"]]
        first_any = min(h["first_epoch"] for h in hits if h["first_epoch"])
        last_any = max(h["last_epoch"] for h in hits if h["last_epoch"])
        total = sum(h["hits"] for h in hits)
        ok_total = sum(h["ok_hits"] for h in hits)
        if oks:
            first_ok = min(oks)
            # An unsuccessful request BEFORE the first success bounds when
            # the file must have appeared -- the most defensible statement a
            # log yields about it, and it manages without the mtime of the
            # copy.
            detail = t(lang, "chain.file.wasThere")
            if first_any < first_ok:
                who = next((h["ip"] for h in hits
                            if h["first_epoch"] == first_any), "")
                by = t(lang, "chain.file.by", ip=who) if who else ""
                detail += t(lang, "chain.file.probeBefore", by=by,
                            at=iso(log_at(first_any, tz)))
            add(log_at(first_ok, tz), "erfolg",
                t(lang, "chain.file.firstOk", name=name), detail, "log",
                artifact, "file", severity=row["worst"])
        else:
            add(log_at(first_any, tz), "versuch",
                t(lang, "chain.file.firstTry", name=name),
                t(lang, "chain.file.firstTry.detail", n=total), "log",
                artifact, "file", severity=row["worst"])
        if last_any and last_any != (min(oks) if oks else first_any):
            add(log_at(last_any, tz), "letzter-zugriff",
                t(lang, "chain.file.last", name=name),
                t(lang, "chain.file.last.detail", n=total, ok=ok_total),
                "log", artifact, "file", severity=row["worst"])

    # --- confirmed clients: first contact and the triggering calls -----
    for ip in clients:
        row = by_artifact[ip]
        actor = facts["clients"].get(ip)
        if actor is None:
            continue
        tz = actor["tz"] or 0
        add(log_at(actor["first_epoch"], tz), "erstkontakt",
            t(lang, "chain.client.first", ip=ip),
            t(lang, "chain.client.first.detail", n=actor["requests"]),
            "log", ip, "client", ip, row["worst"])
        for a in actor["alerts"]:
            if a["severity"] >= db.SEV_INFO or not a["epoch"]:
                continue
            # The alert text itself comes from the index and is English: it
            # is stored and travels into findings and the archive.
            add(log_at(a["epoch"], tz), "alarm", a["detail"],
                t(lang, "chain.alert.detail", example=a["example"]), "log",
                ip, "client", ip, a["severity"])
        add(log_at(actor["last_epoch"], tz), "letzter-zugriff",
            t(lang, "chain.client.last", ip=ip), "", "log", ip, "client",
            ip, row["worst"])

    # --- accounts created WITHIN THE PERIOD OF THE CASE -----------------
    # An account from 2019 does not belong in the chronology of an incident
    # from 2026. The period of the log is the most honest window the case has
    # for that.
    for acc in accounts:
        at = dump_at(acc["registered"])
        if at is None or span_first is None or not (span_first <= at <= span_last):
            continue
        detail = t(lang, "chain.account.detail",
                   table=acc["tbl"] or t(lang, "chain.account.userTable"))
        last = dump_at(acc["last_login"])
        if last and span_first <= last <= span_last:
            detail += t(lang, "chain.account.lastLogin", at=iso(last))
        title = t(lang, "chain.account.created", login=acc["login"])
        if acc["admin"]:
            title += t(lang, "chain.account.admin")
        add(at, "konto", title, detail, "dump",
            severity=db.SEV_HIGH if acc["admin"] else db.SEV_MEDIUM)

    # EVERY CONFIRMED ARTIFACT MUST SHOW UP -- in the chain or here. A
    # chronology from which a decision of the analyst quietly disappears is
    # the more dangerous half of a lie: it looks complete.
    for row in confirmed:
        if row["artifact"] in dated:
            continue
        kind = row["artifact_kind"]
        key = ("chain.undated." + kind
               if kind in ("table", "dump", "file", "client")
               else "chain.undated.other")
        undated.append({
            "artifact": row["artifact"], "artifact_kind": kind,
            "why": t(lang, key)})

    events.sort(key=lambda e: e["at"])
    truncated = len(events) > EVENT_CAP
    if truncated:
        events = events[:EVENT_CAP]

    # --- what the case does NOT prove ----------------------------------
    if not confirmed:
        gaps.append(t(lang, "chain.gap.noConfirmed"))
    elif not events:
        gaps.append(t(lang, "chain.gap.noTimes"))
    if events and span_first is not None and events[0]["at"] - span_first < 60:
        gaps.append(t(lang, "chain.gap.atLogStart", at=iso(span_first)))
    if files and not any(e["kind"] == "erfolg" for e in events):
        gaps.append(t(lang, "chain.gap.onlyAttempts"))
    if truncated:
        gaps.append(t(lang, "chain.gap.truncated", n=EVENT_CAP))
    # A set offset is part of the statement and therefore stands with the
    # limitations -- whoever reads the chain has to know that the clocks were
    # turned, and by whom.
    for source, off in (("logs", off_logs), ("dump", off_dump)):
        if off:
            gaps.append(t(
                lang, "chain.gap.clockOffset",
                source=t(lang, "chain.clock.source." + source),
                hours=f"{abs(off) / 3600:g}",
                direction=t(lang, "chain.clock.forward" if off > 0
                            else "chain.clock.back")))

    return {
        "span": {"first": span_first, "last": span_last},
        "events": events, "gaps": gaps, "undated": undated,
        "confirmed": len(confirmed), "truncated": truncated,
        "offsets": offsets,
    }
