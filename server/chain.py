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
  2. MEASURED TIME ONLY. A 2xx records a response for the file's path. File
     system timestamps are shown only for confirmed webshells and explicitly
     as metadata of the evidence copy: they do not prove deployment, upload
     or access. Access time is deliberately omitted because reading or mount
     policy can change it.
  3. GAPS ARE NAMED, NOT BRIDGED.

The chronology retains its explicit log/UTC display modes. Each event also
has a separate absolute epoch when its source supplies one; automatic incident
anchors use that value, never naive database times or display-time ordering.

Its own module rather than a closure inside `create_app`: this is the one
piece of narrative the server writes, it is shared by the `/chain` route and
the JSON export, and it is worth testing on its own.
"""
import json
import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from server import db
from server import coverage
from server.artifacts import ART_SQL, uri_targets, web_path
from server.engines import logindex
from server.i18n import t
from server.engines.fsutil import io_path

EVENT_CAP = 80


def _registered_file(path, roots):
    """A metadata candidate must still belong to this case's evidence."""
    try:
        target = Path(io_path(path)).resolve(strict=True)
        if not target.is_file():
            return False
        for root in roots:
            try:
                resolved = Path(io_path(root)).resolve(strict=True)
                if target == resolved or target.is_relative_to(resolved):
                    return True
            except (OSError, ValueError, RuntimeError):
                continue
    except (OSError, ValueError, RuntimeError):
        pass
    return False


def _event_id(source, kind, artifact, raw_time, identity=""):
    payload = json.dumps([source, kind, artifact, raw_time, identity],
                         ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8", "surrogatepass")).hexdigest()


def local(epoch, tz=0):
    """Log time as naive local time -- the same one shown everywhere."""
    return None if not epoch else int(epoch) + int(tz or 0)


def offset_label(tz=0):
    """`UTC+02:00`, or plain `UTC` for zero -- the one offset whose name is
    not a guess.

    NO ZONE NAMES. A log line carries an OFFSET, and `+0200` is CEST and
    equally EET and SAST. Printing a name would be a guess wearing the
    clothes of a measurement."""
    tz = int(tz or 0)
    if not tz:
        return "UTC"
    sign = "-" if tz < 0 else "+"
    total = abs(tz) // 60
    return f"UTC{sign}{total // 60:02d}:{total % 60:02d}"


def iso(value, tz=0, mode="log"):
    """A readable timestamp for running text, WITH the zone it is in.

    A bare `2026-06-10 22:58:11` in a report is not a time, it is a time and
    a question.

    `value` IS ALREADY IN THE FRAME `mode` NAMES. Everything that reaches
    here has come through `log_at()`, which adds the log's offset in `log`
    mode and adds nothing in `utc` mode -- so this function only formats and
    labels. It used to subtract the offset again in `utc` mode, on the
    assumption that the value was always local; for values that were already
    UTC that made the prose wrong by exactly the offset, while the event the
    sentence hung on carried the right time. Two timestamps for one moment,
    two hours apart, in one paragraph.

    Shifting belongs in ONE place, and that place is `log_at`."""
    if not value:
        return "—"
    stamp = datetime.fromtimestamp(int(value), tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S")
    return f"{stamp} {'UTC' if mode == 'utc' else offset_label(tz)}"


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


def filesystem_times(path):
    """Portable file times as UTC epochs, without changing their meaning.

    Windows ctime is creation time; on POSIX it is metadata-change time. Some
    POSIX platforms additionally expose a birth time. Keeping those fields
    separate prevents one number from receiving two incompatible labels when
    a case moves between systems. Access time is intentionally absent: merely
    reviewing evidence can modify it.
    """
    try:
        stat = os.stat(path)
    except OSError:
        return {}

    def epoch(value):
        try:
            return int(float(value)) if value is not None else None
        except (OverflowError, TypeError, ValueError):
            return None

    birth = getattr(stat, "st_birthtime", None)
    created = birth if birth is not None else (
        stat.st_ctime if os.name == "nt" else None)
    changed = None if os.name == "nt" else stat.st_ctime
    return {
        "created": epoch(created),
        "modified": epoch(stat.st_mtime),
        "changed": epoch(changed),
    }


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


def case_chain(case_dir, lang="en", tz_mode="log", event_cap=EVENT_CAP):
    """The chronology as data -- shared by the route and the exports: what
    the analyst reads in the dashboard has to be the same thing the case
    hands out.

    ``event_cap=None`` returns the complete sequence.  The interactive route
    uses that form and paginates the result explicitly; reports retain the
    conservative default cap so an unexpectedly large case cannot make an
    export unbounded.
    """
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
        # A confirmed FILE is not automatically a webshell: manual review can
        # also dismiss files, and other scanners produce file findings. These
        # are the two sources that make the narrower statement needed for the
        # filesystem observations below.
        webshell_files = {r["artifact"] for r in db.rows(
            conn, "SELECT DISTINCT artifact FROM findings "
                  "WHERE artifact_kind = 'file' AND triage = 'confirmed' "
                  "AND (source = 'webshell' "
                  "OR rule_id = 'analyst.file_review')")}
        accounts = db.rows(
            conn, "SELECT login, registered, admin, last_login, tbl "
                  "FROM db_accounts WHERE registered != ''")
        evidence = db.rows(conn, "SELECT kind, path FROM evidence")
        indexing = bool(db.one(conn, "SELECT id FROM jobs WHERE kind = 'index_logs' "
                                    "AND state IN ('queued', 'running') LIMIT 1"))
        confirmed_alerts = {(r["artifact"], r["rule_id"]) for r in db.rows(
            conn, f"SELECT DISTINCT f.artifact, f.rule_id FROM findings f {db.RETIRE_JOIN} "
                  "WHERE f.artifact_kind='client' AND f.source='logs' "
                  f"AND f.triage='confirmed' AND ({db.LIVE_PREDICATE})")}
        # Applied clusters retain the exact matching request window. A generic
        # confirmed IP is insufficient: this specific Hunt finding must still
        # be confirmed, including Findings' existing retirement semantics.
        hunt_matches = db.rows(conn, f"""
            SELECT c.*, a.pattern_id, a.pattern_version, a.rule_hash,
                   h.index_fingerprint, h.tz
              FROM hunt_application_clusters c
              JOIN hunt_applications a ON a.id = c.application_id
              JOIN hunt_tests h ON h.id = a.test_id
             WHERE EXISTS (
                 SELECT 1 FROM findings f {db.RETIRE_JOIN}
                  WHERE f.artifact = c.client AND f.artifact_kind = 'client'
                    AND f.triage = 'confirmed'
                    AND f.rule_id = 'hunt.' || a.pattern_id || '.v' || a.pattern_version
                    AND ({db.LIVE_PREDICATE}))
             ORDER BY c.first_epoch, c.id
        """)
        offsets = clock_offsets(conn)
    finally:
        conn.close()

    off_logs, off_dump = offsets["logs"], offsets["dump"]
    overview = logindex.overview(case_dir) or {}
    log_targets = [r["path"] for r in evidence if r["kind"] == "access_logs"]
    log_fresh = bool(log_targets and not indexing and not overview.get("partial")
                     and logindex.status(case_dir, log_targets)["fresh"])
    index_fingerprint = logindex.index_fingerprint(case_dir) if log_fresh else ""
    evidence_roots = [r["path"] for r in evidence]
    # EVERY offset the logs carry, not one. A single server that ran through
    # a DST change writes two -- an Austrian log crosses +0100/+0200 twice a
    # year -- and several servers in one case can write anything. Labelling
    # the whole chronology with one of them would be wrong by an hour for the
    # rest, and wrong in the way nobody checks.
    tz_offsets = [int(o) for o in (overview.get("tz_offsets") or [])]
    span_tz = tz_offsets[0] if len(tz_offsets) == 1 else 0
    span_first = local(overview.get("first_epoch"),
                       0 if tz_mode == "utc" else span_tz)
    if span_first is not None:
        span_first += off_logs
    span_last = local(overview.get("last_epoch"),
                      0 if tz_mode == "utc" else span_tz)
    if span_last is not None:
        span_last += off_logs

    # THE WINDOW THAT DECIDES WHICH ACCOUNTS BELONG IS NOT THE ONE ON SCREEN.
    # `span_first`/`span_last` follow the display mode, because that is what
    # the reader sees. The account filter below compares them against dump
    # timestamps, which are naive wall-clock readings and do not follow any
    # mode -- so with the display window moving and the dump times standing
    # still, switching to UTC added or dropped accounts near the edges. A
    # display toggle decided whether a created account was part of the story.
    #
    # This window is the log period as a WALL CLOCK reading, always, which is
    # the same thing the dump timestamps are. Comparing like with like.
    window_first = local(overview.get("first_epoch"), span_tz)
    if window_first is not None:
        window_first += off_logs
    window_last = local(overview.get("last_epoch"), span_tz)
    if window_last is not None:
        window_last += off_logs

    facts = logindex.chain_facts(
        case_dir,
        leaves=[os.path.basename(p) for p in files.values()],
        ips=clients)

    events, undated, gaps = [], [], []
    # Confirmed artifacts whose events exist but fall past the cap.
    beyond = set()

    # Every log time through ONE funnel, every dump time through the other --
    # that way no single spot can forget the offset.
    def log_at(epoch, tz=0):
        # The MODE decides here, not in the browser: the chronology hands out
        # times already shifted, so a reader that shifted again would be
        # applying the offset twice. In `utc` mode nothing is added.
        at = local(epoch, 0 if tz_mode == "utc" else tz)
        return None if at is None else at + off_logs

    def dump_at(text):
        at = stamp_to_local(text)
        return None if at is None else at + off_dump

    def filesystem_at(epoch):
        """Put an absolute filesystem time into the active chain reading.

        Filesystem epochs are UTC. In log-time mode a case with one measured
        log offset is displayed in that wall-clock frame, so apply the same
        display shift. Unlike log and dump clocks, there is no analyst offset
        for the evidence filesystem.
        """
        if epoch is None:
            return None
        return int(epoch) + (span_tz if tz_mode != "utc" else 0)

    dated = set()

    def add(at, kind, title, detail, source, artifact="", artifact_kind="",
            ip="", severity=None, *, raw_time=None, epoch=None,
            identity="", basis=None, eligible=False, selectable=False):
        if at is None:
            return
        dated.add(artifact)
        events.append({"id": _event_id(source, kind, artifact, raw_time, identity),
                       "at": at, "epoch": epoch, "kind": kind, "title": title,
                       "detail": detail, "source": source,
                       "artifact": artifact, "artifact_kind": artifact_kind,
                       # The SAME artifact, webroot-relative. `artifact` is
                       # the absolute path on this machine and is the identity
                       # the interface opens windows with; anything that
                       # LEAVES the machine has to use this one instead, or
                       # the report carries the analyst's directory layout.
                       # For clients and tables the two are identical.
                       "artifact_rel": files.get(artifact, artifact),
                       "ip": ip, "severity": severity,
                       "first_sign_basis": basis,
                       "first_sign_eligible": bool(eligible and epoch is not None),
                       "first_sign_selectable": bool(selectable and epoch is not None)})

    # --- confirmed files: when was it there, when was it used ----------
    for artifact, rel in files.items():
        row = by_artifact[artifact]
        name = os.path.basename(rel)
        file_registered = _registered_file(artifact, evidence_roots)
        if artifact in webshell_files:
            metadata_detail = t(lang, "chain.file.fs.detail")
            file_times = filesystem_times(artifact)
            add(filesystem_at(file_times.get("created")), "datei-erstellt",
                t(lang, "chain.file.fs.created", name=name),
                metadata_detail, "filesystem", artifact, "file",
                severity=row["worst"], raw_time=file_times.get("created"),
                epoch=file_times.get("created"), basis="filesystem",
                eligible=file_registered, selectable=file_registered)
            add(filesystem_at(file_times.get("modified")), "datei-geaendert",
                t(lang, "chain.file.fs.modified", name=name),
                metadata_detail, "filesystem", artifact, "file",
                severity=row["worst"], raw_time=file_times.get("modified"),
                epoch=file_times.get("modified"), basis="filesystem",
                eligible=file_registered, selectable=file_registered)
            add(filesystem_at(file_times.get("changed")), "metadaten-geaendert",
                t(lang, "chain.file.fs.changed", name=name),
                metadata_detail, "filesystem", artifact, "file",
                severity=row["worst"], raw_time=file_times.get("changed"),
                epoch=file_times.get("changed"))
        hits = [h for h in facts["files"].get(name, [])
                if uri_targets(h["uri"], rel)]
        if not hits:
            continue
        # THE OFFSET OF A REQUEST THAT HAS ONE. `max()` over all of them let a
        # line whose timestamp could not be read -- offset stored as NULL and
        # coerced to 0 -- outrank a real NEGATIVE offset, so this file's events
        # were dated in UTC while the client events beside them in the same
        # chronology were dated in log time. Two frames in one sequence, hours
        # apart, with nothing on screen saying so: a chronology is read as an
        # ORDER, and that order was then wrong. Invisible at offset zero, and
        # invisible above it too, because with a positive offset max() happens
        # to pick the real one.
        seen_tz = [h["tz"] for h in hits if h["tz"] is not None]
        tz = max(seen_tz, key=abs) if seen_tz else 0
        oks = [h["first_ok"] for h in hits if h["first_ok"]]
        # A file can be requested by lines whose TIMESTAMP could not be read.
        # The index keeps those at epoch 0 rather than throwing the request
        # away, so `hits` can exist while not one of them carries a time --
        # and `min()` over the empty result raised, taking the whole
        # chronology with it, not just this one event.
        firsts = [h["first_epoch"] for h in hits if h["first_epoch"]]
        lasts = [h["last_epoch"] for h in hits if h["last_epoch"]]
        if not firsts:
            # Requested, but never at a time this case can state. It belongs
            # in `undated` with the rest -- which is where it lands, because
            # `add` is never called and the loop at the bottom catches it.
            continue
        first_any = min(firsts)
        last_any = max(lasts) if lasts else first_any
        total = sum(h["hits"] for h in hits)
        ok_total = sum(h["ok_hits"] for h in hits)
        if oks:
            first_ok = min(oks)
            # Earlier responses remain context. Neither an error nor a 2xx
            # proves that a file was absent/present or executed successfully.
            detail = t(lang, "chain.file.wasThere")
            if first_any < first_ok:
                who = next((h["ip"] for h in hits
                            if h["first_epoch"] == first_any), "")
                by = t(lang, "chain.file.by", ip=who) if who else ""
                detail += t(lang, "chain.file.probeBefore", by=by,
                            at=iso(log_at(first_any, tz), tz, tz_mode))
            add(log_at(first_ok, tz), "erfolg",
                t(lang, "chain.file.firstOk", name=name), detail, "log",
                artifact, "file", severity=row["worst"], raw_time=first_ok,
                epoch=first_ok + off_logs, basis="request",
                eligible=log_fresh and file_registered and artifact in webshell_files,
                selectable=log_fresh and file_registered)
        else:
            add(log_at(first_any, tz), "versuch",
                t(lang, "chain.file.firstTry", name=name),
                t(lang, "chain.file.firstTry.detail", n=total), "log",
                artifact, "file", severity=row["worst"], raw_time=first_any,
                epoch=first_any + off_logs, basis="request",
                selectable=log_fresh and file_registered)
        if last_any and last_any != (min(oks) if oks else first_any):
            add(log_at(last_any, tz), "letzter-zugriff",
                t(lang, "chain.file.last", name=name),
                t(lang, "chain.file.last.detail", n=total, ok=ok_total),
                "log", artifact, "file", severity=row["worst"], raw_time=last_any,
                epoch=last_any + off_logs, basis="request",
                selectable=log_fresh and file_registered)

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
            "log", ip, "client", ip, row["worst"], raw_time=actor["first_epoch"],
            epoch=(actor["first_epoch"] + off_logs) if actor["first_epoch"] else None,
            basis="request", selectable=log_fresh)
        for a in actor["alerts"]:
            verified_epoch = a.get("first_sign_epoch")
            event_epoch = verified_epoch or a["epoch"]
            event_tz = a.get("first_sign_tz") if verified_epoch else tz
            example = a.get("first_sign_example") if verified_epoch else a["example"]
            example = example or a["example"]
            if a["severity"] >= db.SEV_INFO or not event_epoch:
                continue
            # The alert text itself comes from the index and is English: it
            # is stored and travels into findings and the archive.
            add(log_at(event_epoch, event_tz), "alarm", a["detail"],
                t(lang, "chain.alert.detail", example=example), "log",
                ip, "client", ip, a["severity"], raw_time=event_epoch,
                epoch=event_epoch + off_logs, identity=[a.get("kind", ""), example],
                basis="request", eligible=(log_fresh and bool(verified_epoch)
                    and (ip, "logs." + a.get("kind", "")) in confirmed_alerts),
                selectable=log_fresh and bool(verified_epoch))
        add(log_at(actor["last_epoch"], tz), "letzter-zugriff",
            t(lang, "chain.client.last", ip=ip), "", "log", ip, "client",
            ip, row["worst"], raw_time=actor["last_epoch"],
            epoch=(actor["last_epoch"] + off_logs) if actor["last_epoch"] else None,
            basis="request", selectable=log_fresh)

    # A saved Hunt cluster is already a measured match, not a reputation
    # lookup or a client's unrelated earlier browsing. Keep only the confirmed
    # applied finding and the same current index that produced this cluster.
    hunt_seen = set()
    # A recheck may apply the same cluster again. Prefer its current snapshot
    # before deduplicating, or an older stale application would hide the fresh
    # evidence solely because it was stored first.
    for match in sorted(hunt_matches, key=lambda item: (
            item["index_fingerprint"] != index_fingerprint, item["id"])):
        epoch = match["first_epoch"]
        ip = match["client"]
        identity = f"{match['rule_hash']}:{match['cluster_key']}"
        key = (ip, epoch, identity)
        if not epoch or ip not in by_artifact or key in hunt_seen:
            continue
        hunt_seen.add(key)
        fresh = bool(log_fresh and index_fingerprint
                     and match["index_fingerprint"] == index_fingerprint)
        add(log_at(epoch, match["tz"]), "hunt-match",
            t(lang, "chain.hunt.first", ip=ip),
            t(lang, "chain.hunt.detail", method=match["method"],
              uri=match["uri_pattern"], status=match["status_class"]),
            "log", ip, "client", ip, by_artifact[ip]["worst"],
            raw_time=epoch, epoch=epoch + off_logs, identity=identity,
            basis="hunt_match", eligible=fresh, selectable=fresh)

    # --- accounts created WITHIN THE PERIOD OF THE CASE -----------------
    # An account from 2019 does not belong in the chronology of an incident
    # from 2026. The period of the log is the most honest window the case has
    # for that.
    for acc in accounts:
        at = dump_at(acc["registered"])
        if at is None or window_first is None \
                or not (window_first <= at <= window_last):
            continue
        detail = t(lang, "chain.account.detail",
                   table=acc["tbl"] or t(lang, "chain.account.userTable"))
        last = dump_at(acc["last_login"])
        if last and window_first <= last <= window_last:
            detail += t(lang, "chain.account.lastLogin", at=iso(last, 0, tz_mode))
        title = t(lang, "chain.account.created", login=acc["login"])
        if acc["admin"]:
            title += t(lang, "chain.account.admin")
        add(at, "konto", title, detail, "dump",
            severity=db.SEV_HIGH if acc["admin"] else db.SEV_MEDIUM,
            raw_time=acc["registered"], identity=f"{acc['tbl']}:{acc['login']}")

    # Index replacement may race a read-only dashboard refresh. Historical
    # timeline context remains visible, but no mixed generation is selectable.
    if log_fresh and logindex.index_fingerprint(case_dir) != index_fingerprint:
        for event in events:
            if event["source"] == "log":
                event["first_sign_eligible"] = False
                event["first_sign_selectable"] = False

    events.sort(key=lambda e: e["at"])
    total_events = len(events)
    event_span = {
        "first": events[0]["at"] if events else None,
        "last": events[-1]["at"] if events else None,
    }
    truncated = event_cap is not None and total_events > event_cap
    if truncated:
        # WHAT THE CAP CUTS OFF STILL HAS TO BE ACCOUNTED FOR. `dated` was
        # filled while the events were being built, so an artifact whose only
        # events fall past the cap counted as dated and then vanished with
        # them -- present in neither list.
        #
        # THE FIRST ATTEMPT AT THIS PUT THEM IN `undated`, AND THAT WAS WORSE.
        # `undated` says "the log proves no request for this file", so on a
        # real case nine confirmed webshells -- every JCE drop -- were listed
        # as never requested while the log holds 91 successful retrievals of
        # them. Losing a fact is bad; asserting its opposite is a different
        # thing altogether.
        #
        # Cut artifacts are their own answer: they HAVE measured times, and
        # this chronology does not reach them.
        events, cut = events[:event_cap], events[event_cap:]
        still_shown = {e["artifact"] for e in events}
        for event in cut:
            artifact = event["artifact"]
            if artifact and artifact not in still_shown:
                dated.discard(artifact)
                beyond.add(artifact)

    # EVERY CONFIRMED ARTIFACT MUST SHOW UP -- in the chain or here. A
    # chronology from which a decision of the analyst quietly disappears is
    # the more dangerous half of a lie: it looks complete.
    for row in confirmed:
        if row["artifact"] in dated:
            continue
        kind = row["artifact_kind"]
        if row["artifact"] in beyond:
            key = "chain.beyondCap"
        else:
            key = ("chain.undated." + kind
                   if kind in ("table", "dump", "file", "client")
                   else "chain.undated.other")
        undated.append({
            "artifact": row["artifact"], "artifact_kind": kind,
            "artifact_rel": files.get(row["artifact"], row["artifact"]),
            "why": t(lang, key, n=event_cap)})

    # --- what the case does NOT prove ----------------------------------
    if not confirmed:
        gaps.append(t(lang, "chain.gap.noConfirmed"))
    elif not events:
        gaps.append(t(lang, "chain.gap.noTimes"))
    if events and span_first is not None and events[0]["at"] - span_first < 60:
        gaps.append(t(lang, "chain.gap.atLogStart", at=iso(span_first, span_tz, tz_mode)))
    if files and not any(e["kind"] == "erfolg" for e in events):
        gaps.append(t(lang, "chain.gap.onlyAttempts"))
    if truncated:
        gaps.append(t(lang, "chain.gap.truncated", n=event_cap))
    # WHERE THE LOGS ARE SILENT is the same kind of statement as the gaps
    # above: something the case cannot show. A window somebody removed and a
    # quiet night look identical from here, so this points at the question
    # rather than answering it.
    # NOT the coverage notes. They stand in their own block directly above
    # the chronology now -- what the logs cannot show belongs before the
    # sequence built out of them, and once is enough. `gaps` keeps what only
    # the chain knows: no confirmed artifact yet, no measured time, the
    # first event sitting on the edge of the log period.
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
        "event_span": event_span,
        "events": events, "gaps": gaps, "undated": undated,
        "confirmed": len(confirmed), "truncated": truncated,
        "total_events": total_events,
        "offsets": offsets,
        # What zone the times above are in. The events carry no offset of
        # their own -- they arrive already shifted -- so this is the only
        # place that says what they mean, and a chronology whose times do
        # not say that is a chronology nobody can quote.
        "tz_mode": tz_mode,
        # What the times above are in. In log time a case is only
        # unambiguous when the logs carry ONE offset; with several, the
        # honest answer is to name them and say that UTC is the reading
        # that can be compared.
        "zone": ("UTC" if tz_mode == "utc"
                 else offset_label(span_tz) if len(tz_offsets) <= 1
                 else ""),
        "tz_offsets": [offset_label(o) for o in tz_offsets],
        "tz_mixed": tz_mode != "utc" and len(tz_offsets) > 1,
    }
