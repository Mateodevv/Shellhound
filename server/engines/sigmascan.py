# server/engines/sigmascan.py
"""The analyst's own SIGMA rules over the access log index.

The log-side counterpart to `yarascan.py`, and the same bargain: the rules
this toolkit ships are opinionated, which is useful right up to the moment
somebody arrives with a rule set of their own. YARA is the format that
already exists for files; SIGMA is the one that already exists for log
events, so the log side adds no dialect either.

THE RULES BELONG TO THE WORKSPACE (`<workspace>/sigma/`), not to the case --
the same decision as the pattern library and the YARA rules, for the same
reason: knowledge about what to look for grows across cases, while a case
only records what it found.

ADDITIVE, NOT A REPLACEMENT. The six built-in log rules stay where they are.
Four of them could be expressed in SIGMA -- but three need real regular
expressions over a path, which this backend does not run yet, and rewriting
them as substring lists would silently change what they match. The two
remaining ones are a flood and a sequence, which need SIGMA's aggregation
part. So nothing is converted here; this adds a way to write more.

FINDINGS LAND ON THE CLIENT, like every other log rule, so triage and the
IOC box carry on unchanged instead of opening a second work list.

OUTCOME-GATING IS THE CALLER'S JOB, not the rule's. A SIGMA rule cannot say
"only if one of these was answered 2xx", so the backend always reports how
many were, and a rule that hit only refusals lands at LOW instead of the
level it asked for -- the same bargain every probe rule in this tool makes.
"""
from __future__ import annotations

import os

from server import db, ruleswitch, sigma
from server.engines import logindex

RULES_DIR = "sigma"
RULE_SUFFIXES = (".yml", ".yaml")


def rules_dir(workspace):
    return os.path.join(str(workspace), RULES_DIR)


def rule_file_names(workspace):
    directory = rules_dir(workspace)
    if not os.path.isdir(directory):
        return []
    return sorted(n for n in os.listdir(directory)
                  if n.lower().endswith(RULE_SUFFIXES))


def load_rules(workspace, off=frozenset()):
    """(usable, broken). A rule this backend cannot answer lands in `broken`
    with its reason -- never loaded and left to match nothing, which is the
    worst thing a detection rule can do."""
    usable, broken = [], []
    directory = rules_dir(workspace)
    for name in rule_file_names(workspace):
        try:
            with open(os.path.join(directory, name), "r",
                      encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            meta, where, params = sigma.compile_rule(text)
        except (OSError, sigma.SigmaError) as e:
            broken.append({"file": name, "error": str(e)[:200]})
            continue
        if meta["id"] in off:
            continue
        usable.append({**meta, "file": name, "where": where,
                       "params": params, "source": text})
    return usable, broken


def status(workspace):
    """What the interface needs: what would run, and what could not be read.

    Two silences must not be confused -- no rules placed at all, versus
    rules that were placed and refused."""
    names = rule_file_names(workspace)
    usable, broken = load_rules(workspace)
    return {"dir": rules_dir(workspace), "files": names,
            "rules": len(usable), "broken": broken,
            "reason": "norules" if not names else ""}


def scan(case_dir, workspace=None, ctx=None):
    """Run every workspace SIGMA rule against the log index."""
    stats = {"rules": 0, "findings": 0, "clients": 0, "broken_rules": 0}
    if workspace is None:
        return stats

    off = ruleswitch.disabled_ids(workspace)
    usable, broken = load_rules(workspace, off)
    stats["rules"] = len(usable)
    stats["broken_rules"] = len(broken)
    if broken:
        stats["broken"] = [b["file"] for b in broken]

    log_conn = logindex.open_readonly(case_dir)
    if log_conn is None:
        return stats

    conn = db.connect(case_dir)
    try:
        run = db.begin_run(conn, "sigmascan")
        cancelled = False
        conn.execute("DELETE FROM skipped WHERE source = 'sigma'")
        for entry in broken:
            conn.execute(
                "INSERT INTO skipped (source, path, reason) VALUES (?,?,?)",
                ("sigma", entry["file"],
                 f"rule not usable: {entry['error']}"))
        touched = set()
        for i, rule in enumerate(usable):
            if ctx is not None:
                if ctx.cancelled():
                    cancelled = True
                    break
                ctx.progress(0.05 + (i / (len(usable) or 1)) * 0.9,
                             f"{rule['title']}")
            try:
                clients = sigma.clients_matching(
                    log_conn, rule["where"], rule["params"])
                example = sigma.example_uri(
                    log_conn, rule["where"], rule["params"])
            except Exception as e:            # sqlite3.Error and friends
                conn.execute(
                    "INSERT INTO skipped (source, path, reason) VALUES (?,?,?)",
                    ("sigma", rule["file"], f"query failed: {str(e)[:160]}"))
                continue
            for client in clients:
                ok = client["ok_hits"] > 0
                # The rule's own level applies only when something was
                # answered. A wave that was refused is not the same finding.
                #
                # GATING LOWERS, IT NEVER RAISES. A rule declared
                # `level: informational` already sits below LOW -- higher
                # number, milder -- so forcing the refused case to LOW made
                # "everything was blocked" more serious than "some got
                # through", which is the statement backwards.
                severity = (rule["severity"] if ok
                            else max(rule["severity"], db.SEV_LOW))
                db.upsert_finding(
                    conn, "logs", severity, rule["title"], "client",
                    client["ip"],
                    evidence=(f"{client['hits']}x matched, of those "
                              f"{client['ok_hits']}x 2xx - SIGMA rule "
                              f"{rule['id']} ({rule['file']})"
                              + (f" - e.g. {example}" if example else ""))[:400],
                    rule_id=rule["id"], engine="sigmascan", run=run)
                stats["findings"] += 1
                touched.add(client["ip"])
        stats["clients"] = len(touched)
        conn.commit()
        # A cancelled run has no opinion about the rules it never ran. A run
        # over an emptied rule folder completes with nothing -- findings of
        # deleted rules stop being current, and the next run of a restored
        # rule brings them back with their triage untouched.
        if not cancelled:
            db.complete_run(conn, "sigmascan", run)
    finally:
        conn.close()
        log_conn.close()
    return stats
