"""Build the synthetic local case used for README screenshots.

The fixture is intentionally made only from RFC 5737 addresses, ``.test``
domains and tiny detector probes. It never reads an analyst workspace.
Run it against an ignored directory, for example::

    python -m tools.build_docs_fixture workspace/docs-preview
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from datetime import datetime, time, timedelta, timezone
from pathlib import Path

from server import db, workspace
from server.engines import cmsinventory, logindex, sqldump, webshell
from tests.fixtures import HTACCESS, SQL_DUMP, WEBSHELL_FILES, WP_VERSION, _access_log


CASE_NAME = "Synthetic incident review"
CASE_REFERENCE = "SYN-2026-001"
RUN_ID = "docs-fixture"
MARKER = ".shellhound-docs-fixture"
INCIDENT_END = datetime.now(timezone.utc).date() - timedelta(days=1)
FIXTURE_MTIME = datetime.combine(
    INCIDENT_END, time(11, 0), tzinfo=timezone.utc).timestamp()


def _recent_access_log() -> str:
    """Move the four fixture log days immediately before today."""
    text = _access_log()
    original_start = datetime(2026, 1, 5, tzinfo=timezone.utc).date()
    recent_start = INCIDENT_END - timedelta(days=3)
    months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    for offset in range(4):
        old = original_start + timedelta(days=offset)
        new = recent_start + timedelta(days=offset)
        old_stamp = f"{old.day:02d}/{months[old.month - 1]}/{old.year}"
        new_stamp = f"{new.day:02d}/{months[new.month - 1]}/{new.year}"
        text = text.replace(old_stamp, new_stamp)
    return text


def _write_evidence(root: Path) -> tuple[Path, Path, Path]:
    webroot = root / "evidence" / "webroot"
    logs = root / "evidence" / "logs"
    dump = root / "evidence" / "cms-export.sql"

    for relative, body in WEBSHELL_FILES.items():
        path = webroot / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    (webroot / "wp-content/uploads/2026/01/.htaccess").write_text(
        HTACCESS, encoding="utf-8")
    wp_include = webroot / "wp-includes"
    wp_include.mkdir(parents=True, exist_ok=True)
    (wp_include / "version.php").write_text(WP_VERSION, encoding="utf-8")

    plugins = {
        "contact-form/contact-form.php": "Plugin Name: Contact Form\nVersion: 2.4.1\n",
        "cache-helper/cache-helper.php": "Plugin Name: Cache Helper\nVersion: 1.8.0\n",
        "shop-tools/shop-tools.php": "Plugin Name: Shop Tools\nVersion: 4.2.0\n",
    }
    for relative, body in plugins.items():
        path = webroot / "wp-content" / "plugins" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"<?php\n/*\n{body}*/\n", encoding="utf-8")
    theme = webroot / "wp-content" / "themes" / "aurora" / "style.css"
    theme.parent.mkdir(parents=True, exist_ok=True)
    theme.write_text("/*\nTheme Name: Aurora Demo\nVersion: 3.1.0\n*/\n", encoding="utf-8")

    logs.mkdir(parents=True, exist_ok=True)
    (logs / "access.log").write_text(_recent_access_log(), encoding="utf-8")
    recent_account = datetime.combine(INCIDENT_END, time(3, 17)).strftime(
        "%Y-%m-%d %H:%M:%S")
    dump.write_text(
        SQL_DUMP.replace("s.keller", "demo-admin")
        .replace("S. Keller", "Demo Administrator")
        .replace("keller@example.test", "admin@synthetic.example.test")
        .replace("2026-01-08 03:17:00", recent_account),
        encoding="utf-8",
    )
    # Preserve a plausible forensic sequence: the synthetic file timestamps
    # must not post-date the requests that supposedly reached those files.
    for path in webroot.rglob("*"):
        if path.is_file():
            os.utime(path, (FIXTURE_MTIME, FIXTURE_MTIME))
    return webroot, logs, dump


def build(target: Path, replace: bool) -> Path:
    target = target.resolve()
    if target.exists():
        if not replace:
            raise SystemExit(f"{target} already exists; pass --replace to rebuild it")
        if target.name != "docs-preview" or not (target / MARKER).is_file():
            raise SystemExit(
                "--replace only removes a docs-preview directory created by this tool")
        shutil.rmtree(target)
    target.mkdir(parents=True)
    (target / MARKER).write_text("synthetic documentation fixture\n", encoding="utf-8")

    webroot, logs, dump = _write_evidence(target)
    case_dir = workspace.create_case(target, CASE_NAME, CASE_REFERENCE,
                                     "Invented evidence for documentation only.")
    conn = db.connect(case_dir)
    try:
        rows = (
            ("webroot", webroot, "Synthetic webroot"),
            ("access_logs", logs, "Synthetic access logs"),
            ("sql_dump", dump, "Synthetic CMS export"),
        )
        for kind, path, label in rows:
            conn.execute(
                "INSERT INTO evidence (kind, path, added, label) VALUES (?,?,?,?)",
                (kind, str(path), db.now(), label),
            )
        conn.commit()
    finally:
        conn.close()

    stats = {
        "webshell": webshell.scan(case_dir, [str(webroot)], workspace=target),
        "cms": cmsinventory.scan(case_dir, [str(webroot)]),
        "index_logs": logindex.build(case_dir, [str(logs)], workspace=target),
        "sqldb": sqldump.scan(case_dir, [str(dump)], workspace=target),
    }

    shell = webroot / "wp-content" / "uploads" / "2026" / "01" / "kb-media.php"
    conn = db.connect(case_dir)
    try:
        now = db.now()
        conn.execute("UPDATE findings SET triage='reviewed', triage_note=?",
                     ("Reviewed in the synthetic documentation fixture.",))
        conn.execute(
            "UPDATE findings SET triage='confirmed', triage_note=? "
            "WHERE artifact IN (?,?)",
            ("Synthetic evidence correlates the file and reserved test client.",
             str(shell), "203.0.113.42"),
        )
        undecided = conn.execute(
            "SELECT DISTINCT artifact FROM findings WHERE triage='reviewed' LIMIT 3"
        ).fetchall()
        for row in undecided:
            conn.execute("UPDATE findings SET triage='new', triage_note='' WHERE artifact=?",
                         (row[0],))

        for kind, result in stats.items():
            conn.execute(
                "INSERT INTO jobs (kind,state,progress,message,created,started,finished,stats,run_id) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (kind, "done", 1, "Synthetic documentation run", now, now, now,
                 json.dumps(result), RUN_ID),
            )
        conn.execute("UPDATE evidence SET scanned_at=?, stats=?",
                     (now, json.dumps({"fixture": "synthetic"})))

        path_id = db.add_ioc(conn, "wp-content/uploads/2026/01/kb-media.php", "path",
                             ("confirmed", "synthetic"), "Synthetic confirmed file",
                             "Documentation fixture")
        hash_id = db.add_ioc(conn, hashlib.sha256(shell.read_bytes()).hexdigest(), "hash",
                             ("sha256", "synthetic"), "Hash of synthetic probe",
                             "Documentation fixture")
        client_id = db.add_ioc(conn, "203.0.113.42", "ip",
                               ("reserved", "synthetic"), "RFC 5737 test address",
                               "Documentation fixture")
        db.link_iocs(conn, path_id, hash_id, "hash-of")
        db.link_iocs(conn, client_id, path_id, "requested")
        conn.commit()
    finally:
        conn.close()

    print(case_dir.name)
    return case_dir


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path)
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    build(args.target, args.replace)


if __name__ == "__main__":
    main()
