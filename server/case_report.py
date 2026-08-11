"""Self-contained, printable HTML report assembled only from case facts."""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from datetime import datetime, timezone
from html import escape
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from server import coverage, db, iocs as ioclib, workspace
from server.artifacts import web_path
from server.chain import case_chain


WORDS = {
    "en": {
        "report": "Case report", "generated": "Generated", "reference": "Reference",
        "notes": "Case notes", "findings": "Findings", "artifacts": "Artifacts",
        "confirmed": "Confirmed", "iocs": "Indicators", "evidence": "Evidence inventory",
        "source": "Source", "kind": "Kind", "files": "Files", "bytes": "Bytes",
        "scanned": "Last analysed", "partial": "partial count",
        "no_hash": "Source paths are omitted. This version does not record evidence-source hashes.",
        "decisions": "Confirmed artifacts", "artifact": "Artifact", "severity": "Severity",
        "rules": "Rules", "decision_note": "Decision note", "chronology": "Chronology",
        "time": "Time", "event": "Event", "detail": "Detail", "limitations": "Limits and gaps",
        "indicators": "IOC box", "type": "Type", "value": "Value", "tags": "Tags",
        "origin": "Origin", "related": "Related", "hunts": "Pattern hunts",
        "pattern": "Pattern", "ran": "Run at", "hits": "Hits", "clients": "Clients",
        "cross": "Matches in other open cases", "case": "Case", "none": "None",
        "zone": "Time reading", "tool": "SHELLHOUND version",
        "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO",
    },
    "de": {
        "report": "Fallbericht", "generated": "Erstellt", "reference": "Referenz",
        "notes": "Fallnotizen", "findings": "Findings", "artifacts": "Artefakte",
        "confirmed": "Bestätigt", "iocs": "Indikatoren", "evidence": "Evidence-Inventar",
        "source": "Quelle", "kind": "Art", "files": "Dateien", "bytes": "Bytes",
        "scanned": "Zuletzt analysiert", "partial": "Teilzählung",
        "no_hash": "Quellpfade werden ausgelassen. Diese Version speichert keine Hashes der Evidence-Quellen.",
        "decisions": "Bestätigte Artefakte", "artifact": "Artefakt", "severity": "Schwere",
        "rules": "Regeln", "decision_note": "Entscheidungsnotiz", "chronology": "Chronologie",
        "time": "Zeit", "event": "Ereignis", "detail": "Detail", "limitations": "Grenzen und Lücken",
        "indicators": "IOC Box", "type": "Typ", "value": "Wert", "tags": "Tags",
        "origin": "Herkunft", "related": "Verknüpft", "hunts": "Muster-Jagden",
        "pattern": "Muster", "ran": "Ausgeführt", "hits": "Treffer", "clients": "Clients",
        "cross": "Treffer in anderen offenen Fällen", "case": "Fall", "none": "Keine",
        "zone": "Zeitdarstellung", "tool": "SHELLHOUND-Version",
        "high": "HOCH", "medium": "MITTEL", "low": "NIEDRIG", "info": "INFO",
    },
}


def _tool_version() -> str:
    try:
        return version("shellhound")
    except PackageNotFoundError:
        return "development"


def _e(value) -> str:
    return escape("" if value is None else str(value), quote=True)


def _fmt_bytes(value) -> str:
    size = float(value or 0)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return "0 B"


def _fmt_event_time(value, zone) -> str:
    if not value:
        return "—"
    stamp = datetime.fromtimestamp(int(value), timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S")
    return f"{stamp} {zone}".strip()


def _redactor(roots):
    variants = []
    for root in roots:
        text = str(root or "").rstrip("/\\")
        if text:
            variants.extend((text, text.replace("\\", "/"), text.replace("/", "\\")))
    variants = sorted(set(variants), key=len, reverse=True)

    def redact(value):
        text = "" if value is None else str(value)
        for root in variants:
            text = text.replace(root, "[evidence]")
        return text
    return redact


def collect(case_dir: Path, lang="en", tz_mode="log", cross_case=None) -> dict:
    """Collect report data without evidence content or analyst host paths."""
    lang = "de" if lang == "de" else "en"
    case_dir = Path(case_dir)
    info = workspace.case_info(case_dir)
    summary = workspace.case_summary(case_dir)
    conn = db.connect(case_dir)
    try:
        evidence = db.rows(
            conn, "SELECT id, kind, label, files, bytes, scanned_at, meta_partial "
                  "FROM evidence ORDER BY kind, id")
        redact = _redactor(db.evidence_roots(conn))
        findings = db.rows(
            conn, "SELECT artifact, artifact_kind, severity, rule, rule_id, "
                  "triage_note, triaged_at FROM findings WHERE triage = 'confirmed' "
                  "ORDER BY severity, artifact, id")
        grouped = OrderedDict()
        for finding in findings:
            key = (finding["artifact_kind"], finding["artifact"])
            item = grouped.setdefault(key, {
                "artifact": finding["artifact"], "kind": finding["artifact_kind"],
                "severity": finding["severity"], "rules": [], "notes": [],
                "triaged_at": finding["triaged_at"] or "",
            })
            item["severity"] = min(item["severity"], finding["severity"])
            rule = finding["rule"]
            if finding["rule_id"]:
                rule += f" [{finding['rule_id']}]"
            if rule not in item["rules"]:
                item["rules"].append(rule)
            if finding["triage_note"] and finding["triage_note"] not in item["notes"]:
                item["notes"].append(finding["triage_note"])
        decisions = []
        for item in grouped.values():
            if item["kind"] == "file":
                item["artifact"] = web_path(conn, item["artifact"])
            item["artifact"] = redact(item["artifact"])
            item["rules"] = [redact(rule) for rule in item["rules"]]
            item["notes"] = [redact(note) for note in item["notes"]]
            decisions.append(item)

        iocs = db.rows(conn, "SELECT * FROM iocs ORDER BY type, value")
        by_ioc = {}
        for link in db.ioc_links(conn):
            forward, back = ioclib.LINK_LABELS.get(
                link["kind"], (link["kind"], link["kind"]))
            by_ioc.setdefault(link["src_id"], []).append(
                f"{forward} {redact(link['dst_value'])}")
            by_ioc.setdefault(link["dst_id"], []).append(
                f"{back} {redact(link['src_value'])}")
        for ioc in iocs:
            if ioc["type"] == "path":
                ioc["value"] = db.case_relative_path(conn, ioc["value"])
            ioc["value"] = redact(ioc["value"])
            ioc["note"] = redact(ioc["note"])
            ioc["origin"] = redact(ioc["origin"])
            try:
                ioc["tags"] = json.loads(ioc["tags"] or "[]")
            except (TypeError, ValueError):
                ioc["tags"] = []
            ioc["related"] = by_ioc.get(ioc["id"], [])
        hunts = db.rows(conn, "SELECT * FROM hunt_runs ORDER BY ran_at, pattern")
    finally:
        conn.close()

    chain = case_chain(case_dir, lang, tz_mode)
    for event in chain.get("events") or []:
        for field in ("artifact", "title", "detail"):
            event[field] = redact(event.get(field))
    for item in chain.get("undated") or []:
        item["artifact"] = redact(item.get("artifact"))
        item["artifact_rel"] = redact(item.get("artifact_rel"))
        item["why"] = redact(item.get("why"))
    chain["gaps"] = [redact(gap) for gap in chain.get("gaps") or []]
    cov = coverage.report(case_dir, lang, tz_mode)
    cov["notes"] = [redact(note) for note in cov.get("notes") or []]

    return {
        "info": info, "summary": summary, "evidence": evidence,
        "decisions": decisions, "iocs": iocs, "hunts": hunts,
        "chain": chain, "coverage": cov,
        "cross_case": cross_case or {}, "version": _tool_version(),
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "lang": lang,
    }


def _table(headers, rows, empty):
    if not rows:
        return f'<p class="quiet">{_e(empty)}</p>'
    head = "".join(f"<th>{_e(value)}</th>" for value in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
        for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def render(case_dir: Path, lang="en", tz_mode="log", cross_case=None) -> str:
    data = collect(case_dir, lang, tz_mode, cross_case)
    w = WORDS[data["lang"]]
    info, summary = data["info"], data["summary"]
    severity = (w["high"], w["medium"], w["low"], w["info"])
    chain = data["chain"]
    zone = (chain.get("zone") or ", ".join(chain.get("tz_offsets") or [])
            or "source local time")

    evidence_rows = []
    for index, item in enumerate(data["evidence"], 1):
        label = item.get("label") or f"{item['kind']} {index}"
        scanned = item.get("scanned_at") or "—"
        if item.get("meta_partial"):
            scanned += f" ({w['partial']})"
        evidence_rows.append((_e(label), _e(item["kind"]),
                              _e(item.get("files") or 0),
                              _e(_fmt_bytes(item.get("bytes"))), _e(scanned)))
    decision_rows = [(
        _e(item["artifact"]), _e(item["kind"]),
        _e(severity[min(max(int(item["severity"]), 0), 3)]),
        _e("; ".join(item["rules"])), _e("; ".join(item["notes"]) or "—"),
    ) for item in data["decisions"]]
    event_rows = [(
        _e(_fmt_event_time(event["at"], zone)), _e(event["title"]),
        _e(event.get("detail") or "—"), _e(event.get("source") or ""),
    ) for event in chain["events"]]
    ioc_rows = [(
        _e(ioc["value"]), _e(ioc["type"]), _e(" ".join(ioc["tags"])),
        _e(ioc["note"] or "—"), _e(ioc["origin"] or "—"),
        _e("; ".join(ioc["related"]) or "—"),
    ) for ioc in data["iocs"]]
    hunt_rows = [(
        _e(hunt["label"] or hunt["pattern"]), _e(hunt["ran_at"]),
        _e(hunt["hits"]), _e(hunt["clients"]),
    ) for hunt in data["hunts"]]

    limitations = list(data["coverage"].get("notes") or []) + list(chain.get("gaps") or [])
    limitations.extend(
        f"{item['artifact']}: {item['why']}" for item in chain.get("undated") or [])
    if limitations:
        limitations_html = "<ul>" + "".join(
            f"<li>{_e(item)}</li>" for item in limitations) + "</ul>"
    else:
        limitations_html = f'<p class="quiet">{_e(w["none"])}</p>'

    cross_rows = []
    for entry in (data["cross_case"].get("entries") or []):
        for match in entry["matches"]:
            cross_rows.append((_e(entry["value"]), _e(entry["type"]),
                               _e(match["name"]),
                               _e(match.get("reference") or "—")))

    cards = ((w["findings"], summary["findings"]),
             (w["artifacts"], summary["artifacts"]),
             (w["confirmed"], summary["confirmed"]),
             (w["iocs"], summary["iocs"]))
    card_html = "".join(
        f'<div class="card"><strong>{_e(value)}</strong><span>{_e(label)}</span></div>'
        for label, value in cards)
    case_notes = _e(info.get("notes") or "—").replace("\n", "<br>")

    return f'''<!doctype html>
<html lang="{data["lang"]}"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(info["name"])} — SHELLHOUND</title><style>
:root{{--ink:#17202a;--muted:#64748b;--line:#d8dee7;--soft:#f4f7fa;--accent:#275d92}}
*{{box-sizing:border-box}} body{{margin:0 auto;max-width:1180px;padding:42px;color:var(--ink);font:14px/1.5 system-ui,sans-serif}}
h1{{margin:0;font-size:30px}} h2{{margin:32px 0 10px;border-bottom:2px solid var(--accent);padding-bottom:5px;font-size:18px}}
.meta,.quiet{{color:var(--muted)}} .cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:22px 0}}
.card{{border:1px solid var(--line);border-radius:8px;padding:12px;background:var(--soft)}} .card strong{{display:block;font-size:22px}} .card span{{color:var(--muted)}}
table{{width:100%;border-collapse:collapse;font-size:12px}} th,td{{border:1px solid var(--line);padding:7px;vertical-align:top;text-align:left;overflow-wrap:anywhere}} th{{background:var(--soft)}}
ul{{padding-left:22px}} code{{font-family:ui-monospace,monospace}} footer{{margin-top:38px;border-top:1px solid var(--line);padding-top:12px;color:var(--muted);font-size:11px}}
@media print{{body{{max-width:none;padding:12mm}} h2{{break-after:avoid}} tr{{break-inside:avoid}}}}
@media(max-width:700px){{body{{padding:18px}}.cards{{grid-template-columns:repeat(2,1fr)}}}}
</style></head><body>
<header><h1>{_e(info["name"])}</h1><div class="meta">{_e(w["report"])} · {_e(w["reference"])}: {_e(info.get("reference") or "—")} · {_e(w["generated"])}: {_e(data["generated"])}</div></header>
<div class="cards">{card_html}</div>
<h2>{_e(w["notes"])}</h2><p>{case_notes}</p>
<h2>{_e(w["evidence"])}</h2><p class="quiet">{_e(w["no_hash"])}</p>{_table((w["source"],w["kind"],w["files"],w["bytes"],w["scanned"]), evidence_rows, w["none"])}
<h2>{_e(w["decisions"])}</h2>{_table((w["artifact"],w["kind"],w["severity"],w["rules"],w["decision_note"]), decision_rows, w["none"])}
<h2>{_e(w["chronology"])}</h2><p class="quiet">{_e(w["zone"])}: {_e(zone)}</p>{_table((w["time"],w["event"],w["detail"],w["source"]), event_rows, w["none"])}
<h2>{_e(w["limitations"])}</h2>{limitations_html}
<h2>{_e(w["indicators"])}</h2>{_table((w["value"],w["type"],w["tags"],w["notes"],w["origin"],w["related"]), ioc_rows, w["none"])}
<h2>{_e(w["hunts"])}</h2>{_table((w["pattern"],w["ran"],w["hits"],w["clients"]), hunt_rows, w["none"])}
<h2>{_e(w["cross"])}</h2>{_table((w["value"],w["type"],w["case"],w["reference"]), cross_rows, w["none"])}
<footer>{_e(w["tool"])}: {_e(data["version"])} · SHA-256 is returned in the HTTP <code>X-Content-SHA256</code> header.</footer>
</body></html>'''


def render_bytes(case_dir: Path, lang="en", tz_mode="log", cross_case=None):
    body = render(case_dir, lang, tz_mode, cross_case).encode("utf-8")
    return body, hashlib.sha256(body).hexdigest()
