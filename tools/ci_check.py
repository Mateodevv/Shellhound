#!/usr/bin/env python3
"""Prüft, ob die Erkennung im Beispiel-Fall noch findet, was darin steckt.

    python tools/ci_check.py <workspace>

Der Beispiel-Fall (tools/sample_case.py) legt ECHTE Evidence an und lässt
die normalen Engines darüber laufen. Er erzählt eine bekannte Geschichte —
also lässt sich prüfen, ob sie noch erzählt wird. Das ist der billigste
End-to-End-Test, den dieses Projekt haben kann: er deckt Log-Index,
Webshell-Scan, CMS-Inventar und SQL-Dump in einem Lauf ab.

Die Erwartungen sind bewusst UNTERGRENZEN, keine exakten Zahlen. Eine neue
Regel, die zusätzlich anspringt, darf die CI nicht rot färben; eine Regel,
die aufhört zu finden, muss es."""
import sqlite3
import sys
from pathlib import Path


def fail(msg):
    print(f"  FEHLT: {msg}")
    return 1


def main():
    if len(sys.argv) < 2:
        print("usage: ci_check.py <workspace>")
        return 2
    workspace = Path(sys.argv[1]).expanduser()
    cases = [d for d in workspace.iterdir()
             if d.is_dir() and (d / "case.db").exists()]
    if not cases:
        print(f"Kein Fall in {workspace} gefunden.")
        return 1
    case = cases[0]
    print(f"Prüfe {case.name}")

    conn = sqlite3.connect(case / "case.db")
    conn.row_factory = sqlite3.Row
    bad = 0

    findings = conn.execute("SELECT count(*) FROM findings").fetchone()[0]
    artifacts = conn.execute(
        "SELECT count(DISTINCT artifact) FROM findings").fetchone()[0]
    print(f"  {findings} Findings auf {artifacts} Artefakten")
    if findings < 10:
        bad += fail(f"zu wenige Findings ({findings} < 10)")

    # Die abgelegte Shell -- der zentrale Fund des Beispiels.
    shell = conn.execute(
        "SELECT count(*) FROM findings WHERE artifact LIKE '%kb-media.php%'"
    ).fetchone()[0]
    print(f"  {shell} Finding(s) auf der abgelegten Shell")
    if shell < 1:
        bad += fail("die Webshell kb-media.php wurde nicht gefunden")

    # Jede Engine muss etwas beigetragen haben.
    sources = {r["source"] for r in conn.execute(
        "SELECT DISTINCT source FROM findings")}
    print(f"  Quellen: {', '.join(sorted(sources)) or '—'}")
    for needed in ("webshell", "logs", "sqldb"):
        if needed not in sources:
            bad += fail(f"keine Findings aus der Engine '{needed}'")

    # Das untergeschobene Admin-Konto aus dem Dump.
    admin = conn.execute(
        "SELECT count(*) FROM db_accounts WHERE admin = 1").fetchone()[0]
    accounts = conn.execute("SELECT count(*) FROM db_accounts").fetchone()[0]
    print(f"  {accounts} Konten, davon {admin} Administrator(en)")
    if admin < 2:
        bad += fail("das untergeschobene Admin-Konto fehlt")

    # Das CMS-Inventar.
    installs = conn.execute("SELECT count(*) FROM cms_installs").fetchone()[0]
    items = conn.execute("SELECT count(*) FROM cms_items").fetchone()[0]
    print(f"  {installs} CMS-Installation(en), {items} Erweiterung(en)")
    if installs < 1:
        bad += fail("kein CMS erkannt")

    conn.close()

    # Der Log-Index ist eine eigene Datenbank -- ohne ihn gibt es keine
    # Actors, keine Traces und keine Muster-Jagd.
    logdb = case / "logindex.db"
    if not logdb.exists():
        bad += fail("logindex.db wurde nicht gebaut")
    else:
        lc = sqlite3.connect(logdb)
        lines = lc.execute("SELECT count(*) FROM requests").fetchone()[0]
        clients = lc.execute("SELECT count(*) FROM actors").fetchone()[0]
        alerts = lc.execute("SELECT count(*) FROM alerts").fetchone()[0]
        lc.close()
        print(f"  Log-Index: {lines} Requests, {clients} Clients, {alerts} Alarme")
        if lines < 100:
            bad += fail(f"zu wenige indizierte Requests ({lines})")
        if alerts < 1:
            bad += fail("keine Log-Alarme — die Angriffsmuster fehlen")

    if bad:
        print(f"\n{bad} Prüfung(en) fehlgeschlagen.")
        return 1
    print("\nAlles gefunden, was im Beispiel-Fall steckt.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
