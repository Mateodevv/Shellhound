# SHELLHOUND — web-native DFIR workbench

Forensik-Workbench für Webserver-Kompromittierungen (WordPress/Joomla).
Fünf Views über einem Fall: **Findings · Actors · IOC Box · CMS Inventory ·
Database** — gespeist von Engines, die jede Evidence **genau einmal**
indizieren. Traces und Suchen sind danach SQL-Abfragen, keine Log-Pässe.

## Start

```
pip install -r requirements.txt
cd web && npm install && npm run build && cd ..
python -m server.main
```

Der Browser öffnet sich auf `http://127.0.0.1:8710`. Workspace (Fall-Ordner)
liegt per Default unter `~/ShellhoundCases`, überschreibbar mit
`--workspace` oder `SHELLHOUND_WORKSPACE`.

## Workflow

1. **Case anlegen** → Evidence registrieren (Webroot-Kopie, Access-Logs,
   SQL-Dump) — oder einen Fall-Ordner automatisch durchsuchen lassen.
2. **Analysieren**: ein Klick startet die Pipeline
   - Access-Logs → `logindex.db` (interniert, Actor-Statistiken, Alerts —
     ~55k Zeilen/s, 2-GB-Logs in ~2 Minuten)
   - Webroot → Webshell-Scan (Regeln aus den echten Joomla-Fällen portiert,
     inkl. `_JEXEC`/`ABSPATH`-Guard-Diskriminator) + CMS-Inventar
   - SQL-Dump → Injected Code + Account-/Admin-Inventar (streamend, GB-tauglich)
3. **Triage** in den Findings (Tastatur: `j`/`k`, `c` bestätigen, `d` False
   Positive). Bestätigen legt Pfad + SHA-256 in die IOC Box und sammelt die
   Clients ein, die die Datei laut Index angefragt haben.
4. **Actors**: jeder Client mit Sparkline und Verhalten (Scanner, Brute-Force,
   Shell-Zugriff 2xx). Beliebig viele Clients markieren → kombinierter Trace
   in Millisekunden, Export als CSV.
5. **IOC Box** exportiert CSV / JSON / STIX 2.1.
6. **Fall abschließen** (Evidence & Jobs): packt den kompletten Fall in ein
   ZIP unter `<workspace>/archive/` und entfernt die Arbeitskopie — der Fall
   ist aus der Plattform raus. Zurückholen über „Fall importieren" auf der
   Startseite (aus dem Archiv-Ordner oder von einem beliebigen Pfad, z.B.
   einer Übergabe von einem anderen Rechner).

## Architektur

```
server/            FastAPI + stdlib-SQLite (pro Fall: case.db + logindex.db)
  engines/         accesslog, logindex, webshell, cmsinventory, sqldump, detect
web/               Vite + React + TS + Tailwind (Build wird vom Server serviert)
```

Grundsätze aus dem Legacy-Projekt, die strukturell übernommen sind: ein Fall
ist ein Ordner (zippen = übergeben; `logindex.db` ist derived und wird nicht
archiviert), Triage-Zustände haben stabile Fingerprints und überleben
Re-Scans, »dismissed« löscht nie, Probe-Alerts sind outcome-gated (2xx),
Evidence wird nie ausgeliefert — Findings tragen Text-Exzerpte.

Ein importiertes Archiv ist eine Datei von außen: das Entpacken weist
absolute Pfade und `..`-Traversal zurück (statt sie zu bereinigen) und
überschreibt nie einen bestehenden Fall — ein Slug-Konflikt landet unter
einem freien Namen.

Sicherheit: Bind auf `127.0.0.1`, Token auf jedem API-Call und WebSocket;
ein Nicht-Loopback-Bind erfordert ein explizites `--token`. Der Datei-Viewer
liest ausschließlich Pfade, die *aufgelöst* innerhalb einer registrierten
Evidence-Wurzel des Falls liegen, und liefert den Inhalt als JSON-Daten —
nie als Dokument, das der Browser parsen würde.

## Fall-Daten gehören nicht ins Repository

Dieses Werkzeug arbeitet mit echten Beweismitteln: Webroots mit
funktionsfähigen Webshells, Access-Logs mit Kunden- und Besucher-IPs,
Datenbank-Exporte mit Konten und E-Mail-Adressen. Nichts davon darf in die
Versionsverwaltung — die `.gitignore` ist entsprechend breit gefasst
(Fall-Ordner, `*.db`, `*.sql`, `*.log`, Archive, `.env`). Der Workspace liegt
per Default außerhalb des Projektverzeichnisses, damit ein `git add -A` gar
nicht erst in die Nähe von Fall-Daten kommt.

## Herkunft

Nachfolger von **shellhound-cli**, dem modularen Kommandozeilen-Toolkit
(stdlib-only). Die Detection-Regeln sind von dort portiert — sie wurden an
echten Joomla-Vorfällen auf Fehlalarme getrimmt und tragen diese Arbeit hier
weiter. Neu sind die Schale und das Datenmodell: Index-first statt
CSV-Austausch, eine Datenbank pro Fall statt Report-Dateien, fünf Views statt
vierzehn Module.
