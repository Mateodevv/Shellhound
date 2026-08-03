# Changelog

Alle nennenswerten Änderungen an SHELLHOUND. Format nach
[Keep a Changelog](https://keepachangelog.com/de/1.1.0/).

## [Unreleased]

### Geändert — Triage läuft über Artefakte, nicht über einzelne Findings

Die Einheit der Arbeit ist jetzt das **Artefakt**: diese Datei, dieser
Client, diese Tabelle. Acht Regeln auf einer abgelegten Shell sind acht
Beobachtungen über *eine* Datei — die Frage „gehört das zum Vorfall?" stellt
sich einmal. Vorher wurde jedes Finding einzeln entschieden; das erzeugte
Antworten, die einander widersprechen konnten, und eine Zahl, die den Fall
größer aussehen ließ, als er war („119 Findings" waren 14 Dateien).

- Die Findings-View listet **Artefakte** als Zeilen, gruppiert nach
  Kategorie. Die Findings eines Artefakts stehen aufgeklappt darunter — als
  Begründung, nicht als eigene Entscheidung.
- Markieren, Bulk-Aktionen und die Tastenkürzel (`c` True Positive, `d`
  False Positive, `r` gesichtet, `x` markieren, `Enter` Detail) wirken auf
  Artefakte.
- Filter, Chip-Zähler, Dashboard-Kacheln und die Fall-Zusammenfassung zählen
  Artefakte: Schweregrad ist der schwerste Fund des Artefakts, Triage seine
  Entscheidung. Die Zahl der Findings steht als Größenangabe daneben.
- Ein gefiltertes Artefakt kommt **immer vollständig** — auch bei einem
  Suchtreffer auf nur einer Regel. Ein Filter darf nichts verstecken, worauf
  eine Entscheidung beruht.
- `POST /api/cases/{slug}/triage` nimmt `artifacts`; `fingerprints` werden
  weiter akzeptiert und als Zeiger auf ihr Artefakt gelesen. Der frühere
  `cascade`-Schalter entfällt — Bestätigen und Verwerfen sind jetzt
  symmetrisch, weil beides über dasselbe entscheidet.
- Bestehende Fälle brauchen keine Migration: der Zustand eines Artefakts
  wird aus seinen Findings gefaltet (ein „bestätigt" gewinnt, „verworfen"
  zählt nur einstimmig), damit auch per-Finding triagierte Altfälle lesbar
  bleiben.

### Hinzugefügt

- **Artefakt-Detail** (`GET /api/cases/{slug}/artifact`): eine Antwort mit
  allem, was zur Entscheidung nötig ist — jede Regel mit Erklärung und
  Evidence, Dateimetadaten (Größe, mtime, SHA-256, CMS-Guard, Upload-Ordner),
  Dateiinhalt um die stärkste Fundstelle, Actor-Profil, Tabellen-/Dump-Fakten.
  Die Entscheidung samt Notiz steht oben im Drawer, nicht am Ende.
- **IPs als Traces**: `related_ips` sammelt jede Adresse, die an einem
  Artefakt hängt — wer die Datei angefragt hat, den Client selbst, Adressen
  aus der Evidence — mit dem Grund, warum sie dort steht, und dem Hinweis, ob
  sie schon in der IOC Box liegt. Jede öffnet direkt einen Trace, einzeln
  oder alle zusammen.
- Der Trace-Drawer ist eine geteilte Komponente (`components/TraceDrawer`)
  und damit überall verfügbar, wo eine IP steht — nicht mehr nur in Actors.

### Behoben

- **Der Datei-Viewer öffnete hinter der Detail-Ansicht.** Drawer haben jetzt
  Ebenen: was man aus einem Drawer heraus öffnet, liegt davor. `Escape`
  schließt nur den obersten, statt die ganze Kette abzuräumen.
- Ein bestätigtes Datei-Artefakt kam **ohne SHA-256** in die IOC Box, wenn
  der Hash nicht schon aus dem Scan vorlag — obwohl das Detail ihn anzeigte.
  Er wird jetzt an derselben Grenze (32 MB) nachberechnet.
- Die Sammel-Quittung nach dem Bestätigen zeigte denselben Indikator mehrfach,
  einmal je Regel des Artefakts.

### Entfernt

- Die Themes **Terminal**, **Ember** und **Arctic**. Es bleiben **Synthwave**
  (neuer Standard) und **Shellhound**. Ein gespeichertes Theme, das es nicht
  mehr gibt, fällt sauber auf den Standard zurück, statt `<html>` auf ein
  Theme ohne CSS-Block zu setzen.
- `GET /api/cases/{slug}/findings/{fingerprint}/context` — ersetzt durch das
  Artefakt-Detail.

## [0.1.0] — 2026-08-02

Erste Fassung: web-native DFIR-Workbench für Webserver-Kompromittierungen.
Fünf Views über einem Fall (Findings, Actors, IOC Box, CMS Inventory,
Database), Engines für Access-Log-Index, Webshell-Scan, CMS-Inventar und
SQL-Dump-Analyse, Fall-Archivierung als ZIP.
