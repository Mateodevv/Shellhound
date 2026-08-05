# SHELLHOUND

Lokale DFIR-Werkbank für kompromittierte Webserver (WordPress, Joomla).

Webroot-Kopie, Access-Logs und Datenbank-Export werden einmal indiziert.
Danach ist jede Auswertung eine Datenbank-Abfrage: Triage über Artefakte,
Chronologie aus gemessenen Zeiten, IOC-Export als CSV, JSON oder STIX 2.1.

Läuft vollständig offline auf der Analyse-Maschine. Kein Dienst, kein
Konto, keine Telemetrie.

> Oberfläche und Dokumentation sind auf Deutsch. *The interface and
> documentation are in German by design; see [SECURITY.md](SECURITY.md)
> for an English summary.*

<!-- SCREENSHOT: Dashboard mit Chronologie und Log-Abdeckung -->

## Installation

Voraussetzungen: Python ≥ 3.10, Node ≥ 20.

```bash
git clone https://github.com/Mateodevv/shellhound.git
cd shellhound
pip install -r requirements.txt
cd web && npm ci && npm run build && cd ..
python -m server.main
```

Die Oberfläche öffnet sich auf `http://127.0.0.1:8710`.

## Funktionsumfang

**Analyse**

- Access-Log-Index mit rund 55.000 Zeilen/s, GB-tauglich
- 33 Detektionsregeln über Webroot, Datenbank-Export und Logs, dokumentiert
  in [`docs/rules.md`](docs/rules.md)
- CMS-Inventar mit Versionserkennung und Quellenangabe
- Vergleich des Webroots gegen eine bekannt saubere Referenzkopie

**Auswertung**

- Triage auf Artefakt-Ebene statt je Finding
- Chronologie der bestätigten Artefakte, ausschließlich aus gemessenen
  Zeiten
- Trace beliebig vieler Clients mit Filter, Sortierung und Verlaufskurve
- Muster-Jagd: eigene URL-Muster, fallübergreifend gespeichert
- Länderzuordnung von IP-Adressen aus einer lokalen GeoIP-Datenbank
- Volltextsuche über den Fall (<kbd>Strg</kbd>+<kbd>K</kbd>)

**Ausgabe**

- IOC-Box mit Beziehungen zwischen Indikatoren
- Export als CSV, JSON und STIX 2.1
- Trace-Export als ZIP mit Manifest und SHA-256
- Fall-Archivierung als ZIP

## Verwendung

### Beweismittel registrieren

Unter *Evidence & Jobs* die Pfade eintragen:

| Art | Inhalt |
|---|---|
| Webroot | Kopie des Web-Verzeichnisses |
| Access-Logs | Apache- oder Nginx-Logs, auch komprimiert |
| SQL-Dump | Datenbank-Export des CMS |
| Referenzkopie | Sauberes CMS-Release derselben Version (optional) |

Alternativ durchsucht *Fall-Ordner durchsuchen* ein Verzeichnis und schlägt
Kandidaten vor.

<!-- SCREENSHOT: Evidence-Ansicht mit erkannten Kandidaten -->

### Triage

Entschieden wird über das Artefakt, nicht über einzelne Findings. Mehrere
Regeln auf derselben Datei sind Beobachtungen zu einem Objekt.

| Taste | Funktion |
|---|---|
| <kbd>j</kbd> / <kbd>k</kbd> | Nächstes / vorheriges Artefakt |
| <kbd>Enter</kbd> | Detailfenster |
| <kbd>c</kbd> | True Positive |
| <kbd>d</kbd> | False Positive |
| <kbd>r</kbd> | Gesichtet |
| <kbd>x</kbd> | Markieren |

Ein True Positive überträgt Pfad und SHA-256 in die IOC-Box und entscheidet
Clients mit, die die Datei laut Log geladen haben. Clients mit erfolglosen
Anfragen werden vorgeschlagen, nicht entschieden.

<!-- SCREENSHOT: Findings-Ansicht mit gruppierten Artefakten -->
<!-- SCREENSHOT: Artefakt-Detailfenster mit Dateiinhalt und Clients -->

### Weitere Ansichten

- **Actors** — alle Clients aus den Logs mit Verhalten, Länderflagge und
  Aktivitätsdauer. Mehrfachauswahl ergibt einen kombinierten Trace.
- **Muster-Jagd** — hinterlegte URL-Muster gegen den Log-Index. Kennzahlen
  je Suche, Protokoll auch erfolgloser Läufe.
- **Database** — Konten mit benannten Auffälligkeiten, eingeschleuster Code
  in Datenfeldern, Tabellen-Inventar.
- **Dateien** — Evidence durchsuchen, Dateien manuell als IOC aufnehmen,
  Vergleich gegen die Referenzkopie.
- **IOC Box** — gesammelte Indikatoren mit Verknüpfungen und Export.

<!-- SCREENSHOT: Actors-Liste mit Flaggen und Verhaltens-Badges -->
<!-- SCREENSHOT: Muster-Jagd mit Kennzahlen und Trefferliste -->
<!-- SCREENSHOT: Webroot-Diff mit zusätzlich/verändert/fehlt -->
<!-- SCREENSHOT: IOC Box mit aufgeklappten Verknüpfungen -->

### Chronologie

Die bestätigten Artefakte in zeitlicher Abfolge. Jede Zeile nennt ihre
Quelle (Access-Log oder Datenbank-Export). Die Chronologie ordnet gemessene
Beobachtungen und leitet keine Ursachen ab.

Der Zeitpunkt, zu dem eine Datei vorlag, wird über ihren ersten
erfolgreichen Abruf belegt, nicht über die mtime der Kopie. Zeitliche Lücken
werden ausgewiesen. Abweichende Uhren zwischen Log- und Datenbankserver
lassen sich als Versatz je Quelle setzen; der Versatz wird gespeichert und
in der Chronologie vermerkt.

<!-- SCREENSHOT: Chronologie mit Lücken und Herkunftsangaben -->

## Konfiguration

| Option | Bedeutung |
|---|---|
| `--workspace PFAD` | Ablage der Fälle, Standard `~/ShellhoundCases` |
| `--port PORT` | Standard `8710` |
| `--host HOST` | Standard `127.0.0.1`; abweichende Bindung erfordert `--token` |
| `--token TOKEN` | Fester Zugriffstoken statt eines zufälligen je Start |
| `--no-browser` | Browser nicht automatisch öffnen |

Umgebungsvariablen: `SHELLHOUND_WORKSPACE`, `SHELLHOUND_GEOIP`.

Ein Fall ist ein Verzeichnis. `logindex.db` ist abgeleitet und wird nicht
archiviert.

## Sicherheit

SHELLHOUND ist ein Einzelplatz-Werkzeug ohne Benutzerkonten und ohne TLS.
Für den Zugriff von einem anderen Rechner ist ein SSH-Tunnel vorgesehen,
keine Bindung an `0.0.0.0`.

Der einzige ausgehende Netzwerkzugriff ist der optionale Download der
GeoIP-Länderdatenbank; er erfolgt nur nach ausdrücklicher Bestätigung und
überträgt keine Falldaten.

Untersuchtes Material enthält funktionsfähigen Angriffscode. Empfohlen sind
eine isolierte Maschine, ausschließlich Kopien der Originale und eine
Virenscanner-Ausnahme für das Evidence-Verzeichnis.

Vollständiges Bedrohungsmodell und Meldeweg für Schwachstellen:
[SECURITY.md](SECURITY.md).

## Architektur

```
<workspace>/       hunt_patterns.json, *.mmdb (optional)
  <fall>/          case.db, logindex.db (abgeleitet), evidence/
server/            FastAPI, SQLite aus der Standardbibliothek
  engines/         accesslog, logindex, webshell, cmsinventory,
                   sqldump, webrootdiff, detect
web/               Vite, React, TypeScript, Tailwind
docs/rules.md      Detektionsregeln mit Auslöser, Aussage und Grenzen
```

Grundsätze:

- Triage-Zustände überleben Re-Scans; Fingerprints sind stabil.
- Verworfene Findings werden nicht gelöscht, sondern bleiben filterbar.
- Log-Alarme sind outcome-gated: ein mit 404 beantworteter Angriffsversuch
  wird anders bewertet als ein erfolgreicher.
- Evidence wird nie ausgeliefert. Findings enthalten Text-Exzerpte,
  Dateiinhalte werden als JSON-Daten übertragen.
- Gefilterte Artefakte werden immer vollständig geliefert.

### Entwicklung

```bash
cd web && npm run dev
python -m server.main --no-browser --token dev
# http://localhost:5173/?token=dev
```

## Mitwirken

Fehlerberichte und Pull Requests sind willkommen. Schwachstellen bitte
nicht als öffentliches Issue melden, siehe [SECURITY.md](SECURITY.md).

Beiträge dürfen keine Daten aus realen Vorfällen enthalten. Für
Reproduktionen beschreibe stattdessen die Form der Daten oder baue ein
Minimalbeispiel. Neue Detektionsregeln gehören mit Auslöser, Aussage und
Grenzen nach [`docs/rules.md`](docs/rules.md) — und mit einem Test in
`tests/`, der belegt, dass sie anspringt.

Tests laufen ohne zusätzliche Abhängigkeiten:

```bash
python -m unittest discover -s tests -t .
```

Sie bauen ihre Beweismittel selbst: winzige, erfundene Dateien, von denen
jede genau eine Regel auslöst. Ein Fehlschlag benennt damit die kaputte
Regel, statt auf einen großen Datenklumpen zu zeigen.

## Lizenz

[Apache-2.0](LICENSE). Drittanbieter-Komponenten: [NOTICE](NOTICE).
