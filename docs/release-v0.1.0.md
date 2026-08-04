# SHELLHOUND 0.1.0

Erste öffentliche Veröffentlichung.

Lokale DFIR-Werkbank für kompromittierte Webserver (WordPress, Joomla).
Webroot-Kopie, Access-Logs und Datenbank-Export werden einmal indiziert;
danach ist jede Auswertung eine Datenbank-Abfrage. Läuft vollständig
offline auf der Analyse-Maschine.

## Funktionsumfang

- **Analyse** — Access-Log-Index (~55.000 Zeilen/s), 33 Detektionsregeln
  über Webroot, Datenbank-Export und Logs, CMS-Inventar mit
  Versionserkennung, Vergleich gegen eine saubere Referenzkopie
- **Triage** auf Artefakt-Ebene statt je Finding, mit Übernahme auf
  Clients, die eine bestätigte Datei laut Log geladen haben
- **Chronologie** der bestätigten Artefakte aus gemessenen Zeiten, mit
  Herkunftsangabe je Zeile und ausgewiesenen Lücken
- **Trace** beliebig vieler Clients mit Filter, Sortierung und
  Verlaufskurve
- **Muster-Jagd** mit fallübergreifender Musterbibliothek
- **IOC-Box** mit Beziehungen zwischen Indikatoren, Export als CSV, JSON
  und STIX 2.1
- **Länderzuordnung** von IP-Adressen aus einer lokalen GeoIP-Datenbank

Detektionsregeln sind in [`docs/rules.md`](docs/rules.md) mit Auslöser,
Aussage und Grenzen dokumentiert.

## Installation

```bash
git clone https://github.com/Mateodevv/shellhound.git
cd shellhound
pip install -r requirements.txt
cd web && npm ci && npm run build && cd ..
python -m server.main
```

Voraussetzungen: Python ≥ 3.10, Node ≥ 20. Ein Beispiel-Fall zum
Ausprobieren steht über `python tools/sample_case.py` bereit.

## Hinweise

- Einzelplatz-Werkzeug ohne Benutzerkonten und ohne TLS. Für den Zugriff
  von einem anderen Rechner ist ein SSH-Tunnel vorgesehen. Siehe
  [SECURITY.md](SECURITY.md).
- Der einzige ausgehende Netzwerkzugriff ist der optionale Download der
  GeoIP-Länderdatenbank nach ausdrücklicher Bestätigung; Falldaten werden
  dabei nicht übertragen.
- Oberfläche und Dokumentation sind auf Deutsch.

## Bekannte Einschränkungen

- Zugeschnitten auf WordPress und Joomla. Andere CMS werden gelesen, aber
  ohne Inventar und ohne CMS-spezifische Regeln.
- Kein Bericht-Generator; Chronologie, IOCs und Begründungen liegen vor,
  die Ausformulierung erfolgt manuell.
- Indikatoren sind fallgebunden. Ein Abgleich über mehrere Fälle hinweg
  ist nicht enthalten.
- CI deckt Linux und Windows ab. macOS ist ungetestet.

## Lizenz

[Apache-2.0](LICENSE). Drittanbieter-Komponenten: [NOTICE](NOTICE).

---

## English

SHELLHOUND is a local DFIR workbench for compromised webservers
(WordPress, Joomla). It indexes a webroot copy, access logs and a database
dump once, then answers queries against that index: artifact-level triage,
a timeline built from measured timestamps, and IOC export as CSV, JSON or
STIX 2.1.

It runs entirely offline. The only outbound request is an optional GeoIP
database download, performed after explicit confirmation and without
transmitting case data.

Interface and documentation are in German by design. See
[SECURITY.md](SECURITY.md) for an English summary of the threat model.
This is a single-user tool without accounts or TLS; use an SSH tunnel for
remote access.
