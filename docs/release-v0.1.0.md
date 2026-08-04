# SHELLHOUND 0.1.0

**Forensik-Werkbank für gehackte Webserver.** Du hast eine Kopie des
Webroots, die Access-Logs und einen Datenbank-Export — SHELLHOUND macht
daraus in wenigen Minuten eine Arbeitsliste, eine Chronologie und eine
IOC-Liste für den Bericht.

Läuft lokal auf deiner Forensik-Maschine. Kein Cloud-Dienst, kein Konto,
keine Telemetrie: die Beweismittel verlassen den Rechner nicht.

---

## Wofür

Nach einem Webserver-Einbruch stellt man immer dieselben Fragen, und
beantwortet sie immer wieder von Hand: *Was liegt da, das nicht dahin
gehört? Wer hat es abgerufen? Wann kam es dahin? Was muss in den Bericht?*

SHELLHOUND indiziert die Beweismittel **einmal** — danach ist jede dieser
Fragen eine Datenbank-Abfrage statt eines Log-Durchlaufs. Ein 2-GB-Log ist
in rund zwei Minuten durch; der Trace von zwanzig Clients steht danach
sofort.

## Was drin ist

**Triage über Artefakte, nicht über Findings.** Acht Regeln auf einer
abgelegten Shell sind acht Beobachtungen über *eine* Datei — die Frage
„gehört das zum Vorfall?" stellt sich einmal. Ein True Positive legt Pfad
und SHA-256 in die IOC Box und entscheidet die Clients mit, die die Datei
laut Log wirklich geladen haben. Wer sie nur erfolglos angefragt hat, wird
*vorgeschlagen* statt entschieden.

**33 Detektionsregeln** über Webroot, Datenbank-Export und Access-Logs —
jede in [`docs/rules.md`](docs/rules.md) mit Auslöser, Aussage **und
Grenzen** dokumentiert. Log-Alarme sind outcome-gated: ein Angriffsversuch
mit 404 ist etwas anderes als einer mit 200.

**Chronologie des Falls.** Die bestätigten Artefakte in ihrer zeitlichen
Abfolge — der erste Absatz deines Berichts. Sie ordnet Gemessenes und
behauptet keine Ursache: an jeder Zeile steht, ob die Zeit aus dem Log oder
aus dem Datenbank-Export stammt. Dass eine Datei dalag, belegt ihr erster
erfolgreicher Abruf, nicht die mtime der Kopie. Lücken werden benannt, nicht
überbrückt.

**Muster-Jagd.** Eigene URL-Muster hinterlegen („diesen Pfad ruft nur auf,
wer diesen Exploit fährt") — das Werkzeug sagt, wer sie abgerufen hat. Die
Bibliothek gehört dem Workspace: einmal angelegt, in jedem Fall verfügbar.
Auch erfolglose Suchen werden protokolliert; *„wir haben darauf geprüft, es
war nichts"* steht sonst nirgends.

**IOC Box mit Beziehungen.** Hash ↔ Pfad, wer den Pfad abgerufen hat, welche
Domain in welchem eingeschleusten Code stand. Export als CSV, JSON (inkl.
Chronologie) und **STIX 2.1** mit echten `relationship`-Objekten. Pfade sind
relativ zum Webroot — deine VM-Pfade wandern nicht in den Bericht.

**Webroot-Diff** gegen ein bekannt sauberes CMS-Release: zusätzliche,
veränderte und gelöschte Dateien. **Länderflaggen** an jeder IP, offline aus
einer lokalen Datenbank. **Zitierfähiger Trace-Export** als ZIP mit Manifest
und SHA-256. **Strg+K** sucht über den ganzen Fall.

## Loslegen

```bash
git clone https://github.com/Mateodevv/shellhound.git
cd shellhound
pip install -r requirements.txt
cd web && npm ci && npm run build && cd ..
python -m server.main
```

Öffnet `http://127.0.0.1:8710`.

**Ohne echten Fall ausprobieren:**

```bash
python tools/sample_case.py
python -m server.main --workspace ~/ShellhoundSample
```

Das baut einen vollständigen erfundenen Fall (WordPress + Joomla, zwei
Wochen Logs, ein Datenbank-Export) und lässt die **echten** Engines darüber
laufen. Was du danach siehst, hat die Erkennung wirklich gefunden — das
Beispiel ist zugleich der End-to-End-Test dieses Projekts und läuft in der
CI mit.

## Was du wissen musst

- **Einzelplatz-Werkzeug.** Keine Benutzerkonten, keine Rollen. Wer den
  Token hat, hat den vollen Fall. Bindet auf `127.0.0.1`; für Zugriff von
  einem anderen Rechner einen **SSH-Tunnel** benutzen, nicht
  `--host 0.0.0.0`. Details in [SECURITY.md](SECURITY.md).
- **Ein einziger Netz-Kontakt**, und nur auf ausdrücklichen Klick: der
  Download der GeoIP-Länderdatenbank. Ein Fenster fragt vorher; abgelehnt
  wird nichts geladen. Es gehen **keine Falldaten** hinaus.
- **Immer mit einer Kopie arbeiten**, auf einer isolierten Maschine. Und
  **den Evidence-Ordner beim Virenscanner ausnehmen** — sonst löscht er
  Beweismittel, ohne dass es jemand merkt.
- **Oberfläche und Dokumentation sind auf Deutsch.** Bewusste Entscheidung
  für den deutschsprachigen DFIR-Alltag.

## Grenzen dieser Fassung

- Auf **WordPress und Joomla** zugeschnitten. Andere CMS werden gelesen,
  aber ohne Inventar und ohne CMS-spezifische Regeln.
- Kein Bericht-Generator — die Bausteine (Chronologie, IOCs, Begründungen)
  sind da, das Zusammenschreiben ist Handarbeit.
- Indikatoren sind **fallgebunden**: „habe ich diese IP schon einmal
  gesehen?" über mehrere Fälle hinweg gibt es noch nicht.
- Entwickelt auf Windows, CI läuft auf Linux und Windows. Auf macOS
  ungetestet.

---

## Lizenz

[Apache-2.0](LICENSE). Drittanbieter-Komponenten und ihre Lizenzen stehen in
[NOTICE](NOTICE).

Sicherheitslücken bitte **nicht** als öffentliches Issue melden — Weg in
[SECURITY.md](SECURITY.md).

---

## In English

SHELLHOUND is a **local DFIR workbench for compromised webservers**
(WordPress/Joomla). Point it at a copy of the webroot, the access logs and a
database dump; it indexes everything once and turns that into a triage
worklist, a measured timeline and an IOC list you can export as CSV, JSON or
STIX 2.1.

Runs entirely on your own machine — no cloud, no account, no telemetry. It
makes exactly **one** outbound request in its lifetime, only on an explicit
click, to download the GeoIP country database; no case data ever leaves the
machine.

**The interface and documentation are in German by design.** See
[SECURITY.md](SECURITY.md) for an English summary of the threat model, and
be aware this is a single-user tool with no accounts or TLS — use an SSH
tunnel for remote access.
