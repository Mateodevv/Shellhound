# SHELLHOUND

**Forensik-Werkbank für gehackte Webserver.** Du hast eine Kopie des
Webroots, die Access-Logs und einen Datenbank-Export — SHELLHOUND macht
daraus in wenigen Minuten eine Arbeitsliste, eine Chronologie und eine
IOC-Liste für den Bericht.

Läuft lokal auf deiner Forensik-Maschine. Kein Cloud-Dienst, kein Konto,
keine Telemetrie: die Beweismittel verlassen den Rechner nicht.

> **Sprache:** Oberfläche und Dokumentation sind auf Deutsch. Das ist eine
> bewusste Entscheidung für den deutschsprachigen DFIR-Alltag, kein
> Versehen. *The interface and docs are in German by design; see
> [SECURITY.md](SECURITY.md) for an English summary of the threat model.*

<!-- SCREENSHOT: Dashboard mit Chronologie und Log-Abdeckung -->

---

## In fünf Minuten loslegen

```bash
git clone https://github.com/Mateodevv/shellhound.git
cd shellhound
pip install -r requirements.txt
cd web && npm ci && npm run build && cd ..
python -m server.main
```

Der Browser öffnet sich auf `http://127.0.0.1:8710`. Fertig.

**Erst mal ausprobieren, ohne echten Fall?**

```bash
python tools/sample_case.py
python -m server.main --workspace ~/ShellhoundSample
```

Das baut einen vollständigen erfundenen Fall — Webroot mit WordPress und
Joomla, zwei Wochen Logs, ein Datenbank-Export — und lässt die *echten*
Engines darüber laufen. Was du danach siehst, hat die Erkennung wirklich
gefunden. Das Skript druckt am Ende einen Rundgang durch alle Ansichten.

---

## Der Ablauf eines Falls

### 1. Fall anlegen und Beweismittel eintragen

Neuer Case → unter **Evidence & Jobs** die Pfade eintragen. Vier Arten:

| Art | Was das ist |
|---|---|
| **Webroot** | Kopie des Web-Verzeichnisses. *Kopie, nicht das Live-System.* |
| **Access-Logs** | Apache/Nginx-Logs, auch `.gz`/`.bz2`, auch ein ganzer Ordner |
| **SQL-Dump** | Datenbank-Export des CMS (`mysqldump`, `.sql`/`.sql.gz`) |
| **Referenzkopie** | Ein bekannt sauberes CMS-Release derselben Version — optional, für den Datei-Vergleich |

Schneller geht es mit **„Fall-Ordner durchsuchen"**: Ordner angeben, und
SHELLHOUND schlägt vor, was es darin für Webroot, Logs und Dump hält.

<!-- SCREENSHOT: Evidence-Ansicht mit erkannten Kandidaten -->

### 2. Analysieren

Ein Klick startet alles parallel. Der Fortschritt läuft links unten mit.

- **Logs → Index.** Einmal indiziert, danach ist jede Frage eine
  Datenbank-Abfrage statt eines Log-Durchlaufs. ~55.000 Zeilen/s; ein
  2-GB-Log braucht rund zwei Minuten.
- **Webroot → Webshell-Scan + CMS-Inventar.** Regeln aus echten Fällen,
  inklusive der Unterscheidung „hat CMS-Startschutz" vs. „hat keinen".
- **SQL-Dump → eingeschleuster Code + Konten.** Streamend, GB-tauglich.

### 3. Findings durcharbeiten

**Entschieden wird über Artefakte, nicht über einzelne Findings.** Acht
Regeln auf einer abgelegten Shell sind acht Beobachtungen über *eine*
Datei — die Frage „gehört das zum Vorfall?" stellt sich einmal.

<!-- SCREENSHOT: Findings-Ansicht, Artefakte nach Kategorie gruppiert -->

Tastatur:

| Taste | Wirkung |
|---|---|
| `j` / `k` | nächstes / vorheriges Artefakt |
| `Enter` | Detail öffnen |
| `c` | **True Positive** — gehört zum Vorfall |
| `d` | **False Positive** |
| `r` | gesichtet, Entscheidung später |
| `x` | markieren (für Bulk-Aktionen) |

Das Detail-Fenster holt alles zusammen, was zur Entscheidung nötig ist:
Metadaten, Dateiinhalt (Raw und Hex), jede Regel mit ihrer Evidence, das
Verhalten des Clients — und jede IP daran direkt als Trace.

**True Positive tut mehr, als ein Häkchen zu setzen:** Pfad und SHA-256
wandern in die IOC Box, und die Clients, die genau diese Datei laut Log
geladen haben, werden **mitentschieden** — mit Vermerk, woraus, und mit
Rückgängig. Wer sie nur erfolglos angefragt hat, wird *vorgeschlagen* statt
entschieden. Eine Sondierung ins Leere ist etwas anderes als ein Zugriff.

<!-- SCREENSHOT: Artefakt-Detailfenster mit Dateiinhalt und Clients -->

**Filter blenden aus, sie wählen nicht aus.** Jeder Chip versteckt seine
Klasse, der nächste Klick holt sie zurück, mehrere stapeln sich. So
arbeitest du dich durch: Scanner weg, Low weg — übrig bleibt das
Unerklärte.

### 4. Actors: die Grundgesamtheit

Jede IP, die in den Logs vorkommt — auch die, auf die keine Regel
angesprochen hat. Mit Sparkline, Verhalten (Scanner, Brute-Force,
Shell-Zugriff), **Länderflagge** und der Dauer ihrer Aktivität.

<!-- SCREENSHOT: Actors-Liste mit Flaggen und Verhaltens-Badges -->

„Unauffällig" ausblenden lässt genau die Clients übrig, an denen etwas
dran ist. Beliebig viele markieren → **ein kombinierter Trace** in
Millisekunden.

Im Trace lässt sich filtern (URI, User-Agent, Statusklasse, Methode) und
sortieren, und wenn er aus einem Fund heraus geöffnet wurde, ist die
auslösende Zeile **rot markiert** — sonst sucht man sie unter tausenden.

### 5. Muster-Jagd: dein eigenes Wissen einbringen

Findings zeigen, was die *mitgelieferten* Regeln kennen. Hier hinterlegst
du, was **du** weißt: „diesen URL-Pfad ruft nur auf, wer diesen Exploit
fährt." Das Werkzeug sagt dir, wer ihn abgerufen hat.

```
option=com_jce&task=plugin          ← Muster (* ist Platzhalter)
/wp-content/uploads/*.php
```

Über jedem Ergebnis steht der Befund in einer Zeile: **wie viele Adressen
durchkamen** (nicht wie oft geklopft wurde), Anfragen und davon 2xx,
erster bis letzter Treffer mit Zeitspanne.

<!-- SCREENSHOT: Muster-Jagd mit Kennzahlen und Trefferliste -->

**Die Bibliothek gehört dem Workspace, nicht dem Fall** — einmal angelegt,
steht ein Muster in jedem weiteren Fall bereit. Der einzelne Fall
protokolliert nur, wonach gesucht wurde. Auch erfolglos: *„wir haben
darauf geprüft, es war nichts"* steht sonst nirgends und ist im Bericht
Gold wert.

### 6. Datenbank und Dateien

**Database** zeigt, was der Dump verrät: Konten mit benannten
Auffälligkeiten (kürzlich angelegt, schwacher Hash, offene Sitzung), den
eingeschleusten Code in Datenfeldern, das Tabellen-Inventar. Ein
untergeschobenes Konto nimmst du per Knopf als IOC auf — Login und E-Mail,
verknüpft.

**Dateien** lässt dich durch die Evidence klicken und markieren, was den
Regeln entgangen ist. Und wenn eine Referenzkopie eingetragen ist:
**der Webroot-Vergleich** — zusätzliche, veränderte und gelöschte Dateien.

<!-- SCREENSHOT: Webroot-Diff mit zusätzlich/verändert/fehlt -->

### 7. Die Chronologie

In der Fall-Zusammenfassung stehen die bestätigten Artefakte in ihrer
zeitlichen Abfolge — der erste Absatz deines Berichts.

<!-- SCREENSHOT: Chronologie mit Lücken und Herkunftsangaben -->

Sie **ordnet Gemessenes und behauptet keine Ursache.** An jeder Zeile
steht, ob die Zeit aus dem Log oder aus dem Datenbank-Export stammt;
welche Beobachtung aus welcher folgt, entscheidest du.

Dass eine Datei dalag, belegt ihr **erster erfolgreicher Abruf** — nicht
die mtime der Kopie, der niemand ansieht, ob sie vom Original stammt oder
vom Kopiervorgang. Lief davor eine Anfrage auf denselben Pfad ins Leere,
grenzt das die Entstehung ein: *„die Datei entstand zwischen 07-07 04:02
und 07-08 09:13"* ist eine rein gemessene Aussage.

**Lücken werden benannt, nicht überbrückt.** Ein bestätigtes Artefakt, für
das der Fall keine Zeit hergibt, steht gesondert darunter statt
stillschweigend zu fehlen.

Führen Log-Server und Datenbank-Server verschiedene Uhren, setzt du den
**Versatz** oben rechts — er wird gespeichert und in der Kette ausgewiesen.

### 8. IOC Box und Export

Alles Gesammelte, **mit seinen Beziehungen**: Hash ↔ Pfad, wer den Pfad
abgerufen hat, welche Domain in welchem eingeschleusten Code stand. Die
Kanten entstehen beim Einsammeln — von Hand verknüpfen gibt es bewusst
nicht.

<!-- SCREENSHOT: IOC Box mit aufgeklappten Verknüpfungen -->

Pfade sind **relativ zum Webroot** (`webroot/wp-content/…`), nie absolut —
sonst wandern deine VM-Pfade in den Bericht.

| Export | Wofür |
|---|---|
| **CSV** | Excel, Bericht, Passwort-Reset-Liste |
| **JSON** | eigene Skripte — enthält auch die Chronologie |
| **STIX 2.1** | SIEM und Threat-Intel, mit `relationship`-Objekten |

Der **Trace-Export** ist ein ZIP aus CSV und Manifest: Abfrage, Filter,
Zeilenzahl und SHA-256 samt Prüfbefehl. Damit ist er zitierfähig.

### 9. Fall abschließen

Packt alles in ein ZIP unter `<workspace>/archive/` und entfernt die
Arbeitskopie. Zurückholen über „Fall importieren" — auch auf einem anderen
Rechner.

---

## Praktisches

**Überall im Fall suchen:** `Strg`+`K` — Artefakte, Indikatoren, Actors,
Konten. Ein Treffer öffnet direkt das passende Fenster.

**Erklärungen:** Was ein Wert bedeutet, steht im Werkzeug. Ein `?` oder ein
Hover erklärt jede Kennzahl, jede Regel und jedes Abzeichen — inklusive
dessen, was es *nicht* aussagt.

**Länderflaggen** brauchen eine lokale GeoIP-Datenbank. Fehlt sie, bietet
das Dashboard an, die freie DB-IP Country Lite zu laden (mit Nachfrage —
es ist der einzige Netz-Kontakt des Werkzeugs). Alternativ eine `*.mmdb`
in den Workspace legen oder `SHELLHOUND_GEOIP` setzen.

**Wo liegen meine Fälle?** Unter `~/ShellhoundCases`, änderbar mit
`--workspace` oder `SHELLHOUND_WORKSPACE`. Ein Fall ist ein Ordner —
zippen heißt übergeben.

**Von einem anderen Rechner zugreifen?** Über einen SSH-Tunnel, nicht über
`--host 0.0.0.0`. Siehe [SECURITY.md](SECURITY.md).

---

## Arbeiten Sie sicher

Ein untersuchtes Webroot enthält **funktionsfähigen Angriffscode**.
SHELLHOUND führt nichts davon aus — es liest, hasht und zeigt an. Trotzdem:

- Isolierte VM, Snapshot vorher, kein Netzzugang.
- Immer mit einer **Kopie** arbeiten.
- **Virenscanner-Ausnahme für den Evidence-Ordner.** Sonst löscht er
  Beweismittel, ohne dass es jemand merkt — auf Windows reproduzierbar für
  Dateien mit bestimmten PHP-Mustern.

---

## Unter der Haube

```
<workspace>/       hunt_patterns.json (Muster-Bibliothek, fallübergreifend)
                   *.mmdb (GeoIP, optional)
  <fall>/          case.db + logindex.db (abgeleitet) + evidence/
server/            FastAPI + stdlib-SQLite
  engines/         accesslog, logindex, webshell, cmsinventory,
                   sqldump, webrootdiff, detect
web/               Vite + React + TypeScript + Tailwind
docs/rules.md      jede Detektionsregel: Auslöser, Aussage, Grenzen
```

Grundsätze, die überall gelten:

- **Ein Fall ist ein Ordner.** `logindex.db` ist abgeleitet und wird nicht
  archiviert.
- **Triage überlebt Re-Scans** — Fingerprints sind stabil.
- **„Verworfen" löscht nie.** Es bleibt sichtbar und filterbar, mit Notiz.
- **Alarme sind outcome-gated.** Ein Angriffsversuch, den der Server mit
  404 beantwortet hat, ist etwas anderes als einer mit 200.
- **Evidence wird nie ausgeliefert.** Findings tragen Text-Exzerpte;
  Dateiinhalte kommen als JSON-Daten, nie als Dokument, das der Browser
  ausführen könnte.
- **Ein gefiltertes Artefakt kommt immer vollständig.** Ein Filter darf nie
  einen Teil dessen verstecken, worauf eine Entscheidung beruht.

Entwicklung mit Hot Reload:

```bash
cd web && npm run dev            # Vite auf 5173, leitet /api und /ws weiter
python -m server.main --no-browser --token dev
# dann http://localhost:5173/?token=dev
```

---

## Mitmachen

Fehlerberichte und Pull Requests sind willkommen — für **Sicherheitslücken
bitte kein öffentliches Issue**, siehe [SECURITY.md](SECURITY.md).

**Niemals Daten aus einem echten Fall anhängen.** Kein Webroot, keine Logs,
keine Kunden-IPs. Beschreibe stattdessen die *Form* der Daten oder baue ein
Minimalbeispiel — `tools/sample_case.py` zeigt, wie das geht.

Neue Detektionsregeln gehören mit ihrer Begründung nach
[`docs/rules.md`](docs/rules.md): was sie auslöst, was sie aussagt und wo
sie danebenliegen kann.

---

## Lizenz

[Apache-2.0](LICENSE) — siehe [NOTICE](NOTICE) für die verwendeten
Drittanbieter-Komponenten.
