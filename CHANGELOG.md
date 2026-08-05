# Changelog

Alle nennenswerten Änderungen an SHELLHOUND. Format nach
[Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionierung
nach [Semantic Versioning](https://semver.org/lang/de/).

## [Unreleased]

### Behoben — „database is locked" während einer laufenden Analyse

Jede geöffnete Datenbankverbindung schrieb, bevor der Aufrufer irgendetwas
wollte: `connect()` legte bedingungslos das Schema an und zog zwei
Datenkorrekturen nach (Scanner-Findings auf INFO herabstufen, IOC-Pfade
relativieren). Damit begann **jede Anfrage** mit einer Schreib-Transaktion
— auch eine rein lesende wie die Job-Liste, die die Oberfläche im
Sekundentakt abfragt, solange eine Analyse läuft.

Trifft diese Transaktion auf die Schreibsperre der arbeitenden Engine,
scheitert sie mit `sqlite3.OperationalError: database is locked` — als
Traceback im Server-Fenster und als fehlgeschlagene Anfrage in der
Oberfläche. Verschärfend: die Transaktion blieb offen, bis der Aufrufer
committete oder die Verbindung schloss; jede Leseanfrage hielt also
ihrerseits eine Schreibsperre.

- Das Fall-Schema trägt jetzt eine **Fassungsnummer** (`schema_version` in
  `meta`). Geschrieben wird nur, wenn sie abweicht: **einmal je Fall statt
  einmal je Anfrage**. Der Normalfall ist reines Lesen und kollidiert mit
  nichts.
- `PRAGMA busy_timeout` wird ausdrücklich gesetzt, damit eine belegte
  Sperre abgewartet statt sofort aufgegeben wird.
- Der Journal-Modus wird nur umgestellt, wenn er noch nicht auf WAL steht —
  der Wechsel verlangt kurz exklusiven Zugriff, das Auslesen nicht.
- Scheitert die Aktualisierung an einer Sperre, gilt sie als **Wartung**
  und wird vertagt: die laufende Anfrage wird davon nicht mitgerissen. Bei
  einer noch leeren Datei muss sie dagegen gelingen, dort wird der Fehler
  durchgereicht.

Bestehende Fälle brauchen nichts: sie stehen auf Fassung 0, werden beim
nächsten Öffnen einmal nachgezogen und danach gestempelt.

## [0.1.0] — 2026-08-05

**Erste öffentliche Veröffentlichung.**

Alles darunter ist die Entwicklung bis dahin — sie steht hier vollständig,
weil die Begründungen zu den Entscheidungen gehören. Ab dieser Fassung gibt
es ein LICENSE (Apache-2.0), eine SECURITY.md mit dem Bedrohungsmodell, ein
installierbares Paket (`pip install .`, Kommando `shellhound`) und CI, die
Linux und Windows mit Python 3.10 und 3.13 abdeckt.

### Hinzugefügt — Länderflaggen an IP-Adressen

Jede IP in Actors, Muster-Jagd, IOC Box, Trace, Artefakt-Fenster und
Chronologie trägt ihre Länderflagge — mit einem Tooltip, der sagt, was
GeoIP ist: **eine Schätzung der Registrierung, kein Aufenthaltsort.**
VPNs, Proxys, Tor und Botnetz-Knoten stehen woanders.

- **Vollständig offline.** Gelesen wird eine lokale MMDB aus dem Workspace
  (`SHELLHOUND_GEOIP` oder `*.mmdb` im Workspace-Ordner). Fall-IPs verlassen
  den Rechner nie.
- **Banner statt Suchen:** fehlt die Datenbank, sagt es ein Banner im
  Dashboard — wie beim fehlenden Evidence. Der Download startet nicht auf
  den ersten Klick: ein Bestätigungsfenster sagt vorher, **was gleich
  passiert** (eine Datei von download.db-ip.com, DB-IP Country Lite,
  CC BY 4.0, ~8 MB, keine Falldaten) — der einzige Netz-Kontakt des ganzen
  Werkzeugs, und wer auf einer abgeschotteten Maschine arbeitet, kann Nein
  sagen, bevor irgendetwas den Rechner verlässt. Alternativ eine
  GeoLite2-Country.mmdb von Hand hineinlegen. „Nicht mehr zeigen" bleibt
  gemerkt.
- **Sonderbereiche kommen ohne Datenbank:** private Netze (RFC 1918),
  Loopback, Dokumentations-Bereiche tragen ein gestricheltes Kürzel statt
  einer Flagge — im Log ist „die Quell-IP ist privat" oft die wichtigere
  Aussage als jedes Land (Proxy davor oder Verkehr aus dem eigenen Netz).
- Flaggen sind lokal gebündelte SVGs (flag-icons, MIT): Windows rendert
  Flaggen-Emojis nicht, und ein Forensik-Werkzeug lädt nichts von CDNs.
- Abfragen laufen gebündelt (ein Batch je Ansicht) gegen `POST /api/geo`,
  mit modulweitem Cache.

### Hinzugefügt — Webroot-Diff gegen eine Referenzkopie

Die klassische Handarbeit nach jedem Webserver-Vorfall, als Abfrage: das
kompromittierte Webroot neben ein bekannt sauberes Release derselben
CMS-Version legen und fragen, was abweicht.

- Neue Evidence-Art **Referenzkopie** — sie ist der Maßstab, nicht Evidence:
  die Engines scannen sie nicht.
- Der Vergleich läuft als Job (Dateien-Ansicht): **zusätzlich** (hier wohnen
  abgelegte Shells), **verändert** (eingeschleuster Code in legitimen
  Dateien, per Größe und SHA-256), **fehlt** (oft die Spur eines
  Aufräumversuchs). Gleiche Größe über der Hash-Grenze wird als
  **ungeprüft** gemeldet statt still als gleich durchgewunken.
- Jede Abweichung lässt sich ansehen und direkt als IOC flaggen; was schon
  in der Box liegt, trägt ein Abzeichen. Ein Treffer ist ein **Kandidat,
  kein Fund** — die Bewertung bleibt beim Analysten.

### Hinzugefügt — Globale Suche (Strg+K)

Ein Feld über den ganzen Fall: Artefakte, Indikatoren, Actors und Konten.
Ein Treffer öffnet das Artefakt-Fenster direkt — egal, welche Ansicht
gerade offen ist. Die Palette ist ein Sprungbrett, keine Ergebnisliste:
jede Gruppe ist hart gedeckelt, für mehr sind die Ansichten mit ihren
Filtern da.

### Hinzugefügt — Uhren-Abgleich Log ↔ Datenbank-Export

Log-Server und Datenbank-Server können verschiedene Uhren führen, und ein
Versatz kann die Reihenfolge der Chronologie drehen. Der Analyst kann je
Quelle einen Versatz setzen (am Chronologie-Kopf); er wird im Fall
gespeichert, auf alle Ketten-Zeiten angewendet und **in der Kette
ausgewiesen** — eine Aussage des Analysten, keine Vermutung des Werkzeugs.

### Geändert — Exporte belegen sich selbst

- Der **Trace-Export** ist jetzt ein ZIP aus `trace.csv` und `MANIFEST.txt`:
  Fall, Abfrage (Clients **und aktive Filter**), Zeilenzahl und SHA-256 der
  CSV samt Prüfbefehl. Damit ist er zitierfähig — jeder Empfänger kann die
  Unversehrtheit nachrechnen. Vorher ignorierte der Export die Filter der
  Ansicht.
- Der **JSON-Export** trägt die Chronologie mit (`chain`): Ereignisse,
  Lücken, undatierte Artefakte und gesetzte Uhren-Versätze. Die Reihenfolge
  ist die Aussage, die den Fall ausmacht — sie stand bisher nur im
  Dashboard.

### Aufgeräumt

- Verirrte leere `package-lock.json` aus dem Repo-Wurzelverzeichnis
  entfernt.
- Konstanten und Hooks aus Komponenten-Dateien gelöst
  (`artifactKinds.ts`, `useTriage.ts`, `copy.ts`) — oxlint ist wieder
  still, und Fast Refresh funktioniert überall.

### Hinzugefügt — Bedienbarkeit quer durch die Ansichten

- **IOC Box: Kopier-Knopf an jedem Indikator**, mit Quittung (Häkchen) und
  sichtbarem Fehlschlag (rotes ×). Der Rückfallweg über ein verstecktes
  Textfeld deckt den LAN-Bind ohne HTTPS ab, wo `navigator.clipboard` gar
  nicht existiert — vorher hätte der Knopf dort wortlos nichts getan. Die
  bestehenden Kopier-Knöpfe (Artefakt-Pfad, SHA-256, Datei-Viewer) nutzen
  denselben Weg.
- **Dauer-Spalte in Actors und Muster-Jagd**: erster bis letzter Treffer in
  einer Zeiteinheit („4 Minuten", „3 Tage"). 40 Aufrufe in zwei Minuten sind
  ein Werkzeuglauf, 40 über drei Wochen ein Dauergast — dieselbe Requestzahl
  bedeutet zweierlei. In der Muster-Jagd sortierbar.
- **Chronologie zuklappbar** (Zustand: offen), mit Zähler im Kopf.
- **Muster-Bibliothek zuklappbar**: sie wächst mit jedem Fall, und beim
  Auswerten will man die Ergebnisse sehen, nicht die Liste, aus der sie
  stammen.
- **Rogue-Konto als IOC** (Database): ein Knopf an jeder Konto-Zeile nimmt
  den **Login** in die Box (`user`, im STIX-Export als
  `user-account:account_login`) und die **E-Mail** als eigenen, verknüpften
  Eintrag (`account-of`-Kante). Die Bewertung bleibt beim Analysten — ein
  Dump kann nicht sagen, dass ein Admin bösartig ist, deshalb ist es ein
  Knopf und keine Regel. Bereits aufgenommene Konten zeigen ein Abzeichen
  statt des Knopfs.
- **Sichtbare Erklär-Punkte** überall dort, wo Tooltips bisher unsichtbar
  waren: Muster-Summary, Chronologie-Titel, IOC-Tags-Zeile, Dauer-Spalten.
  Ohne sichtbare Einladung hovert niemand über einer Kennzahl.

### Geändert — Database: Konten zuerst, Export-Summary erklärt sich

- **Eingeschleuster Code steht jetzt nach den Konten.** Wer diese Ansicht
  öffnet, sucht zuerst das untergeschobene Konto; der eingeschleuste Code ist
  der zweite Befund und liest sich erst richtig, wenn man weiß, wessen Konto
  ihn geschrieben haben könnte.
- **Die Summary des Exports** (Datenbank / Erstellt / Server / Werkzeug)
  erklärt jede Angabe statt nur einer: was sie ist und was sie für den Fall
  bedeutet — etwa dass das Export-Werkzeug bestimmt, was überhaupt im Dump
  steht (manche Backup-Plugins lassen Sitzungen oder Log-Tabellen weg).
  Ein Fragezeichen in jeder Kachel zeigt, dass es dort etwas zu lesen gibt;
  ohne diese Einladung hovert niemand über einer Kennzahl.

### Hinzugefügt — Chronologie des Falls

Jede Ansicht beantwortete „was": welche Datei, welcher Client, welches
Konto. Keine beantwortete **„in welcher Reihenfolge"** — und genau das ist
der erste Absatz jedes Berichts. Bisher tippte man ihn ab, indem man
zwischen Actors, Findings und Database hin- und hersprang und Zeitstempel im
Kopf sortierte.

Neu in der Fall-Zusammenfassung, keine sechste Ansicht daneben: die
Geschichte **ist** der Fall.

- **Sie ordnet gemessene Tatsachen und behauptet keine Ursache.** „09:12
  erste Anfrage dieser Adresse, 09:13 erster erfolgreicher Abruf der Shell"
  ist eine Beobachtung; „der Angreifer lud die Shell hoch" ist eine
  Schlussfolgerung — die gehört dem Analysten. An jeder Zeile steht, woraus
  die Zeit stammt (Access-Log oder Datenbank-Export).
- **Nur bestätigte Artefakte.** Die Triage entscheidet, was zur Geschichte
  gehört, nicht die Erkennung.
- **Der erste 2xx statt der mtime.** Dass eine Datei dalag, belegt der erste
  erfolgreiche Abruf — der mtime einer Kopie sieht niemand an, ob sie vom
  Original stammt oder vom Kopiervorgang. Lief davor eine Anfrage auf
  denselben Pfad ins Leere, grenzt das die Entstehung ein: „die Datei
  entstand zwischen 07-07 04:02 und 07-08 09:13" ist rein gemessen.
- **Konten**, deren Anlagedatum in den Log-Zeitraum fällt, stehen mit drin —
  das Fenster des Logs ist das ehrlichste, das der Fall dafür hat.
- **Lücken werden benannt, nicht überbrückt**: Abstände über einer Stunde
  stehen als „ohne belegte Beobachtung" in der Leiste, und ein bestätigtes
  Artefakt, für das der Fall keine Zeit hergibt (eine injizierte Tabelle
  etwa), erscheint unter „bestätigt, aber ohne Zeitbezug" statt stillschweigend
  zu verschwinden.
- Aus jeder Zeile lassen sich Artefakt-Fenster und Trace direkt öffnen.
- Beide Uhren stehen ohne Zone da — die Logzeile in ihrer Serverzeit, der
  Kontozeitstempel in der des Datenbankservers. Sie werden verglichen, wie
  sie dastehen; alles andere hieße, eine Zeitzone zu erfinden.

### Hinzugefügt — Kennzahlen je Muster-Suche

Die Muster-Jagd zeigte drei Zahlen in einer Zeile. Jetzt steht über jedem
Ergebnis, was in den Bericht wandert: **Adressen** (davon erfolgreiche),
**Anfragen** (davon 2xx), **erster und letzter Treffer** sowie die
**Zeitspanne** und die Zahl der getroffenen URLs.

- `ok_clients` ist die Zahl, die zählt: 300 Anfragen von 40 Adressen, von
  denen genau eine eine 2xx bekam, ist ein anderer Befund als 300 Anfragen
  mit 300 Erfolgen.
- Die Spanne trennt die einzelne Kampagne (Minuten) vom Hintergrundrauschen,
  das seit Monaten mitläuft.
- Die Zahl der getroffenen URLs war **falsch**: angezeigt wurde die Länge
  der gedeckelten Liste, also höchstens 50, auch wenn das Muster 3.000 URLs
  traf. Gerade diese Zahl soll verraten, dass ein Muster zu weit greift.
- `hunt_runs` speichert die Kennzahlen mit, damit das Protokoll ohne einen
  zweiten Lauf aussagt, was gefunden wurde.
- Die Kennzahlen stehen als **eine Zeile** statt als vier gleich große
  Kacheln: der Befund („1 von 2 Adressen kam durch") groß und farbig voran,
  die Belege dahinter im Fließtext. Vier gleich gewichtete Kästen gaben der
  entscheidenden Zahl dasselbe Gewicht wie der nebensächlichsten.
- Der **Zeitraum je Client** steht jetzt auf die Sekunde genau in zwei
  Spalten (erster / letzter Treffer) statt als Datum ohne Uhrzeit — bei einem
  Muster-Treffer sagt erst die Uhrzeit, ob die Aufrufe in einem Schwung kamen
  oder über Wochen verteilt.
- Die Trefferliste ist nach jeder Spalte **sortierbar**, Adressen numerisch
  (`192.0.2.9` vor `192.0.2.10`).

### Hinzugefügt — Indikatoren tragen ihre Beziehungen

Ein Hash und der Pfad, dessen Datei er beschreibt, entstehen im selben
Moment aus demselben Fund. Davon überlebte bisher nur ein Satz im
`origin`-Feld („sha-256 of kb-media.php"): gut lesbar, nicht auswertbar, und
im Export gar nicht vorhanden. Wer den Pfad später verwarf, ließ seinen Hash
verwaist stehen. Die IOC Box hielt eine flache Liste, obwohl die Daten eine
Kette hergeben — *diese IP rief diese Shell auf, die diesen Hash hat*.

- Neue Tabelle `ioc_links`. Drei Arten, alle **automatisch beim Einsammeln**:
  `hash-of` (Hash ↔ Pfad, aus dem Bestätigen und aus dem Datei-Browser),
  `requested` (Client ↔ abgerufener Pfad, mit Trefferzahl und 2xx-Anteil) und
  `host-in` (eingeschleuste Domain ↔ Fundort). Bestehende Fälle bekommen die
  Tabelle beim Öffnen; alte Einträge bleiben unverknüpft, weil die
  Zusammengehörigkeit nachträglich nicht mehr feststellbar ist.
- **Kein Verknüpfen von Hand.** Eine Kante, die der Analyst pflegen muss,
  wird nach dem dritten Fall nicht mehr gepflegt. Und sie trägt nur
  Information, wenn sie spezifisch ist — „gehört zum selben Fall" gilt für
  jedes Paar in der Box.
- Die Box zeigt sie am Eintrag: ein Zähler klappt die Nachbarn auf, jeder in
  der Leserichtung dieses Eintrags (am Pfad „hat den SHA-256", am Hash „ist
  der SHA-256 von"), Klick springt zum Nachbarn und hebt ihn kurz hervor.
  Keine eigene Ansicht und kein Graph: bei 40 Knoten aus einem Fall ist ein
  Graph hübsch und unlesbar.
- **Export.** CSV bekommt eine Spalte `Related`, JSON ein Feld `related`, und
  das STIX-Bundle echte `relationship`-Objekte — bisher empfing ein SIEM eine
  Handvoll unverbundener Indicators. Kanten auf Indikatoren ohne
  STIX-Pattern (Tabellennamen etwa) entfallen, statt das Bundle ungültig zu
  machen.
- Löschen räumt die Kanten mit ab.

### Behoben — IPs einsammeln scheiterte auf großen Fällen

`POST /actors/collect` (aus der Muster-Jagd und aus Actors) holte die
**gesamte** Actor-Tabelle, um darin die paar ausgewählten Adressen zu
suchen. Die Alarm-Abfrage darüber band eine SQL-Variable pro Client — auf
einem echten Fall mit zehntausenden Adressen brach das mit
`sqlite3.OperationalError: too many SQL variables` ab, und zwar schon beim
Aufnehmen einer **einzelnen** IP.

- Neu `logindex.actors_by_ip()`: schlägt gezielt die angefragten Adressen
  nach, in Blöcken von 500.
- Die Alarm- und Sparkline-Abfragen gehen durch dieselbe Blockbildung, damit
  eine datenabhängige Listenlänge das nicht wieder auslösen kann.
- Geprüft mit 3.185 Adressen in einem Aufruf: keine Ausnahme, echte
  Adressen behalten ihre Verhaltens-Tags.

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

### Geändert

- **IOC-Pfade sind fallrelativ statt absolut** (`webroot/images/shell.php`
  statt `D:/Arbeit/real-world-data/…/webroot/images/shell.php`). Der absolute
  Pfad beschreibt, wo die *Kopie* auf der Forensik-Maschine liegt — eine
  Angabe, die in einem Bericht niemandem hilft, auf einem anderen Rechner
  falsch ist und beim Export die eigene Verzeichnisstruktur mit hinausträgt.
  Der Name der Evidence-Wurzel bleibt enthalten, weil er sagt, um welche
  Evidence es geht. Gilt für die Bestätigungs-Kette *und* das manuelle
  Flaggen; **auch die Herkunft trägt keinen absoluten Pfad mehr**, und
  bestehende Einträge werden beim Öffnen des Falls mitgezogen (Konflikte
  bleiben unangetastet).
- **Reihenfolge im Menü:** IOC Box → Database → CMS Inventory → Dateien →
  Evidence & Jobs.

### Hinzugefügt

- **Beispiel-Fall zum Ausprobieren** (`tools/sample_case.py`): baut einen
  vollständigen erfundenen Fall — WordPress + Joomla im Webroot, zwei Wochen
  Access-Logs, ein Datenbank-Export — und lässt die **normalen Engines**
  darüber laufen. Nichts wird in die Datenbank geschrieben, was die Erkennung
  nicht selbst gefunden hat; das Beispiel ist damit zugleich ein
  End-to-End-Test. Der Fall erzählt eine Geschichte (Abklopfen → Shell
  abgelegt → benutzt, daneben Brute-Force und normaler Verkehr), sodass jede
  Ansicht etwas zu zeigen hat, und druckt am Ende einen Rundgang.
  Alle Adressen stammen aus den Dokumentations-Bereichen (RFC 5737), Domains
  enden auf `.test`, und die »Webshells« sind die kürzestmöglichen
  Prüfmuster — kein funktionsfähiges Werkzeug.
- In [`docs/rules.md`](docs/rules.md) dokumentiert, dass „could not be read"
  in der Praxis meist der **Virenscanner der Analyse-Maschine** ist: er
  blockiert den Zugriff auf genau die eindeutigsten Funde. Der Generator
  prüft seine eigenen Dateien nach dem Schreiben und sagt es, statt still
  einen halben Fall zu bauen.

- **Actors: „Unauffällig" ausblenden.** Der Chip entfernt genau die Zeilen,
  an denen „unauffällig" steht — die Bedingung spiegelt exakt die Regeln, die
  ein Abzeichen erzeugen. Übrig bleibt, woran etwas dran ist.
- **Der Trace markiert die auslösende Zeile rot** — überall, wo er aufgeht.
  Aus Actors sind das die Beispiel-URIs der Alarme, aus der Muster-Jagd die
  getroffenen URLs, und **aus dem Artefakt-Fenster die Zeilen, in denen das
  Artefakt aufgerufen wurde**: bei einer Datei ihr Pfad (Teilstring, weil die
  Query-Varianten dahinter nicht vorher bekannt sind), bei einem Client der
  Aufruf, der seinen Alarm ausgelöst hat. Eine Legende sagt jeweils, was
  markiert ist und warum. Ohne das sucht man den einen Aufruf, um den es
  geht, unter tausenden von Hand — im Beispielfall 32 markierte Zeilen unter
  52 beim Datei-Artefakt, 15 beim Client.
- **Einzelne Treffer-Adressen in die IOC Box**: neben dem Sammelknopf steht
  der Knopf jetzt auch an jeder Client-Zeile der Muster-Ergebnisse.
- **Dateien** (neuer Menüpunkt): durch die registrierte Evidence klicken und
  markieren, was den Regeln entgangen ist — die Datei, die am falschen Ort
  liegt, deren Name nicht passt, deren Änderungsdatum in die Nacht des
  Vorfalls fällt. Aufgenommen wird **Pfad und SHA-256**: der Pfad sagt, wo
  etwas auf diesem Server lag, der Hash erkennt dieselbe Datei überall
  wieder. Einzeln oder gesammelt, mit Notiz. Jeder Eintrag zeigt gleich, was
  der Fall über ihn schon weiß (Findings, bereits in der IOC Box), damit man
  nicht von Hand markiert, was längst erfasst ist. Man beginnt bei den
  Evidence-Wurzeln, und tiefer geht es nur innerhalb davon — dieselbe
  Schranke wie beim Datei-Viewer, auf dem *aufgelösten* Pfad.
- **Der Pfad-Dialog zeigt Dateien**, nicht nur Ordner — mit Größe und direkt
  auswählbar. Nicht jede Evidence ist ein Ordner: ein SQL-Dump ist eine
  einzelne Datei, und wer sie nicht sieht, kann sie nicht registrieren.
- **Muster lassen sich nachträglich bearbeiten** (Pfad, Name, Notiz). Die
  Änderung gilt für alle Fälle; bereits geschriebene Findings bleiben stehen
  — sie halten fest, was zum Zeitpunkt der Suche galt.
- **Treffer-Adressen gesammelt in die IOC Box**: ein Knopf je Muster-Ergebnis
  übernimmt alle gefundenen Clients, mit dem Muster als Herkunft — „hat den
  Exploit-Pfad abgerufen" ist die Angabe, die im Bericht zählt, nicht „aus
  einer Liste eingesammelt".
- **Der Verlauf zeigt jetzt drei Reihen:** Balken für alle Anfragen, dazu
  Kurven für die **beantworteten (2xx)** und die **abgewiesenen (4xx/5xx)**.
  Die Gesamtzahl sagt, wie viel los war; das Verhältnis sagt, *was* los war —
  500 Anfragen mit 20 Erfolgen sind ein Abklopfen, 500 mit 480 sind Betrieb,
  und eine Erfolgskurve, die mitten in einer Fehlerwelle nach oben geht, ist
  der Moment, in dem etwas funktioniert hat, das vorher nicht funktionierte.
  Dafür führt der Log-Index eine neue Spalte (`days.ok`, Schema 3) — **offene
  Fälle melden ihren Index als veraltet und wollen einmal neu gebaut werden.**
  Ohne Neubau fehlt nur die Erfolgskurve, nichts stürzt ab.
- **Der Trace bringt den Verlauf seiner Auswahl mit** — dieselbe Kurve, nur
  auf die getracten Clients eingeschränkt. Erst daran sieht man, ob 185
  Requests über zwei Wochen verteilt sind oder an einem Nachmittag passiert
  sind. Sie beschreibt immer den ganzen Zeitraum und ändert sich beim
  Blättern oder Filtern nicht.
- **Der Trace lässt sich filtern und sortieren:** Suche über URI und
  User-Agent, Statusklasse (2xx/3xx/4xx/5xx), HTTP-Methode (angeboten werden
  nur die vorkommenden), Sortierung nach Zeit (vorwärts/rückwärts), Status,
  Größe oder URI. Beides läuft in SQL über den ganzen Trace — eine Suche, die
  nur die angezeigten 500 Zeilen durchsucht, hätte alles davor und danach
  übersehen.
- Die Diagramme folgen dem **Theme** statt in fest verdrahtetem Blau zu
  stehen; 2xx trägt die OK-Farbe, Fehler die Warnfarbe — dieselbe Bedeutung
  wie überall sonst in der Oberfläche.

- **Muster-Jagd** (neuer Menüpunkt): eigene URL-Muster hinterlegen — die
  Aufrufe, die zu einem bekannten Exploit gehören — und das Werkzeug sagt,
  welche Clients sie abgerufen haben. Die Gegenrichtung zum Rest: nicht was
  die mitgelieferten Regeln finden, sondern was *du* suchst.
  - **Die Bibliothek gehört dem Workspace**, nicht dem Fall (`hunt_patterns.json`
    neben den Fällen): einmal angelegt, steht ein Muster in jedem weiteren
    Fall bereit. Als lesbares JSON, das zugleich das Austauschformat ist —
    Import (auch als einfache Zeilenliste mit `Muster | Name | Notiz`) und
    Export lesen dieselbe Datei.
  - **Treffer werden Findings** auf dem Client-Artefakt: mit 2xx beantwortet
    HIGH, reine Versuche LOW — damit laufen Triage, Übernahme auf Dateien
    und IOC-Sammlung unverändert weiter, statt eine zweite Arbeitsliste
    aufzumachen.
  - **Der Fall protokolliert auch die Fehlschläge** (`hunt_runs`): „wir haben
    darauf geprüft, es war nichts" steht sonst nirgends, weil Findings nur
    Funde festhalten.
  - Matching ist Teilstring mit `*` als Platzhalter, nicht Regex — was ein
    Muster trifft, muss man in einem Bericht erklären können. Die getroffenen
    URLs stehen im Ergebnis, damit ein zu weites Muster auffällt.
  - Läuft ohne Neu-Indizierung: das Muster wird gegen die *distinkten* URIs
    geprüft, die Requests holt der bestehende `leaf`-Index als Vorfilter.
    Bewusst **kein** Online-Abgleich gegen CVE-Datenbanken.

- **Eine Entscheidung wird nicht zweimal getroffen.** Wer eine Webshell als
  True Positive entscheidet, hat damit auch über die Clients entschieden, die
  sie geladen haben — bisher standen die als eigene Artefakte nochmal zur
  Bewertung an. Jetzt wandert die Entscheidung **einen Schritt** entlang
  dessen, was der Log-Index belegen kann, in beide Richtungen (Datei →
  Clients und Client → Dateien):
  - **stark** (der Client hat genau diese Datei geladen und 2xx bekommen):
    wird mitentschieden, mit Vermerk „übernommen: hat *x* geladen (n× 2xx)".
    Eine Meldung nennt jedes mitentschiedene Artefakt und bietet
    **Rückgängig** — das den Zustand von davor exakt wiederherstellt.
  - **mittel** (gleicher Pfad, nie erfolgreich): wird **vorgeschlagen**, nicht
    entschieden. Eine Sondierung ins Leere ist etwas anderes als ein Zugriff.
  - Von Hand vergebene Entscheidungen werden nie überschrieben, und die
    Übernahme geht genau einen Schritt weit — sonst stünde am Ende ein ganzer
    Fall auf einer einzigen Entscheidung.
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

- **Alle Detailansichten sind zentrierte Fenster** statt Drawer am Rand.
  Das Artefakt-Detail (1280 px) zweispaltig: links die Entscheidung mit
  Metadaten und jeder Regel, die angesprochen hat, rechts Dateiinhalt,
  Actor-Profil und die Clients — beurteilt wird aus dem Zusammenhang, und der
  entsteht nebeneinander, nicht untereinander. Unter 1024 px eine Spalte.
  Datei-Viewer und Trace ebenso; sie werden aus dem Artefakt-Fenster geöffnet
  und sind je Stufe etwas kleiner, damit sichtbar bleibt, wohin man
  zurückkommt. Die Drawer-Komponente entfällt.
- **Die Artefakt-Liste zeigt, worum es geht, ohne dass man sie öffnen muss:**
  Symbol und Farbe für Art und Schweregrad, die Regeln als Chips unter dem
  Namen, ein Balken für die Verteilung der Findings über die Schweregrade
  (viermal LOW ist ein anderes Bild als zweimal HIGH) und der Zustand als
  Pille. Kategorien tragen ein eigenes Symbol, einen nach rechts auslaufenden
  Farbverlauf in ihrem Schweregrad und einen Fortschrittsbalken „x von y
  entschieden".
- **Mitgelieferte SQL-Dateien verschütten den Export nicht mehr.** Ein
  Webroot enthält Dutzende `install.mysql.utf8.sql`, `uninstall…` und
  `updates/mysql/2.0.1.sql` — jede Erweiterung bringt ihre eigenen mit. Sie
  sind keine Datenbank-Exports (keine Daten, keine Konten, kein Kopf) und
  standen bisher gleichberechtigt neben dem einen echten Dump. Sie stehen
  jetzt zusammengefaltet in einer Zeile; erkannt am Joomla-Platzhalter-Präfix
  `#__`, der in einem `mysqldump` nie vorkommt, gestützt durch Pfad und
  Fehlen von Daten. Ihre Tabellen fluten auch das Inventar nicht mehr.
  **Gescannt werden sie weiter:** eine manipulierte `install.sql` läuft bei
  der nächsten Installation wieder an und überlebt jedes Aufräumen im
  Dateisystem — trägt eine Findings, steht das vorne an der Zeile.
- **Behoben: `#__`-Tabellen wurden gar nicht geparst.** Die Regex für
  Tabellennamen kannte kein `#`, womit `CREATE TABLE \`#__x\`` und
  `INSERT INTO \`#__x\`` durchfielen — eingeschleuster Code in genau diesen
  Dateien war für den Scanner unsichtbar.
- **Database neu aufgebaut.** Die Seite war ein Stapel aus vier
  unverbundenen Tabellen; sie beantwortet jetzt die Frage, wegen der man sie
  öffnet — was hat der Angreifer in der Datenbank hinterlassen?
  - Oben steht der **Export selbst**: Datenbankname, Server, Werkzeug und vor
    allem der **Erstellungszeitpunkt** — ein Dump von vor dem Vorfall zeigt
    einen anderen Zustand als einer von danach.
  - **Konten stehen nach Auffälligkeit**, mit benannten Beobachtungen statt
    einer Punktzahl: Admin, kurz vor dem Export angelegt, schwacher Hash, nie
    angemeldet, offene Sitzung, gesperrt. Die Engine liest dafür neu den
    letzten Login und den Sperrstatus (Joomla: `lastvisitDate`/`block`;
    WordPress: `user_status` und, falls ein Plugin sie schreibt, Login-Meta
    bzw. offene Sitzungen). Fehlt die Angabe, steht »nicht im Dump« — das
    heißt ausdrücklich nicht »nie angemeldet«.
  - **Eingeschleuster Code ist anklickbar** und öffnet die Tabelle im
    Artefakt-Fenster; die Seite ist damit Arbeitsort statt Anzeigeort.
  - **Tabellen kennen ihre Findings** und markieren leere Tabellen sichtbar.
  - **CSV-Export der Konten** (alle oder nur Admins) für die Reset-Liste —
    ausdrücklich **ohne Passwort-Hashes**: das Werkzeug dokumentiert einen
    Vorfall, es bereitet keinen Angriff vor.
- **CMS Inventory neu aufgebaut.** Statt eines Kachel-Mosaiks aus 10–15
  Typ-Tabellen (Joomla machte jede Plugin-Gruppe zur eigenen Karte) zeigt
  jede Installation EINE durchgehende Liste mit Gruppen-Bändern; die Typen
  falten sich auf Plugin/Theme/Template/Component/Module zusammen —
  Plugin-Gruppe und Site/Admin stehen als Tag an der Zeile. Der Install-Kopf
  ist eine Karte mit der Version als wichtigster Zahl. Neu ist der
  Fall-Bezug: der Server verknüpft jede Erweiterung mit den geflaggten
  Dateien unter ihrem Pfad — ein Badge »n Artefakte« beantwortet „welche
  Erweiterung ist kompromittiert?" und öffnet das Artefakt-Fenster direkt.
  Einzeldatei-Extensions (hello.php) erben dabei nie ihren Container, sonst
  würde jede Shell im plugins-Ordner jedem Einzeldatei-Plugin zugerechnet.
  Filter im Ausblende-Schema: Typ-Chips plus »mit/ohne Version«. Die
  Gruppen-Bänder lassen sich zuklappen (ein Filter oder eine Suche klappt
  wieder auf, damit kein Treffer hinter einem Klick verschwindet).
- Die Kürzel an den Extension-Zeilen **erklären sich**: »Site« und »Admin«
  sagen, ob der Teil ohne Anmeldung erreichbar ist, die Joomla-Plugin-Gruppe
  sagt, wann Joomla das Plugin aufruft (`system` läuft bei jedem
  Seitenaufruf — die begehrteste Gruppe für Persistenz). Dabei behoben: die
  Engine lässt den Bereich bei Komponenten aus `administrator/components`
  weg, bei Modulen und Templates dagegen bei den *Site*-Verzeichnissen — ein
  unbeschriftetes »Component« stand also für Backend, ein unbeschriftetes
  »Module« für Frontend. Die Ansicht schreibt den stillen Bereich jetzt aus.
- **Versionen sind prüfbar und korrigierbar.** Die Engine merkt sich, aus
  welcher Datei eine Version gelesen wurde — Manifest-XML, `style.css`,
  Plugin-Header, `version.php` —, und ein Klick auf die Versionszelle öffnet
  ein Fenster, das die Quelle nennt und die Datei aufmacht. Dort lässt sich
  die Version von Hand setzen (mit Begründung), wenn das Manifest fehlt oder
  gefälscht ist. Die Korrektur **ersetzt den Messwert nicht**, sondern legt
  sich darüber: beides bleibt nebeneinander sichtbar, und weil die Korrektur
  in einer eigenen Tabelle liegt, überlebt sie jede Re-Analyse — anders als
  das Inventar selbst, das bei jedem Lauf neu geschrieben wird.
- **Alle Filter-Chips sind Ausblende-Schalter.** Ein Klick versteckt die
  Klasse (durchgestrichener Chip), der nächste holt sie zurück; beliebig
  viele stapeln sich — Scanner weg, Brute-Force weg, übrig bleibt das
  Unerklärte. Gilt für Schweregrade, Triage-Zustände und Quellen in
  Findings, die Verhaltens-Flags in Actors und Typen/Tags in der IOC Box.
  Die Checkboxen »False Positives/Info ausblenden« gehen darin auf (beide
  Klassen starten ausgeblendet); »x Artefakte ausgeblendet« mit
  »alles einblenden« steht unter der Chip-Leiste. In der IOC Box
  verschwindet ein Eintrag erst, wenn *alle* seine Tags ausgeblendet sind —
  ein sichtbares Tag genügt zum Bleiben.
- **Actors ist die Jagd, Findings die Entscheidung** — und beide kennen
  denselben Stand. Actors öffnet standardmäßig mit **allen** Clients (die
  Grundgesamtheit ist das, was die Seite einzigartig macht; „Auffällig"
  bleibt als Chip). Clients mit Findings tragen ihr Triage-Badge direkt in
  der Zeile und öffnen per **Artefakt**-Knopf dasselbe Detail-Fenster wie in
  Findings — mit Entscheidung, Übernahme und Meldung. Niemand bewertet in
  Actors neu, was drüben schon beantwortet ist. Technisch sind
  Artefakt-Fenster und Triage-Nachsorge jetzt geteilte Komponenten
  (`ArtifactWindow`, `useTriage`/`TriageFollowUp`).
- **Die Arbeitsliste blendet jetzt False Positives aus, nicht True
  Positives.** Bestätigte Artefakte bleiben stehen und treten nur optisch
  zurück — sie sind das Ergebnis, und der Bericht entsteht aus derselben
  Liste, in der gearbeitet wurde. Verworfene verschwinden aus der
  Arbeitsliste und bleiben über den Filter »False Positive« mit ihrer Notiz
  erreichbar. Der Parameter heißt entsprechend `hide_dismissed`.
- Die **Listenbox umschließt ihren Inhalt**, statt immer die volle Fensterhöhe
  zu füllen. Unter der letzten Zeile stand sonst eine leere Fläche, die
  aussah, als fehle dort etwas.

### Behoben

- **Der Datei-Viewer öffnete hinter der Detail-Ansicht.** Overlays haben jetzt
  Ebenen: was man aus dem Artefakt-Fenster heraus öffnet (Datei, Trace), liegt
  davor. `Escape` schließt nur das oberste, statt die ganze Kette abzuräumen.
- Ein bestätigtes Datei-Artefakt kam **ohne SHA-256** in die IOC Box, wenn
  der Hash nicht schon aus dem Scan vorlag — obwohl das Detail ihn anzeigte.
  Er wird jetzt an derselben Grenze (32 MB) nachberechnet.
- **Der Hunt verglich nur den Dateinamen, nicht den Pfad.** Eine Shell namens
  `index.php` sammelte damit jeden Besucher jeder beliebigen Startseite als
  IOC in den Fall — Menschen, die mit dem Vorfall nichts zu tun haben.
  Verglichen wird jetzt der Pfad unterhalb der Evidence-Wurzel; das gilt für
  die IOC-Sammlung, die Client-Liste im Artefakt-Detail und die Übernahme.
- Die Sammel-Quittung nach dem Bestätigen zeigte denselben Indikator mehrfach,
  einmal je Regel des Artefakts.

### Entfernt

- Die Themes **Terminal**, **Ember** und **Arctic**. Es bleiben **Synthwave**
  (neuer Standard) und **Shellhound**. Ein gespeichertes Theme, das es nicht
  mehr gibt, fällt sauber auf den Standard zurück, statt `<html>` auf ein
  Theme ohne CSS-Block zu setzen.
- `GET /api/cases/{slug}/findings/{fingerprint}/context` — ersetzt durch das
  Artefakt-Detail.

### Grundlage — die erste Fassung (2026-08-02, nie veröffentlicht)

Ausgangspunkt: web-native DFIR-Workbench für Webserver-Kompromittierungen.
Fünf Views über einem Fall (Findings, Actors, IOC Box, CMS Inventory,
Database), Engines für Access-Log-Index, Webshell-Scan, CMS-Inventar und
SQL-Dump-Analyse, Fall-Archivierung als ZIP.
