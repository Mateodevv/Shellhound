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

## [0.1.0] — 2026-08-02

Erste Fassung: web-native DFIR-Workbench für Webserver-Kompromittierungen.
Fünf Views über einem Fall (Findings, Actors, IOC Box, CMS Inventory,
Database), Engines für Access-Log-Index, Webshell-Scan, CMS-Inventar und
SQL-Dump-Analyse, Fall-Archivierung als ZIP.
