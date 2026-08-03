# Detektionsregeln

Jede Regel, die in SHELLHOUND ein Finding erzeugt — was sie technisch
auslöst, was sie **aussagt** und was sie **nicht** aussagt.

Diese Datei ist Referenz, keine zweite Quelle: die Regeln stehen in
[`server/engines/`](../server/engines), die Klartexte in
[`web/src/explain.ts`](../web/src/explain.ts). Wer eine Regel ändert, ändert
sie dort und zieht diese Datei nach.

Die **Konto-Beobachtungen** der Database-Ansicht (Admin, kurz vor dem Export
angelegt, schwacher Hash, nie angemeldet, offene Sitzung, gesperrt) sind
ebenfalls keine Findings, sondern eine Sortierhilfe: ein Dump kann nicht
sagen, dass ein Konto bösartig ist — nur, was an ihm auffällt.

Das **CMS-Inventar** erzeugt keine Findings — es beschreibt, was installiert
ist. Jede Versionsangabe trägt die Datei mit sich, aus der sie gelesen wurde
(Manifest, `style.css`, Plugin-Header, `version.php`), und lässt sich im
Inventar von Hand korrigieren; der gemessene Wert bleibt daneben stehen.

## Zwei Prinzipien, die überall gelten

**Probe-Regeln sind outcome-gated.** SQL-Injection, Path-Traversal und
Zugriffe auf PHP in Upload-Verzeichnissen werden nur zum Finding, wenn
mindestens eine dieser Anfragen mit **2xx** beantwortet wurde. Abgewehrte
Versuche bleiben als Zähler am Actor sichtbar — eine geblockte Angriffswelle
soll die Arbeitsliste nicht röten.

**Was nicht bewertet werden konnte, verschwindet nicht.** Eine unlesbare oder
zu große Datei am falschen Ort wird selbst zum Finding. Inerte PHP-Stubs und
übersprungene Dateien landen in eigenen Tabellen (`inert_php`, `skipped`).
Ein nicht geprüfter Fund wird gemeldet, nicht verschwiegen.

## Schweregrade

| Grad | Bedeutung |
|---|---|
| **HIGH** (0) | Sachverhalt, für den es kaum eine harmlose Erklärung gibt. |
| **MEDIUM** (1) | Auffällig, kann aber legitim sein — braucht Kontext. |
| **LOW** (2) | Schwaches Signal, meist nur im Zusammenhang interessant. |
| **INFO** (3) | Kontext ohne Aussage über *dieses* System. Standardmäßig ausgeblendet. |

## Übersicht

| Engine | Regel | Grad |
|---|---|---|
| Webshell | Unguarded PHP in writable upload directory | HIGH |
| Webshell | Double extension disguise | HIGH |
| Webshell | PHP code hidden inside image file | HIGH |
| Webshell | Unguarded-location PHP could not be read | HIGH |
| Webshell | PHP in writable upload directory (too large to inspect) | HIGH |
| Webshell | eval/assert on decoded or request input | HIGH |
| Webshell | Variable function called on request input | HIGH |
| Webshell | Command execution on request input | HIGH |
| Webshell | preg_replace with /e modifier | HIGH |
| Webshell | create_function / callback on request input | HIGH |
| Webshell | File dropper writing request input to disk | HIGH |
| Webshell | .htaccess maps non-PHP extension to PHP handler | HIGH |
| Webshell | .htaccess auto_prepend/append_file backdoor | HIGH |
| Webshell | Obfuscation decode chain | MEDIUM |
| Webshell | Hex/octal string obfuscation | MEDIUM |
| Webshell | chr() concatenation obfuscation | MEDIUM |
| Webshell | goto-based control-flow obfuscation | MEDIUM |
| Webshell | Standalone command-execution shell | MEDIUM |
| Datenbank | PHP open tag in database value | HIGH |
| Datenbank | eval/assert on decoded or request input | HIGH |
| Datenbank | Obfuscation decode chain | HIGH |
| Datenbank | Command execution call in database value | HIGH |
| Datenbank | create_function / dynamic callback | HIGH |
| Datenbank | Inline `<script>` in database value | MEDIUM |
| Datenbank | Injected `<iframe>` in database value | MEDIUM |
| Datenbank | document.write (script injection) | MEDIUM |
| Logs | Possible successful brute-force | HIGH |
| Logs | Requested PHP in upload/cache directory answered 2xx | HIGH |
| Logs | CMS login POST flood | MEDIUM |
| Logs | SQL injection patterns in URIs answered 2xx | MEDIUM |
| Logs | Path traversal patterns answered 2xx | MEDIUM |
| Logs | Scanner tool User-Agent | INFO |

---

# Webshell-Scan

Quelle: [`server/engines/webshell.py`](../server/engines/webshell.py) ·
Artefakt: **Datei**

## Standort und Dateiname

### Unguarded PHP in writable upload directory — HIGH

**Auslöser:** PHP-Datei in einem beschreibbaren Verzeichnis (`images`, `tmp`,
`cache`, `media`, `files`, `assets`, `upload(s)`, `wp-content/uploads`,
`wp-content/cache`) **und** kein CMS-Startschutz in den ersten 4 KB
(`_JEXEC`, `JPATH_PLATFORM`, `ABSPATH`, `WPINC`, „restricted access")
**und** ausführbare Oberfläche (Request-Superglobals, `eval`/`system`/…,
Decoder, Schreibfunktionen, variable Funktionsaufrufe).

**Was es sagt:** Eine ausführbare PHP-Datei liegt dort, wo Uploads landen,
und trägt nicht den Startschutz, den jede echte CMS-Datei hat.

**Warum es zählt:** Zusammen mit „kann etwas ausführen" ist das der
klassische Fund einer abgelegten Shell. Der Guard ist der wirksamste
Diskriminator aus den echten Joomla-Fällen — er trennt die Installation von
dem, was jemand hineingelegt hat.

**Grenzen:** Der Guard wird als Zeichenkette gesucht, nicht strukturell
geprüft — ein `// _JEXEC` im Kommentar entwaffnet diese Regel. Die
Inhaltsregeln unten greifen dann weiterhin. Ohne ausführbare Oberfläche wird
die Datei als `inert` verbucht statt gemeldet; das hält die Liste frei von
den Tausenden leerer `index.php`-Stubs, die ein CMS anlegt.

### Double extension disguise — HIGH

**Auslöser:** Dateiname endet auf harmlose + ausführbare Endung, z. B.
`logo.jpg.php`, `dokument.pdf.phtml`.

**Was es sagt:** Der Name tarnt sich mit einer harmlosen Endung vor der
echten.

**Warum es zählt:** Ausgeführt wird die **letzte** Endung. Diese Kombination
entsteht praktisch nur beim Umgehen von Upload-Filtern.

### PHP code hidden inside image file — HIGH

**Auslöser:** `<?php` oder `<?=` in einer Datei mit Bild-Endung.

**Was es sagt:** In einer Bilddatei steht ein PHP-Tag.

**Warum es zählt:** Ein echtes Bild enthält keinen PHP-Code. Typisch für
Uploads, die an einer Bildprüfung vorbeigeschmuggelt wurden.

### Unguarded-location PHP could not be read — HIGH

**Auslöser:** PHP im Upload-Verzeichnis, aber Lese- oder Statfehler.

**Was es sagt:** Die Datei liegt am falschen Ort und war nicht lesbar
(Rechte, defekte Kopie).

**Warum es zählt:** Ein nicht geprüfter Fund wird gemeldet statt verschwiegen.
Rechte prüfen und erneut sichern.

### PHP in writable upload directory (too large to inspect) — HIGH

**Auslöser:** PHP im Upload-Verzeichnis, größer als 5 MB.

**Was es sagt:** Die Datei liegt am falschen Ort, war aber zu groß für die
Inhaltsprüfung.

**Warum es zählt:** Nicht bewertet, sondern gemeldet — hier lohnt der
manuelle Blick.

## Inhalt

Zeilenweise gegen den Dateitext; die Fundzeile steht am Finding. Diese Regeln
laufen gegen **jede** PHP-Datei, unabhängig vom Ort — anders als die
Standortregel oben. Eine Shell mit gefälschtem Guard bleibt hier sichtbar.

### eval/assert on decoded or request input — HIGH

**Auslöser:** `eval(` / `assert(` direkt auf `base64_decode`, `gzinflate`,
`gzuncompress`, `str_rot13`, `strrev` oder `$_POST`/`$_GET`/`$_REQUEST`/
`$_COOKIE`.

**Was es sagt:** Der Code führt aus, was von außen hereinkommt oder gerade
entpackt wurde.

**Warum es zählt:** Damit kann der Aufrufer beliebigen Code ausführen lassen
— das Kernstück fast jeder Webshell.

### Variable function called on request input — HIGH

**Auslöser:** `$variable($_POST[...])` — Funktionsname aus einer Variablen,
Argument aus dem Request.

**Was es sagt:** Welche Funktion aufgerufen wird, entscheidet ein Parameter
aus dem Request.

**Warum es zählt:** Verschleierte Form von „führe aus, was ich schicke".
Legitimer Code tut das praktisch nie.

### Command execution on request input — HIGH

**Auslöser:** `system`, `exec`, `shell_exec`, `passthru`, `proc_open`,
`popen`, `pcntl_exec` mit Request-Daten innerhalb von 40 Zeichen im Argument.

**Was es sagt:** Ein Systembefehl wird mit Werten aus dem Request
zusammengebaut.

**Warum es zählt:** Erlaubt Befehle auf dem Server. Wenn die Datei erreichbar
war, ist das ein Zugang zum System.

### preg_replace with /e modifier — HIGH

**Auslöser:** `preg_replace` mit `e`-Modifier im Muster.

**Was es sagt:** Eine veraltete PHP-Funktion, die den Ersetzungstext als
**Code** ausführt.

**Warum es zählt:** Seit PHP 7 entfernt — in aktuellem Code gibt es dafür
keinen legitimen Grund.

### create_function / callback on request input — HIGH

**Auslöser:** `create_function('...` oder `call_user_func(_array)($_...)`.

**Was es sagt:** Code wird zur Laufzeit aus Text erzeugt bzw. der Aufruf kommt
aus dem Request.

**Warum es zählt:** Seit langem veraltet; in Webshells gängig, um die
eigentliche Nutzlast zu verstecken.

### File dropper writing request input to disk — HIGH

**Auslöser:** `move_uploaded_file`, `file_put_contents` oder `fwrite` mit
`$_POST`/`$_GET`/`$_REQUEST`/`$_FILES` innerhalb von 80 Zeichen.

**Was es sagt:** Die Datei schreibt hereinkommende Daten auf die Festplatte.

**Warum es zählt:** So werden weitere Shells nachgeladen. Prüfe, was in der
Umgebung sonst noch neu ist.

### Obfuscation decode chain — MEDIUM

**Auslöser:** Verschachtelte Decoder, z. B. `base64_decode(str_rot13(...))`,
`gzinflate(base64_decode(...))`.

**Was es sagt:** Mehrere Kodierungs-Schritte sind ineinander verschachtelt.

**Warum es zählt:** Verschleierung dieser Bauart dient dem Verstecken. Was am
Ende herauskommt, muss man sich ansehen.

### Hex/octal string obfuscation — MEDIUM

**Auslöser:** Mindestens 10 aufeinanderfolgende `\xNN`- oder `\NNN`-Escapes.

**Was es sagt:** Text ist als lange Kette von Escapes geschrieben statt als
Klartext.

**Warum es zählt:** Macht Suchbegriffe unsichtbar. Legitimer Code schreibt
URLs und Funktionsnamen ausgeschrieben.

### chr() concatenation obfuscation — MEDIUM

**Auslöser:** Mindestens fünf `chr(n).`-Glieder hintereinander.

**Was es sagt:** Zeichenketten werden aus einzelnen Zeichencodes
zusammengesetzt.

**Warum es zählt:** Gleiches Ziel wie oben: nichts soll durchsuchbar sein.

### goto-based control-flow obfuscation — MEDIUM

**Auslöser:** `goto label;`

**Was es sagt:** Der Programmfluss springt mit `goto` durcheinander.

**Warum es zählt:** Typische Ausgabe automatischer Verschleierer.
Handgeschriebener PHP-Code sieht so nicht aus.

### Standalone command-execution shell — MEDIUM

**Auslöser:** `shell_exec`, `passthru`, `proc_open` oder `pcntl_exec` — ohne
erkennbaren Request-Bezug.

**Was es sagt:** Die Datei kann Systembefehle ausführen.

**Warum es zählt:** Allein noch kein Beweis — manche Admin-Tools tun das
auch. Entscheidend ist, wo die Datei liegt und ob sie dorthin gehört.

## .htaccess

### .htaccess maps non-PHP extension to PHP handler — HIGH

**Auslöser:** `AddHandler`, `AddType` oder `SetHandler` in Verbindung mit
`php` / `x-httpd`.

**Was es sagt:** Eine `.htaccess` lässt untypische Endungen als PHP
ausführen.

**Warum es zählt:** So wird aus einer harmlos aussehenden Datei ausführbarer
Code. Fast immer nachträglich eingebracht.

### .htaccess auto_prepend/append_file backdoor — HIGH

**Auslöser:** `auto_prepend_file` oder `auto_append_file`.

**Was es sagt:** Eine `.htaccess` lädt bei **jedem** Aufruf eine zusätzliche
Datei mit.

**Warum es zählt:** Persistenz-Trick: Der Code läuft auch dann noch, wenn die
eigentliche Shell gelöscht ist.

---

# Datenbank-Dump

Quelle: [`server/engines/sqldump.py`](../server/engines/sqldump.py) ·
Artefakt: **Tabelle**

Die Regeln laufen gegen **Datenwerte** in `INSERT`-Zeilen, nicht gegen das
Schema. Zeilennummer und Auszug stehen am Finding.

### PHP open tag in database value — HIGH

**Auslöser:** `<?php` oder `<?=` in einer Spalte.

**Was es sagt:** In einem Datenfeld der Datenbank steht PHP-Code.

**Warum es zählt:** Ein CMS speichert Code in Dateien, nie in der Datenbank.
Der Code überlebt jedes Bereinigen der Dateien.

### eval/assert on decoded or request input — HIGH

**Auslöser:** `eval(`/`assert(` auf Decoder oder `$_`-Superglobals, in einem
Datenwert.

**Was es sagt:** Ausführbarer Code in einem Datenfeld.

**Warum es zählt:** Wie oben — gehört nicht in Daten.

### Obfuscation decode chain — HIGH

**Auslöser:** Verschachtelte `base64_decode`/`gzinflate`/`gzuncompress`/
`str_rot13` in einem Datenwert.

**Was es sagt:** Verschleierter Code in der Datenbank.

**Warum es zählt:** In einer Datenspalte ist Verschleierung kein Grauton
mehr, sondern eingeschleuster Code — deshalb hier HIGH statt MEDIUM wie in
Dateien.

### Command execution call in database value — HIGH

**Auslöser:** `system`, `shell_exec`, `passthru`, `proc_open`, `popen`,
`pcntl_exec` in einem Datenwert.

**Was es sagt:** Ein Datenfeld enthält einen Aufruf zur Befehlsausführung.

**Warum es zählt:** Gehört nicht in Daten. Prüfe, wo dieser Inhalt ausgegeben
wird.

### create_function / dynamic callback — HIGH

**Auslöser:** `create_function(` in einem Datenwert.

**Was es sagt:** Zur Laufzeit erzeugter Code in der Datenbank.

**Warum es zählt:** Wie oben; zusätzlich ein Hinweis auf älteren
Schadcode-Baukasten.

### Inline `<script>` in database value — MEDIUM

**Auslöser:** `<script` gefolgt von Leerzeichen oder `>`.

**Was es sagt:** In einem Datenfeld steht JavaScript.

**Warum es zählt:** Kann legitim sein (eingebettete Inhalte, Tracking) — hier
zählt der Kontext: Passt das zu dieser Tabelle?

### Injected `<iframe>` in database value — MEDIUM

**Auslöser:** `<iframe` gefolgt von Leerzeichen oder `>`.

**Was es sagt:** Ein iframe steckt in einem Datenfeld.

**Warum es zählt:** Klassisch für untergeschobene Weiterleitungen und Werbung
— kann aber auch redaktionell eingebaut sein.

### document.write (script injection) — MEDIUM

**Auslöser:** `document.write(`.

**Was es sagt:** Ein Datenfeld schreibt per JavaScript weiteren Inhalt in die
Seite.

**Warum es zählt:** Gängige Technik, um nachgeladenen Fremdcode zu
verstecken. Ziel-Host im Auszug prüfen.

---

# Access-Logs

Quelle: [`server/engines/logindex.py`](../server/engines/logindex.py) ·
Artefakt: **Client-IP**

Die Muster werden **einmal pro eindeutiger Zeichenkette** ausgewertet, nicht
pro Zeile — deshalb kostet ein 10-Millionen-Zeilen-Log nicht das
Zehnmillionenfache.

### Possible successful brute-force — HIGH

**Auslöser:** ≥ 30 POSTs auf Login-Endpunkte **und** mindestens eine Antwort
301/302/303.

**Was es sagt:** Nach vielen Login-Versuchen kam eine Weiterleitung zurück.

**Warum es zählt:** Genau so sieht ein **geglückter** Login aus. Unbedingt
prüfen: Welches Konto, und was passierte danach?

### Requested PHP in upload/cache directory answered 2xx — HIGH

**Auslöser:** URI auf PHP in einem Upload-/Cache-Verzeichnis (Spiegel der
Webshell-Standortregel) **und** mindestens eine 2xx-Antwort.

**Was es sagt:** Jemand hat PHP in einem Upload-Verzeichnis abgerufen — und
der Server hat mit Erfolg geantwortet.

**Warum es zählt:** Das ist kein Scan ins Leere: Dort lag etwas Ausführbares
und wurde ausgeliefert. Die stärkste Log-Spur einer benutzten Shell.

### CMS login POST flood — MEDIUM

**Auslöser:** ≥ 30 POSTs auf `wp-login.php`, `xmlrpc.php`,
`/administrator/index.php`, `option=com_login`, `task=user.login` oder
`option=com_users`.

**Was es sagt:** Auffällig viele Login-Absendungen von derselben Adresse.

**Warum es zählt:** Ein Anmelde-Versuch in Serie. Erfolg zeigt erst der
Statuscode — siehe Weiterleitungen.

### SQL injection patterns in URIs answered 2xx — MEDIUM

**Auslöser:** `union select`, `information_schema`, `concat(`, `' or 1=1`,
`benchmark(`, `sleep(` in der URI **und** 2xx.

**Was es sagt:** Angriffs-Muster für Datenbank-Injektion in der URL, vom
Server mit Erfolg beantwortet.

**Warum es zählt:** Nur „beantwortet" heißt noch nicht „geklappt" — aber es
lohnt der Abgleich mit den Datenbank-Funden.

### Path traversal patterns answered 2xx — MEDIUM

**Auslöser:** Mindestens zwei `../` (auch `%2e%2e%2f`, `..%2f`) **und** 2xx.

**Was es sagt:** Versuche, mit `../` aus dem Web-Verzeichnis auszubrechen,
wurden erfolgreich beantwortet.

**Warum es zählt:** Kann das Auslesen fremder Dateien bedeuten. Welche URLs
betroffen sind, steht im Trace.

### Scanner tool User-Agent — INFO

**Auslöser:** User-Agent nennt ein bekanntes Werkzeug: sqlmap, nikto, nmap,
masscan, dirbuster, gobuster, feroxbuster, wpscan, joomscan, hydra, acunetix,
nessus, nuclei, zgrab, censys, httpx, wfuzz, ffuf.

**Was es sagt:** Der Client hat sich als bekanntes Scan-Werkzeug zu erkennen
gegeben.

**Warum es zählt:** Hintergrundrauschen, solange nichts erfolgreich war — als
Vorgeschichte trotzdem interessant. Deshalb INFO und standardmäßig
ausgeblendet: Scans passieren jedem Server rund um die Uhr und würden die
echte Arbeit zudecken.
