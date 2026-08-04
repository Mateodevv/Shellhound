# Sicherheit

*English summary at the bottom.*

## Eine Schwachstelle melden

Bitte **kein öffentliches Issue** für Sicherheitsprobleme. Stattdessen über
GitHub → *Security* → *Report a vulnerability* (Private Vulnerability
Reporting) oder per Mail an den Repository-Inhaber.

Was hilft: betroffene Version bzw. Commit, ein möglichst kleiner
Reproduktionsweg, und was ein Angreifer damit erreichen könnte. Antwort
kommt, sobald es geht — dies ist ein Projekt ohne Support-Vertrag, keine
zugesicherte Frist.

**Nichts aus einem echten Fall mitschicken.** Kein Webroot, keine Logs, kein
Dump, keine Kunden-IPs. Wenn ein Fehler nur mit bestimmten Daten auftritt,
beschreibe deren *Form* — „ein Access-Log mit `\r\n` in der Zeile", „ein Dump
mit `#__`-Tabellenpräfix" — oder baue ein Minimalbeispiel.

## Wofür SHELLHOUND gebaut ist — und wofür nicht

SHELLHOUND ist ein **Einzelplatz-Werkzeug für eine Forensik-Maschine**. Es
bindet standardmäßig an `127.0.0.1` und geht davon aus, dass genau eine
Person am Rechner arbeitet, die ohnehin Zugriff auf alle Beweismittel hat.

**Es ist kein Mehrbenutzer-Dienst.** Es gibt keine Benutzerkonten, keine
Rollen, kein Audit-Log darüber, wer was gesehen hat. Wer den Token hat, hat
den vollen Fall.

Daraus folgen ein paar Dinge, die man wissen muss:

| Punkt | Was gilt |
|---|---|
| **Kein TLS** | Der Server spricht reines HTTP. Für `127.0.0.1` ist das richtig. Für den Zugriff von einem anderen Rechner: **SSH-Tunnel**, nicht `--host 0.0.0.0` ins offene Netz. |
| **Token in der URL** | Der Zugriffstoken wird als `?token=…` akzeptiert. Das landet in Browser-Verlauf und in den Logs jedes Proxys dazwischen. Bei einem Loopback-Bind wird er in die Seite injiziert und taucht nicht in der URL auf. |
| **Zufälliger Token pro Start** | Ohne `--token` erzeugt jeder Start einen neuen. Ein Nicht-Loopback-Bind **erzwingt** ein explizites `--token`. |
| **Dateisystem-Browser** | `/api/pickpath` blättert absichtlich durch das *gesamte* Dateisystem des Rechners — anders ließe sich Evidence nicht auswählen. Wer den Token hat, kann damit Verzeichnisse auflisten. |
| **Datei-Viewer ist eingezäunt** | Gelesen wird nur, was *aufgelöst* innerhalb einer registrierten Evidence-Wurzel des Falls liegt. Symlinks und `..` führen nicht hinaus. |
| **Evidence wird nie ausgeliefert** | Findings tragen Text-Exzerpte, keine Dateien. Der Viewer liefert Inhalte als JSON-**Daten**; eine bösartige `.html` aus einem Webroot ist hier eine Zeichenkette in einem `<pre>`, keine Seite, die der Browser ausführt. |
| **Import ist misstrauisch** | Ein Fall-Archiv ist eine Datei von außen: absolute Pfade und `..`-Traversal werden **abgewiesen**, nicht bereinigt, und ein Import überschreibt nie einen bestehenden Fall. |

## Netzwerk-Kontakt

SHELLHOUND spricht an **genau einer Stelle** nach draußen, und nur auf einen
ausdrücklichen Klick: dem Download der GeoIP-Länderdatenbank von
`download.db-ip.com`. Ein Bestätigungsfenster sagt das vorher; abgelehnt
wird nichts geladen. Dabei gehen **keine Falldaten** hinaus — der Request
enthält nichts als den Dateinamen.

Alles andere — Analyse, Traces, Länderzuordnung, Exporte — läuft
vollständig offline. Auf einer Maschine ohne Netzfreigabe legt man die
`*.mmdb` von Hand in den Workspace.

## Umgang mit lebendigen Webshells

Ein untersuchtes Webroot enthält funktionsfähigen Angriffscode. SHELLHOUND
führt nichts davon aus — es liest, hasht und zeigt an. Trotzdem:

- **Auf einer isolierten Maschine arbeiten**, idealerweise einer VM ohne
  Netzzugang, mit Snapshot davor.
- **Mit einer Kopie arbeiten, nicht mit dem Live-System.**
- Ein Virenscanner kann Evidence-Dateien **stillschweigend blockieren oder
  löschen** — auf Windows war das reproduzierbar für Dateien mit bestimmten
  PHP-Mustern. Der Evidence-Ordner gehört in die Ausnahmen, sonst fehlen
  Beweismittel, ohne dass es jemand merkt.

## Was nie ins Repository gehört

Die `.gitignore` ist bewusst breit: kein Webroot, keine Logs, keine Dumps,
keine Fall-Ordner. Ein zu viel ignoriertes Testfile kostet nichts; eine
versehentlich veröffentlichte Kundendatei lässt sich nicht zurücknehmen.

---

## English summary

SHELLHOUND is a **single-user tool for a forensic workstation**, not a
multi-user service. It binds to `127.0.0.1`, has no accounts or roles, and
whoever holds the token holds the whole case. There is no TLS — use an SSH
tunnel for remote access rather than binding to `0.0.0.0`.

It makes **exactly one outbound network request** in its entire lifetime,
and only on an explicit click: downloading the GeoIP country database from
`download.db-ip.com`. No case data ever leaves the machine.

To report a vulnerability, use GitHub's private vulnerability reporting —
please do not open a public issue, and **never attach data from a real
incident**.
