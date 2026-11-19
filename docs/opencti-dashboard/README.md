# Shellhound-Dashboard für OpenCTI 7.261103.0

Native, importierbare Dashboard-Vorlage mit deutschen Überschriften und
horizontalen Balkendiagrammen statt Monatsverläufen. Balkenbeschriftungen
verwenden kurze lesbare SH-Labels, etwa `SH Größe: 10–49`. Keine
Verbindung zu deiner Instanz und keine Zugangsdaten erforderlich, um die Dateien
zu erzeugen. Die Vorlage verwendet normale Dashboard-Widgets und Label-Filter;
keine Enterprise Custom Fields.

## Import: Reihenfolge beachten

1. **Labelkatalog importieren:** `01-shellhound-label-catalogue.stix.json` über
   den normalen STIX-Dateiimport von OpenCTI hochladen. Den Import vollständig
   verarbeiten lassen. Falls ein Import-Connector ausgewählt werden muss:
   einen Connector für STIX 2.1 JSON verwenden. Der Connector muss laufen und
   dein Konto muss den Import und das Anlegen von Labels erlauben.
2. In OpenCTI prüfen, ob das Label
   `SH Abfluss: bestätigt` vorhanden ist. Der Katalog
   legt alle Auswahlwerte an, auch wenn es dazu noch keine Fälle gibt.
3. **Dashboard importieren:** In der Liste der benutzerdefinierten Dashboards
   **Import dashboard** wählen und
   `02-shellhound-dashboard-7.261103.0.json` hochladen. Diese Datei gehört nicht
   in den STIX-Datenimport. Das Dashboard heißt
   **Shellhound · Fallprofile · Kurzlabels**.
4. Einen erfolgreich übertragenen Shellhound-Fall in der Fallliste öffnen und
   seine Profil-Labels mit den Kennzahlen vergleichen. Bei leeren Ergebnissen:
   Profiltransfer prüfen, Sichtbarkeits-/Markierungsrechte prüfen und den
   Dashboard-Datumsfilter zurücksetzen. Ältere Fälle ohne die neuen Labels
   müssen mit Shellhound erneut übertragen werden. Ist die alte Vorlage mit
   Monatsverläufen bereits importiert, entsteht beim Import ein neues Dashboard;
   das alte kann nach erfolgreicher Prüfung entfernt werden.

Der Katalog enthält genau ein technisches System und ein Grouping mit Labels.
Er enthält keine Beispielfälle, Unternehmen oder vertraulichen Angaben. Er
ändert keine bestehenden Fallprofile. Diese technischen Objekte erscheinen
nicht in den Dashboard-Fallzahlen. Die Importreihenfolge ist wichtig:
OpenCTI löst beim Dashboard-Import die portablen Standard-IDs der Labels in
lokale IDs auf. Wurde das Dashboard zuerst importiert, nach erfolgreichem
Katalogimport erneut importieren und das unbrauchbare erste Dashboard entfernen.

## Was angezeigt wird

- Sechs Kennzahlen: Fallzahl, bestätigter Datenabfluss, bestätigte
  Angreiferverschlüsselung, unbekannter Zugangsweg sowie nicht untersuchter
  Datenabfluss und nicht untersuchte Verschlüsselung.
- Zwölf horizontale Balkendiagramme, absteigend nach Fallzahl:
  Unternehmensgröße, Hostingmodell, Anbieter,
  IT-Betriebsmodell, Zugangsweg und dessen Bewertungsstatus, Ausbreitung,
  Datenabfluss, Verschlüsselung, entdeckende Partei, Entdeckungsweg sowie
  bestätigter Datenabfluss nach Hostingmodell.
- Die neuesten 20 Fälle mit Namen, Datum, Labels und Markierungen.

Die Diagramm-Widgets belegen jeweils drei statt sechs Rasterzeilen und stehen
zu zweit nebeneinander. Dadurch werden auch wenige Treffer kompakter dargestellt.
Die Breite der Balken, Schriftarten und Farben steuert weiterhin OpenCTI selbst;
diese Eigenschaften lassen sich in dieser Version nicht über das Dashboard-JSON
frei einstellen.

Gezählt werden ausschließlich `Case-Incident`-Objekte mit einem gültigen
SH-Label für die Unternehmensgröße, einschließlich `unknown`. Jeder
Fall zählt einmal, auch wenn mehrere Fälle dasselbe Unternehmen betreffen.
Alle Widgets zeigen standardmäßig alle Zeiten. Die Balken zählen die
`object-label`-Verknüpfungen von diesen Fällen zu den Labels des jeweiligen
Profilfelds. Pro Fall und Label besteht eine Zuordnung. Die Filter auf Quellfälle
und Ziel-Labels verhindern, dass Labels anderer Felder, Organisationen, IOCs
oder der technische Labelkatalog die Balken verfälschen.

**Für einen konsistenten Gesamtvergleich den globalen Datumsfilter leer lassen.**
Die native Datumswahl wirkt auf unterschiedliche Datensätze: Bei Balken auf
`created_at` der Label-Zuordnung in OpenCTI, bei Kennzahlen und Fallliste auf
`created` des Falls (Anlage in Shellhound). Eine neue oder erneuerte Zuordnung
kann daher zeitlich von der Fallanlage abweichen. Eine ausgewählte Zeitspanne
liefert keine einheitliche Fallkohorte über alle Widgets. Keine dieser Angaben
ist das Angriffsdatum oder die Entdeckungszeit. Die Balken zeigen den
**zuletzt übertragenen Profilstand**, keine Statushistorie.

`unknown`, `not_investigated`, `not_observed`, `suspected` und `confirmed`
bleiben getrennt. „Nicht beobachtet“ bedeutet nicht nachgewiesene Abwesenheit.
Anbieter und Ausbreitung erlauben mehrere Werte pro Fall; deren Kategorien
addieren sich deshalb nicht zur Gesamtzahl. Die 15 Kataloganbieter und unbekannt
sind für die Auswertung berücksichtigt. Kategorien ohne Treffer erscheinen
nicht als Balken; ohne Treffer zeigt das Widget keine Daten. Frei eingegebene
Anbieter und die frei erfasste initiale CVE bleiben in den Fall-Labels sichtbar
und filterbar, erhalten aber kein eigenes vorgefertigtes Diagramm. Achsen und Fallfilter nutzen ausschließlich die kurzen SH-Labels.

Fallzahlen liefern keine Schadenwahrscheinlichkeit: Versicherungsbestand,
Expositionsdauer und Vergleichsgruppen fehlen. Kosten, Entdeckungsdauer,
Patchverläufe und Präventionswirksamkeit sind mit diesen Labels nicht messbar.
Schadenverläufe oder kausale Aussagen lassen sich aus den Verteilungen
nicht ableiten. Berechtigungen und Markierungen begrenzen die sichtbaren Fälle.

## Erzeugen und prüfen

Aus dem Repository-Verzeichnis:

```powershell
.\.venv\Scripts\python.exe -m tools.opencti_dashboard
.\.venv\Scripts\python.exe -m unittest tests.test_opencti_dashboard
```

Die JSON-Dateien werden reproduzierbar aus den aktuellen Profil-Auswahlwerten
erzeugt. Nach Erweiterung der Auswahlwerte Katalog und Dashboard neu erzeugen
und in dieser Reihenfolge erneut importieren. Bestehende Dashboards werden
durch erneuten Import nicht automatisch aktualisiert.

Das Format wurde gegen den offiziellen Quellcode des Tags `7.261103.0`
geprüft: [Dashboard-Import und ID-Auflösung](https://github.com/OpenCTI-Platform/opencti/blob/7.261103.0/opencti-platform/opencti-graphql/src/modules/dashboard/dashboard-utils.ts),
[Widget-Schema](https://github.com/OpenCTI-Platform/opencti/blob/7.261103.0/opencti-platform/opencti-front/src/utils/widget/widget.d.ts)
und [Datumsfilter](https://github.com/OpenCTI-Platform/opencti/blob/7.261103.0/opencti-platform/opencti-front/src/components/dashboard/dashboardVizUtils.ts).
Die Balken verwenden das native [Beziehungs-Balkendiagramm](https://github.com/OpenCTI-Platform/opencti/blob/7.261103.0/opencti-platform/opencti-front/src/private/components/common/stix_relationships/StixRelationshipsHorizontalBars.tsx)
mit der [unterstützten Beziehung `object-label`](https://github.com/OpenCTI-Platform/opencti/blob/7.261103.0/opencti-platform/opencti-front/src/utils/widget/widgetUtils.tsx)
und Aggregation auf die Label-Zielseite (`internal_id`, `isTo: true`).
Die [offizielle Python-Implementierung der Label-IDs](https://github.com/OpenCTI-Platform/client-python/blob/master/pycti/entities/opencti_label.py)
definiert die portablen Filter-IDs. Offline wurden Struktur, Labelbezüge,
Filtereingrenzung und Layoutkollisionen geprüft. Ein tatsächlicher Import und
die Darstellung in deiner laufenden OpenCTI-Instanz sind noch nicht geprüft.

## Bestehende Fälle umstellen

Den aktualisierten Katalog vor dem neuen Dashboard importieren. Dann entweder
die Fälle aus der aktualisierten Shellhound-Version erneut übertragen oder
[die vollständige Label-Zuordnung](LABELS.md) verwenden und die passenden
Kurzlabels am jeweiligen Case eintragen und nach Prüfung die alten
`shellhound:profile:`-Zuordnungen entfernen. Diese werden im neuen Dashboard nicht mehr verwendet.
Jeder Shellhound-Case erhält außerdem `Webserver Compromise`. Dieses feste
Falllabel ist eine Kennzeichnung des Workflows und kein automatischer Beweis
einer Kompromittierung. Beide Labelgruppen gelten ausschließlich für Cases.

Der Namensraum `SH ` ist für Shellhound reserviert. Beim nächsten Transfer
werden veraltete SH-Labels am Case ersetzt. Gleichlautende manuelle Labels in
diesem Namensraum werden ebenfalls abgeglichen; fremde Labels bleiben erhalten.
Die Balkenfarben folgen weiterhin den Label-Farben in OpenCTI. Einheitliche
Farben kannst du dort an den SH-Labels einstellen.
