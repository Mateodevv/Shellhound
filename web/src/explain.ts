// explain.ts — Klartext für alles, was sonst nur Fachbegriff wäre.
//
// Jede Regel, jedes Badge, jeder Tag und jeder Zustand bekommt hier ZWEI
// Sätze: was der Befund SAGT und was er für die Bewertung bedeutet. Der
// zweite ist der wichtige — "eval auf Request-Input" hilft niemandem, der
// nicht ohnehin weiß, was das heißt.
//
// Regel für den Inhalt (gleiche Disziplin wie in den Engines): hier steht
// nur, was die Regel selbst schon aussagt. Kein Text darf eine Bewertung
// behaupten, die die Detection nicht hergibt — "ist ein Backdoor" wäre
// falsch, "kann Befehle ausführen, wenn sie erreichbar ist" ist die Aussage.

export interface Explanation {
  what: string       // was der Befund feststellt
  why?: string       // warum das relevant ist / was als Nächstes zu tun ist
}

// --- Severity ---------------------------------------------------------------

export const SEVERITY_EXPLAIN: Record<number, Explanation> = {
  0: {
    what: 'HIGH — die Regel beschreibt einen Sachverhalt, für den es kaum eine harmlose Erklärung gibt.',
    why: 'Zuerst ansehen. Wenn es stimmt, gehört es in den Bericht und die Artefakte in die IOC Box.',
  },
  1: {
    what: 'MEDIUM — auffällig, kann aber legitim sein.',
    why: 'Braucht Kontext: Wo liegt die Datei, passt sie zur Installation, wer hat sie angefasst?',
  },
  2: {
    what: 'LOW — schwaches Signal, meist nur im Zusammenhang interessant.',
    why: 'Selten allein aussagekräftig. Interessant, wenn dasselbe Artefakt auch stärkere Treffer hat.',
  },
  3: {
    what: 'INFO — Kontext, keine Aussage über dieses System.',
    why: 'Wird festgehalten, aber standardmäßig ausgeblendet: Dinge wie Scanner-Besuche passieren jedem Server rund um die Uhr und würden die echte Arbeit zudecken.',
  },
}

// --- Triage -----------------------------------------------------------------

// Entschieden wird über das ARTEFAKT — die Datei, den Client, die Tabelle.
// Die Findings darunter sind die Begründung, keine eigenen Fragen.

export const TRIAGE_EXPLAIN: Record<string, Explanation> = {
  new: {
    what: 'Noch niemand hat sich dieses Artefakt angesehen.',
  },
  reviewed: {
    what: 'Angesehen, aber noch nicht entschieden.',
    why: 'Für alles, was du später mit mehr Kontext nochmal beurteilen willst.',
  },
  confirmed: {
    what: 'True Positive — das Artefakt ist real und Teil des Vorfalls.',
    why: 'Bleibt in der Liste stehen, nur abgeblendet: es ist das Ergebnis, aus dem der Bericht entsteht. Legt Artefakt und Hash in die IOC Box und holt die anfragenden Clients aus dem Log-Index.',
  },
  dismissed: {
    what: 'False Positive — geprüft und nicht relevant.',
    why: 'Wird nie gelöscht, nur ausgeblendet: über den Filter »False Positive« bleibt es mit deiner Notiz jederzeit erreichbar. Eine stillschweigend verschwundene Zeile ist nicht nachvollziehbar.',
  },
}

// --- Evidence ---------------------------------------------------------------

export const EVIDENCE_EXPLAIN: Record<string, Explanation> = {
  webroot: {
    what: 'Eine Kopie des Web-Verzeichnisses (dort, wo WordPress/Joomla liegt).',
    why: 'Basis für Webshell-Scan und CMS-Inventar. Am besten eine Kopie, nicht das Live-System.',
  },
  access_logs: {
    what: 'Die Zugriffs-Logs des Webservers (Apache/Nginx, auch .gz/.bz2).',
    why: 'Wird einmal indiziert — danach ist jede Frage („wer hat diese Datei geholt?") eine Abfrage in Millisekunden.',
  },
  sql_dump: {
    what: 'Ein Datenbank-Export des CMS (mysqldump, .sql/.sql.gz).',
    why: 'Liefert Accounts inklusive Admins sowie Code, der in Datenspalten eingeschleust wurde.',
  },
}

export const EVIDENCE_LABEL: Record<string, string> = {
  webroot: 'Webroot',
  access_logs: 'Access-Logs',
  sql_dump: 'SQL-Dump',
}

// --- Regeln -----------------------------------------------------------------
// Schlüssel ist ein Teilstring des Regelnamens (erste Übereinstimmung
// gewinnt), damit neue Regel-Varianten nicht sofort unerklärt dastehen.

const RULE_EXPLAIN: [string, Explanation][] = [
  ['Unguarded PHP in writable upload', {
    what: 'Eine ausführbare PHP-Datei liegt in einem Upload-/Cache-Verzeichnis und hat KEINEN CMS-Startschutz (_JEXEC bzw. ABSPATH).',
    why: 'Jede echte CMS-Datei trägt diesen Schutz; hochgeladene Dateien nicht. Zusammen mit „kann etwas ausführen" ist das der klassische Fund einer abgelegten Shell.',
  }],
  ['Double extension disguise', {
    what: 'Der Dateiname tarnt sich mit einer harmlosen Endung vor der echten (z.B. bild.jpg.php).',
    why: 'Ausgeführt wird die LETZTE Endung. Diese Kombination entsteht praktisch nur beim Umgehen von Upload-Filtern.',
  }],
  ['PHP code hidden inside image', {
    what: 'In einer Bilddatei steht ein PHP-Tag.',
    why: 'Ein echtes Bild enthält keinen PHP-Code. Typisch für Uploads, die an einer Bildprüfung vorbeigeschmuggelt wurden.',
  }],
  ['eval/assert on decoded or request input', {
    what: 'Der Code führt aus, was von außen hereinkommt oder gerade entpackt wurde.',
    why: 'Damit kann der Aufrufer beliebigen Code ausführen lassen — das Kernstück fast jeder Webshell.',
  }],
  ['Variable function called on request input', {
    what: 'Welche Funktion aufgerufen wird, entscheidet ein Parameter aus dem Request.',
    why: 'Verschleierte Form von „führe aus, was ich schicke". Legitimer Code tut das praktisch nie.',
  }],
  ['Command execution on request input', {
    what: 'Ein Systembefehl wird mit Werten aus dem Request zusammengebaut.',
    why: 'Erlaubt Befehle auf dem Server. Wenn die Datei erreichbar war, ist das ein Zugang zum System.',
  }],
  ['File dropper writing request input', {
    what: 'Die Datei schreibt hereinkommende Daten auf die Festplatte.',
    why: 'So werden weitere Shells nachgeladen. Prüfe, was in der Umgebung sonst noch neu ist.',
  }],
  ['preg_replace with /e', {
    what: 'Eine veraltete PHP-Funktion, die den Ersetzungstext als CODE ausführt.',
    why: 'Seit PHP 7 entfernt — in aktuellem Code gibt es dafür keinen legitimen Grund.',
  }],
  ['create_function', {
    what: 'Code wird zur Laufzeit aus Text erzeugt.',
    why: 'Seit langem veraltet; in Webshells gängig, um die eigentliche Nutzlast zu verstecken.',
  }],
  ['Obfuscation decode chain', {
    what: 'Mehrere Kodierungs-Schritte sind ineinander verschachtelt (base64, gzinflate, rot13 …).',
    why: 'Verschleierung dieser Bauart dient dem Verstecken. Was am Ende herauskommt, muss man sich ansehen.',
  }],
  ['Hex/octal string obfuscation', {
    what: 'Text ist als lange Kette von Hex-/Oktal-Escapes geschrieben statt als Klartext.',
    why: 'Macht Suchbegriffe unsichtbar. Legitimer Code schreibt URLs und Funktionsnamen ausgeschrieben.',
  }],
  ['chr() concatenation', {
    what: 'Zeichenketten werden aus einzelnen Zeichencodes zusammengesetzt.',
    why: 'Gleiches Ziel wie oben: nichts soll durchsuchbar sein.',
  }],
  ['goto-based control-flow', {
    what: 'Der Programmfluss springt mit goto durcheinander.',
    why: 'Typische Ausgabe automatischer Verschleierer. Handgeschriebener PHP-Code sieht so nicht aus.',
  }],
  ['Standalone command-execution shell', {
    what: 'Die Datei kann Systembefehle ausführen.',
    why: 'Allein noch kein Beweis — manche Admin-Tools tun das auch. Entscheidend ist, wo die Datei liegt und ob sie dorthin gehört.',
  }],
  ['.htaccess maps non-PHP extension', {
    what: 'Eine .htaccess lässt untypische Endungen als PHP ausführen.',
    why: 'So wird aus einer harmlos aussehenden Datei ausführbarer Code. Fast immer nachträglich eingebracht.',
  }],
  ['.htaccess auto_prepend', {
    what: 'Eine .htaccess lädt bei JEDEM Aufruf eine zusätzliche Datei mit.',
    why: 'Persistenz-Trick: Der Code läuft auch dann noch, wenn die eigentliche Shell gelöscht ist.',
  }],
  ['too large to inspect', {
    what: 'Die Datei liegt am falschen Ort, war aber zu groß für die Inhaltsprüfung.',
    why: 'Nicht bewertet, sondern gemeldet — hier lohnt der manuelle Blick.',
  }],
  ['could not be read', {
    what: 'Die Datei liegt am falschen Ort und war nicht lesbar (Rechte, defekte Kopie).',
    why: 'Ein nicht geprüfter Fund wird gemeldet statt verschwiegen. Rechte prüfen und erneut sichern.',
  }],
  // --- Datenbank ---
  ['PHP open tag in database value', {
    what: 'In einem Datenfeld der Datenbank steht PHP-Code.',
    why: 'Ein CMS speichert Code in Dateien, nie in der Datenbank. Der Code überlebt jedes Bereinigen der Dateien.',
  }],
  ['Command execution call in database value', {
    what: 'Ein Datenfeld enthält einen Aufruf zur Befehlsausführung.',
    why: 'Wie oben: gehört nicht in Daten. Prüfe, wo dieser Inhalt ausgegeben wird.',
  }],
  ['Inline <script> in database value', {
    what: 'In einem Datenfeld steht JavaScript.',
    why: 'Kann legitim sein (eingebettete Inhalte, Tracking) — hier zählt der Kontext: Passt das zu dieser Tabelle?',
  }],
  ['Injected <iframe>', {
    what: 'Ein iframe steckt in einem Datenfeld.',
    why: 'Klassisch für untergeschobene Weiterleitungen und Werbung — kann aber auch redaktionell eingebaut sein.',
  }],
  ['document.write', {
    what: 'Ein Datenfeld schreibt per JavaScript weiteren Inhalt in die Seite.',
    why: 'Gängige Technik, um nachgeladenen Fremdcode zu verstecken. Ziel-Host im Auszug prüfen.',
  }],
  // --- Logs ---
  ['Possible successful brute-force', {
    what: 'Nach vielen Login-Versuchen kam eine Weiterleitung (301/302/303) zurück.',
    why: 'Genau so sieht ein GEGLÜCKTER Login aus. Unbedingt prüfen: Welches Konto, und was passierte danach?',
  }],
  ['CMS login POST flood', {
    what: 'Auffällig viele Login-Absendungen von derselben Adresse.',
    why: 'Ein Anmelde-Versuch in Serie. Erfolg zeigt erst der Statuscode — siehe Weiterleitungen.',
  }],
  ['Requested PHP in upload/cache directory answered 2xx', {
    what: 'Jemand hat PHP in einem Upload-/Cache-Verzeichnis abgerufen — und der Server hat mit Erfolg geantwortet.',
    why: 'Das ist kein Scan ins Leere: Dort lag etwas Ausführbares und wurde ausgeliefert. Die stärkste Log-Spur einer benutzten Shell.',
  }],
  ['SQL injection patterns in URIs answered 2xx', {
    what: 'Angriffs-Muster für Datenbank-Injektion in der URL, vom Server mit Erfolg beantwortet.',
    why: 'Nur „beantwortet" heißt noch nicht „geklappt" — aber es lohnt der Abgleich mit den Datenbank-Funden.',
  }],
  ['Path traversal patterns answered 2xx', {
    what: 'Versuche, mit ../ aus dem Web-Verzeichnis auszubrechen, wurden erfolgreich beantwortet.',
    why: 'Kann das Auslesen fremder Dateien bedeuten. Welche URLs betroffen sind, steht im Trace.',
  }],
  ['Scanner tool User-Agent', {
    what: 'Der Client hat sich als bekanntes Scan-Werkzeug zu erkennen gegeben (sqlmap, nikto, …).',
    why: 'Hintergrundrauschen, solange nichts erfolgreich war — als Vorgeschichte trotzdem interessant.',
  }],
]

export function explainRule(rule: string): Explanation | null {
  for (const [needle, explanation] of RULE_EXPLAIN) {
    if (rule.includes(needle)) return explanation
  }
  return null
}

// --- Kategorien -------------------------------------------------------------
// Die oberste Gliederung der Findings-Liste: nicht "welche Datei", sondern
// "was für eine Art Fund". Ein Fall mit 119 Findings hat vielleicht 8
// Kategorien — das ist die Übersicht, mit der man anfängt.
//
// Die Reihenfolge ist die Lesereihenfolge einer Untersuchung: erst was
// SICHER da war (Shells, eingeschleuster Code), dann was jemand GETAN hat
// (Zugriff, Brute-Force), zuletzt das Rauschen (Scanner).

export interface Category {
  id: string
  label: string
  what: string
  order: number
}

export const CATEGORIES: Record<string, Category> = {
  webshell: {
    id: 'webshell', order: 1,
    label: 'Webshells & Backdoors',
    what: 'Dateien, die Befehle ausführen oder Eingaben von außen verarbeiten — und dort liegen, wo sie nicht hingehören.',
  },
  obfuscation: {
    id: 'obfuscation', order: 2,
    label: 'Verschleierter Code',
    what: 'Code, der absichtlich unlesbar gemacht wurde (kodierte Zeichenketten, goto-Sprünge). Verschleierung ist kein Beweis, aber ein Grund hinzusehen.',
  },
  htaccess: {
    id: 'htaccess', order: 3,
    label: '.htaccess-Manipulation',
    what: 'Server-Konfiguration, die harmlose Dateien ausführbar macht oder bei jedem Aufruf zusätzlichen Code lädt.',
  },
  db_injected: {
    id: 'db_injected', order: 4,
    label: 'Eingeschleuster Code in der Datenbank',
    what: 'Ausführbarer Code in Datenfeldern. Ein CMS speichert Code in Dateien — solcher Code überlebt jedes Bereinigen der Dateien.',
  },
  db_markup: {
    id: 'db_markup', order: 5,
    label: 'Script & Markup in Datenfeldern',
    what: 'JavaScript, iframes und Weiterleitungen in Inhalten. Kann redaktionell gewollt sein — hier zählt der Kontext.',
  },
  shell_access: {
    id: 'shell_access', order: 6,
    label: 'Zugriff auf abgelegte Dateien',
    what: 'Clients, die PHP in Upload-/Cache-Verzeichnissen abgerufen haben — und der Server hat erfolgreich geantwortet.',
  },
  bruteforce: {
    id: 'bruteforce', order: 7,
    label: 'Brute-Force & Logins',
    what: 'Massenhafte Login-Versuche. Ob einer davon geklappt hat, verrät die Weiterleitung danach.',
  },
  probes: {
    id: 'probes', order: 8,
    label: 'Angriffsmuster in URLs',
    what: 'SQL-Injection- und Path-Traversal-Muster, die der Server erfolgreich beantwortet hat.',
  },
  scanner: {
    id: 'scanner', order: 9,
    label: 'Scanner',
    what: 'Clients, die sich als bekanntes Scan-Werkzeug zu erkennen gegeben haben. Meist Hintergrundrauschen.',
  },
  other: {
    id: 'other', order: 99,
    label: 'Sonstige Funde',
    what: 'Alles, was in keine der übrigen Kategorien fällt.',
  },
}

// (Quelle, Regel-Teilstring) -> Kategorie. Die Quelle steht mit drin, weil
// dieselbe Regel in zwei Engines anderes bedeutet: "Obfuscation decode chain"
// in einer Datei ist Verschleierung, in einer Datenspalte eingeschleuster Code.
const CATEGORY_RULES: [string | null, string, string][] = [
  // --- Dateien (webshell) ---
  ['webshell', 'Obfuscation decode chain', 'obfuscation'],
  ['webshell', 'Hex/octal string obfuscation', 'obfuscation'],
  ['webshell', 'chr() concatenation', 'obfuscation'],
  ['webshell', 'goto-based control-flow', 'obfuscation'],
  ['webshell', '.htaccess', 'htaccess'],
  ['webshell', '', 'webshell'],                 // alles Übrige aus dem Datei-Scan
  // --- Datenbank (sqldb) ---
  ['sqldb', 'Inline <script>', 'db_markup'],
  ['sqldb', 'Injected <iframe>', 'db_markup'],
  ['sqldb', 'document.write', 'db_markup'],
  ['sqldb', '', 'db_injected'],                 // PHP, eval, exec, Verschleierung
  // --- Logs ---
  ['logs', 'upload/cache directory', 'shell_access'],
  ['logs', 'brute-force', 'bruteforce'],
  ['logs', 'login POST flood', 'bruteforce'],
  ['logs', 'Scanner tool User-Agent', 'scanner'],
  ['logs', 'SQL injection', 'probes'],
  ['logs', 'Path traversal', 'probes'],
]

export function categorize(source: string, rule: string): Category {
  for (const [src, needle, category] of CATEGORY_RULES) {
    if (src !== null && src !== source) continue
    if (needle === '' || rule.includes(needle)) return CATEGORIES[category]
  }
  return CATEGORIES.other
}

/** "12 Dateien" / "66 Clients" — wie die Artefakte einer Kategorie heißen. */
export function artifactNoun(kind: string, n: number): string {
  if (kind === 'file') return n === 1 ? 'Datei' : 'Dateien'
  if (kind === 'client') return n === 1 ? 'Client' : 'Clients'
  if (kind === 'table') return n === 1 ? 'Tabelle' : 'Tabellen'
  if (kind === 'dump') return n === 1 ? 'Dump' : 'Dumps'
  return n === 1 ? 'Artefakt' : 'Artefakte'
}

// --- Actor-Badges -----------------------------------------------------------

export const BADGE_EXPLAIN: Record<string, Explanation> = {
  'Login erfolgreich?': {
    what: 'Weiterleitung nach einer Serie von Login-Versuchen.',
    why: 'Das Muster eines geglückten Logins. Höchste Priorität in dieser Liste.',
  },
  'Shell-Zugriff 2xx': {
    what: 'Hat PHP in einem Upload-/Cache-Verzeichnis geladen und Erfolg zurückbekommen.',
    why: 'Dieser Client hat etwas benutzt, das dort nicht liegen sollte.',
  },
  'Brute-Force': {
    what: 'Viele Login-Absendungen von dieser Adresse.',
    why: 'Ob erfolgreich, verrät der Statuscode — siehe „Login erfolgreich?".',
  },
  'Scanner-UA': {
    what: 'Nennt sich selbst nach einem Scan-Werkzeug.',
    why: 'Meist automatisiertes Abklopfen; ohne Erfolgstreffer selten der Einstieg.',
  },
  'SQLi 2xx': {
    what: 'Injektions-Muster, die der Server erfolgreich beantwortet hat.',
  },
  'SQLi-Versuche': {
    what: 'Injektions-Muster, die NICHT erfolgreich beantwortet wurden.',
    why: 'Als Versuch geführt, nicht als Alarm — abgewehrte Angriffe sollen die Liste nicht röten.',
  },
  'Traversal 2xx': {
    what: 'Ausbruchsversuche aus dem Web-Verzeichnis, erfolgreich beantwortet.',
  },
}

// --- IOC-Tags ---------------------------------------------------------------

export const TAG_EXPLAIN: Record<string, Explanation> = {
  analyst: { what: 'Von dir selbst eingetragen.' },
  finding: { what: 'Stammt aus einem Finding dieses Falls.' },
  confirmed: { what: 'Wurde beim Bestätigen eines Findings aufgenommen.' },
  hunt: { what: 'Aus dem Log-Index: Dieser Client hat eine bestätigte Datei angefragt.' },
  actor: { what: 'Aus der Actors-Liste eingesammelt.' },
  derived: { what: 'Automatisch abgeleitet — etwa der SHA-256 zu einer bestätigten Datei.' },
  webshell: { what: 'Kennzeichnet den Fund als Webshell (laut der Regel, die ihn ausgelöst hat).' },
  'injected-code': { what: 'Eingeschleuster Code, z.B. in einer Datenbank-Spalte.' },
  'modified-file': { what: 'Veränderte Datei.' },
  account: { what: 'Ein Benutzerkonto.' },
  scanner: { what: 'Trat als Scan-Werkzeug auf.' },
  'brute-force': { what: 'Hat massenhaft Logins versucht.' },
  successful: { what: 'Etwas davon war erfolgreich (2xx bzw. Login-Weiterleitung).' },
  'threat-list': { what: 'Steht auf einer Bedrohungsliste.' },
}

// --- IOC-Typen --------------------------------------------------------------

export const IOC_TYPE_EXPLAIN: Record<string, string> = {
  ip: 'IP-Adresse eines Clients',
  hash: 'Prüfsumme einer Datei (SHA-256/SHA-1/MD5)',
  url: 'Vollständige URL',
  domain: 'Domain-Name',
  email: 'E-Mail-Adresse',
  path: 'Datei oder Pfad',
  user: 'Benutzerkonto',
  other: 'Sonstiges — z.B. ein Tabellenname',
}

// --- Spaltenköpfe & Kennzahlen ---------------------------------------------

export const FIELD_EXPLAIN: Record<string, string> = {
  requests: 'Wie viele Anfragen dieser Client insgesamt gestellt hat.',
  sparkline: 'Aktivität über den gesamten Zeitraum der Logs — eine Säule je Zeitabschnitt.',
  errors: 'Antworten mit 4xx/5xx. Viele Fehler bei wenigen Treffern sehen nach Abklopfen aus.',
  timespan: 'Erste und letzte Anfrage dieses Clients in den analysierten Logs.',
  cms_guard: 'Jede echte CMS-Datei beginnt mit einem Startschutz (_JEXEC / ABSPATH). Fehlt er, stammt die Datei nicht aus der Installation.',
  upload_dir: 'Verzeichnisse, in die ein Webserver schreiben darf (images, tmp, cache, uploads …). PHP gehört dort nicht hin.',
  sha256: 'Prüfsumme der Datei — eindeutige Kennung für Berichte und den Abgleich mit anderen Fällen.',
  log_index: 'Die Logs werden einmal in eine Datenbank eingelesen. Danach ist jede Auswertung eine Abfrage statt eines erneuten Durchlaufs.',
  unknown_version: 'Zu dieser Erweiterung ließ sich keine Version bestimmen — häufig bei unvollständigen oder veränderten Installationen.',
  admin_account: 'Konto mit vollen Rechten (WordPress: Administrator, Joomla: Super User).',
  weak_hash: 'Veraltetes Passwort-Verfahren (MD5). Solche Passwörter sind schnell zu knacken.',
  triage_note: 'Deine Begründung. Sie wandert mit in das Fall-Archiv.',
}
