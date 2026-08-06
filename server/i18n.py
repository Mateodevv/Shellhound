"""Language handling for the prose the SERVER assembles.

Most of what SHELLHOUND shows is written in the frontend and translated
there. Some of it is not: the chronology of a case, the GeoIP descriptions,
the observations on an account, and the error messages of the API are
assembled from measured data at request time and can only be phrased where
that data is.

Those texts go through this module. The browser sends its language in the
`X-Lang` header (`api.ts`), a download link sends it as `?lang=`, and
`lang_of()` turns either into one of `LANGUAGES`.

WHAT DOES **NOT** BELONG HERE is anything that gets STORED: the origin of an
indicator, the evidence line of a finding, the detail of an alert, the
progress message of a job. Those travel into the case archive and into
reports, and an archive whose wording depends on which language happened to
be selected at the time of a click is worthless as evidence. They are
English, always -- the project language.

The catalogue is flat and dotted, like the frontend one, so a key can be
grepped across both halves of the codebase.
"""
from __future__ import annotations

LANGUAGES = ("en", "de")
DEFAULT = "en"

# key -> {lang: text}. `{name}` placeholders are filled by `t()`.
CATALOGUE: dict[str, dict[str, str]] = {
    # --- chronology: events -------------------------------------------
    "chain.file.firstOk": {
        "en": "First successful request for {name}",
        "de": "Erster erfolgreicher Abruf von {name}",
    },
    "chain.file.wasThere": {
        "en": "the file was there at this point at the latest",
        "de": "die Datei lag spätestens zu diesem Zeitpunkt dort",
    },
    "chain.file.probeBefore": {
        "en": ". A request for it{by} came up empty at {at} — so the file "
              "appeared in between",
        "de": ". Eine Anfrage darauf{by} lief um {at} noch ins Leere — die "
              "Datei entstand also dazwischen",
    },
    "chain.file.by": {"en": " from {ip}", "de": " von {ip}"},
    "chain.file.firstTry": {
        "en": "First request for {name}",
        "de": "Erste Anfrage auf {name}",
    },
    "chain.file.firstTry.detail": {
        "en": "requested {n}×, never answered with 2xx — the log does not "
              "prove a successful access",
        "de": "{n}× angefragt, nie mit 2xx beantwortet — ein erfolgreicher "
              "Zugriff ist im Log nicht belegt",
    },
    "chain.file.last": {
        "en": "Last request for {name}",
        "de": "Letzter Abruf von {name}",
    },
    "chain.file.last.detail": {
        "en": "{n} request(s) in total, {ok}× of them 2xx",
        "de": "insgesamt {n} Anfrage(n), davon {ok}× 2xx",
    },
    "chain.client.first": {
        "en": "First request from {ip}",
        "de": "Erste Anfrage von {ip}",
    },
    "chain.client.first.detail": {
        "en": "{n} request(s) in total",
        "de": "{n} Anfrage(n) insgesamt",
    },
    "chain.client.last": {
        "en": "Last request from {ip}",
        "de": "Letzte Anfrage von {ip}",
    },
    "chain.alert.detail": {
        "en": "triggered by: {example}",
        "de": "ausgelöst durch: {example}",
    },
    "chain.account.created": {
        "en": "Account {login} created",
        "de": "Konto {login} angelegt",
    },
    "chain.account.admin": {"en": " (administrator)", "de": " (Administrator)"},
    "chain.account.detail": {
        "en": "created in {table}",
        "de": "in {table} angelegt",
    },
    "chain.account.userTable": {
        "en": "the user table", "de": "der Benutzertabelle",
    },
    "chain.account.lastLogin": {
        "en": "; last login according to the export {at}",
        "de": "; letzte Anmeldung laut Export {at}",
    },

    # --- chronology: what carries no measured time --------------------
    "chain.undated.table": {
        "en": "the database export carries no timestamp for it — when the "
              "code was injected is something the case does not say",
        "de": "der Datenbank-Export trägt keinen Zeitstempel dafür — wann "
              "der Code eingeschleust wurde, sagt der Fall nicht",
    },
    "chain.undated.dump": {
        "en": "a dump as a whole has no point in time within the incident",
        "de": "ein Dump als Ganzes hat keinen Zeitpunkt im Vorfall",
    },
    "chain.undated.file": {
        "en": "the log proves no request for this file — when it was placed "
              "there is something the case does not say",
        "de": "im Log ist kein Abruf dieser Datei belegt — wann sie dort "
              "abgelegt wurde, sagt der Fall nicht",
    },
    "chain.undated.client": {
        "en": "this client appears in no indexed log",
        "de": "dieser Client steht in keinem indizierten Log",
    },
    "chain.undated.other": {
        "en": "without a measured point in time",
        "de": "ohne gemessenen Zeitpunkt",
    },

    # --- chronology: what the case does NOT prove ---------------------
    "chain.gap.noConfirmed": {
        "en": "No artifact has been confirmed as a true positive yet. Until "
              "then this only lists what the database export dates by "
              "itself — the chronology fills up with the triage.",
        "de": "Noch ist kein Artefakt als True Positive bestätigt. Bis dahin "
              "steht hier nur, was der Datenbank-Export von sich aus "
              "datiert — die Chronologie füllt sich mit der Triage.",
    },
    "chain.gap.noTimes": {
        "en": "The case carries no measured time for the confirmed "
              "artifacts: neither the log nor the database export says when "
              "they came into being.",
        "de": "Zu den bestätigten Artefakten trägt der Fall keine gemessene "
              "Zeit: weder das Log noch der Datenbank-Export sagt, wann sie "
              "entstanden sind.",
    },
    "chain.gap.atLogStart": {
        "en": "The first event sits at the start of the log coverage ({at}). "
              "What happened before is not proven — the incident may be "
              "older than the logs at hand.",
        "de": "Das erste Ereignis liegt am Anfang der Log-Abdeckung ({at}). "
              "Was davor geschah, ist nicht belegt — der Vorfall kann älter "
              "sein als die vorliegenden Logs.",
    },
    "chain.gap.onlyAttempts": {
        "en": "For none of the confirmed files does the log prove a "
              "successful access — only attempts.",
        "de": "Auf keine der bestätigten Dateien ist im Log ein "
              "erfolgreicher Zugriff belegt — nur Versuche.",
    },
    "chain.gap.truncated": {
        "en": "More than {n} events; the chronology shows the earliest.",
        "de": "Mehr als {n} Ereignisse; die Chronologie zeigt die frühesten.",
    },
    "chain.gap.clockOffset": {
        "en": "Clock alignment: the times from the {source} are moved "
              "{hours} hour(s) {direction} — set by the analyst.",
        "de": "Uhren-Abgleich: die Zeiten aus dem {source} sind um {hours} "
              "Stunde(n) {direction}gestellt — vom Analysten gesetzt.",
    },
    "chain.clock.source.logs": {"en": "log", "de": "Log"},
    "chain.clock.source.dump": {
        "en": "database export", "de": "Datenbank-Export",
    },
    "chain.clock.forward": {"en": "forward", "de": "vor"},
    "chain.clock.back": {"en": "back", "de": "zurück"},

    # --- account observations -----------------------------------------
    "account.admin": {
        "en": "Account with full privileges.",
        "de": "Konto mit vollen Rechten.",
    },
    "account.young.sameDay": {
        "en": "created on the day of the export",
        "de": "am Tag des Exports angelegt",
    },
    "account.young.why": {
        "en": "Registered shortly before the export — in an incident the "
              "first question: who was that?",
        "de": "Kurz vor dem Export registriert — bei einem Vorfall die erste "
              "Frage: wer war das?",
    },
    "account.weakHash.why": {
        "en": "MD5 without a salt — such passwords are cracked quickly.",
        "de": "MD5 ohne Salt — solche Passwörter sind schnell geknackt.",
    },
    "account.neverLoggedIn.why": {
        "en": "An administrator who has never signed in was created for "
              "something else.",
        "de": "Ein Administrator, der sich nie angemeldet hat, wurde für "
              "etwas anderes angelegt.",
    },
    "account.session.why": {
        "en": "This account was signed in at the time of the export.",
        "de": "Beim Export war dieses Konto angemeldet.",
    },
    "account.conspicuous": {"en": "Conspicuous", "de": "Auffällig"},

    # --- GeoIP ---------------------------------------------------------
    "geo.loopback": {
        "en": "Loopback — the server itself",
        "de": "Loopback — der Server selbst",
    },
    "geo.private": {
        "en": "Private network (RFC 1918) — the traffic came through a "
              "proxy/load balancer or from the local network",
        "de": "Privates Netz (RFC 1918) — der Verkehr kam durch einen "
              "Proxy/Load-Balancer oder aus dem eigenen Netz",
    },
    "geo.documentation": {
        "en": "Documentation range (RFC 5737/3849) — deliberately "
              "unattributable",
        "de": "Dokumentations-Bereich (RFC 5737/3849) — absichtlich "
              "unzuordenbar",
    },
    "geo.reserved": {"en": "Reserved range", "de": "Reservierter Bereich"},
    "geo.unlisted": {
        "en": "not listed in the database",
        "de": "in der Datenbank nicht verzeichnet",
    },
    "geo.noPackage": {
        "en": "Python package maxminddb is not installed.",
        "de": "Python-Paket maxminddb ist nicht installiert.",
    },
    "geo.noDatabase": {
        "en": "No GeoIP database found — put a *.mmdb into the workspace "
              "(GeoLite2-Country or DB-IP Lite) or set SHELLHOUND_GEOIP.",
        "de": "Keine GeoIP-Datenbank gefunden — eine *.mmdb in den Workspace "
              "legen (GeoLite2-Country oder DB-IP Lite) oder "
              "SHELLHOUND_GEOIP setzen.",
    },

    # --- log coverage: what the logs do NOT cover ----------------------
    "coverage.quiet": {
        "en": "The logs are silent for {hours} h between {start} and {end} — "
              "far longer than this log's own rhythm. That can be a quiet "
              "night; it can also be a window somebody removed.",
        "de": "Die Logs schweigen {hours} h zwischen {start} und {end} — weit "
              "länger als der eigene Takt dieses Logs. Das kann eine ruhige "
              "Nacht sein; es kann auch ein Fenster sein, das jemand "
              "entfernt hat.",
    },
    "coverage.truncated": {
        "en": "{file} begins in the middle of a record. Rotation cuts on "
              "line boundaries — a head that starts mid-line means the "
              "beginning was removed.",
        "de": "{file} beginnt mitten in einem Eintrag. Rotation schneidet an "
              "Zeilengrenzen — ein Anfang mitten in der Zeile heißt, dass "
              "der Beginn entfernt wurde.",
    },
    "coverage.backwards": {
        "en": "In {file} the timestamps step backwards {n}×. A web server "
              "appends in order, so lines were edited, reordered or spliced.",
        "de": "In {file} gehen die Zeitstempel {n}× rückwärts. Ein Webserver "
              "hängt der Reihe nach an — also wurden Zeilen bearbeitet, "
              "umsortiert oder zusammengesetzt.",
    },
    "coverage.staleMtime": {
        "en": "{file} was last modified BEFORE its own last entry. A file "
              "cannot be written before the last thing written into it.",
        "de": "{file} wurde zuletzt VOR seinem eigenen letzten Eintrag "
              "geändert. Eine Datei kann nicht geschrieben worden sein, "
              "bevor das Letzte in sie geschrieben wurde.",
    },
    "coverage.summary": {
        "en": "{n} note(s) on the coverage of these logs — see the "
              "chronology.",
        "de": "{n} Anmerkung(en) zur Abdeckung dieser Logs — siehe "
              "Chronologie.",
    },

    # --- log index status ----------------------------------------------
    "index.none": {"en": "no index built", "de": "kein Index gebaut"},
    "index.stale": {
        "en": "evidence has changed ({added} file(s) new/modified, {gone} "
              "removed) — rebuild the index",
        "de": "Evidence hat sich geändert ({added} Datei(en) neu/verändert, "
              "{gone} entfernt) — Index neu bauen",
    },
    "index.oldVersion": {
        "en": "index comes from an older version",
        "de": "Index stammt von einer älteren Version",
    },

    # --- errors and validation -----------------------------------------
    "err.jobsRunning": {
        "en": "Jobs are still running that could not be stopped in time. "
              "Please wait a moment and close the case again.",
        "de": "Es laufen noch Jobs, die nicht rechtzeitig beendet werden "
              "konnten. Bitte kurz warten und den Fall erneut schließen.",
    },
    "err.fileNotFound": {"en": "file not found", "de": "Datei nicht gefunden"},
    "err.outsideEvidence": {
        "en": "This file lies outside the registered evidence of this case "
              "and is not read.",
        "de": "Diese Datei liegt außerhalb der registrierten Evidence dieses "
              "Falls und wird nicht gelesen.",
    },
    "err.notRegularFile": {
        "en": "not a regular file", "de": "kein reguläres File",
    },
    "err.noFolder": {"en": "no folder given", "de": "kein Ordner angegeben"},
    "err.sameTree": {
        "en": "a tree compared with itself says nothing",
        "de": "ein Baum verglichen mit sich selbst sagt nichts",
    },
    "err.patternKnown": {
        "en": "This pattern is already in the library.",
        "de": "Dieses Muster steht schon in der Bibliothek.",
    },

    # --- evidence detection ---------------------------------------------
    "detect.contains": {"en": "contains", "de": "enthält"},
    "detect.cms": {
        "en": "{cms} installation —", "de": "{cms}-Installation —",
    },
    "detect.phpHere": {
        "en": "{n} PHP file(s) at this level",
        "de": "{n} PHP-Datei(en) auf dieser Ebene",
    },
    "detect.logFiles": {
        "en": "{n} log file(s), {bytes} bytes",
        "de": "{n} Log-Datei(en), {bytes} Bytes",
    },
    "detect.inDirs": {
        "en": "in {n} directories", "de": "in {n} Verzeichnissen",
    },
    "detect.logParsed": {
        "en": "{parsed} of {sampled} sample lines parse as web server "
              "requests (e.g. {example})",
        "de": "{parsed} von {sampled} Beispielzeilen parsen als "
              "Webserver-Requests (z.B. {example})",
    },

    # --- pattern library validation --------------------------------------
    "err.patternTooShort": {
        "en": "The pattern is too unspecific — at least 3 characters besides "
              "wildcards.",
        "de": "Das Muster ist zu unspezifisch — mindestens 3 Zeichen außer "
              "Platzhaltern.",
    },
    "err.patternUnknown": {"en": "Unknown pattern.", "de": "Unbekanntes Muster."},
    "err.patternJson": {"en": "not valid JSON", "de": "Kein gültiges JSON"},
    "err.patternBundled": {
        "en": "A pattern shipped with SHELLHOUND cannot be edited — it is the "
              "same on every installation, which is what makes it citable. "
              "Switch it off and add your own version.",
        "de": "Ein mit SHELLHOUND ausgeliefertes Muster lässt sich nicht "
              "ändern — es ist auf jeder Installation dasselbe, und genau "
              "das macht es zitierbar. Schalte es ab und lege deine eigene "
              "Fassung an.",
    },

    # --- account signal labels -------------------------------------------
    "signal.admin": {"en": "Admin", "de": "Admin"},
    "signal.young.days": {
        "en": "created {n} day(s) ago", "de": "vor {n} Tag(en) angelegt",
    },
    "signal.weakHash": {"en": "weak hash", "de": "schwacher Hash"},
    "signal.never": {"en": "never signed in", "de": "nie angemeldet"},
    "signal.session": {"en": "open session", "de": "offene Sitzung"},
    "signal.blocked": {"en": "blocked", "de": "gesperrt"},
    "account.blocked.why": {
        "en": "Disabled by the CMS.", "de": "Vom CMS deaktiviert.",
    },

    # --- accounts.csv column heads ---------------------------------------
    "csv.login": {"en": "Login", "de": "Login"},
    "csv.email": {"en": "E-mail", "de": "E-Mail"},
    "csv.role": {"en": "Role", "de": "Rolle"},
    "csv.table": {"en": "Table", "de": "Tabelle"},
    "csv.registered": {"en": "Registered", "de": "Registriert"},
    "csv.lastLogin": {"en": "Last login", "de": "Letzter Login"},
    "csv.hashScheme": {"en": "Hash scheme", "de": "Hash-Verfahren"},
    "csv.blocked": {"en": "Blocked", "de": "Gesperrt"},
    "csv.administrator": {"en": "Administrator", "de": "Administrator"},
    "csv.user": {"en": "User", "de": "User"},
    "csv.yes": {"en": "yes", "de": "ja"},
    "csv.no": {"en": "no", "de": "nein"},
}


def lang_of(value: str | None) -> str:
    """Normalise whatever the client sent into a supported language."""
    code = (value or "").strip().lower()[:2]
    return code if code in LANGUAGES else DEFAULT


def t(lang: str, key: str, **vars: object) -> str:
    """Look up `key` and fill its placeholders.

    An unknown key returns itself: a missing translation should be
    conspicuous in the interface, not silently empty.
    """
    entry = CATALOGUE.get(key)
    if entry is None:
        return key
    text = entry.get(lang) or entry.get(DEFAULT) or key
    for name, value in vars.items():
        text = text.replace("{%s}" % name, str(value))
    return text
