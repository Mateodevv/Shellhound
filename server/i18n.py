"""English copy for server-generated narratives and API messages.

Legacy language arguments remain accepted so existing clients and download
links continue to work. They do not change the wording or stored case data.
"""
from __future__ import annotations

LANGUAGES = ("en",)
DEFAULT = "en"

CATALOGUE: dict[str, str] = {
    "chain.file.firstOk": "First request for {name} answered 2xx",
    "chain.file.wasThere": "The access log records a 2xx response for this path; this alone does not establish successful exploitation.",
    "chain.file.probeBefore": " An earlier request for it{by} was recorded at {at}.",
    "chain.hunt.first": "First selected Pattern Hunt match from {ip}",
    "chain.hunt.detail": "{method} {uri} · {status}; selected evidence from a confirmed finding. An HTTP response alone does not establish successful exploitation.",
    "chain.file.by": " from {ip}",
    "chain.file.firstTry": "First request for {name}",
    "chain.file.firstTry.detail": "requested {n}×, never answered with 2xx — the log does not prove a successful access",
    "chain.file.last": "Last request for {name}",
    "chain.file.last.detail": "{n} request(s) in total, {ok}× of them 2xx",
    "chain.file.fs.created": "Evidence copy of {name} created",
    "chain.file.fs.modified": "Content timestamp of {name}",
    "chain.file.fs.changed": "Metadata timestamp of {name}",
    "chain.file.fs.detail": "Filesystem metadata of the evidence copy; it does not prove when the webshell was uploaded, deployed or accessed.",
    "chain.client.first": "First request from {ip}",
    "chain.client.first.detail": "{n} request(s) in total",
    "chain.client.last": "Last request from {ip}",
    "chain.alert.detail": "triggered by: {example}",
    "chain.account.created": "Account {login} created",
    "chain.account.admin": " (administrator)",
    "chain.account.detail": "created in {table}",
    "chain.account.userTable": "the user table",
    "chain.account.lastLogin": "; last login according to the export {at}",
    "chain.undated.table": "the database export carries no timestamp for it — when the code was injected is something the case does not say",
    "chain.undated.dump": "a dump as a whole has no point in time within the incident",
    "chain.undated.file": "the log proves no request for this file — when it was placed there is something the case does not say",
    "chain.undated.client": "this client appears in no indexed log",
    "chain.undated.other": "without a measured point in time",
    "chain.beyondCap": "measured, but later than the {n} events shown here — the chronology is cut, not the evidence",
    "chain.gap.noConfirmed": "No artifact has been confirmed as a true positive yet. Until then this only lists what the database export dates by itself — the chronology fills up with the triage.",
    "chain.gap.noTimes": "The case carries no measured time for the confirmed artifacts: neither the log nor the database export says when they came into being.",
    "chain.gap.atLogStart": "The first event sits at the start of the log coverage ({at}). What happened before is not proven — the incident may be older than the logs at hand.",
    "chain.gap.onlyAttempts": "For none of the confirmed files does the log prove a successful access — only attempts.",
    "chain.gap.truncated": "More than {n} events; the chronology shows the earliest.",
    "related.fromEvidence": "named in the evidence of: {rule}",
    "chain.gap.clockOffset": "Clock alignment: the times from the {source} are moved {hours} hour(s) {direction} — set by the analyst.",
    "chain.clock.source.logs": "log",
    "chain.clock.source.dump": "database export",
    "chain.clock.forward": "forward",
    "chain.clock.back": "back",
    "account.admin": "Account with full privileges.",
    "account.young.sameDay": "created on the day of the export",
    "account.young.why": "Registered shortly before the export — in an incident the first question: who was that?",
    "account.weakHash.why": "MD5 without a salt — such passwords are cracked quickly.",
    "account.neverLoggedIn.why": "An administrator who has never signed in was created for something else.",
    "account.session.why": "This account was signed in at the time of the export.",
    "account.conspicuous": "Conspicuous",
    "geo.loopback": "Loopback — the server itself",
    "geo.private": "Private network (RFC 1918) — the traffic came through a proxy/load balancer or from the local network",
    "geo.documentation": "Documentation range (RFC 5737/3849) — deliberately unattributable",
    "geo.reserved": "Reserved range — not allocated on the public internet; as a source this points at spoofing or a capture artefact",
    "geo.unlisted": "not listed in the database",
    "geo.noPackage": "Python package maxminddb is not installed.",
    "geo.noDatabase": "No GeoIP database found — put a *.mmdb into the workspace (GeoLite2-Country or DB-IP Lite) or set SHELLHOUND_GEOIP.",
    "coverage.quiet": "The logs are silent for {hours} h between {start} and {end} — far longer than this log's own rhythm. That can be a quiet night; it can also be a window somebody removed.",
    "coverage.truncated": "{file} begins in the middle of a record. Rotation cuts on line boundaries — a head that starts mid-line means the beginning was removed.",
    "coverage.staleMtime": "{file} was last modified BEFORE its own last entry. A file cannot be written before the last thing written into it.",
    "coverage.summary": "{n} note(s) on the coverage of these logs — see the chronology.",
    "index.none": "no index built",
    "index.stale": "evidence has changed ({added} file(s) new/modified, {gone} removed) — rebuild the index",
    "index.oldVersion": "index comes from an older version",
    "err.jobsRunning": "Jobs are still running that could not be stopped in time. Please wait a moment and close the case again.",
    "err.fileNotFound": "file not found",
    "err.fileAccessDenied": "access to this evidence file was denied; check permissions and security software",
    "err.filePathUnavailable": "the evidence path could not be resolved; check the drive, network connection and path",
    "err.outsideEvidence": "This file lies outside the registered evidence of this case and is not read.",
    "err.notRegularFile": "not a regular file",
    "err.revealUnavailable": "the local file manager is unavailable",
    "err.noFolder": "no folder given",
    "err.sameTree": "a tree compared with itself says nothing",
    "err.patternKnown": "This pattern is already in the library.",
    "detect.contains": "contains",
    "detect.cms": "{cms} installation —",
    "detect.phpHere": "{n} PHP file(s) at this level",
    "detect.logFiles": "{n} log file(s), {bytes} bytes",
    "detect.inDirs": "in {n} directories",
    "detect.logParsed": "{parsed} of {sampled} sample lines parse as web server requests (e.g. {example})",
    "err.patternTooShort": "The pattern is too unspecific — at least 3 characters besides wildcards.",
    "err.patternUnknown": "Unknown pattern.",
    "err.patternJson": "not valid JSON",
    "err.patternEmpty": "A pattern needs at least one path.",
    "err.patternTooMany": "At most 8 paths in one pattern — beyond that it stops being a rule and becomes a query.",
    "err.patternMatchMode": "Unknown combination. Either 'any' (a client that hit at least one path) or 'all' (only clients that hit every one).",
    "err.ruleUnknown": "Unknown rule.",
    "err.yaraName": "A rule file name may hold letters, digits, dot, dash and underscore only.",
    "err.yaraUnknown": "No such rule file.",
    "err.yaraCompile": "YARA could not compile this rule",
    "err.evidenceMissing": "Path does not exist: {path}",
    "err.patternBundled": "A pattern shipped with SHELLHOUND cannot be edited — it is the same on every installation, which is what makes it citable. Switch it off and add your own version.",
    "signal.admin": "Admin",
    "signal.young.days": "created {n} day(s) ago",
    "signal.weakHash": "weak hash",
    "signal.never": "never signed in",
    "signal.session": "open session",
    "signal.blocked": "blocked",
    "account.blocked.why": "Disabled by the CMS.",
    "csv.login": "Login",
    "csv.email": "E-mail",
    "csv.role": "Role",
    "csv.table": "Table",
    "csv.registered": "Registered",
    "csv.lastLogin": "Last login",
    "csv.hashScheme": "Hash scheme",
    "csv.blocked": "Blocked",
    "csv.administrator": "Administrator",
    "csv.user": "User",
    "csv.yes": "yes",
    "csv.no": "no"
}


def lang_of(value: str | None) -> str:
    """All requests use English, including legacy language preferences."""
    return DEFAULT


def t(lang: str, key: str, **vars: object) -> str:
    """Look up English copy and fill placeholders; unknown keys stay visible."""
    text = CATALOGUE.get(key, key)
    for name, value in vars.items():
        text = text.replace("{%s}" % name, str(value))
    return text
