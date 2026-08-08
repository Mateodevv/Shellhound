# Detection rules

Every rule that produces a finding in SHELLHOUND — what triggers it
technically, what it **states** and what it does **not** state.

This file is a reference, not a second source: the rules live in
[`server/engines/`](../server/engines), their plain-language texts in
[`web/src/explain.ts`](../web/src/explain.ts) and the catalogues under
[`web/src/i18n/`](../web/src/i18n). Whoever changes a rule changes it there
and brings this file along.

The **account observations** of the database view (admin, created shortly
before the export, weak hash, never signed in, open session, blocked) are
likewise not findings but a sorting aid: a dump cannot say that an account is
malicious — only what stands out about it.

**CMS coverage.** WordPress and Joomla are parsed in detail: inventory,
extension versions, and accounts read by column position from their fixed
schemas. Drupal, TYPO3, Magento, PrestaShop and Contao are RECOGNISED — the
dump is named and its accounts are read by column NAME, which is the only
signal left when the schema is unknown. Any other CMS falls into the same
generic path: a table counts as an account table when its columns carry an
identity, an e-mail and a password. All three are required — a name and an
e-mail alone would turn every orders table into an account list and bury the
one planted administrator.

The **CMS inventory** produces no findings — it describes what is installed.
Every version carries with it the file it was read from (manifest,
`style.css`, plugin header, `version.php`) and can be corrected by hand in
the inventory; the measured value stays visible next to it.

## Where a rule lives

| Kind of rule | Written as | Where |
|---|---|---|
| What is **inside** a file | YARA | [`server/rules_bundled/`](../server/rules_bundled), shipped with the version |
| Your own rules over files | YARA | `<workspace>/yara/`, yours alone |
| Your own rules over the logs | SIGMA | `<workspace>/sigma/`, yours alone |
| Values in a database export | Python regex | `server/engines/sqldump.py` |
| A file's **location** or **name** | Python | `server/engines/webshell.py` |
| Aggregates over the log index | Python | `server/engines/logindex.py` |

The split is not arbitrary. YARA is handed bytes and never learns where they
came from, so "this PHP file sits in an upload directory" is not expressible
in it — and a database cell or a count over a million log lines is not a file
at all. Everything that *is* a question about file content is a YARA rule, and
can be read in the interface: **Settings → Detection** shows the source of
every rule beside its switch, because what a rule matches on is the only thing
that says whether you want it.

`yara-python` is therefore a **required** dependency, not an optional one. It
was optional while YARA only ran rules you brought yourself; now a missing
package would mean thirteen detections quietly not running.

### SIGMA, for the logs

YARA answers "is this pattern in this file". A log line is not a file and the
questions are about a FIELD -- this status, that method, a user agent
containing something. SIGMA is the format that already exists for that, so
`<workspace>/sigma/*.yml` runs against the log index and writes findings on
the client, like every other log rule.

**A rule this backend cannot answer is refused at load, with the reason, and
listed under skipped.** It is never loaded and left to match nothing: a
detection rule that silently never fires is the worst object in a forensic
tool, because it looks like evidence of absence.

| Supported | Not supported |
|---|---|
| `contains`, `startswith`, `endswith`, equality | `\|re` |
| `and`, `or`, `not`, parentheses | `\| count() by ...` and `timeframe` |
| `all of them`, `1 of them`, `all of sel*` | fields the index does not carry |
| `c-uri`, `c-useragent`, `cs-method`, `sc-status`, `c-ip` | |

**Outcome-gating stays the engine's job**, because a SIGMA rule cannot state
it: the backend always reports how many matches were answered 2xx, and a rule
that hit only refusals lands at LOW rather than the level it asked for.

**None of the six built-in log rules were converted.** Only the scanner
user-agent rule translates without loss; the injection, traversal and
upload-path rules are real regular expressions over a path, and rewriting them
as substring lists would silently change what they match. The other two are a
flood and a sequence, which need SIGMA's aggregation part. They stay in the
engine until the backend can run them unchanged.

## Every rule can be switched off

Under *Settings → Detection*, per workspace, by the stable id each rule
carries (`webshell.upload_php`, `logs.sqli`, ...). The id lives beside the
rule in the engine, so it survives a change of wording.

**A switch is not a retraction.** A rule that is switched off stops running;
findings it already wrote stay where they are, with their triage.

**But the work list shrinks.** An artifact whose findings ALL came from muted
rules leaves the list — that is what the switch is for. Only while it is still
UNDECIDED: a confirmed or reviewed artifact stays, because the decision is
yours and outranks the rule that prompted it. Nothing is deleted either way,
and the list states how many artifacts went, because a work list that quietly
shrinks reads like a clean system.

The setting belongs to the **workspace**, not the case: "this rule is noise on
the systems I work on" is knowledge about the analyst's practice, not about
one incident. A rule an upgrade adds arrives switched **on** — an unknown id
counts as enabled, so a stale off-list cannot silence something new.

## Two principles that hold everywhere

**Probe rules are outcome-gated.** SQL injection, path traversal and requests
for PHP in upload directories only become a finding when at least one of
those requests was answered with **2xx**. Repelled attempts stay visible as a
counter on the actor — a blocked wave of attacks should not redden the work
list.

**What could not be assessed does not disappear.** An unreadable or oversized
file in the wrong place becomes a finding itself. Inert PHP stubs and skipped
files land in their own tables (`inert_php`, `skipped`). An unexamined find
is reported, not passed over in silence.

## Severities

| Level | Meaning |
|---|---|
| **HIGH** (0) | A state of affairs for which there is hardly a harmless explanation. |
| **MEDIUM** (1) | Conspicuous, but it can be legitimate — needs context. |
| **LOW** (2) | Weak signal, usually interesting only in combination. |
| **INFO** (3) | Context without a statement about *this* system. Hidden by default. |

## Overview

| Engine | Rule | Level |
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
| Webshell | Callback taken straight from the request | HIGH |
| Webshell | File dropper writing request input to disk | HIGH |
| Webshell | .htaccess maps non-PHP extension to PHP handler | HIGH |
| Webshell | .htaccess auto_prepend/append_file backdoor | HIGH |
| Webshell | Obfuscation decode chain | MEDIUM |
| Webshell | Hex/octal string obfuscation | MEDIUM |
| Webshell | chr() concatenation obfuscation | MEDIUM |
| Webshell | goto-based control-flow obfuscation | MEDIUM |
| Webshell | Standalone command-execution shell | MEDIUM |
| Webshell | Code assembled at runtime with create_function | MEDIUM |
| Webshell | PHP file containing no PHP, only an HTML page | MEDIUM |
| Webshell | Upload destination taken from the request | MEDIUM |
| Database | PHP open tag in database value | HIGH |
| Database | eval/assert on decoded or request input | HIGH |
| Database | Obfuscation decode chain | HIGH |
| Database | Command execution call in database value | HIGH |
| Database | create_function / dynamic callback | HIGH |
| Database | Inline `<script>` in database value | MEDIUM |
| Database | Injected `<iframe>` in database value | MEDIUM |
| Database | document.write (script injection) | MEDIUM |
| Logs | Possible successful brute-force | HIGH |
| Logs | Requested PHP in upload/cache directory answered 2xx | HIGH |
| Logs | Requested PHP directly in a CMS extension directory answered 2xx | HIGH |
| Logs | CMS login POST flood | MEDIUM |
| Logs | SQL injection patterns in URIs answered 2xx | MEDIUM |
| Logs | Path traversal patterns answered 2xx | MEDIUM |
| Logs | Request matching a stored pattern | HIGH / LOW |
| Logs | Scanner tool User-Agent | INFO |
| Error log | PHP error names this file (fatal/parse) | MEDIUM |
| Error log | PHP error names this file | LOW |
| YARA | *your own rules* | from rule metadata |

---

# Webshell scan

Source: [`server/engines/webshell.py`](../server/engines/webshell.py) ·
Artifact: **file**

## Location and file name

### Unguarded PHP in writable upload directory — HIGH

**Trigger:** a PHP file in a writable directory (`images`, `tmp`, `cache`,
`media`, `files`, `assets`, `upload(s)`, `wp-content/uploads`,
`wp-content/cache`) **and** no CMS bootstrap guard in the first 4 KB
(`_JEXEC`, `JPATH_PLATFORM`, `ABSPATH`, `WPINC`, "restricted access")
**and** an executable surface (request superglobals, `eval`/`system`/…,
decoders, write functions, variable function calls).

**What it states:** an executable PHP file sits where uploads land, and it
does not carry the bootstrap guard that every genuine CMS file has.

**Why it counts:** together with "can execute something" this is the classic
find of a dropped shell. The guard is the most effective discriminator from
the real Joomla cases — it separates the installation from what someone put
into it.

**Limits:** the guard is searched for as a string, not checked structurally —
a `// _JEXEC` in a comment disarms this rule. The content rules below still
apply then. Without an executable surface the file is booked as `inert`
rather than reported; that keeps the list free of the thousands of empty
`index.php` stubs a CMS creates.

### Double extension disguise — HIGH

**Trigger:** the file name ends in a harmless plus an executable extension,
e.g. `logo.jpg.php`, `document.pdf.phtml`.

**What it states:** the name disguises itself with a harmless extension in
front of the real one.

**Why it counts:** what gets executed is the **last** extension. This
combination arises practically only when upload filters are being bypassed.

### PHP code hidden inside image file — HIGH

**Trigger:** `<?php` or `<?=` in a file with an image extension.

**What it states:** a PHP tag sits inside an image file.

**Why it counts:** a genuine image contains no PHP code. Typical for uploads
smuggled past an image check.

### Unguarded-location PHP could not be read — HIGH

**Trigger:** PHP in an upload directory, but a read or stat error.

**What it states:** the file sits in the wrong place and could not be read
(permissions, damaged copy).

**Why it counts:** an unexamined find is reported rather than passed over.
Check permissions and secure it again.

**Most common cause in practice:** the **antivirus scanner of the analysis
machine**. It intervenes on ACCESS, not on copying — so the file is present
in the webroot image but cannot be opened (under Windows Defender as
`[Errno 22] Invalid argument`), or it disappears into quarantine. Affected
are, of all things, the clearest finds, such as `eval()` on request input.
Whoever examines a real webroot copy therefore excludes the evidence folder
from real-time scanning — otherwise exactly what one is looking for goes
missing.

### PHP in writable upload directory (too large to inspect) — HIGH

**Trigger:** PHP in an upload directory, larger than 5 MB.

**What it states:** the file sits in the wrong place but was too large for
the content check.

**Why it counts:** not assessed but reported — a manual look pays off here.

## Content

Line by line against the file text; the matching line is attached to the
finding. These rules run against **every** PHP file, regardless of location —
unlike the location rule above. A shell with a forged guard stays visible
here.

### eval/assert on decoded or request input — HIGH

**Trigger:** `eval(` / `assert(` directly on `base64_decode`, `gzinflate`,
`gzuncompress`, `str_rot13`, `strrev` or `$_POST`/`$_GET`/`$_REQUEST`/
`$_COOKIE`.

**What it states:** the code executes what comes in from outside or what was
just unpacked.

**Why it counts:** this lets the caller have arbitrary code executed — the
core piece of almost every web shell.

### Variable function called on request input — HIGH

**Trigger:** `$variable($_POST[...])` — function name from a variable,
argument from the request.

**What it states:** which function is called is decided by a parameter from
the request.

**Why it counts:** an obfuscated form of "execute what I send". Legitimate
code practically never does this.

### Command execution on request input — HIGH

**Trigger:** `system`, `exec`, `shell_exec`, `passthru`, `proc_open`,
`popen`, `pcntl_exec` with request data within 40 characters in the argument.

**What it states:** a system command is assembled from values out of the
request.

**Why it counts:** it allows commands on the server. If the file was
reachable, this is a way into the system.

### preg_replace with /e modifier — HIGH

**Trigger:** `preg_replace` with the `e` modifier in the pattern.

**What it states:** an obsolete PHP function that executes the replacement
text as **code**.

**Why it counts:** removed since PHP 7 — in current code there is no
legitimate reason for it.

### Callback taken straight from the request — HIGH

**Trigger:** `call_user_func(_array)($_...)`.

**What it states:** which function is called is decided by the request.

**Why it counts:** whatever the browser can spell, it can call. Legitimate
code names its own callbacks.

**Was one rule with the next-but-one entry** until the shared name --
"create_function / callback on request input" -- turned out to be false of
half of what it matched: `create_function` names no superglobal.

### Code assembled at runtime with create_function — MEDIUM

**Trigger:** `create_function('...`.

**What it states:** a function body is built from a string at runtime.

**Why it counts:** in a shell it stands in for `eval`. In a library older
than PHP 7.2 it is ordinary, which is why this alone is not HIGH.

### File dropper writing request input to disk — HIGH

**Trigger:** `file_put_contents` or `fwrite` with
`$_POST`/`$_GET`/`$_REQUEST`/`$_FILES` within 80 characters.

**Not `move_uploaded_file`.** It is the one correct way to accept an upload
in PHP -- the function exists to refuse a path that was not uploaded -- so
every CMS with an upload form contains it, and each was answered with HIGH
and "this is how further shells are pulled in". The narrow case worth
keeping is the entry below.

**What it states:** the file writes incoming data to disk.

**Why it counts:** this is how further shells are pulled in. Check what else
is new in the surroundings.

### Upload destination taken from the request — MEDIUM

**Trigger:** `move_uploaded_file(..., ...$_POST/$_GET/$_REQUEST...)` -- request
input in the DESTINATION argument, after the comma.

**What it states:** an upload is moved to a path the request chose.

**Why it counts:** whoever picks the path picks the extension. MEDIUM and not
HIGH because a form that keeps the filename the browser sent looks the same
from here; what to check is whether the extension is restricted.

### PHP file containing no PHP, only an HTML page — MEDIUM

**Trigger:** a `.php` file with `<html` in it and no `<?` anywhere.

**What it states:** the interpreter has nothing to do with this file,
and a visitor is served it under the site's own address.

**Why it counts:** measured on a compromised Joomla — 671 PHP files, two
of them without a single `<?`. One was a changelog carrying the
extension: text, no HTML, not matched here. The other was the site's
`index.php`, 893 KB of a foreign-language spam page, and not one rule
said a word about it. Across all 1744 files of that webroot this rule
fires once.

**Why MEDIUM.** Nothing here executes. What the finding states is that a
file is not what its name says — and where that file is the webroot's own
`index.php`, it is the most visible fact about the case.

### Obfuscation decode chain — MEDIUM

**Trigger:** nested decoders, e.g. `base64_decode(str_rot13(...))`,
`gzinflate(base64_decode(...))`.

**What it states:** several encoding steps are nested inside one another.

**Why it counts:** obfuscation of this kind serves to hide. What comes out at
the end has to be looked at.

### Hex/octal string obfuscation — MEDIUM

**Trigger:** at least 10 consecutive `\xNN` or `\NNN` escapes.

**What it states:** text is written as a long chain of escapes instead of
plain text.

**Why it counts:** it makes search terms invisible. Legitimate code writes
URLs and function names out in full.

### chr() concatenation obfuscation — MEDIUM

**Trigger:** at least five `chr(n).` links in a row.

**What it states:** strings are assembled from individual character codes.

**Why it counts:** the same aim as above: nothing should be searchable.

### goto-based control-flow obfuscation — MEDIUM

**Trigger:** `goto label;`

**What it states:** the program flow jumps around with `goto`.

**Why it counts:** typical output of automatic obfuscators. Hand-written PHP
code does not look like this.

### Standalone command-execution shell — MEDIUM

**Trigger:** `shell_exec`, `passthru`, `proc_open` or `pcntl_exec` — without
a recognisable request reference.

**What it states:** the file can execute system commands.

**Why it counts:** on its own not yet proof — some admin tools do this too.
What matters is where the file sits and whether it belongs there.

## .htaccess

### .htaccess maps non-PHP extension to PHP handler — HIGH

**Trigger:** `AddHandler`, `AddType` or `SetHandler` in connection with
`php` / `x-httpd`.

**What it states:** an `.htaccess` lets untypical extensions execute as PHP.

**Why it counts:** this turns a harmless-looking file into executable code.
Almost always introduced after the fact.

### .htaccess auto_prepend/append_file backdoor — HIGH

**Trigger:** `auto_prepend_file` or `auto_append_file`.

**What it states:** an `.htaccess` loads an additional file on **every**
request.

**Why it counts:** a persistence trick: the code still runs once the actual
shell has been deleted.

---

# Database dump

Source: [`server/engines/sqldump.py`](../server/engines/sqldump.py) ·
Artifact: **table**

The rules run against **data values** in `INSERT` rows, not against the
schema. Line number and excerpt are attached to the finding.

### PHP open tag in database value — HIGH

**Trigger:** `<?php` or `<?=` in a column.

**What it states:** PHP code sits in a data field of the database.

**Why it counts:** a CMS stores code in files, never in the database. The
code survives every cleanup of the files.

### eval/assert on decoded or request input — HIGH

**Trigger:** `eval(`/`assert(` on decoders or `$_` superglobals, inside a
data value.

**What it states:** executable code in a data field.

**Why it counts:** as above — it does not belong in data.

### Obfuscation decode chain — HIGH

**Trigger:** nested `base64_decode`/`gzinflate`/`gzuncompress`/`str_rot13`
inside a data value.

**What it states:** obfuscated code in the database.

**Why it counts:** in a data column, obfuscation is no longer a shade of grey
but injected code — hence HIGH here instead of MEDIUM as in files.

### Command execution call in database value — HIGH

**Trigger:** `system`, `shell_exec`, `passthru`, `proc_open`, `popen`,
`pcntl_exec` inside a data value.

**What it states:** a data field contains a call to execute commands.

**Why it counts:** it does not belong in data. Check where this content gets
rendered.

### create_function / dynamic callback — HIGH

**Trigger:** `create_function(` inside a data value.

**What it states:** code generated at runtime, in the database.

**Why it counts:** as above; in addition a pointer to an older malware kit.

### Inline `<script>` in database value — MEDIUM

**Trigger:** `<script` followed by whitespace or `>`.

**What it states:** JavaScript sits in a data field.

**Why it counts:** it can be legitimate (embedded content, tracking) — here
the context decides: does it fit this table?

### Injected `<iframe>` in database value — MEDIUM

**Trigger:** `<iframe` followed by whitespace or `>`.

**What it states:** an iframe sits inside a data field.

**Why it counts:** classic for planted redirects and advertising — but it can
also have been placed there editorially.

### document.write (script injection) — MEDIUM

**Trigger:** `document.write(`.

**What it states:** a data field writes further content into the page via
JavaScript.

**Why it counts:** a common technique to hide foreign code that is pulled in
later. Check the target host in the excerpt.

---

# Access logs

Source: [`server/engines/logindex.py`](../server/engines/logindex.py) ·
Artifact: **client IP**

The patterns are evaluated **once per distinct string**, not per line — which
is why a ten-million-line log does not cost ten million times as much.

### Possible successful brute-force — HIGH

**Trigger:** ≥ 30 POSTs against login endpoints **and** at least one
301/302/303 response.

**What it states:** after many login attempts a redirect came back.

**Why it counts:** this is exactly what a **successful** login looks like.
Check without fail: which account, and what happened afterwards?

### Requested PHP in upload/cache directory answered 2xx — HIGH

**Trigger:** a URI for PHP in an upload/cache directory (the mirror of the
webshell location rule) **and** at least one 2xx response.

**What it states:** someone requested PHP in an upload directory — and the
server answered successfully.

**Why it counts:** this is not a scan into the void: something executable was
there and was delivered. The strongest log trace of a shell in use.

### Requested PHP directly in a CMS extension directory answered 2xx — HIGH

**Trigger:** a URI for a `.php` lying DIRECTLY in `templates/`,
`modules/`, `plugins/` or `components/` (with or without the
`administrator/` prefix) **and** at least one 2xx response.

**What it states:** a PHP file at a depth the CMS does not use was
requested — and served.

**Why it counts:** a template is `templates/<name>/…`, a module
`modules/mod_<name>/…`, a plugin `plugins/<group>/<name>/…`. Nothing the
CMS ships sits one level in, so a bare `.php` there was put there.

**Why the DEPTH and not the directory.** Widening the upload rule to
cover these four folders is the obvious move and the wrong one: they are
full of legitimate PHP. Measured on a compromised Joomla — 615 PHP files
under those four directories, 29 of them without a `_JEXEC` guard
(vendor autoloaders, `CHANGELOG.php`, an Akeeba restore script), and not
one directly inside. The log held three at that depth, one of them
answered 2xx five times, and no rule said a word about any of them.

### CMS login POST flood — MEDIUM

**Trigger:** ≥ 30 POSTs against `wp-login.php`, `xmlrpc.php`,
`/administrator/index.php`, `option=com_login`, `task=user.login` or
`option=com_users`.

**What it states:** a conspicuous number of login submissions from the same
address, **and the window they ran in** — `40 POSTs against login endpoints
over 71 s (2,028/h)`.

The window is not part of the condition, on purpose: a rate in the trigger
would silently drop findings on a case whose logs are thin, and a count is
what an analyst can check by hand. But the count ALONE cannot tell the two
apart. Measured on a real case, four clients crossed the threshold — 92 POSTs
spread over twenty-three days, 714 over eight, and two that fired 40 and 32
inside the same minute. All four were reported with the same word and the
same shape of number.

**Why it counts:** login attempts in series. Success only shows in the status
code — see redirects.

### SQL injection patterns in URIs answered 2xx — MEDIUM

**Trigger:** `union select`, `information_schema`, `concat(`, `' or 1=1`,
`benchmark(`, `sleep(` in the URI **and** 2xx.

**What it states:** attack patterns for database injection in the URL,
answered successfully by the server.

**Why it counts:** "answered" does not yet mean "worked" — but comparing this
against the database findings pays off.

### Path traversal patterns answered 2xx — MEDIUM

**Trigger:** at least two `../` (also `%2e%2e%2f`, `..%2f`) **and** 2xx.

**What it states:** attempts to break out of the web directory with `../`
were answered successfully.

**Why it counts:** it can mean that foreign files were read. Which URLs are
affected is in the trace.

### Request matching a stored pattern — HIGH / LOW

**Trigger:** a URL pattern from the **pattern library** (view *Pattern hunt*)
matches a requested URI. Answered with 2xx → HIGH, attempts only → LOW.

**What it states:** this client requested a path that was determined to belong
to an exploit — either by you, or by the version of SHELLHOUND you are running.

**Why it counts:** the only rule whose weight depends on the pattern rather
than on the code — it is as good as the pattern is. That is why the view
always shows the URLs actually hit: a pattern that reaches too far can only be
recognised by *what* it hit.

**Particularity:** the evidence line records **which half of the library the
pattern came from**. A pattern shipped with the tool is identical on every
installation and can therefore be checked by whoever reads the report; one
written on the analysing machine cannot, and the report should say so.

Shipped patterns live in the package and are read-only; your own live in the
**workspace**, not in the case — created once, a pattern is ready in every
further case. A shipped pattern is switched off, an own one deleted: the
shipped one would come back on the next start, so parking it is the only
honest form of removal. The case records what was searched for in it,
**including without success**: "we checked for this, there was nothing" is
written down nowhere else, because findings only record finds.

### Scanner tool User-Agent — INFO

**Trigger:** the User-Agent names a known tool: sqlmap, nikto, nmap, masscan,
dirbuster, gobuster, feroxbuster, wpscan, joomscan, hydra, acunetix, nessus,
nuclei, zgrab, censys, httpx, wfuzz, ffuf.

**What it states:** the client identified itself as a known scanning tool.

**Why it counts:** background noise as long as nothing succeeded — still
interesting as prior history. Hence INFO and hidden by default: scans happen
to every server around the clock and would bury the real work.

---

# Error log

Source: [`server/engines/errorlog.py`](../server/engines/errorlog.py) ·
Artifact: **file**

Apache and Nginx error logs were recognised and skipped until now — correctly,
because they are not access logs, but it threw away the second most useful log
on the server.

### PHP error names this file — LOW / MEDIUM

**Trigger:** a PHP fatal, parse error, warning or notice that names an absolute
path ending in `.php`/`.phtml`/`.inc`/`.phar` with a line number. MEDIUM for a
fatal, parse error or uncaught exception; LOW otherwise.

**What it states:** the interpreter EXECUTED this path at that time. Nothing
more.

**Why it counts:** it catches what the access log structurally cannot — a shell
run from cron or the CLI that produced no request line, a file pulled in by an
`include` rather than requested, and a shell that crashed on its own broken
payload.

**Limits:** an error naming a file is NOT evidence that the file is malicious —
legitimate code throws warnings all day. That is why it is LOW on its own; it
earns its weight by landing on the same artifact as something else, which is
what artifact-level triage is for.

**Restraint:** a path is only written when it resolves to a file that is
PRESENT under a registered webroot. An error log mentions every file on the
server, and a case must not fill up with findings about paths nobody can open.
Unresolvable paths are counted in the job's statistics rather than dropped in
silence.

**A file deleted before the copy was taken produces no finding**, and this
paragraph used to promise the opposite. The claim was attractive — "this path
executed and is no longer here" is the strongest sentence an error log can
offer, and nothing else in the toolkit makes it: the webroot diff only sees
files a reference CMS release contains, so a dropped-and-then-deleted shell in
an upload directory is invisible to it too. But the restraint above and that
promise cannot both hold, and it is the restraint the engine implements.

Reporting the absent path needs a rule that can place it without being able to
open it, and every cheap way of doing that is wrong: accepting a path because
its parent directory happens to exist in the copy was measured at 99 false
resolutions out of 102 against neighbouring sites on the same host — each one
carrying the sentence "this path was executed and is not in the copy" about a
file belonging to somebody else. A rule that learns the server-side webroot
prefix from the paths that DID resolve scores 0 of those 102, but its noise
floor on a real, month-long error log from a site that was updated between the
incident and the copy has not been measured, because no such log has been
available. Until it has, the tool says less rather than more.

---

# YARA

Source: [`server/engines/yarascan.py`](../server/engines/yarascan.py) ·
Artifact: **file**

Optional (`pip install shellhound[yara]`). Rules come from `<workspace>/yara/`
and belong to the workspace, not to a case — a rule set grows across cases.

**Severity** comes from the rule's own `meta: severity = "high" | "medium" |
"low" | "info"`. Without it a match is MEDIUM: a hit is "somebody's rule
matched", and until a human looks that is what it is. Defaulting to HIGH would
let a foreign rule set decide the colour of the work list.

**Evidence** names the string identifiers that matched and their offsets
(`$a@6`), never the matched bytes — a rule can match on a credential, and the
evidence line travels into the case archive.

**A broken rule file costs one rule, not the run.** Each file is compiled on its
own; one that does not compile is listed by name under skipped, and the rest
still run.
