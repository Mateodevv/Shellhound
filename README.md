# SHELLHOUND

**Local DFIR workbench for compromised web servers.**

You point it at three things — a copy of the webroot, the access logs, a
database export. It indexes them once. After that every question you ask is a
database query instead of another pass over gigabytes: which files are
suspect, who requested them, when they were first there, what the attacker
touched next.

Runs entirely on the analysis machine. No service, no account, no telemetry.
The interface ships in English and German, switchable from the sidebar.

![Dashboard](assets/docs/dashboard.png)

---

**Contents** — [Install](#install) · [First case in five
minutes](#first-case-in-five-minutes) · [Working a case](#working-a-case) ·
[Configuration](#configuration) · [Security](#security) ·
[Development](#development)

---

## Install

Requirements: **Python ≥ 3.10**, **Node ≥ 20** (only to build the interface).

```bash
git clone https://github.com/Mateodevv/shellhound.git
```

```bash
cd shellhound && pip install -r requirements.txt
```

```bash
cd web && npm ci && npm run build && cd ..
```

```bash
python -m server.main
```

The browser opens at `http://127.0.0.1:8710` with a token in the URL. That is
the whole installation — the workspace directory is created on first start.

<details>
<summary><b>Install as a package instead</b> (gives you a <code>shellhound</code> command)</summary>

The built interface is bundled into the package, so an installed copy needs no
Node toolchain — but building the wheel does, and the build output has to be
copied into the package first.

```bash
cd web && npm ci && npm run build && cd ..
```

```bash
cp -r web/dist server/static
```

```powershell
Copy-Item -Recurse -Force web/dist server/static
```

```bash
pip install .
```

```bash
shellhound
```

Inside the repository the copy is unnecessary — there the server finds
`web/dist` by itself.

</details>

<details>
<summary><b>Optional: your own YARA rules</b></summary>

```bash
pip install "yara-python>=4.3"
```

Drop `.yar` files into `<workspace>/yara/`. They belong to the workspace, not
to a case — a rule set grows across cases. Without the package everything else
works unchanged, and the interface tells you which of the two silences it is:
no rules, or no YARA.

</details>

<details>
<summary><b>Optional: country flags for IP addresses</b></summary>

Attribution comes from a **local** GeoIP database, never from a lookup
service. Point `SHELLHOUND_GEOIP` at a `.mmdb` file, or drop one into the
workspace. Without it everything works, only without flags.

</details>

## First case in five minutes

### 1 · Collect the evidence

Work on copies. Four kinds go in, and only the first three matter to start:

| Kind | What it is |
|---|---|
| **Webroot** | Copy of the web directory |
| **Access logs** | Apache or Nginx, `.gz` included |
| **SQL dump** | Database export of the CMS |
| Reference copy | Clean CMS release of the same version — optional, enables the diff |

### 2 · Register it

New case → *Evidence & jobs* → enter the paths. Or paste the folder your
evidence sits in and let **Detect evidence automatically** propose the parts:
it recognises webroot, logs and database export by their content — CMS
markers, parsable log lines, dump headers — and says why for each.

![Evidence and jobs](assets/docs/evidence.png)

### 3 · Press *Analyse*

The engines run once. On a million log lines this is the only slow step
(roughly 55,000 lines/s); everything afterwards is a query. You can keep
working while it runs — each job reports its own progress and can be
cancelled.

### 4 · Decide

Go to *Findings*. That is the rest of the job.

## Working a case

### Findings — decide about artifacts, not about findings

Thirty-four rules across webroot, database export and logs produce findings.
The list you work on is **not** that list: findings are grouped into the
object they are about — a file, a client, a table — and you decide about the
object once. Five rules firing on one dropped shell is five observations about
one thing, not five decisions.

![Findings](assets/docs/findings.png)

| Key | |
|---|---|
| <kbd>j</kbd> / <kbd>k</kbd> | Next / previous artifact |
| <kbd>Enter</kbd> | Detail window |
| <kbd>c</kbd> | True positive |
| <kbd>d</kbd> | False positive |
| <kbd>r</kbd> | Reviewed |
| <kbd>x</kbd> | Check |

The detail window is where the decision is actually made: the file content
around the offending line, every rule that fired with its reasoning, and the
clients that loaded this file according to the log.

![Artifact detail](assets/docs/artifact-detail.png)

A **true positive** carries path and SHA-256 into the IOC box, and takes the
requesting clients with it. Clients whose requests were never answered
successfully are *suggested*, not decided — the propagation stops after
exactly one step, so the tool never builds a chain of conclusions behind your
back.

A **false positive** is not deleted. It leaves the work list and stays
reachable through the filter, with your note attached.

### Chronology — measured times only

The confirmed artifacts in temporal order, every line naming its source. It
orders observations and derives no causes.

![Chronology](assets/docs/chronology.png)

When a file was present is established through its **first successful
request** — not through the mtime of the copy, which says nothing about where
the copy came from and which an attacker can set to anything. Gaps are stated
rather than closed. If log server and database server disagree about the time,
set the offset per source; it is stored and reported in the chronology.

### Trace — what one client actually did

Every request from a selection of clients, with the activity of that selection
over time. Filter by URI or user agent, by status class, by method; sort by
time, status, size or URI. Export as a ZIP with manifest and SHA-256.

![Trace](assets/docs/trace.png)

The timeline always describes the whole period and does not change when you
page or filter — otherwise it would answer a different question each time you
looked at it.

### Pattern hunt — your own URL patterns

A CVE gives you a path. This runs it against the log index and answers who hit
it, how often, how much of it worked, and over what stretch of time. Patterns
are stored in the workspace and survive the case.

![Pattern hunt](assets/docs/pattern-hunt.png)

Runs that found nothing are recorded too. "We looked and there was nothing" is
a result worth having in a report.

### CMS inventory — what is installed, and which version

Every extension with its version and the source that version came from.
WordPress and Joomla in detail; Drupal, TYPO3, Magento, PrestaShop and Contao
are recognised, and their accounts read generically.

![CMS inventory](assets/docs/cms-inventory.png)

### Further views

- **Actors** — every client from the logs with its behaviour, country and
  duration of activity. Select several for one combined trace.
- **Database** — accounts with named observations (created on the day of the
  export, never signed in, blocked), code injected into data fields, table
  inventory.
- **Files** — browse the evidence, take files into the IOC box by hand,
  compare against the reference copy.
- **IOC box** — the collected indicators with their relationships, exportable
  as CSV, JSON or STIX 2.1.

### Settings — third-party lookups

Optional, off until you switch it on. One value leaves the machine per click:
a SHA-256 to VirusTotal, an IP to AbuseIPDB. Nothing else — not the case, not
the path, not the other indicators.

![Settings](assets/docs/settings.png)

What comes back is a **foreign opinion, not a measurement**. It is kept apart
from the findings and never moves a severity or a triage decision: a file is
not a web shell because VirusTotal says so, and not clean because VirusTotal
is silent.

## Configuration

| Option | Meaning |
|---|---|
| `--workspace PATH` | Where cases are kept, default `~/ShellhoundCases` |
| `--port PORT` | Default `8710` |
| `--host HOST` | Default `127.0.0.1`; a different bind requires `--token` |
| `--token TOKEN` | Fixed access token instead of a random one per start |
| `--no-browser` | Do not open a browser automatically |

Environment: `SHELLHOUND_WORKSPACE`, `SHELLHOUND_GEOIP`.

A case is a directory. `logindex.db` is derived from the logs and is not
archived. API keys live in `<workspace>/settings.json` — in the workspace,
never in a case archive.

## Security

Single-seat tool, no user accounts, no TLS. For access from another machine an
SSH tunnel is the intended route, not a bind to `0.0.0.0`.

**The material under examination contains working attack code.** An isolated
machine, copies of the originals only, and an antivirus exception for the
evidence directory are recommended.

Outbound network access happens in exactly three places, all optional and all
opt-in: the GeoIP database download, and the two lookup services above. None
of them transmits case data beyond the single value you click on.

Full threat model and how to report vulnerabilities: [SECURITY.md](SECURITY.md).

## Development

```bash
cd web && npm run dev
```

```bash
python -m server.main --no-browser --token dev
```

Then `http://localhost:5173/?token=dev`.

Tests run without additional dependencies:

```bash
python -m unittest discover -s tests -t .
```

They build their own evidence: tiny, invented files, each triggering exactly
one rule. A failure names the broken rule instead of pointing at a large lump
of data.

### Layout

```
<workspace>/       settings.json, hunt_patterns.json, yara/, *.mmdb
  <case>/          case.db, logindex.db (derived), evidence/
server/            FastAPI, SQLite from the standard library
  engines/         accesslog, logindex, webshell, cmsinventory, sqldump,
                   errorlog, yarascan, webrootdiff, detect
web/               Vite, React, TypeScript, Tailwind
docs/rules.md      Every rule with trigger, statement and limits
```

### Principles

- Triage states survive re-scans; fingerprints are stable.
- Dismissed findings are not deleted, only filtered out.
- Log alerts are outcome-gated: an attack attempt answered with 404 weighs
  differently from one answered with 200.
- Evidence is never served. Findings carry text excerpts; file contents are
  transferred as JSON data.
- Filtered artifacts are always delivered in full.
- **Everything the case stores is written in English** — origins, notes,
  evidence lines. An archive whose wording depends on the language selected at
  the time of a click is worthless as evidence. Only rendered prose follows
  the interface language.

## Contributing

Bug reports and pull requests are welcome. Please do not report
vulnerabilities as a public issue — see [SECURITY.md](SECURITY.md).

Contributions **must not contain data from real incidents**. For a
reproduction, describe the shape of the data or build a minimal example. New
detection rules belong in [`docs/rules.md`](docs/rules.md) with their trigger,
statement and limits — and with a test in `tests/` proving that they fire.

## License

[Apache-2.0](LICENSE). Third-party components: [NOTICE](NOTICE).
