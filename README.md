# SHELLHOUND

Local DFIR workbench for compromised web servers (WordPress, Joomla).

A copy of the webroot, the access logs and a database export are indexed
once. After that every analysis is a database query: triage over artifacts,
a chronology built from measured times, IOC export as CSV, JSON or STIX 2.1.

Runs entirely offline on the analysis machine. No service, no account, no
telemetry.

The interface ships in English and German and can be switched at runtime
from the sidebar.

<!-- SCREENSHOT: Dashboard with chronology and log coverage -->

## Installation

Requirements: Python ≥ 3.10, Node ≥ 20.

```bash
git clone https://github.com/Mateodevv/shellhound.git
cd shellhound
pip install -r requirements.txt
cd web && npm ci && npm run build && cd ..
python -m server.main
```

The interface opens at `http://127.0.0.1:8710`.

## Features

**Analysis**

- Access log index at roughly 55,000 lines/s, sized for gigabytes
- 33 detection rules across webroot, database export and logs, documented
  in [`docs/rules.md`](docs/rules.md)
- Your own YARA rules from the workspace, alongside the shipped ones
  (optional: `pip install shellhound[yara]`)
- CMS inventory with version detection and the source of every version
  (WordPress and Joomla in detail; Drupal, TYPO3, Magento, PrestaShop and
  Contao are recognised and their accounts read generically)
- Comparison of the webroot against a known-clean reference copy

**Assessment**

- Triage at artifact level rather than per finding
- Chronology of the confirmed artifacts, from measured times only
- Trace of any number of clients with filter, sorting and a timeline
- Pattern hunt: your own URL patterns, stored across cases
- Country attribution for IP addresses from a local GeoIP database
- Full-text search across the case (<kbd>Ctrl</kbd>+<kbd>K</kbd>)

**Output**

- IOC box with relationships between indicators
- Export as CSV, JSON and STIX 2.1
- Trace export as a ZIP with manifest and SHA-256
- Case archival as a ZIP

## Usage

### Register evidence

Enter the paths under *Evidence & jobs*:

| Kind | Content |
|---|---|
| Webroot | Copy of the web directory |
| Access logs | Apache or Nginx logs, compressed ones included |
| SQL dump | Database export of the CMS |
| Reference copy | Clean CMS release of the same version (optional) |

Alternatively, *Search case folder* scans a directory and suggests
candidates.

<!-- SCREENSHOT: Evidence view with detected candidates -->

### Triage

The decision is made about the artifact, not about individual findings.
Several rules on the same file are observations about one object.

| Key | Function |
|---|---|
| <kbd>j</kbd> / <kbd>k</kbd> | Next / previous artifact |
| <kbd>Enter</kbd> | Detail window |
| <kbd>c</kbd> | True positive |
| <kbd>d</kbd> | False positive |
| <kbd>r</kbd> | Reviewed |
| <kbd>x</kbd> | Check |

A true positive carries path and SHA-256 into the IOC box and decides along
with it the clients that loaded the file according to the log. Clients whose
requests were never answered successfully are suggested, not decided.

<!-- SCREENSHOT: Findings view with grouped artifacts -->
<!-- SCREENSHOT: Artifact detail window with file content and clients -->

### Further views

- **Actors** — every client from the logs with its behaviour, country flag
  and duration of activity. A multiple selection yields one combined trace.
- **Pattern hunt** — stored URL patterns against the log index. Key figures
  per search, and a record of unsuccessful runs as well.
- **Database** — accounts with named observations, code injected into data
  fields, table inventory.
- **Files** — browse the evidence, take files into the IOC box by hand,
  compare against the reference copy.
- **IOC box** — collected indicators with their relationships, and export.

<!-- SCREENSHOT: Actors list with flags and behaviour badges -->
<!-- SCREENSHOT: Pattern hunt with key figures and hit list -->
<!-- SCREENSHOT: Webroot diff with extra/modified/missing -->
<!-- SCREENSHOT: IOC box with relationships expanded -->

### Chronology

The confirmed artifacts in temporal order. Every line names its source
(access log or database export). The chronology orders measured
observations and derives no causes.

The point in time at which a file was present is established through its
first successful request, not through the mtime of the copy. Temporal gaps
are stated. Diverging clocks between log and database server can be set as
an offset per source; the offset is stored and reported in the chronology.

<!-- SCREENSHOT: Chronology with gaps and source attributions -->

## Configuration

| Option | Meaning |
|---|---|
| `--workspace PATH` | Where cases are kept, default `~/ShellhoundCases` |
| `--port PORT` | Default `8710` |
| `--host HOST` | Default `127.0.0.1`; a different bind requires `--token` |
| `--token TOKEN` | Fixed access token instead of a random one per start |
| `--no-browser` | Do not open a browser automatically |

Environment variables: `SHELLHOUND_WORKSPACE`, `SHELLHOUND_GEOIP`.

API keys for third-party lookups are set in the interface under *Settings*
and stored in the workspace, never in a case archive.

A case is a directory. `logindex.db` is derived and is not archived.

## Security

SHELLHOUND is a single-seat tool without user accounts and without TLS. For
access from another machine an SSH tunnel is the intended route, not a bind
to `0.0.0.0`.

The only outbound network access is the optional download of the GeoIP
country database; it happens only after an explicit confirmation and
transmits no case data.

The material under examination contains working attack code. An isolated
machine, copies of the originals only, and an antivirus exception for the
evidence directory are recommended.

Full threat model and how to report vulnerabilities:
[SECURITY.md](SECURITY.md).

## Architecture

```
<workspace>/       hunt_patterns.json, *.mmdb (optional)
  <case>/          case.db, logindex.db (derived), evidence/
server/            FastAPI, SQLite from the standard library
  engines/         accesslog, logindex, webshell, cmsinventory,
                   sqldump, webrootdiff, detect
web/               Vite, React, TypeScript, Tailwind
docs/rules.md      Detection rules with trigger, statement and limits
```

Principles:

- Triage states survive re-scans; fingerprints are stable.
- Dismissed findings are not deleted but stay reachable through the filter.
- Log alerts are outcome-gated: an attack attempt answered with 404 is
  weighted differently from a successful one.
- Evidence is never served. Findings carry text excerpts; file contents are
  transferred as JSON data.
- Filtered artifacts are always delivered in full.
- Everything the case stores is written in English — origins, notes,
  evidence lines. An archive whose wording depends on the language selected
  at the time of a click is worthless as evidence.

### Development

```bash
cd web && npm run dev
python -m server.main --no-browser --token dev
# http://localhost:5173/?token=dev
```

## Contributing

Bug reports and pull requests are welcome. Please do not report
vulnerabilities as a public issue, see [SECURITY.md](SECURITY.md).

Contributions must not contain data from real incidents. For a
reproduction, describe the shape of the data instead, or build a minimal
example. New detection rules belong in [`docs/rules.md`](docs/rules.md) with
their trigger, statement and limits — and with a test in `tests/` proving
that they fire.

Tests run without additional dependencies:

```bash
python -m unittest discover -s tests -t .
```

They build their own evidence: tiny, invented files, each of which triggers
exactly one rule. A failure therefore names the broken rule instead of
pointing at a large lump of data.

## License

[Apache-2.0](LICENSE). Third-party components: [NOTICE](NOTICE).
