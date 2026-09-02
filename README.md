<p align="center">
  <img src="assets/brand/banner.svg" alt="SHELLHOUND" width="900">
</p>

<p align="center">
  <a href="https://shellhound-tool.tachipy.chatgpt.site"><strong>Project website</strong></a>
  ·
  <a href="#installation">Installation</a>
  ·
  <a href="#security">Security</a>
</p>

**Local DFIR workbench for compromised web servers.**

SHELLHOUND indexes a copy of the webroot, the access logs and a database
export once. Every question after that is a query against the index instead of
another pass over gigabytes: which files are suspect, which clients requested
them, when a file was first present, what those clients did next.

| | |
|---|---|
| **Input** | Copy of the webroot, access logs, database export of the CMS |
| **Output** | Findings and triage state, chronology, a portable HTML case report, IOC export as CSV, JSON or STIX 2.1 |
| **Operation** | Entirely on the analysis machine, on `127.0.0.1`. No service, no account, no telemetry |
| **Interface** | English and German, switchable in the sidebar |

![Dashboard](assets/docs/dashboard.png)

---

**Contents** — [Installation](#installation) · [Workflow](#workflow) ·
[Views](#views) · [Configuration](#configuration) · [Security](#security) ·
[Development](#development) · [Contributing](#contributing)

---

## Installation

| Component | Version | Needed for |
|---|---|---|
| Python | ≥ 3.10 | Server and engines |
| Node | ≥ 20 | Building the interface only |

```bash
git clone https://github.com/Mateodevv/shellhound.git
cd shellhound && pip install -r requirements.txt
cd web && npm ci && npm run build && cd ..
python -m server.main
```

The browser opens at `http://127.0.0.1:8710` with a token in the URL. The
workspace directory is created on first start.

### Your own rules

The shipped rules are opinionated, which is useful right up to the moment
somebody arrives with a rule set of their own. Both formats that already exist
for that are supported, and neither gets a dialect added to it.

| | Format | Where | Runs over |
|---|---|---|---|
| Files | YARA | `<workspace>/yara/*.yar` | The webroot copy |
| Logs | SIGMA | `<workspace>/sigma/*.yml` | The access log index |

They belong to the workspace, not to a case: a rule set grows across cases.
YARA files are written under *Settings* — write, edit, switch off, delete — or
dropped into the folder, so a set from a CERT or a vendor feed arrives
unchanged. Saving compiles first: a rule that does not compile costs that file
and not the scan, and hearing it at save time beats hearing it mid-case. A file
is switched off rather than edited, because it may be somebody else's text.

**A SIGMA rule this tool cannot answer is refused at load, by name, with the
reason** — never loaded and left to match nothing. What is supported and what
is not is in [`docs/rules.md`](docs/rules.md).

### Optional components

| Feature | Requirement | Without it |
|---|---|---|
| Country flags for IP addresses | A GeoIP database (`.mmdb`), fetched in *Settings* or pointed at with `SHELLHOUND_GEOIP` | Everything works, only without flags |

Country attribution reads a local database and never queries a lookup service.

<details>
<summary><b>Installation as a package</b> (provides a <code>shellhound</code> command)</summary>

The built interface is bundled into the package, so an installed copy needs no
Node toolchain. Building a release artifact does: the PEP 517 backend runs the
frontend build and stages its output in the wheel automatically.

```bash
pip install build
python -m build
```

Install the wheel from `dist/` on the analysis machine. That machine only
needs Python; Node is a build-time dependency.

```bash
pip install dist/shellhound-0.2.0-py3-none-any.whl
shellhound
```

Inside the repository the server continues to find `web/dist` directly.

</details>

## Workflow

The case sidebar keeps **Dashboard** in Overview, the four numbered case stages
in Workflow, and the less frequent screens under the always-visible
**Investigation tools** heading. The current case and the next useful action stay
visible while views load; the action only navigates and never starts analysis
or changes a decision by itself.

### 1 · Evidence & analysis

Work on copies. Four kinds of evidence go in, three of them are needed to
start.

| Kind | What it is | Needed to start |
|---|---|---|
| Webroot | Copy of the web directory | yes |
| Access logs | Apache/Nginx Combined or Common and IIS W3C Extended, `.gz` included | yes |
| SQL dump | Database export of the CMS | yes |
| Reference copy | Clean CMS release of the same version | no, enables the webroot diff |

#### Evidence registration

New case → **1 Evidence & analysis** → enter the paths.

Alternative: enter the folder the evidence sits in and use **Detect evidence
automatically**. It recognises webroot, logs and database export by their
content (CMS markers, parsable log lines, dump headers), states the reason for
each proposal and can apply the complete detected set. Applied proposals leave
the checklist instead of remaining actionable.

![Evidence and analysis](assets/docs/evidence.png)

#### Analysis

**Run analysis** runs the engines once, at roughly 55,000 log lines per second. On a
million log lines this is the only slow step of a case; everything after it is
a query. Later registrations appear separately as **New evidence** and
**Analyze new evidence** scans only the affected file or SQL roots. A new log
source rebuilds the complete case-wide log index, because partial log indexes
can give stale answers. Use **Reanalyze all evidence** when files changed inside
an already registered directory. Existing analyst decisions and notes survive
either mode. Jobs run in the background, report progress and can be cancelled;
all engines started by one click share one expandable analysis run and durable
run id.

### 2 · Findings

Review the artifact queue. Filters and saved views stay behind their named
controls so the queue itself remains the starting point.

### 3 · IOC box

Review the indicators collected from confirmed artifacts or added manually,
then export the required scope.

### 4 · Report & close

Check readiness, preview the selected report sections, and close only when the
case is ready. Closing retains its existing typed confirmation.

## Views

### Findings

38 rules across webroot, database export and logs produce findings
([`docs/rules.md`](docs/rules.md)). The work list is not a list of findings:
findings are grouped into the object they are about, a file, a client or a
table, and the decision is made once per object. Five rules firing on one
dropped shell are five observations about one thing, not five decisions.

![Findings](assets/docs/findings.png)

| Key | Action |
|---|---|
| <kbd>j</kbd> / <kbd>k</kbd> | Next / previous artifact |
| <kbd>Enter</kbd> | Detail window |
| <kbd>c</kbd> | Confirm & collect |
| <kbd>d</kbd> | False positive |
| <kbd>r</kbd> | Reviewed |
| <kbd>x</kbd> | Check |

The detail window presents what the decision is made on in reading order:

- why the artifact was flagged and the matching evidence excerpt,
- supporting file facts, hashes, clients and trace context,
- the analyst's reasoning and decision controls.

![Artifact detail](assets/docs/artifact-detail.png)

**True positive** carries path and SHA-256 into the IOC box, together with the
requesting clients. Clients whose requests were never answered successfully
are suggested, not decided. The propagation stops after exactly one step, so
no chain of conclusions is built automatically.

**False positive** is not deleted. The artifact leaves the work list and stays
reachable through the filter, with the note attached.

The current queue is linkable: view, severity, triage, source, search and the
open artifact survive refresh and browser back. Frequently used combinations
can be named and stored as saved views in the browser.

### Chronology

The dedicated timeline orders confirmed artifacts in evidential time, every
line naming its source. It stays focused on incident evidence: scans, hunts
and analyst actions are not mixed into the incident chronology. It orders
observations and derives no causes.

![Chronology](assets/docs/chronology.png)

- The presence of a file is dated by its **first successful request** in the
  log, not by the mtime of the copy. An mtime can be set by an attacker and
  says nothing about where the copy came from.
- Gaps are stated, not closed.
- If log server and database server disagree about the time, the offset can be
  set per source. It is stored and reported in the chronology.

### Trace

Every request from a selection of clients, with the activity of that selection
over time.

| | |
|---|---|
| **Filter** | URI, user agent, status class, method |
| **Sort** | Time, status, size, URI |
| **Export** | ZIP with manifest and SHA-256 |

![Trace](assets/docs/trace.png)

The timeline always describes the whole period. It does not change with paging
or filtering, otherwise it would answer a different question on each look.

### Pattern hunt

The workbench keeps the rule library, selected-rule meaning, editable draft,
audited test results and application step visibly separate. Testing a URL rule,
for example a path from a CVE, queries the log index and reports who requested
it, how often, the HTTP responses, and the time span. A test does not create
findings; only explicitly selected request clusters are applied. Runs without a
hit are recorded as well.

![Pattern hunt](assets/docs/pattern-hunt.png)

**A pattern is four fields and one condition:** one or more paths, a name, the
advisory it belongs to, and what a hit proves.

Several paths in one entry are combined **over clients**, not over a single
request — a URI cannot be two paths at once. `any` counts a client that hit at
least one of them; `all` only clients that hit every one. "This address
fetched the exploit path AND the file it dropped" is a different claim from
"it fetched one of them", and the one that survives being questioned.

The library has two halves, and which half a pattern came from is recorded on
every finding it produces:

| | Lives in | Editable | Removable |
|---|---|---|---|
| **Shipped** | The package ([`server/patterns_bundled.json`](server/patterns_bundled.json)) | No | Switched off per workspace |
| **Own** | `<workspace>/hunt_patterns.json` | Yes | Yes |

Shipped patterns are identical on every installation of a version, which is
what lets a report cite one; that is also why they are read-only, since an
entry that changed while keeping its id and its CVE would mean two different
things on two machines. An upgrade brings new entries without touching the own
half, and entries switched off stay off.

The shipped set is deliberately short. A pattern that ships is one every
installation runs, so a false positive there does not cost one analyst a look
— it costs all of them a filled work list. Entries are added when somebody has
hunted with them, through the
[hunt pattern issue form](https://github.com/Mateodevv/shellhound/issues/new?template=hunt_pattern.yml),
not because a path appears on a scanner list.

Every pattern carries a **description**: what a hit proves, and what it does
not. It is the field that is worth something six months later, when the CVE
number alone no longer says why the path was on the list.

Nothing runs automatically. A match proves that a request was made — the
status code decides the rest, and the hunt reports it.

The export carries the own patterns only, descriptions included. The shipped
ones travel with the tool, so exporting them would arrive as duplicates.

### CMS inventory

Every extension with its version and the source the version was read from.
WordPress and Joomla in detail; Drupal, TYPO3, Magento, PrestaShop and Contao
are recognised, and their accounts read generically.

![CMS inventory](assets/docs/cms-inventory.png)

### Further views

| View | Contents |
|---|---|
| **Clients & actors** | Every client from the logs with its behaviour, country and duration of activity. Several can be selected for one combined trace |
| **Database** | Accounts with named observations (created on the day of the export, never signed in, blocked), code injected into data fields, table inventory |
| **Files** | Browse from evidence-root breadcrumbs, retain copyable absolute paths, take files into the IOC box by hand, compare against the reference copy |
| **Access logs** | Search the original request stream first; field distributions and the traffic overview expand only when needed |
| **IOC box** | The collected indicators with their relationships and exact matches from other open cases, exportable as CSV, JSON or STIX 2.1 |

![Access Log Explorer](assets/docs/access-logs.png)

**Report & close** edits the case summary, checks evidence, running/failed
analyses and open triage, and previews a selectable-section report before the
case is archived. The self-contained HTML contains no evidence-root paths or
remote resources and carries the SHA-256 of the exact response in its download
header. Cross-case matching reads only the IOC boxes in the current workspace;
it never searches raw findings or evidence.

### Third-party lookups

Optional, off until switched on in *Settings*. One value leaves the machine
per click:

| Service | Transmitted value |
|---|---|
| VirusTotal | one SHA-256 |
| AbuseIPDB | one IP address |

Nothing else is sent: not the case, not the path, not the other indicators.

![Settings](assets/docs/settings.png)

The result is a foreign opinion, not a measurement. It is kept apart from the
findings and never moves a severity or a triage decision.

## Configuration

| Option | Meaning |
|---|---|
| `--workspace PATH` | Where cases are kept, default `~/ShellhoundCases` |
| `--port PORT` | Default `8710` |
| `--host HOST` | Default `127.0.0.1`; a different bind requires `--token` |
| `--token TOKEN` | Fixed access token instead of a random one per start |
| `--no-browser` | Do not open a browser automatically |

| Environment variable | Meaning |
|---|---|
| `SHELLHOUND_WORKSPACE` | Workspace directory |
| `SHELLHOUND_GEOIP` | Path to a GeoIP `.mmdb` file |

A case is a directory. `logindex.db` is derived from the logs and is not
archived. API keys live in `<workspace>/settings.json`, in the workspace and
never in a case archive.

## Security

**The material under examination contains working attack code.** Recommended:
an isolated machine, copies of the originals only, and an antivirus exception
for the evidence directory.

Single-seat tool, no user accounts, no TLS. For access from another machine an
SSH tunnel is the intended route, not a bind to `0.0.0.0`.

Outbound network access happens in exactly three places, all optional and all
opt-in:

| Request | Transmitted value |
|---|---|
| GeoIP database download | — |
| VirusTotal lookup | one SHA-256 |
| AbuseIPDB lookup | one IP address |

None of them transmits case data beyond the single value of the lookup.

Full threat model and how to report vulnerabilities:
[SECURITY.md](SECURITY.md).

## Development

Interface with hot reload:

```bash
cd web && npm run dev
```

Server:

```bash
python -m server.main --no-browser --token dev
```

The interface is then at `http://localhost:5173/?token=dev`.

Tests run without additional dependencies:

```bash
python -m unittest discover -s tests -t .
```

They build their own evidence: tiny, invented files, each triggering exactly
one rule. A failure names the broken rule instead of pointing at a large lump
of data.

On Windows, Defender may quarantine those intentionally suspicious test probes
when Python writes them below `%TEMP%`. Do not exclude the whole AppData temp
folder. Instead, create an ignored folder below `workspace/` and point `TEMP`
and `TMP` there for that test process.

### Layout

```
<workspace>/       settings.json, hunt_patterns.json, yara/, *.mmdb
  <case>/          case.db, logindex.db (derived), evidence/
server/            FastAPI, SQLite from the standard library
  engines/         accesslog, logindex, webshell, cmsinventory, sqldump,
                   errorlog, yarascan, webrootdiff, detect
  patterns_bundled.json   Hunt patterns shipped with this version
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
- Everything the case stores is written in English: origins, notes, evidence
  lines. Only rendered prose follows the interface language. An archive whose
  wording depends on the language selected at the time of a click is worthless
  as evidence.

## Contributing

Bug reports and pull requests are welcome.

- Vulnerabilities do not belong in a public issue, see
  [SECURITY.md](SECURITY.md).
- Contributions **must not contain data from real incidents**. For a
  reproduction, describe the shape of the data or build a minimal example.
- New detection rules belong in [`docs/rules.md`](docs/rules.md) with their
  trigger, statement and limits, and with a test in `tests/` proving that they
  fire.

## License

[Apache-2.0](LICENSE). Third-party components: [NOTICE](NOTICE).
