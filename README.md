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
| **Interface** | English |

![Dashboard](assets/docs/dashboard.png)

---

**Contents** — [Installation](#installation) · [Updating](#updating) · [Workflow](#workflow) ·
[Views](#views) · [Configuration](#configuration) · [Security](#security) ·
[Development](#development) · [Contributing](#contributing)

---

## Installation

### 1 · Install the prerequisites once

| Component | Requirement | Purpose |
|---|---|---|
| [Python](https://www.python.org/downloads/) | 3.10 or newer | Runs Shellhound; enable **Add Python to PATH** on Windows |
| [Node.js with npm](https://nodejs.org/en/download) | 22.12+ recommended; 20.19+ in the 20.x series also works | Prepares the interface when it changes |
| [Git](https://git-scm.com/downloads) | Needed for Git updates | Gets newer code when you choose Update |

Reopen your terminal after installing these tools. On Debian/Ubuntu, Python
also needs the `python3-venv` package. Shellhound does not install system tools
or require administrator rights.

Clone this repository, or download and extract its source ZIP into a writable
folder. A clone supports the Update launcher:

```text
git clone https://github.com/Mateodevv/shellhound.git
```

### 2 · Start Shellhound

**Windows:** open the project folder and double-click **Start-Shellhound.bat**.

**Linux/macOS:** open a terminal in that folder and run:

```sh
./shellhound.sh
```

For a downloaded ZIP whose script is not executable, use `sh shellhound.sh`.

The first start creates a private `.venv` inside the project, installs its
Python and interface packages, and builds the interface. These package
downloads may need internet access and take a few minutes. Progress appears
in the launcher window; if a step fails, it explains what to check. Correct
the problem and run the same launcher again.

When the server is ready, the browser opens at `http://127.0.0.1:8710`.
Authentication is handled automatically on localhost; no token needs copying.
**Keep the launcher window open. Press Ctrl+C there to stop Shellhound.**
If an analysis is running, stopping cancels it and waits for its pending writes
to finish. Wait until the launcher exits before starting again or updating;
cancelled analyses can be rerun after the next start.

Later starts reuse the prepared environment and interface. With no changed or
missing dependencies, starting and using the workbench works offline. Startup
does not check GitHub for new versions.

Cases stay in `~/ShellhoundCases` by default. Existing `--workspace` options
and `SHELLHOUND_WORKSPACE` settings still work; setup never moves or clears
your cases. For example, in PowerShell:

```powershell
.\Start-Shellhound.bat --workspace "D:\Cases" --no-browser
```

## Updating

1. Stop Shellhound with **Ctrl+C** in its launcher/server window.
2. On Windows, double-click **Update-Shellhound.bat**. On Linux/macOS, run
   `./shellhound.sh --update`.
3. Wait for preparation to finish and the browser to open, then refresh any
   previously open Shellhound tab.

Update pulls the **current branch's configured upstream** and then starts the
updated launcher. It only accepts a fast-forward: local edits or divergent
branches are left for you to resolve. It never switches branches, resets your
work, pushes anything, or modifies case data. Use the same workspace options
for Update that you use for Start.

**Already use `git pull`?** Keep doing that, then launch normally. Both the
launchers and `python -m server.main` automatically rebuild an outdated
interface. No separate npm commands are needed. An existing installation
receives one initial preparation pass to establish its build record.

For a source ZIP, download a fresh copy into a separate folder and launch it
with the same case workspace. Installed wheels use the package update route
below; they do not need Git or Node on the analysis machine.

### Startup troubleshooting

| Message or symptom | What to do |
|---|---|
| Python or Node is missing/too old | Install a supported version from the links above, reopen the terminal, and start again. |
| Python environment setup fails on Linux | Check that `python3-venv` is installed and the project folder is writable. |
| Packages could not be installed | Check internet/proxy access and the displayed package error, then rerun Start. Dependencies are installed only inside the project. |
| Interface build fails | Correct the displayed error, then rerun Start. Shellhound preserves the previous build and stops instead of serving it with newer backend code. |
| Already running / port unavailable | Stop the existing server first. A different application using port 8710 can be accommodated with `--port 9000`. |
| Update reports local changes or divergence | Commit or set aside your work and resolve the Git state yourself. Use Start to run the current local source. |
| Update reports no upstream / detached checkout | Select the intended branch and configure its upstream in Git. Update follows that branch, not a hardcoded repository or branch. |
| Git authentication or network failure | Check your Git credentials and connection. No update is attempted during ordinary Start. |
| Existing `.venv` is incomplete/incompatible | Stop Shellhound, move that `.venv` aside, and rerun Start with supported Python. Your case workspace is separate; do not remove it. |
| Browser does not open (for example on a headless machine) | Open the printed address yourself, or use `--no-browser`. |

One managed Shellhound instance runs per source folder. Its operating-system
lock releases on exit; do not delete lock files to force an update while it
is running. Separate source folders can run independently on different ports.

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

To update an installed package, stop it and install the newer wheel using
that environment's Python: `python -m pip install --upgrade PATH_TO_NEW_WHEEL`.
Then run `shellhound` again with your usual workspace options. Downloading or
building the wheel is a separate release step; the installed app never builds
the interface or creates a source environment.

</details>

## Workflow

The case sidebar keeps **Dashboard** in Overview, the four numbered case stages
in Workflow, and the less frequent screens under the always-visible
**Investigation tools** heading. The current case and the next useful action stay
visible while views load; the action only navigates and never starts analysis
or changes a decision by itself.

### Case dashboard

The dashboard separates **Case status**, **Recommended next step**, **Top
findings**, and **Case data overview**. Analysis coverage describes what was examined; the case
assessment describes the analyst's decisions. No findings does not mean a site
is clean. Red marks confirmed incident findings or failed checks, yellow marks
work needing attention, and green marks completed checks or review. Use the
linked counts at the top or the recommended action to continue. Accepting a
skipped file clears its warning; the decision remains available under
**Evidence → Resolved scan skips** without keeping a dashboard warning open.
Top findings shows up to three groups from the whole case, with distinct
affected-item counts and a representative file, IP, or database item. Red groups
contain analyst-confirmed findings; yellow groups await review. Mixed groups
label both counts separately. Click a group to open its removable category
filter in Findings, or use **View all findings** for the full list. Dismissed
and hidden items do not enter the highlights; historical confirmed findings
keep their decisions and are marked when no longer reported by current scans.
Informational observations remain available in Findings. Empty results only
turn green once analysis is complete, and distinguish no detections from items
the analyst dismissed. The case data overview shows software observed in the
evidence, including analyst-corrected versions and source coverage.
When the latest saved Pattern Hunt check has matches, Top findings also shows
its matching-pattern count and names, with a direct link to that check. These
unconfirmed matches stay separate from Findings and do not inflate artifact
counts or confirm compromise. Partial and historical results are labelled;
changed log evidence requires a new check before drilling into saved matches.

### Pattern Hunt

Pattern Hunt checks indexed access logs against the enabled patterns in the
local reusable library. Open **Pattern Hunt** and use the large **Check all
patterns** button in the first panel. Progress and a compact result summary
stay here; choose **View full results** to investigate. The **Pattern library**
panel below previews enabled patterns and opens the full library. Each run
keeps the pattern versions it checked, including zero matches, failures, and
unfinished checks. You can stop a run and still inspect completed results.
Matches are highlighted in red; query failures in yellow. The match summary
also opens full results. Remaining work is shown during a run; stopped runs
identify any patterns that were not checked.

Open a matched pattern to see request counts, distinct IPs, and first/last
matches. Select an IP, inspect a matching request, then choose **Activity after
this request** to see what it did next, including requests outside the pattern.
**Full activity** includes earlier requests too. A match or a 2xx response is
an observation, not proof of successful exploitation.

Select matching request groups and choose **Add selected to Findings** to send
only those groups for review. Selection is limited to the current page and
clears when you change pages or IPs; existing review decisions are preserved.
Searching alone never adds findings. **Open pattern library** lets you check one
pattern, enable or disable patterns, or preview and save a new one. Previewing
a draft and saving it are separate actions.

Changed evidence or a rebuilt index makes old results historical. Run a new
check before opening or applying their underlying evidence. The library stays
local; Pattern Hunt does not download patterns or contact a shared catalogue.

### 1 · Evidence & analysis

Work on copies. Register any available webroot, access logs, or SQL dump to
start; each can be analyzed independently.

| Kind | What it is | Needed to start |
|---|---|---|
| Webroot | Copy of the web directory | one of these three |
| Access logs | Apache/Nginx Combined or Common and IIS W3C Extended, `.gz` included | one of these three |
| SQL dump | Database export of the CMS | one of these three |
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

Webshell and custom YARA scans first show **Finding files…** with a live file
count, then switch to a scanning percentage. You can cancel during either step.

If individual files cannot be read, exceed the 5 MiB content limit, or time out,
a finished scan shows **Complete with warnings**. Open **Skipped files and
rules** to review the paths and reasons. These files have not been cleared;
the warning remains visible in Evidence, the dashboard, and report coverage notes.
An unreadable evidence root, broken rules, a crashed engine, or cancellation
still leaves analysis incomplete.

The skipped-file list separates **Size limit** from **Other skips**. Tick individual
files or use **Select all** (across all pages, with individual unticking supported).
For size skips, choose **Accept size skip** to dismiss the warning for this
investigation, or **Scan despite size limit** to scan the selected files once with
a higher limit. Acceptance is recorded as a coverage gap; it does not mark the file
as scanned or clean. Use **Show → Accepted** to review or scan those files later.

The explicit larger-file scan allows up to **256 MiB per selected file** and keeps
the existing **20-second YARA timeout**. It does not change the default 5 MiB limit
for future analyses. Files above 256 MiB can still be accepted as coverage gaps.
If a larger-file scan instead fails to read a file or times out, its warning moves
to **Other skips** for review.

After correcting an access or other problem, open **Other skips**, select the
affected files, and choose **Retry selected**. Only those files from that scanner
are retried; other engines and files keep their results. Successful retries resolve
their warnings while the original scan history, analyst decisions, and notes remain
available. Normal retries retain the scanner's default size and time limits.

Changed rules/settings or older scans without a trustworthy source snapshot
need **Reanalyze all evidence** before targeted retries are available. Stop or
finish an active analysis before starting another analysis or retry in that case.

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

To decide a folder at once, check the box beside its name, then choose
**True positive: Collect**, **skipped for now**, or **false positive** in the selection
bar. You can add one shared note. Subfolders are included even when collapsed;
a partially checked box means only some files are selected. Selection follows
the current category and filters and covers the loaded list (up to 2,000
artifacts). Check the selected count before applying the decision.

| Key | Action |
|---|---|
| <kbd>j</kbd> / <kbd>k</kbd> | Next / previous artifact |
| <kbd>Enter</kbd> | Detail window |
| <kbd>c</kbd> | Confirm & collect |
| <kbd>d</kbd> | False positive |
| <kbd>r</kbd> | Reviewed |
| <kbd>x</kbd> | Check |

The bounded detail workspace keeps the decision footer still while evidence
scrolls. For files, identity, hashes, historical reputation results and related
clients stay on the left; flagging reasons and a scrollable inert preview use
the right. **Expand file** turns that preview into the existing paged raw/hex
viewer without leaving the review, and **Show in file manager** selects the
registered copy without executing it.

Choose exactly one decision, then use **Save & next** to continue forward
through the current filtered queue or **Save & close** to return to the list.
Selecting a decision alone stores nothing; a failed save leaves the selection
and optional reasoning in place. The workspace presents what the decision is
made on in reading order:

- file identity, supporting facts, hashes, clients and trace context,
- why the artifact was flagged and the matching evidence excerpt or preview,
- explicit decision controls, followed by optional analyst reasoning.

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

### OpenCTI integration

Configure an HTTPS OpenCTI URL, a dedicated integration token and the existing
TAXII push ingester ID in *Settings*. Then use the IOC box's three separate
actions: **Check in OpenCTI**, **Transfer to OpenCTI**, and **Enrich via OpenCTI**.
Opening a case only reads the local cache. Checking searches existing knowledge;
it never starts an external enrichment connector or changes local triage.

Transfers require a unique case ID and a reviewed preview. A reusable random
organization pseudonym, optional incident profile, Incident and Report retain
the case context. All IOC rows are considered, including collapsed children.
Notes, evidence, profile details, optional Indicators and original samples are
reviewed separately. Local workstation paths are removed. Samples are disabled
by default and must also be selected individually in the preview.

Set internal enrichment connectors to **manual** before transferring data;
automatic feed imports can keep running. Shellhound blocks transfer when an
active enrichment connector still runs automatically. Metadata-only observables
can be enriched explicitly; attached file contents are never forwarded by a
Shellhound enrichment request. Historical VirusTotal/AbuseIPDB results remain
readable, but their direct network APIs and key inputs are retired.

Results distinguish visible knowledge, own exports, no visible match, stale
cache and errors. No visible match does not mean benign. Import receipts track
pending, failed and completed batches; **Resume** checks existing work and
retries unfinished parts. [Setup and behavior](docs/opencti.md).

## Configuration

| Option | Meaning |
|---|---|
| `--workspace PATH` | Where cases are kept, default `~/ShellhoundCases` |
| `--port PORT` | Default `8710` |
| `--host HOST` | Default `127.0.0.1`; a different bind requires `--token` |
| `--token TOKEN` | Fixed access token instead of a random one per start |
| `--no-browser` | Do not open a browser automatically |
| `--update` | In a Git source checkout, pull the current upstream before preparing and starting |

| Environment variable | Meaning |
|---|---|
| `SHELLHOUND_WORKSPACE` | Workspace directory |
| `SHELLHOUND_GEOIP` | Path to a GeoIP `.mmdb` file |

A case is a directory. `logindex.db` is derived from the logs and is not
archived. The integration token lives in `<workspace>/settings.json`, in the workspace and
never in a case archive.

## Security

**The material under examination contains working attack code.** Recommended:
an isolated machine, copies of the originals only, and an antivirus exception
for the evidence directory.

Single-seat tool, no user accounts, no TLS. For access from another machine an
SSH tunnel is the intended route, not a bind to `0.0.0.0`.

During analysis, outbound network access is explicit:

| Request | Transmitted value |
|---|---|
| GeoIP database download | — |
| OpenCTI lookup | selected observable values |
| OpenCTI transfer | the reviewed case graph and individually selected samples |
| OpenCTI enrichment | explicitly selected observable and connector IDs; creation of unknown observables requires consent |

TLP:AMBER+STRICT is the default intended sharing boundary, not an access-control
mechanism. Review domains, email addresses and free text as well as the case
profile. Pseudonyms alone do not anonymize evidence.

Separately, first setup and changed dependency manifests can download Python
and npm packages from the configured package registries. Choosing Update
contacts the branch's Git remote. These operations prepare application code;
they do not read or upload case data. Ordinary prepared startup does not
contact GitHub or package registries.

Full threat model and how to report vulnerabilities:
[SECURITY.md](SECURITY.md).

## Development

The normal source command remains `python -m server.main`; it uses the same
preparation as the launchers and runs the server in the project's `.venv`.
`--help` works before dependencies are installed. Application imports and
`create_app` do not trigger installation, builds, or Git operations.

Interface with hot reload:

```bash
cd web && npm run dev
```

Server:

```bash
python -m server.main --no-browser --token dev
```

The interface is then at `http://localhost:5173/?token=dev`.

Manual `npm ci` / `npm run build` and wheel builds remain available. A build
without a startup receipt is verified by rebuilding once on the next managed
source start. Generated setup state lives in ignored `.shellhound/`; interface
builds remain in ignored `web/dist/`. Do not commit either folder.

Tests run without additional dependencies:

```bash
python -m unittest discover -s tests -t .
```

Use the project's environment (`.venv\Scripts\python.exe` on Windows,
`.venv/bin/python` on Linux/macOS). The focused startup tests are
`python -m unittest tests.test_startup`; `python -m tools.startup_smoke` also
checks real installation/builds and both launch paths in an isolated source
copy. That smoke test may download dependencies and uses only a synthetic
workspace.

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
- Interface text, reports, and tool-generated case descriptions use English.
  Analyst notes and evidence retain their original content.

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
