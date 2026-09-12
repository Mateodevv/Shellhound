# Security

## Reporting a vulnerability

Please do **not open a public issue** for security problems. Use GitHub →
*Security* → *Report a vulnerability* (private vulnerability reporting), or
mail the repository owner.

What helps: the affected version or commit, the smallest reproduction you
can manage, and what an attacker could achieve with it. A reply comes as
soon as possible — this is a project without a support contract, not a
guaranteed response time.

**Never attach anything from a real case.** No webroot, no logs, no dump, no
customer IPs. If a bug only appears with certain data, describe its *shape*
— "an access log with `\r\n` inside a line", "a dump with the `#__` table
prefix" — or build a minimal example.

## What SHELLHOUND is built for — and what it is not

SHELLHOUND is a **single-seat tool for a forensic machine**. It binds to
`127.0.0.1` by default and assumes exactly one person works at the machine,
someone who has access to all the evidence anyway.

**It is not a multi-user service.** There are no user accounts, no roles, no
audit log of who saw what. Whoever holds the token holds the whole case.

A few consequences follow that you need to know:

| Point | What holds |
|---|---|
| **No TLS** | The server speaks plain HTTP. For `127.0.0.1` that is right. For access from another machine: **SSH tunnel**, not `--host 0.0.0.0` into the open network. |
| **Token in the URL** | The access token is accepted as `?token=…`. That ends up in the browser history and in the logs of every proxy in between. On a loopback bind it is injected into the page and does not appear in the URL. |
| **Random token per start** | Without `--token` every start generates a new one. A non-loopback bind **requires** an explicit `--token`. |
| **File system browser** | `/api/pickpath` deliberately browses the *entire* file system of the machine — evidence could not be selected otherwise. Whoever holds the token can list directories with it. |
| **The file viewer is fenced in** | Only what lies *resolved* inside a registered evidence root of the case is read. Symlinks and `..` do not lead out. |
| **Evidence is never served** | Findings carry text excerpts, not files. The viewer delivers content as JSON **data**; a malicious `.html` from a webroot is a string in a `<pre>` here, not a page the browser executes. |
| **Import is suspicious** | A case archive is a file from outside: absolute paths and `..` traversal are **rejected**, not sanitised, and an import never overwrites an existing case. |

## Network contact

Source installation and updates are separate from case analysis. The startup
launcher may download required Python/npm packages when first preparing the
application or when dependencies change. It uses the configured package
registries and announces these steps. The explicit Update action contacts the
current Git upstream; ordinary startup never fetches application updates.
Preparation does not inspect or transmit cases, evidence, workspace settings,
or API keys. A prepared installation starts offline.

During analysis, SHELLHOUND speaks outward at **two places**, both shut by default and both
opened by an explicit click.

**The GeoIP country database** from `download.db-ip.com`. A confirmation
window says so beforehand; if it is declined, nothing is fetched. **No case
data** goes out — the request contains nothing but the file name. On a
machine without network access you place the `*.mmdb` into the workspace by
hand instead.

**OpenCTI integration** uses a dedicated token configured under *Settings*.
Direct VirusTotal and AbuseIPDB network calls are retired; historical results
remain local and readable.

| Point | What holds |
|---|---|
| **Separate actions** | Lookup reads existing OpenCTI knowledge. Transfer submits only a reviewed preview. Enrichment requires a separate connector selection; unknown observables need explicit creation consent. |
| **No network on display** | Views read stored responses. Explicit jobs may poll their submitted work; a separate status action resumes later checks. |
| **Manual enrichment** | Transfers are refused while any active internal enrichment connector is automatic. External feed imports may continue. |
| **Original files** | Uploads default off, require per-file selection, and verify the exact snapshot against preview hashes. Metadata enrichment refuses Artifacts and files with attached content. |
| **Privacy review** | Random organization pseudonyms do not anonymize domains, emails, notes or evidence. Preview exclusions and workstation-path redaction apply before transfer. TLP markings do not replace OpenCTI permissions. |
| **Token storage** | The integration token lives in cleartext `settings.json` outside case archives, owner-readable where supported. Public settings expose only its last four characters. Changing the server URL clears the old token. TLS verification stays enabled; redirects are refused. |

What comes back is stored as a **third-party opinion**: apart from the
findings, never a severity, never a triage decision.

Everything else — analysis, traces, local country attribution, local file exports — runs
entirely offline.

## Handling live web shells

A webroot under examination contains working attack code. SHELLHOUND
executes none of it — it reads, hashes and displays. Even so:

- **Work on an isolated machine**, ideally a VM without network access, with
  a snapshot taken beforehand.
- **Work with a copy, not with the live system.**
- An antivirus scanner can **silently block or delete** evidence files — on
  Windows this was reproducible for files with certain PHP patterns. The
  evidence folder belongs in the exceptions, otherwise evidence goes missing
  without anyone noticing.

## What never belongs in the repository

The `.gitignore` is deliberately broad: no webroot, no logs, no dumps, no
case folders. One test file ignored too many costs nothing; one customer
file published by accident cannot be taken back.
