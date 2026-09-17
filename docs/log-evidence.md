# Investigating log evidence

## Add logs → Analyze → Investigate

1. Open **Evidence → Add logs** and choose one file or a folder. Mixed folders
   and rotated files are supported. The preview shows a detected format for
   each file; correct it if necessary. Give sources helpful names if needed.
2. Keep **Automatic / recorded time zone**, or choose UTC, this computer's named
   zone, another named zone, or Unknown. Check the original-to-UTC preview;
   the server may use a different zone from your computer. Add the sources and choose
   **Run analysis**. A webroot is optional. Discovery and indexing appear in
   Analysis runs; individual source results appear under Log sources.
3. Open **Logs** and choose **Access**, **Web errors**, **FTP**, **Malware
   reports**, or **Other text**. Search and filter the entries, open an entry
   for original line context, and select relevant rows to add to Findings.

Selections apply to the visible page only. The API accepts at most 200 entries
per application; the non-HTTP browser shows 100 per page. Changing pages or
filters clears the selection. Searching does not confirm findings. Yellow
marks detections awaiting review or warnings; red identifies an analyst's
confirmation. Processing completion is not a verdict that the system is clean.

## Reviewing a log finding

Standalone observations and files whose findings come entirely from additional
logs open in a log-focused review. Source facts sit beside an **Evidence** tab:
FTP shows the recorded action and outcome, web errors show their original error
context, malware reports retain the scanner claim, and other text opens the
selected source lines. The viewer does not invent missing session events or
infer a successful exploit from an error. Source details collapse initially on
small screens.

**Linked file** appears only after the current source context verifies a local
file. It uses the same raw/hex viewer and syntax highlighting as file review.
Log line numbers are never passed as file line numbers. With OpenCTI configured,
**Enrichment** uses that file's existing IOC Box entries; opening a tab never
collects or submits an object. Unavailable or stale context retains the saved
excerpt and removes file and enrichment actions. Several saved observations
can be selected individually without losing the pending artifact decision.

Files with a mixture of file detections and log findings retain the file review;
their additional log observations use the same typed evidence cards. Existing
classification controls, decisions, keyboard shortcuts and explicit save still
apply to the artifact being reviewed.

## Supported formats

| Family | Automatic interpretation |
|---|---|
| Access | Existing Apache/Nginx and other supported HTTP formats, with the existing request tools and Pattern Hunt |
| Web errors | Apache/Nginx error entries and indented or numbered multiline continuations; recorded client addresses and referenced file paths |
| FTP | Standard xferlog transfers and native vsftpd activity, including recorded transfer direction, completion, account, remote host and login results |
| Malware reports | ClamAV clamscan/clamdscan text reports: explicit detections, signatures, paths, summaries, errors and reported cleanup actions |
| Other text | Original lines and surrounding context, text search and manual selection; **Not automatically analyzed** |

Plain UTF-8 and BOM-marked UTF-16 text are supported, as are `.gz`, `.bz2` and
`.xz` rotations. Unknown or mixed formats within one file default to manual
review. Empty or unreadable folders have an explicit processing warning.
ClamAV imports an existing report; Shellhound does not install or run a scanner.

Explicit scanner detections create unconfirmed findings carrying the original
scanner claim. Scan limits, encrypted-file notices and scan errors are kept
separate from malware verdicts. Existing PHP error rules still apply; an
unresolved file reference becomes a log observation with source context. FTP activity can support an already
flagged file. Routine transfers, ordinary errors and unsuccessful logins remain
searchable without generating a finding for every event.

Adapter references: [ProFTPD transfer logging](https://github.com/proftpd/www.proftpd.org/blob/master/docs/howto/Logging.html),
[vsftpd logging configuration](https://security.appspot.com/vsftpd/vsftpd_conf.html),
and [ClamAV scan reports](https://docs.clamav.net/manual/Usage/Scanning.html)
with [ClamAV's reported cleanup messages](https://github.com/Cisco-Talos/clamav/blob/main/common/actions.c).

## Source settings, time and paths

Open the source's settings button under **Evidence → Log sources** or within a
log section. Settings are per file, even inside a folder registration. A change
requires reanalysis. Access sources share a case-wide HTTP index, so use
**Run analysis** in Evidence after changing an access source.

Recorded UTC offsets take priority. For timestamps without an offset, supply
`UTC`, a fixed offset such as `+02:00`, or an installed IANA timezone such as
`Europe/Berlin`. If timezone data is unavailable on the machine, use a known
fixed offset or install timezone data through the operating system. Fixed
offsets do not account for daylight-saving transitions. Unknown, repeated or
nonexistent local times stay uncertain; import time is never substituted.

The log browser labels its times in UTC, preserves the original timestamp and
applies the case's log clock correction once, as the timeline does. Only
confirmed, relevant observations with reliable dates can supply an automatic
first known sign—for example, a recorded successful upload of a confirmed
file. A scanner detection date means discovery, not infection.

For remote paths, open **Map server paths to evidence**. For example, map
`/var/www/site` to the registered webroot `D:\Cases\Example\site`. Only exact
local evidence identities, explicit mappings, or unambiguous relative paths
are used. Matching basenames alone is never sufficient. Missing/ambiguous
paths remain visible, and **Open file** appears only for a verified local file.

## Warnings, retries and retained evidence

Use **Analyze source** or **Reanalyze source** for a failed or changed non-HTTP
source. Other sources' results and analyst decisions remain intact. A completed
source is published as a whole. Cancellation or failure retains the previous
generation as historical/stale context, and it cannot be applied as new evidence.

Accept a processing limitation when you have reviewed it and it is acceptable
for the case. Acceptance removes the active coverage warning and retains an
audit record. A changed source or warning requires a fresh review. Accepting a
limitation does not claim that unparsed content was automatically checked.

Overlapping registrations share one canonical file identity. Selected evidence
has stable record references and saved excerpts; repeated application and
reanalysis preserve analyst decisions. Case archives include source settings,
warning reviews and saved observations, but omit the rebuildable event index.
After importing an archive, make its original evidence available and analyze
the sources again before opening current context or applying observations.

All processing stays local. The reader bounds file discovery (10,000 files),
decompressed input (2 GiB / 5 million lines per file), and individual records
(128 KiB, including multiline entries). Use smaller sources if a limit is
reached. Log text is escaped when displayed. Common credential fields are
redacted from excerpts; original evidence remains unchanged on disk. Routine
diagnostics do not contain log entries.

SSH/SFTP authentication logs, binary event logs, PDF/image extraction, custom
format builders and live hoster connections are outside this version. Supply
text exports as Other text when an automatic adapter is not available.
