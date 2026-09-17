# Comparing website backups

Use **Evidence & analysis → Website and backups** to compare several preserved
copies of the same website. Originals stay in place. Shellhound groups review
work; it does not delete duplicate evidence or assume a backup is clean.

1. Add each backup as a **Webroot**. One registered parent folder may contain
   several distinct website roots.
2. Choose **Add backup**. Select or name the website, choose the evidence source,
   and set the website root inside it. **Preview relative paths** helps check
   that, for example, `plugins/example/settings.php` refers to the same location
   in each backup. Give each copy a useful name.
3. Set an optional backup date and its time zone. Mark its coverage **Complete
   website**, **Partial backup**, or **Unknown coverage**. Unknown dates stay
   unknown; a supplied backup date is an observation boundary, never a claim
   about when compromise began.
4. Choose **Prepare comparison**, then **Compare backups**. Preparation is also
   performed after applicable webroot analysis. Progress and cancellation are
   available in Analysis runs. Preparation hashes files; run analysis for
   detection coverage.

The comparison opens on **Suspicious files**, including other versions of those
paths that produced no detection or have not been analyzed. **All changes** and
**All files** show the wider context. Open a path for its backup history, source
locations, full SHA-256 hashes, analyst decisions, and selected-version text
comparison. Backup, path, and pair selection survive page refresh.

Text comparisons are local and escaped, limited to UTF-8 files of 1 MiB and
12,000 lines. Binary or larger versions retain their hashes and original-file
navigation. **Add to Findings** explicitly creates an unresolved observation;
comparison alone creates no scanner detections or confirmations.

## What gets grouped

A review group has one website, one relative path, and one verified SHA-256.
Identical copies at that location appear once in Findings, with a backup count
and all supporting observations. Changed content remains a separate review
item. Filters and pagination operate on these groups. A different website or
different relative path remains a separate occurrence, even with identical
bytes. Timelines retain each copy's separate recorded observations.

Conflicting earlier confirmed/dismissed decisions remain visible as **Review
conflict**. Hiding dismissed findings cannot hide that conflict. Reports group
confirmed copies while retaining the names and relative paths of their backups.

## Reusing content assessments

Confirming or dismissing file content automatically reuses that assessment for
identical copies in this case. Shellhound verifies the
complete SHA-256, then checks registered webroots in a cancellable background
job. Reuse includes renamed files, other folders and other websites in this
case. The question-mark help beside file classification explains this behavior.

Independent earlier decisions are preserved, with conflicts reported. Reuse
records its origin and an audit entry; it does not independently confirm linked
IPs or requests. A malicious assessment can create a clearly labelled inherited
observation on a previously unflagged copy. A benign assessment does not create
extra Findings just to record that a file exists.

Explicit file/hash assessments in the IOC box are also reused. Historical
occurrence dismissals and default IOC badges are not treated as global content
verdicts. Reuse never crosses case boundaries. Changed bytes need a new decision;
withdrawing a shared assessment restores earlier inherited states without
erasing the audit. Source-specific exceptions stay independent.

## Dates and unavailable evidence

Log and webroot import offer **Automatic / recorded time zone**, **UTC**, this
computer's named zone, **Choose time zone**, and **Unknown**. Automatic preserves
recorded offsets and format-defined UTC. It does not guess the server's zone
from the analyst's computer. Named zones apply historical daylight-saving rules;
ambiguous or nonexistent wall times remain undated. The log preview shows
original times and their interpreted UTC values where available.

Filesystem timestamps already represent recorded instants. The webroot setting
provides source/backup context and does not shift those epochs. Timestamps on an
extracted or copied webroot may reflect that copy operation, not the original
host. Existing clock corrections remain separate.

Missing, unreadable, changed, cancelled, or interrupted sources are labelled
unavailable or historical. A failed discovery keeps the previous published
manifest; incomplete preparations cannot imply that a file disappeared. **Not
present** means absent from that particular readable backup, not necessarily
deleted from the live website. Accepted scan skips still mean the file was not
analyzed. Restore the source and use **Refresh comparison** to retry.

Metadata and decision history stay in the case database and travel with case
archives; original files remain external evidence. Re-register and prepare roots
after moving evidence to another machine. The only added dependency is the small
`tzdata` package for named time zones on systems without a system zone database.
Normal setup downloads it when needed; time-zone conversion is local afterward.
