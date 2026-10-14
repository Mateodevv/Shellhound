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

**No detections in this version** requires a successful scan of that exact file
version. A previous scan of its folder is not enough. New or changed files,
skipped files, and older cases without per-file scan records show **Not analyzed**;
the question mark explains how to run analysis. Refreshing a comparison updates
its file inventory, not its detection coverage.

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

Analysis prepares complete SHA-256 identities for files in the registered
webroots, including cases with no registered backups. Confirming or dismissing
file content reuses that index for identical copies in this case. Saving a
decision does not walk webroots, reread file contents, or start another scan;
it checks the indexed copies' file metadata before applying the assessment.
Reuse includes renamed files, other folders and other websites in this case.
The question-mark help beside file classification explains this behavior.

After adding or changing evidence, run analysis to refresh the index. Changed
or unavailable indexed copies do not receive the new assessment and are reported
in the decision receipt. Changed file metadata withdraws an inherited decision
pending reanalysis; missing sources retain their historical decisions. In an
older case without a prepared identity, the selected decision
can still be saved; run analysis, then save it again to share it with copies.
Existing shared hash assessments are applied to newly indexed copies during
analysis. Preparation can be cancelled through Analysis runs.

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
