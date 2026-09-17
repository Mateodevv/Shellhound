# Testing SHELLHOUND

See [Development](development.md) for setup and the [repository map](repository-structure.md) for source locations.

## Case workflow acceptance

Run the deterministic lifecycle checks with the project Python environment:

    python -m unittest tests.test_case_workflow tests.test_archive_integrity

On Windows, set TEMP and TMP to an existing ignored
`workspace/defender-safe-temp` directory first. Cases, databases, ZIPs and logs
are created in temporary directories and removed by the tests. No customer
workspace or remote OpenCTI is used by these tests.

`tests/fixtures_workflow.py` builds inert marker files, a normal comparison
file, synthetic HTTP requests and a benign SQL export. Actual YARA marker
rules generate multiple observations for one file. Analysis, Pattern Hunt,
triage, jobs, persistence and archive/restore go through the real application
and its HTTP routes. One explicitly synthetic database finding exercises
non-file triage without introducing malicious SQL; this is not a test of
SQL threat detection.

The lifecycle assertions cover:

- Case identity, chosen organization, sector/subsector and geography.
- File classifications, repeated triage without duplicate IoCs/events,
  SHA-256 identity and IP-to-CVE collection from actual log matches.
- Local operation without any OpenCTI client construction.
- Saved decisions across a fresh application instance; interrupted jobs are
  marked failed and analysis can run again without losing review history.
- Enrichment results, tags and score; an accepted transfer interrupted during
  status polling resumes without another push. The external OpenCTI adapter
  is simulated, but its local jobs, receipts and mappings are real.
- Every SQLite table before and after archive/restore, including evidence,
  decisions, IoCs, relationships, enrichment and transfer mappings.
- Explicit missing-source status after restore: original evidence remains
  external; the derived log index is intentionally rebuilt on analysis.
- Unreadable file errors in the log and a successful subsequent read.
- A job arriving between the idle check and archive acquisition returns 409.

Archive fault tests independently cover committed WAL pages pinned by a
reader, disk-write failure, CRC verification failure, repeated closure in the
same second, directory locks, partial cleanup and corrupt restored databases.
Archives are staged and verified before publication. A verified snapshot is
created using SQLite backup, not by copying a potentially outdated case.db.
After publication the working directory is atomically retired, then deleted.
If cleanup is blocked, a hidden `archive/.closed-*` directory remains and the
failure is logged; the ZIP remains usable. It may be removed once the lock is
released. An interrupted build can leave `archive/.closing-*` temporary data;
it is never presented as a valid closed case.

Broader related regressions:

    python -m unittest tests.test_case_profile tests.test_opencti_api tests.test_opencti_service tests.test_opencti_graph tests.test_opencti_sample_context tests.test_jobs tests.test_startup tests.test_scan_retry_api tests.test_incremental_analysis tests.test_evidence_files tests.test_evidence_rows tests.test_diagnostics tests.test_hunt_batches tests.test_review_progress tests.test_regressions

From `web/`, exercise the visible wizard and review interactions:

    npm test -- src/components/casework/CaseWizard.test.tsx src/components/review/ArtifactWindow.test.tsx src/components/enrichment/ReportTransfer.test.tsx src/components/enrichment/OpenCti.test.tsx src/components/review/FileViewer.test.tsx src/views/Start.test.tsx
    npm run build

These checks do not prove behavior against a particular live OpenCTI version,
a physical power loss, or every CMS detection rule. Use the opt-in
`tools.opencti_smoke` command described in `docs/opencti.md` for the remote
boundary. Do not infer remote acceptance from a successful HTTP submission:
the saved receipt must reach complete with visible objects.

## Dashboard evidence timeline

Use the project `.venv`, with Windows `TEMP` and `TMP` set to the ignored
`workspace/defender-safe-temp` directory:

    python -m unittest tests.test_timeline_preview tests.test_incident_dashboard tests.test_incident_summary_groups tests.test_chain_boundaries tests.test_first_sign tests.test_first_sign_api tests.test_first_sign_log_anchors

From `web/`:

    npm test -- src/views/Dashboard.test.tsx src/views/Timeline.test.tsx src/views/Findings.test.tsx src/components/casework/EvidenceTimeline.test.tsx src/components/casework/CaseChain.test.tsx src/App.test.tsx
    npm run build
    npm run lint

Harmless fixtures cover all four event series, stable identities, deduplication,
decision transitions, stale indexes, unknown dates, clock corrections, neutral
database context, bounded long ranges and filtering before pagination. Summary
tests check explicit classifications and whole-case counts beyond list limits.
Frontend tests check independent loading/errors, navigation, keyboard selectors,
single-interval bar geometry, pending decisions and persistent filters.

Use a disposable synthetic case for browser checks in both themes at laptop and
narrow widths. Follow a chart segment and keyboard selector to the same event
set, check summary links, refresh and Back, and inspect pending evidence. Stop
the preview launcher afterward and verify its process exits and checkout lock
is released; a closed HTTP port alone does not prove it stopped.

## First known sign of compromise

Focused backend coverage (use the project `.venv`, with Windows `TEMP` and
`TMP` set to `workspace/defender-safe-temp`):

    python -m unittest tests.test_first_sign tests.test_first_sign_log_anchors tests.test_first_sign_api

Frontend coverage, from `web/`:

    npm test -- src/components/casework/FirstSign.test.tsx src/components/casework/CaseChain.test.tsx

Harmless synthetic evidence covers confirmed-only eligibility, UTC ordering,
copied metadata fallback, unrelated earlier IP activity, stale/removed sources,
partial anchor reads, saved analyst choices, and case isolation. The HTTP tests
exercise an exact timeline link beyond 200 events, including missing links.
Component tests cover note preservation, failures, keyboard focus, pagination
without unwanted jumps, and deliberate repeat jumps.

For visual verification, use a disposable case: follow the dashboard marker,
choose a different event and note, refresh, then restore automatic selection.
Check the marker and editor in both themes at laptop and narrow widths. Stop
the test server and remove the disposable case afterward.

The managed-shutdown regression in `tests.test_startup` deliberately delays
Windows signal handling. This covers Python 3.10's expired subprocess wait:
the coordinator must still forward cancellation, let workers finish, and keep
the checkout lock until cleanup is complete. Do not lengthen its timeout to
hide a stalled supervisor.

## The diagnosis

Three hundred and three tests were green. A deliberate bug hunt over the same
code, at the same commit, found fifty-five real defects — timestamps shifted
twice, a confirmed shell dropping out of the chronology, ordinary shop
customers listed as having touched a webshell, a filter that returned exactly
what it was asked to hide. Every one of them was in code the suite exercised.

That is the fact this whole strategy is built around, so it is worth being
precise about why it happened, because "write more tests" was not the answer.

**Roughly half were invisible because every fixture had the same shape.** The
suite built one case: one log file, one SQL dump, one webroot, lower-case
paths throughout, well under two hundred clients, and a single time zone of
`+0000`. At an offset of zero, applying the offset twice gives the same answer
as applying it once, so five separate time-zone bugs could not be seen. With
one log file, two sources cannot collide on a basename. With one dump, SQLite
hands the re-inserted row the same rowid, so a delete using the wrong id
happens to hit the right rows anyway. With lower-case paths, a lower-casing
bug produces the string it started with. The tests were not weak. They asked
the right questions of an input that could only give one answer.

**Fourteen were on layers with no tests at all** — not thinly tested,
untested. The worst defect of the hunt lived in an HTTP route: a `WHERE`
fragment AND-ed onto the chip filters without brackets, so the query read
`(chips AND active > 0) OR triage != 'new'` and every decided artifact walked
past every filter. The aggregate underneath it was right. The engines were
right. Nothing that called a function could see it, because the defect was in
the assembly, and nothing asked the server and read the answer.

Everything below follows from those two sentences.

## The layers

**The clean fixture** (`tests/fixtures.py`) builds the ordinary case: a
WordPress webroot with a dropped shell, an access log, a dump. It is still
worth having — most assertions want a case where the expected answer can be
written down by hand — but it is now the control rather than the subject.

**The hostile fixtures** (`tests/fixtures_hostile.py`) build the same evidence
along the axes where the code has a choice to make: `+0200`, mixed offsets
across a daylight-saving change, a negative offset, India's half hour, two
vhost logs sharing the basename `access.log`, two dumps, mixed-case paths,
evidence stored under a folder the analyst happened to call `uploads`, a log
whose head was cut off mid-record, two hundred and fifty clients. Twelve named
shapes, each turning one dial, plus one that turns them all at once for the
interactions. They are deliberately not the cartesian product: sixty
combinations is a suite nobody runs.

The shapes are not "more fixtures". Each axis is one of the choices that was
made wrong at least once.

**Example tests** (`test_engines.py`, `test_coverage.py`, `test_errorlog.py`,
`test_patterns.py`, `test_sigma.py`, `test_yara*.py` and the rest) say "this
input gives that answer". They catch a rule that stops firing, a parser that
breaks on a format, a detector that fires on innocent data — and that last one
matters as much as the first, because a tamper check that goes off on ordinary
logs teaches the analyst to ignore it. Counts are asserted as lower bounds
wherever the exact number is not the point: a new rule that fires additionally
must not turn the suite red.

**Regression tests** (`test_regressions.py`) are the specific inputs that once
produced a shipped bug, each with the case that exposed it. They are not tests
of a design and they are not tidy. They exist so that a defect that was in a
release cannot come back quietly.

**Laws** (`test_laws.py`) are the answer to the shape problem. A law does not
say "this input gives that answer"; it says "whatever the input, these two
answers stand in this relation" — switching the display clock moves timestamps
and nothing else, an artifact confirmed in the case appears in the chronology,
the count in the header equals the number of rows. Each law is a loop over
`hostile_shapes()` with a `subTest` naming the shape, so a failure reports
*which* shape broke the relation. This is where a bug that is invisible at
offset zero has nowhere left to hide.

**Promises** (`test_promises.py`) sweep a written-down guarantee across every
place it must hold at once — no absolute host path in any export, every
timestamp carrying its zone, both interface languages complete. A promise that
holds in the one spot somebody thought to test is not a promise, it is a
coincidence.

**The HTTP layer** (`test_http.py`) asks the server over a real socket and
makes every assertion about the response. No endpoint function is called
directly. This is the layer that had none, and the bracket bug is why.

**The contract** (`test_contract.py`) holds `web/src/api.ts` against what the
server actually sends. TypeScript believes the hand-written declaration; the
declaration once claimed fields the endpoint had never sent, so a hunt headline
rendered from `undefined` and looked like a design decision.

**The frontend** (`web/`, vitest) covers the formatting and component
behaviour that a type checker cannot: what a timestamp renders as, what a
table shows when a field is missing. `npx tsc --noEmit` and `npx oxlint src`
must stay clean; they are part of the suite, not a tidiness ritual.

**Repository metadata** (`test_brand.py`, `test_issue_forms.py`,
`test_i18n.py`) guards things that fail without raising anything: a malformed
GitHub issue form is silently not offered, a missing catalogue key renders as a
raw dotted string, two copies of the logo drift apart.

**Mutation testing** is the layer that checks the layers. See below.

## Running it

From the repository root. Python 3.10 or newer, stdlib `unittest`, no pytest:

    python -m unittest discover -s tests -t .
    python -m unittest tests.test_laws -v                 # one module
    python -m unittest tests.test_laws.ClockSwitchLaw -v  # one class

The frontend, from `web/`:

    npm test
    npx tsc --noEmit
    npx oxlint src

CI (`.github/workflows/ci.yml`) runs the backend suite on Linux **and**
Windows, on the oldest and newest supported Python. Path handling is exactly
the class of bug the other operating system reveals, which is why both are
there and why neither is optional.

## Mutation testing

The real question about a suite is not whether it passes but whether it
**fails when the code is wrong**. A mutation run introduces one small
deliberate defect into `server/` — an operator flipped, a constant nudged, a
condition negated — and runs the whole suite against it. If the suite goes
red, the mutant is killed and something was defending that behaviour. If the
suite stays green, the mutant survived, and nothing was.

Surviving mutants are the most useful output this project produces about its
own tests. During the bug hunt this was done fifteen times by hand and twice
the first attempt at a test would have guarded nothing at all — it passed
against the mutant. That is not a rare accident; it is what an unchecked test
looks like from the inside.

The tool is **cosmic-ray**, configured in `pyproject.toml` under a top-level
`[cosmic-ray]` table, with the reasoning written next to it. It is cosmic-ray
and not mutmut for one blunt reason: mutmut 3 checks `platform.system()` before
it does anything else and refuses to start on Windows, and this repository is
developed on Windows. A mutation tool that only the Linux CI can start is a
tool nobody reaches for while they are writing the test, which is the one
moment it is worth anything.

To run it over a single module — which is what you do while writing a test,
never the whole package:

    pip install cosmic-ray
    python - <<'PY'
    import tomllib
    from cosmic_ray.config import serialize_config
    with open("pyproject.toml", "rb") as handle:
        cfg = tomllib.load(handle)["cosmic-ray"]
    cfg["module-path"] = ["server/coverage.py"]
    with open("shard.toml", "w") as handle:
        handle.write(serialize_config(cfg))
    PY
    cosmic-ray baseline shard.toml            # the suite must be green first
    cosmic-ray init shard.toml session.sqlite
    cosmic-ray exec shard.toml session.sqlite
    cr-report --surviving-only --show-diff session.sqlite

`baseline` is not ceremony. If the suite is red for its own reasons then every
mutant is "killed" and the run reports a perfect score it has not earned.

On Windows, pip installs those commands into a per-user `Scripts` directory
that is often not on `PATH`. `python -m cosmic_ray.cli …` stands in for
`cosmic-ray`, but the `cr-*` reporting tools have no `__main__` guard and
running them with `-m` silently prints nothing at all — call the executables by
their full path rather than believing an empty report.

**Cosmic-ray mutates the file on disk and puts it back afterwards.** If a run
is interrupted — Ctrl-C, a closed terminal, a timeout — the last mutant stays
in your working tree, and it is a syntactically valid, silently wrong change to
production code. Check `git status` after every run, and `git checkout --
server/` without hesitating. For the same reason, never run two sessions in one
working tree.

The whole of `server/` is about ten and a half thousand mutants, each costing a
full run of the suite: hours, not minutes. `.github/workflows/mutation.yml`
runs it **manually**, sharded across eight parallel jobs, and uploads the
survivors as an artifact. Both GitHub workflows use only `workflow_dispatch`:
start them only when explicitly requested. Pushes, pull requests and scheduled
timers do not start Actions. Mutation testing gates nothing; reading the
report is a person's job.

One job in that workflow *does* fail the run: the one that checks every `.py`
file under `server/` appears in some shard. A hand-written shard list rots into
a file that is never mutated, silently, forever — which is the "whole layers
with no tests" failure mode wearing a different hat.

The matrix artifacts are merged into `mutation-triage.md` after every run.
That file orders storage, HTTP and indexing modules first, counts survivors by
module and marks an interrupted shard as **PARTIAL**. Its survivor count is a
lower bound, never a flattering score. Triage each entry as a real test gap,
an equivalent mutant or an invalid mutation; only the first category asks for
a test, and the test must fail against that mutant before it is done.

**Not every survivor is a gap.** Some mutants cannot change behaviour at all,
and reading a report means separating those out by hand. `server/artifacts.py`
has a real example: mutating `target[len(best) + 1:]` into `* 1`, `// 1`, `** 1`
or `+ 0` survives every time, because the very next line does `.strip("/")` and
the leading slash the mutant leaves behind is removed either way. Likewise
`str(uri).split("?", 1)[0]` does not care whether the maxsplit is 1 or 2, since
only element zero is ever read. Those are equivalent mutants, not missing
tests, and no amount of test-writing kills them. The survivors worth acting on
are the ones where you can say out loud what would now go wrong — and if you
cannot say it, look harder before you write the test, because the test will
otherwise assert something nobody needs.

## What this strategy deliberately does not do

**There is no line-coverage target, and there will not be one.** The suite that
missed fifty-five bugs had good coverage of the affected files. The lines ran.
They ran with inputs at which the defect produces the correct answer — offset
zero, one log, lower-case paths. Coverage measures which lines executed, and
the fifty-five bugs were all in lines that executed. A percentage would have
been green throughout the entire period the tool was wrong, and chasing it
would have bought more tests over the same clean shape, which is precisely the
thing that failed. Coverage is worth reading when it shows a *zero* — a module
nothing touches at all is a real finding. As a target it measures the wrong
thing, and mutation testing measures the right one.

**Generated prose is not snapshot-tested.** The chronology, the case summary
and the translated rule descriptions are all text the server writes, and the
obvious move is to freeze a known-good output and diff against it. Do not. A
snapshot freezes a bug exactly as readily as it freezes a wording, and it
announces both the same way — as a diff somebody approves on a Tuesday to get
the build green. This is not hypothetical here: the YARA equivalence test did
precisely that, pinning the old regex's output as the expected answer, so it
went on asserting the defect long after the defect was known. Assert the
property instead: that the sentence names the artifact, that it carries a zone,
that the ordering is monotonic, that both languages produce a string and
neither produces a raw catalogue key.

**The hostile shapes are not multiplied together.** Twelve shapes and one
combined shape, not the sixty-odd combinations. The combinations mostly retest
the same decision, and a suite that takes a quarter of an hour is a suite
people stop running before they push.

## Evidence navigation regressions

Run `python -m unittest tests.test_evidence_files tests.test_evidence_rows
tests.test_evidence_navigation tests.test_reveal_file tests.test_windows_paths`
(on one command line) with the project environment. These cover source line
lookup beyond the first raw page, UTF-8 byte boundaries, Explorer paths with
spaces, SQL table row ordinals across INSERTs, compressed exports, bounded
previews, multiple exports, case isolation, and unavailable evidence.

The corresponding interface tests are `FileViewer.test.tsx` and
`DatabaseRowWindow.test.tsx`. For browser verification, use harmless text and
SQL exports in a disposable workspace: open a distant line, page backward and
forward, and open the same table in two exports. Verify row selection and that
closing its window preserves an unsaved analyst note. Stop the test server
afterward; do not reuse real case evidence for these checks.

Database finding links identify a **table row ordinal**, not a line of SQL.
The row viewer shows the selected export's current contents. Existing findings
can combine observations from several exports; the user must choose a source
when several indexed exports contain the table. No existing finding identity
or triage decision is rewritten. Missing or unregistered evidence remains
unavailable until its location or case registration is corrected.

## Where a new test goes

If you fixed a shipped bug, `test_regressions.py`, with the input that exposed
it. If you are asserting a value for a given input, the example file for that
subject. If what you are asserting is a *relation* that must hold whatever the
evidence looks like, `test_laws.py`, as a loop over `hostile_shapes()`. If it
is a guarantee the README or a docstring makes to the analyst,
`test_promises.py`. If it is about what comes back over the wire,
`test_http.py`.

And if you cannot make the test fail — comment out the line it is meant to
defend, or run a mutation session over that one module — you have not written
a test yet. A green suite bought by a test that asserts nothing is exactly how
fifty-five bugs got through.
