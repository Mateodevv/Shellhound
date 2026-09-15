# Publishing Shellhound

Publish from a clean checkout of the reviewed revision. Do not ZIP a development
folder: Git ignores do not exclude files from an Explorer ZIP, and a local
checkout may contain case databases, settings, API keys, screenshots and logs.
GitHub account names and their public noreply addresses are intentional project
attribution. Customer identities and personal contact addresses are not.

## Before opening a pull request

Use invented case references, `.test` domains and documentation-range IPs for
examples. Keep runtime settings and evidence outside the source tree. The ignore
rules also cover runtime `settings.json` backups and private audit/remediation
folders, but ignoring a file does not remove earlier commits or uploaded copies.

Check the tracked working tree and Git identities:

```bash
python -m tools.check_release_privacy source --history
```

The check rejects runtime configuration, case data, log files, evidence/workspace
folders, linked entries and unreviewed binary assets. Intentionally sparse-excluded
files are listed in the summary count without being materialized; a release must
use a full clean checkout, as CI does. The history check inspects raw author,
committer and annotated-tag emails, without applying `.mailmap`. It permits GitHub
noreply addresses and a small list of known technical identities. Configure Git
with the noreply address supplied by your GitHub account before committing.

The check examines tracked entries, including their current working copies. New
files must be staged before relying on this result. It does not silently include
or bless untracked working material.

Run Gitleaks 8.30.1 with full redaction as a separate secret check:

```bash
gitleaks git . --log-opts=--all --redact=100 --ignore-gitleaks-allow
```

CI installs that exact release with a checked archive digest. A failed scan must
be investigated; do not add a broad baseline, path ignore or rule suppression to
make it pass. Test credentials should be unmistakably synthetic. An exposed real
credential must be revoked or rotated separately from removing its committed copy.

## Screenshots and other binary assets

`tools/reviewed_assets.json` records the SHA-256 of each reviewed raster image and
font. Any new or changed binary requires a new review and a deliberate catalog
update. Hash equality detects changes; it does not inspect picture content.

For a screenshot, inspect the full image, metadata and any embedded thumbnail.
Generate its data from a synthetic case. Check case/profile names, identifiers,
accounts, hostnames, URLs, paths, notifications and background windows. Redaction
must remove the information, not place a reversible overlay above it. For fonts,
verify the upstream file and include its license. Do not auto-approve every file
found by a script. The guard recognizes the frontend's `server/static` font path
as the packaged copy of the corresponding `web/public` asset.

## Build and inspect the deliverables

Use the package CI job or a fresh isolated checkout with its own dependencies:

```bash
python -m build
python -m tools.check_release_privacy archives dist/*.whl dist/*.tar.gz
gitleaks dir dist --max-archive-depth=4 --redact=100 --ignore-gitleaks-allow
```

Archive checks read members in place and never extract them. They reject unsafe
paths, links, runtime data, disguised SQLite files, nested archives and binary
assets that do not match the review catalog. Entry/count/total-size limits bound
the inspection. The package CI job runs these checks before installation and
artifact upload, and only uploads `dist/` from its clean runner.

The console output from the structural check contains only violation categories
and entry numbers. For local investigation, add `--details` with a path in a
private directory, for example `--details ../private-audit/details.json`. This
report contains paths and object identifiers: never commit, attach or upload it.
CI keeps detailed Gitleaks output in runner-local temporary files and reports a
generic failure message, rather than publishing matched source context.

These checks do not prove that every sentence, encoded value or image is free of
personal data. Review documentation and examples as well as code. Before promoting
a previously published project, also audit old releases, Actions artifacts/logs,
Git history, issue/PR attachments and edited discussion content; a clean latest
commit does not erase those copies.
