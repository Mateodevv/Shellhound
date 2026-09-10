# Shellhound project guidance

- The interface is English-only. Keep user-facing copy in the shared English
  catalogue; do not restore the removed German interface.

- **Codi reminder:** before starting fixes or code changes, check `git status`
  and run `git fetch origin`. Update a tracking branch with `git pull --ff-only`;
  start new feature work from the latest `origin/main`, or safely integrate it
  into an existing feature branch before editing. Preserve local changes and
  commits; never reset or discard work to make a pull succeed. These routine
  fetch/pull operations are authorized unless the user explicitly asks to work offline.
- User startup: `Start-Shellhound.bat` on Windows, `./shellhound.sh` on Linux/macOS.
  Both delegate to `python -m server.main`; `--update` explicitly updates the current upstream.
- Use the project `.venv` for Python checks. Focused startup checks:
  `python -m unittest tests.test_startup`; real isolated setup/build check:
  `python -m tools.startup_smoke` (may download dependencies).
- On Windows, run the broader suite with `TEMP` and `TMP` pointing into an ignored
  folder under `workspace/defender-safe-temp`, because tests create synthetic attack probes.
- Never commit case data, `.venv`, `.shellhound`, `web/dist`, or `server/static`.
- **Codi reminder:** all user-facing source launches must use the shared startup
  coordinator. A Git pull changes interface sources, not the built interface;
  preserve automatic freshness checks and never fall back to a staged wheel UI.
- **Codi reminder:** retry skipped files through `scan_retries`, retaining their
  original evidence root. A targeted retry must never advance a whole-engine
  retirement marker or clear findings for files it could not examine.
- **Codi reminder:** Defender also scans Codex conversation logs. Avoid printing
  raw webshell fixtures or payload-bearing diffs; use harmless marker rules for
  scanner infrastructure tests. An ignored temporary folder does not prevent
  alerts when a sample is copied into tool output.
- **Codi reminder:** saved Pattern Hunt evidence needs both the current registered
  log-source check and the index generation fingerprint. Changed registrations
  can stale a run before reindexing; rebuilding unchanged files can change request IDs.
- **Codi reminder:** a database finding's `line` is a table row ordinal, not an
  SQL source line. Use the case-scoped row reader and let analysts choose among
  exports with the same table; never treat the table name as a filesystem path.
