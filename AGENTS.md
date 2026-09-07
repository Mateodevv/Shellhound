# Shellhound project guidance

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
