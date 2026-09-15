# Repository structure

The backend groups case profiles, IoCs and integrations by responsibility.
The frontend keeps page views separate from reusable feature components.
Start commands and runtime data locations are unchanged.

```text
server/
  app.py, main.py, startup.py   HTTP application and managed startup
  db.py, workspace.py          Persistence and workspace lifecycle
  casework/                   Case profiles, options, changes and reports
  ioc/                        IoC API, model, tags and export formats
  integrations/
    opencti/                  Client, graph, transfer service and samples
    enrich.py, geoip.py        Direct enrichment and local GeoIP lookup
  engines/                    Evidence parsing and detection
  data/, rules_bundled/       Bundled geography data and detection rules
web/src/
  App.tsx, api.ts              Application shell and API access
  views/                      Page-level features
  components/
    casework/                 Case wizard, profile and chronology
    iocs/                     IoC detail, editing and presentation
    enrichment/               Enrichment, OpenCTI and transfer controls
    logview/                  Log evidence and trace components
    review/                   Artifact review and file/database viewers
    settings/                 Workspace and integration settings
    shell/                    Navigation, branding and background jobs
    ui/                       Shared controls, charts and syntax rendering
  i18n/                       Shared interface text
  test/                       Shared frontend test setup
tests/                        Backend tests and synthetic fixtures
docker/                       Container entrypoint and health check
tools/                        Development, verification and release scripts
docs/                         User and developer guides
  releases/                   Historical release notes
assets/                       Reviewed documentation assets
.github/                      Workflows and contribution templates
```

## Find a feature

| Change | Main locations |
|---|---|
| Case creation or profile changes | `server/casework/`, `web/src/components/casework/` |
| IoC values, tags or relationships | `server/ioc/`, `web/src/components/iocs/`, `web/src/views/IocBox.tsx` |
| OpenCTI lookup, transfer or enrichment | `server/integrations/opencti/`, `web/src/components/enrichment/` |
| Direct enrichment or GeoIP | `server/integrations/`, `web/src/components/settings/` |
| Artifact review and file contents | `web/src/components/review/`, `server/app.py`, `server/engines/` |
| Log evidence and traces | `server/engines/`, `web/src/components/logview/`, `web/src/views/` |
| Shared interface controls | `web/src/components/ui/` |
| Startup, installation or package output | Root launchers, `server/startup.py`, `build_backend.py`, `pyproject.toml`, `Dockerfile` |

## Placement conventions

The root keeps short `README.md` and `AGENTS.md` entry points alongside launch
and build files. Full instructions live in [the user guide](user-guide.md) and
[project guidance](project-guidance.md); changes are in [the changelog](CHANGELOG.md).
The security policy lives under `.github/`, and license texts and notices live
under `docs/legal/`.


Keep a component's test beside it. Feature-specific helpers stay with their
feature; controls used across features belong in `components/ui/`. Page views,
shared root utilities and worker entry points keep their own locations.
Import modules directly so dependencies and lazy-loading boundaries remain
visible.

Backend packages use ordinary `__init__.py` files without eager re-exports.
Preserve function-local imports where needed to avoid cycles between
persistence, IoCs and integrations. Tests remain in one `tests/` directory
because workflow tests exercise several packages together.

Bundled resources stay under `server/data/` and `server/rules_bundled/`, with
package-data configuration in `pyproject.toml`. Resolve resource paths from
their package location, not the current working directory.

`casework/` contains implementation code. Actual cases, settings, evidence,
logs and local databases belong in the configured runtime workspace and must
never be committed. Generated build output is separate from source code.

See [Development](development.md) for commands and [Publishing](PUBLISHING.md)
for release checks.
