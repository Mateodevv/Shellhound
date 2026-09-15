# Development

See [installation](../README.md#installation) for prerequisites and the
[repository map](repository-structure.md) to locate a feature.

## Run from source

The launchers and `python -m server.main` use the same startup coordinator.
It prepares dependencies and the interface, then starts the server in the
project's `.venv`. `--help` works before dependencies are installed.
Application imports and `create_app` do not install packages, build assets or
contact Git.

```bash
python -m server.main --no-browser
```

For interface hot reload, start the backend with a development token:

```bash
python -m server.main --no-browser --token dev
```

In a second terminal:

```bash
cd web
npm run dev
```

Open `http://localhost:5173/?token=dev`.

## Run checks

Use the project environment: `.venv\Scripts\python.exe` on Windows or
`.venv/bin/python` on Linux/macOS. The backend suite uses `unittest` and the
runtime dependencies:

```bash
python -m unittest discover -s tests -t .
```

Tests generate synthetic evidence. On Windows, point `TEMP` and `TMP` at an
existing ignored directory for the test process; do not exclude the whole
AppData temporary directory from antivirus checks:

```powershell
New-Item -ItemType Directory -Force workspace/defender-safe-temp | Out-Null
$env:TEMP = (Resolve-Path workspace/defender-safe-temp).Path
$env:TMP = $env:TEMP
python -m unittest discover -s tests -t .
```

From `web/`, run the interface checks:

```bash
npm test
npm run lint -- src --deny-warnings
npm run build
npm run check:bundle
```

[Testing](TESTING.md) explains fixtures, targeted regressions and acceptance
checks. Frontend tests live beside their components or views; backend tests
are in `tests/`.

The focused startup check is `python -m unittest tests.test_startup`.
`python -m tools.startup_smoke` also checks real installation, builds and both
launch paths in an isolated source copy. It may download dependencies and
uses only a synthetic workspace.

## Build a package

```bash
python -m pip install build
python -m build
```

The build backend bundles the interface into the wheel. Follow the
[publishing guide](PUBLISHING.md) for privacy checks and verification before
distributing an artifact.

Manual `npm ci` and `npm run build` remain available. A build without a startup
receipt is verified by rebuilding once on the next managed source start.
Generated setup state belongs in `.shellhound/`, frontend output in `web/dist/`,
and packaged frontend output in `server/static/`. These directories, `.venv/`,
build artifacts and runtime workspaces are ignored. Do not add case data to Git.

## Application contracts

- Triage states survive re-scans; fingerprints stay stable.
- Dismissed findings are filtered out rather than deleted.
- Log alerts take response outcomes into account: a failed request and a
  successful request support different conclusions.
- Evidence is read through explicit data endpoints, not served as executable
  web content. Original evidence stays outside the source tree.
- Filtered artifacts are delivered in full.
- Interface text, reports and generated case descriptions use English.
  Analyst notes and evidence retain their original content.
- Source launches use the shared startup coordinator and freshness checks.

For contribution terms and handling sensitive reports, see
[Contributing](../README.md#contributing) and [Security](../SECURITY.md).
