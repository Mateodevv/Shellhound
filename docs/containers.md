# Run locally with Docker

Docker Desktop must be running with Linux containers (or use Docker Engine on
Linux), with Docker Compose v2 or newer available. The host does not need Python or
Node.js. The image builds the regular Shellhound wheel and installs it as a
non-root user; the application follows its normal installed-package start path.

## First start

1. Copy `.env.example` to `.env`.
2. Set `SHELLHOUND_TOKEN` to a long random value from a password manager.
   This protects the local Shellhound API; it is not an OpenCTI or enrichment key.
3. Set `SHELLHOUND_EVIDENCE_DIR` to an existing directory containing the evidence
   you want to examine. On Windows use forward slashes, for example
   `D:/Evidence`. Quote paths containing spaces with double quotes in `.env`.
4. From the repository root, run:

```bash
docker compose up --build -d
docker compose ps
```

The first build downloads base images and dependencies. Open
`http://127.0.0.1:8710/?token=YOUR_TOKEN`, replacing `YOUR_TOKEN` with your chosen
token (URL-encode it if it contains special characters). A random hexadecimal
token avoids URL escaping. If port 8710 is occupied, change
`SHELLHOUND_PUBLISHED_PORT` in `.env` and use that port in the URL.

Compose publishes only to the host's loopback address. The server listens on
all interfaces *inside* the container so Docker can forward requests to it.
The page does not automatically reveal the token; API requests without it
receive 401. Configure OpenCTI, direct enrichment keys, themes and GeoIP in the
normal Settings dialog.

## Cases and evidence

- Cases, settings, enrichment keys, GeoIP data and the application log persist
  in the named `workspace` volume mounted at `/workspace`.
- Host evidence is mounted read-only at `/evidence`. Register files and folders
  using their **container paths**, for example `/evidence/sample/webroot`.
- Evidence is never copied into the image or included in a case archive.
  Keep the mount path stable so saved evidence registrations continue to work.
- Use one application container per workspace volume. Do not share the same
  writable case database between replicas.
- On Linux, the runtime user (UID 10001) needs read/traverse permission on the
  evidence directories. The container does not change host permissions.
- Existing desktop cases are not imported automatically. Use case export/import
  and update evidence registrations to the mounted paths. An imported case
  archive does not include its original evidence.

`Show in file manager` cannot open the host's Explorer/Finder from a container.
The built-in file viewer still works. Use the host file manager to navigate to
the directory you mounted.

## Stop, update and inspect

```bash
docker compose stop
docker compose start
docker compose logs --tail=100
```

The detailed application log is stored in the workspace volume. To copy it out:

```bash
docker compose cp shellhound:/workspace/logs/shellhound.log ./shellhound.log
```

Treat logs, the volume and `.env` as private data. Never publish them or include
them in a support attachment without reviewing their contents.

After updating the source checkout, rebuild the image with current base images:

```bash
docker compose build --pull
docker compose up -d
```

Do not use the source updater inside the installed container. Replacing the
container preserves the named volume. `docker compose down` also keeps that
volume; **`docker compose down --volumes` deletes the persistent case data**.
Keep the same Compose project name/directory when updating, or explicitly set
`COMPOSE_PROJECT_NAME` so Compose continues to use the same volume.

## Verification and build context

```bash
docker build -t shellhound:test .
python -m tools.container_smoke --image shellhound:test
```

The smoke test uses only invented data and temporary containers/volumes. It
checks the actual Compose deployment, authentication, the UI and a bundled asset, health, non-root execution,
read-only evidence, case persistence after container replacement, shutdown and
rejection of startup without a token. It also tests the Docker build-context
exclusions against harmless markers.

The `.dockerignore` starts by excluding everything, then admits only required
source and build inputs. Workspace data, audit output, configuration files,
documentation screenshots and host dependencies stay outside the context.
Build from a reviewed checkout; a source allowlist does not inspect source text
for secrets. The wheel build also runs the project's archive privacy check.
See [Publishing](PUBLISHING.md) for the remaining release checks.

The CI container job builds and smoke-tests the image without publishing it
to a registry. See Docker's [build context documentation](https://docs.docker.com/build/building/context/)
and [Compose service reference](https://docs.docker.com/reference/compose-file/services/)
for Docker configuration details.
