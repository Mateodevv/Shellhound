# syntax=docker/dockerfile:1
# Build the regular wheel; the runtime has no source checkout or Node.js.
FROM node:22-bookworm-slim AS frontend
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM python:3.13-slim-bookworm AS wheel
WORKDIR /src
RUN python -m pip install --no-cache-dir build 'pyproject-hooks>=1.3'
COPY pyproject.toml build_backend.py MANIFEST.in ./
COPY LICENSES/ LICENSES/
COPY docs/user-guide.md docs/LICENSING.md docs/
COPY docs/legal/LICENSE docs/legal/NOTICE docs/legal/
COPY server/ server/
COPY --from=frontend /src/web/dist server/static
# Without web/package.json, the build backend uses the prebuilt interface.
RUN python -m build --wheel
COPY tools/check_release_privacy.py tools/reviewed_assets.json tools/
RUN python tools/check_release_privacy.py archives dist/*.whl

FROM python:3.13-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SHELLHOUND_WORKSPACE=/workspace \
    SHELLHOUND_PORT=8710
RUN useradd --create-home --uid 10001 shellhound \
    && mkdir /workspace /evidence \
    && chown shellhound:shellhound /workspace
COPY --from=wheel /src/dist/*.whl /tmp/wheels/
RUN python -m pip install --no-cache-dir /tmp/wheels/*.whl \
    && rm -rf /tmp/wheels
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/shellhound-entrypoint
COPY docker/healthcheck.py /usr/local/lib/shellhound-healthcheck.py
USER shellhound
WORKDIR /home/shellhound
EXPOSE 8710
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "/usr/local/lib/shellhound-healthcheck.py"]
ENTRYPOINT ["/usr/local/bin/shellhound-entrypoint"]
