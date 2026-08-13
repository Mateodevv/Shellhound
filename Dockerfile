# syntax=docker/dockerfile:1
# The container is a THIN SHELL around the same artifact a standalone
# installation uses: the runtime stage installs the wheel that
# `python -m build` produces, with the interface staged under server/static
# the same way build_backend.py stages it. There is deliberately no
# container-only code path in the server -- a VM without virtualisation
# installs the identical wheel with pip and passes the identical arguments
# by hand.

# --- the interface, built once with Node ---------------------------------
# Node is a build-time tool only (see build_backend.py); the runtime image
# never carries it.
FROM node:22-bookworm-slim AS frontend
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# --- the wheel ------------------------------------------------------------
# web/ is NOT copied here, only its dist: build_backend.py rebuilds the
# frontend whenever web/package.json is present, and without it the backend
# takes the sdist path -- verify server/static exists and package it. That
# is exactly the path a release wheel takes.
FROM python:3.12-slim AS wheel
WORKDIR /src
RUN pip install --no-cache-dir build
COPY pyproject.toml build_backend.py MANIFEST.in LICENSE NOTICE README.md ./
COPY server/ server/
COPY --from=frontend /src/web/dist server/static
RUN python -m build --wheel

# --- the Linux test lane --------------------------------------------------
# Not part of the shipped image and not built by a plain `docker build`;
# `docker build --target test .` runs the whole Python suite on Linux --
# the platform the container runs on, and until this stage existed the
# platform the suite had never run on. Path handling is the class of bug
# the other operating system reveals.
FROM python:3.12-slim AS test
WORKDIR /src
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
# The WHOLE repository, not a selection: the suite reads .github/ (issue
# forms), docs/, assets/brand and web/src as fixtures of its own promises.
COPY . .
RUN python -m unittest discover -s tests -t .

# --- the shipped image ----------------------------------------------------
FROM python:3.12-slim AS runtime
# A fixed uid so evidence mounted read-only can be chowned/chmodded FOR the
# container on the host side without guessing.
RUN useradd --create-home --uid 10001 shellhound
COPY --from=wheel /src/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
# The workspace directory exists in the image with the right owner, so a
# named volume inherits that ownership on first use instead of arriving
# root-owned and unwritable.
RUN mkdir /workspace && chown shellhound:shellhound /workspace
COPY docker/entrypoint.sh /usr/local/bin/shellhound-entrypoint
RUN chmod 0755 /usr/local/bin/shellhound-entrypoint
USER shellhound
ENV SHELLHOUND_WORKSPACE=/workspace
VOLUME /workspace
EXPOSE 8710
ENTRYPOINT ["/usr/local/bin/shellhound-entrypoint"]
