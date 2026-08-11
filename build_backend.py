"""PEP 517 backend that makes the React interface part of every release.

Setuptools can include ``server/static`` once it exists, but it cannot create
that directory from the Vite sources.  A plain ``python -m build`` therefore
used to succeed while producing a wheel whose start page only said that the
frontend was missing.  Preparing the interface here makes the build command
itself carry the promise instead of relying on an undocumented step before it.

An installed wheel does not need Node.  Node and npm are build-time tools only.
When a wheel is built from the sdist, the already-built static files travel in
the sdist and this backend deliberately does not try to rebuild them.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from setuptools import build_meta as _setuptools


ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
WEB_DIST = WEB / "dist"
STATIC = ROOT / "server" / "static"


def _prepare_frontend() -> None:
    """Build and stage the interface, or verify an sdist already carries it."""
    package_json = WEB / "package.json"
    if package_json.is_file():
        npm = shutil.which("npm")
        if npm is None:
            raise RuntimeError(
                "Node.js/npm is required to build a SHELLHOUND wheel; "
                "installed wheels do not require it"
            )
        subprocess.run([npm, "ci"], cwd=WEB, check=True)
        subprocess.run([npm, "run", "build"], cwd=WEB, check=True)
        if not (WEB_DIST / "index.html").is_file():
            raise RuntimeError("the frontend build produced no web/dist/index.html")

        # Vite cleans web/dist.  Replace the staging directory too, otherwise
        # old content-hashed assets can survive into a later wheel.
        if STATIC.exists():
            shutil.rmtree(STATIC)
        shutil.copytree(WEB_DIST, STATIC)

    if not (STATIC / "index.html").is_file():
        raise RuntimeError(
            "the source distribution contains no server/static/index.html"
        )


def build_sdist(sdist_directory, config_settings=None):
    _prepare_frontend()
    return _setuptools.build_sdist(sdist_directory, config_settings)


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _prepare_frontend()
    return _setuptools.build_wheel(
        wheel_directory, config_settings, metadata_directory
    )


# Metadata and editable installs do not create a distributable artifact and do
# not need to run npm.  Development continues to use web/dist directly.
get_requires_for_build_sdist = _setuptools.get_requires_for_build_sdist
get_requires_for_build_wheel = _setuptools.get_requires_for_build_wheel
prepare_metadata_for_build_wheel = _setuptools.prepare_metadata_for_build_wheel

if hasattr(_setuptools, "build_editable"):
    build_editable = _setuptools.build_editable
    get_requires_for_build_editable = _setuptools.get_requires_for_build_editable
    prepare_metadata_for_build_editable = (
        _setuptools.prepare_metadata_for_build_editable
    )
