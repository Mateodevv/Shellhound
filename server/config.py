# server/config.py
"""Runtime configuration: workspace location, bind address, access token.

The workspace is one folder holding many cases, each case a self-contained
directory (case.db + logindex.db + exports). Two investigations never share
state -- that is structural, same rule as the legacy toolkit.
"""
import os
import secrets
from pathlib import Path

DEFAULT_PORT = 8710

# Deliberately NOT ~/.shellhound: the legacy toolkit keeps live state there,
# and this rewrite must never touch it. Override with SHELLHOUND_WORKSPACE or
# --workspace.
DEFAULT_WORKSPACE = Path.home() / "ShellhoundCases"


class Config:
    def __init__(self, workspace=None, host="127.0.0.1", port=DEFAULT_PORT,
                 token=None):
        self.workspace = Path(
            workspace
            or os.environ.get("SHELLHOUND_WORKSPACE")
            or DEFAULT_WORKSPACE
        ).expanduser().resolve()
        self.host = host
        self.port = port
        # Every /api and /ws request must present this. On a localhost bind it
        # is injected into the served page for convenience; a non-loopback
        # bind requires the operator to hand it out explicitly.
        self.token = token or secrets.token_urlsafe(24)

    @property
    def loopback(self):
        return self.host in ("127.0.0.1", "::1", "localhost")

    def ensure_workspace(self):
        self.workspace.mkdir(parents=True, exist_ok=True)
        return self.workspace
