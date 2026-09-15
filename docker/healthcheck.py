"""Check the authenticated API without writing credentials or response data."""
import os
import sys
import urllib.request

try:
    port = int(os.environ.get("SHELLHOUND_PORT", "8710"))
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/state",
        headers={"X-Token": os.environ["SHELLHOUND_TOKEN"]},
    )
    with urllib.request.urlopen(request, timeout=3) as response:
        if response.status != 200:
            sys.exit(1)
except Exception:
    sys.exit(1)
