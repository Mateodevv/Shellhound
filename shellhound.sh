#!/bin/sh
# One entry point for Linux/macOS; all options go to the shared Python startup.
set -eu
cd -- "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ -x .venv/bin/python ]; then
    exec .venv/bin/python -m server.main "$@"
elif command -v python3 >/dev/null 2>&1; then
    exec python3 -m server.main "$@"
elif command -v python >/dev/null 2>&1; then
    exec python -m server.main "$@"
else
    echo "[!] Install Python 3.10 or newer, then run this launcher again." >&2
    echo "[!] On Debian/Ubuntu, also install the python3-venv package." >&2
    exit 1
fi
