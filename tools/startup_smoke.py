"""Real source-launch smoke: fresh install, offline restart, and a changed UI.

Uses an isolated source copy and synthetic workspace. First setup may download
the project's dependencies; no case files from the checkout are copied.
Run: python -m tools.startup_smoke
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

from server.startup import stop_child


def get(url):
    with urllib.request.urlopen(url, timeout=2) as response:
        return response.read(), response.headers


def run_once(root, *, launcher=False, offline=False):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    args = ["--no-browser", "--workspace", str(root / "synthetic cases"), "--port", str(port)]
    environment = os.environ.copy()
    environment["SHELLHOUND_NO_PAUSE"] = "1"
    environment["PYTHONUTF8"] = "1"
    if offline:
        # Any accidental package installation must fail quickly, rather than
        # quietly passing because this CI worker happens to have internet.
        environment["PIP_NO_INDEX"] = "1"
        environment["npm_config_offline"] = "true"
        environment["npm_config_cache"] = str(root / "empty npm cache")
    if launcher:
        argv = ([str(root / "Start-Shellhound.bat")] if os.name == "nt" else
                ["sh", str(root / "shellhound.sh")]) + args
    else:
        argv = [sys.executable, "-m", "server.main", *args]
    options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {
        "start_new_session": True}
    log_path = root / "smoke-output.log"
    with log_path.open("w", encoding="utf-8") as output:
        process = subprocess.Popen(argv, cwd=root, env=environment, stdout=output,
                                   stderr=subprocess.STDOUT, **options)
        base = f"http://127.0.0.1:{port}"
        try:
            deadline = time.monotonic() + 240
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise AssertionError(f"Startup exited early:\n{log_path.read_text(encoding='utf-8')}")
                try:
                    body, headers = get(base)
                    break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.1)
            else:
                raise AssertionError("Startup did not become ready within four minutes")
            html = body.decode("utf-8")
            assert headers.get("Cache-Control") == "no-store"
            assets = re.findall(r'(?:src|href)="(/assets/[^\"]+)"', html)
            assert assets, "start page has no built assets"
            for asset in assets:
                content, _ = get(base + asset)
                assert content, "empty frontend asset"
            # A duplicate must fail before setup or a second server can start.
            duplicate = subprocess.run([sys.executable, "-m", "server.main", *args],
                                       cwd=root, env=environment, capture_output=True, text=True, timeout=15)
            assert duplicate.returncode != 0 and "already" in duplicate.stderr
            return html, log_path.read_text(encoding="utf-8")
        finally:
            stop_child(process)


def main():
    source = Path(__file__).resolve().parent.parent
    scratch = source / ".shellhound"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="startup smoke ", dir=scratch) as folder:
        root = Path(folder)
        shutil.copytree(source / "server", root / "server", ignore=shutil.ignore_patterns("__pycache__", "static"))
        shutil.copytree(source / "web", root / "web", ignore=shutil.ignore_patterns(
            "node_modules", "dist", ".vite", "*.tsbuildinfo", ".env*"))
        for name in ("requirements.txt", "pyproject.toml", "Start-Shellhound.bat", "shellhound.sh"):
            shutil.copy2(source / name, root / name)
        cases = root / "synthetic cases"
        cases.mkdir()
        sentinel = cases / "keep-me.txt"
        sentinel.write_bytes(b"synthetic case data stays unchanged")
        print("Smoke: fresh source setup and real HTTP assets", flush=True)
        first, _ = run_once(root)
        receipts = {name: (root / ".shellhound" / name).read_bytes()
                    for name in ("python.json", "npm.json", "frontend.json")}
        print("Smoke: unchanged launcher restart without package downloads", flush=True)
        _, output = run_once(root, launcher=True, offline=True)
        assert "Installing" not in output and "Preparing the updated" not in output
        for name, before in receipts.items():
            assert (root / ".shellhound" / name).read_bytes() == before
        print("Smoke: change interface source and restart through launcher", flush=True)
        index = root / "web/index.html"
        index.write_text(index.read_text(encoding="utf-8").replace(
            "</head>", '<meta name="startup-smoke" content="new-interface"></head>'), encoding="utf-8")
        changed, output = run_once(root, launcher=True, offline=True)
        assert 'content="new-interface"' in changed and 'content="new-interface"' not in first
        assert "Preparing the updated" in output and "Installing" not in output
        print("Smoke: change interface again and restart through Python command", flush=True)
        index.write_text(index.read_text(encoding="utf-8").replace("new-interface", "python-restart"), encoding="utf-8")
        changed, _ = run_once(root, offline=True)
        assert 'content="python-restart"' in changed
        assert sentinel.read_bytes() == b"synthetic case data stays unchanged"
    print("Source startup smoke passed.", flush=True)


if __name__ == "__main__":
    main()
