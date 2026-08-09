"""Smoke-test an installed SHELLHOUND wheel over a real HTTP socket.

Run this from outside the checkout after installing the wheel.  That detail is
part of the test: importing ``server`` from the repository would find
``web/dist`` and could make a wheel with no bundled interface look healthy.
"""

from __future__ import annotations

import json
import re
import socket
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

import server
import uvicorn

from server.app import WEB_DIST, create_app
from server.config import Config


TOKEN = "shellhound-package-smoke"


def _get(url: str, token: str | None = None):
    headers = {"X-Token": token} if token else {}
    with urllib.request.urlopen(
        urllib.request.Request(url, headers=headers), timeout=10
    ) as response:
        return response.status, response.read()


def main() -> None:
    package_dir = Path(server.__file__).resolve().parent
    expected_static = package_dir / "static"
    if WEB_DIST.resolve() != expected_static.resolve():
        raise AssertionError(
            f"frontend resolved outside the installed package: {WEB_DIST}"
        )
    if not (WEB_DIST / "index.html").is_file():
        raise AssertionError("installed wheel has no server/static/index.html")

    with tempfile.TemporaryDirectory(prefix="shellhound-package-smoke-") as root:
        app = create_app(Config(workspace=root, token=TOKEN))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        server_instance = uvicorn.Server(
            uvicorn.Config(app, log_level="error", access_log=False)
        )
        thread = threading.Thread(
            target=server_instance.run, kwargs={"sockets": [sock]}, daemon=True
        )
        thread.start()
        deadline = time.monotonic() + 10
        while not server_instance.started and time.monotonic() < deadline:
            time.sleep(0.01)
        if not server_instance.started:
            raise RuntimeError("installed application did not start")

        base = f"http://127.0.0.1:{port}"
        try:
            status, body = _get(base + "/")
            html = body.decode("utf-8")
            assert status == 200
            assert '<div id="root"></div>' in html
            assert f'window.__SHELLHOUND_TOKEN__="{TOKEN}"' in html

            assets = re.findall(r'(?:src|href)="(/assets/[^"]+)"', html)
            if not assets:
                raise AssertionError("installed index references no bundled asset")
            asset_status, asset = _get(base + assets[0])
            assert asset_status == 200 and asset

            state_status, state_body = _get(base + "/api/state", TOKEN)
            state = json.loads(state_body)
            assert state_status == 200
            assert state["cases"] == []
            assert Path(state["workspace"]).resolve() == Path(root).resolve()
        finally:
            server_instance.should_exit = True
            thread.join(timeout=10)
            sock.close()

    print(f"package smoke ok: {package_dir}")


if __name__ == "__main__":
    main()
