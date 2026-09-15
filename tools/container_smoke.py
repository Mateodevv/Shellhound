"""Build-context and runtime checks using isolated, synthetic Docker data.

Requires a running Linux Docker engine and an already built image. Only the
containers and volume created by this invocation are removed.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]


def docker(*args, check=True, **kwargs):
    result = subprocess.run(["docker", *args], capture_output=True, text=True,
                            timeout=120, **kwargs)
    if check and result.returncode:
        # Do not print daemon output: it can contain credentials or host paths.
        raise RuntimeError(f"Docker {args[0]} failed (exit {result.returncode})")
    return result


def context_check():
    with tempfile.TemporaryDirectory(prefix="shellhound-context-") as directory:
        base = Path(directory)
        source, output = base / "source", base / "output"
        source.mkdir()
        (source / ".dockerignore").write_bytes((ROOT / ".dockerignore").read_bytes())
        allowed = ["server/app.py", "server/ioc/model.py", "web/src/main.tsx",
                   "web/public/favicon.svg", "docs/LICENSING.md", "docs/user-guide.md",
                   "docs/legal/LICENSE", "docs/legal/NOTICE"]
        excluded = [".env", "workspace/probe.py", "cases/probe.py", "private-audit/probe.py",
                    "server/settings.json", "server/private-audit-test/probe.py",
                    "server/workspace/probe.py", "server/static/probe.py",
                    "web/src/.env", "web/src/settings.json", "web/src/evidence/probe.ts",
                    "web/node_modules/probe.ts", "web/dist/probe.ts",
                    "assets/docs/probe.svg", "unlisted-file.txt"]
        for name in allowed + excluded:
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("synthetic container context marker\n", encoding="utf-8")
        docker("build", "--file", "-", "--output", f"type=local,dest={output}",
               str(source), input="FROM scratch\nCOPY . /context/\n")
        for name in allowed:
            assert (output / "context" / name).is_file(), f"Missing build input: {name}"
        for name in excluded:
            assert not (output / "context" / name).exists(), f"Private build input: {name}"
    print("Container build-context exclusions: OK")


def request(base, path, token=None, data=None):
    headers = {"X-Token": token} if token else {}
    payload = None
    if data is not None:
        payload = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    with urllib.request.urlopen(urllib.request.Request(
            base + path, data=payload, headers=headers), timeout=5) as response:
        return response.read()


def runtime_check(image):
    suffix = uuid.uuid4().hex[:12]
    container, volume = f"shellhound-smoke-{suffix}", f"shellhound-smoke-data-{suffix}"
    token = secrets.token_hex(24)
    environment = dict(os.environ, SHELLHOUND_TOKEN=token)
    missing = docker("run", "--rm", image, check=False)
    assert missing.returncode != 0 and "SHELLHOUND_TOKEN" in missing.stderr, "Missing token accepted"
    docker("volume", "create", volume)
    try:
        with tempfile.TemporaryDirectory(prefix="shellhound-evidence-") as directory:
            evidence = Path(directory)
            evidence.chmod(0o755)
            (evidence / "marker.txt").write_text("synthetic evidence\n", encoding="utf-8")
            (evidence / "marker.txt").chmod(0o644)

            def start():
                docker("run", "--detach", "--name", container, "--init",
                       "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                       "--publish", "127.0.0.1::8710", "--env", "SHELLHOUND_TOKEN",
                       "--mount", f"type=volume,source={volume},target=/workspace",
                       "--mount", f"type=bind,source={evidence},target=/evidence,readonly",
                       image, env=environment)
                info = json.loads(docker("inspect", container).stdout)[0]
                binding = info["NetworkSettings"]["Ports"]["8710/tcp"][0]
                assert binding["HostIp"] == "127.0.0.1"
                mounts = {m["Destination"]: m for m in info["Mounts"]}
                assert mounts["/evidence"]["RW"] is False
                assert mounts["/workspace"]["RW"] is True
                base = "http://127.0.0.1:" + binding["HostPort"]
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    try:
                        request(base, "/api/state", token)
                        return base
                    except (OSError, urllib.error.URLError):
                        time.sleep(0.25)
                raise AssertionError("Container did not become ready")

            def stop():
                docker("stop", "--time", "60", container)
                info = json.loads(docker("inspect", container).stdout)[0]
                assert info["State"]["ExitCode"] in (0, 130), "Unclean container shutdown"
                docker("rm", container)

            base = start()
            html = request(base, "/").decode()
            assert '<div id="root"></div>' in html and token not in html
            asset = re.search(r'(?:src|href)="(/assets/[^"]+)"', html)
            assert asset and request(base, asset[1])
            for supplied_token in (None, "synthetic-wrong-token"):
                try:
                    request(base, "/api/state", supplied_token)
                except urllib.error.HTTPError as error:
                    assert error.code == 401
                else:
                    raise AssertionError("Unauthenticated API request accepted")
            docker("exec", container, "python", "/usr/local/lib/shellhound-healthcheck.py")
            code = """import os, shutil
from pathlib import Path
from server.casework.profile_options import geography
assert os.getuid() == 10001
assert shutil.which('node') is None
assert geography()
assert Path('/evidence/marker.txt').read_text() == 'synthetic evidence\\n'
try:
    Path('/evidence/write-probe').write_text('probe')
except OSError:
    pass
else:
    raise AssertionError('Evidence mount is writable')
"""
            docker("exec", container, "python", "-c", code)
            case = json.loads(request(base, "/api/cases", token, {"name": "Container smoke"}))
            assert case["slug"]
            stop()
            base = start()
            state = json.loads(request(base, "/api/state", token))
            assert any(row["slug"] == case["slug"] for row in state["cases"])
            docker("exec", container, "python", "-c",
                   "from pathlib import Path; assert Path('/workspace/logs/shellhound.log').is_file()")
            stop()
    finally:
        docker("rm", "--force", container, check=False)
        docker("volume", "rm", volume, check=False)
    print("Container runtime: auth, assets, health, non-root, read-only evidence, persistence and shutdown OK")


def compose_check(image):
    project = "shellhound-compose-smoke-" + uuid.uuid4().hex[:12]
    override = json.dumps({"services": {"shellhound": {"image": image}}})
    command = ("compose", "--project-name", project, "--file", str(ROOT / "compose.yaml"),
               "--file", "-")
    with tempfile.TemporaryDirectory(prefix="shellhound-compose-evidence-") as directory:
        token = secrets.token_hex(24)
        environment = dict(os.environ, SHELLHOUND_TOKEN=token,
                           SHELLHOUND_EVIDENCE_DIR=directory,
                           SHELLHOUND_PUBLISHED_PORT="0")
        try:
            docker(*command, "up", "--detach", "--no-build", "--wait",
                   "--wait-timeout", "60", input=override, env=environment)
            container = docker(*command, "ps", "--quiet", input=override,
                               env=environment).stdout.strip()
            info = json.loads(docker("inspect", container).stdout)[0]
            assert info["State"]["Health"]["Status"] == "healthy"
            mounts = {m["Destination"]: m for m in info["Mounts"]}
            assert mounts["/evidence"]["RW"] is False
            assert mounts["/workspace"]["RW"] is True
            binding = info["NetworkSettings"]["Ports"]["8710/tcp"][0]
            assert binding["HostIp"] == "127.0.0.1"
            base = "http://127.0.0.1:" + binding["HostPort"]
            assert json.loads(request(base, "/api/state", token))["cases"] == []
        finally:
            docker(*command, "down", "--volumes", "--timeout", "60",
                   input=override, env=environment)
    print("Compose deployment: healthy, authenticated and localhost-only OK")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="shellhound:test")
    args = parser.parse_args()
    context_check()
    runtime_check(args.image)
    compose_check(args.image)


if __name__ == "__main__":
    main()
