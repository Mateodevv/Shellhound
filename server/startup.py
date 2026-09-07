"""Source preparation; importing this module never installs, builds, or updates.

Only generated application directories are managed here. Case workspaces are
passed to the server unchanged and are never inspected by setup or Git updates.
"""
from __future__ import annotations

from contextlib import AbstractContextManager, contextmanager, nullcontext
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time


class StartupError(Exception):
    """An expected failure with a safe, user-facing recovery message."""


def announce(message):
    print(f"[*] {message}", flush=True)


@contextmanager
def termination_signals():
    """Let the coordinator clean up its active child on terminal termination."""
    saved = {}
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    if threading.current_thread() is threading.main_thread():
        for name in ("SIGTERM", "SIGHUP", "SIGBREAK"):
            value = getattr(signal, name, None)
            if value is not None:
                saved[value] = signal.signal(value, interrupted)
    try:
        yield
    finally:
        for value, handler in saved.items():
            signal.signal(value, handler)


def is_source_checkout(root):
    return (root / "web/package.json").is_file() and (root / "requirements.txt").is_file()


def managed_path(root, relative):
    path = root / relative
    if not path.resolve().is_relative_to(root.resolve()) or path.is_symlink():
        raise StartupError(f"The generated folder {relative} points outside this checkout. "
                           "Use a regular local folder, then start again.")
    return path


class CheckoutLock(AbstractContextManager):
    """OS-owned lock: a crash releases it; an old lock file is harmless."""
    def __init__(self, root):
        self.directory = managed_path(root, ".shellhound")
        self.file = None

    def __enter__(self):
        self.directory.mkdir(exist_ok=True)
        self.file = (self.directory / "run.lock").open("a+b")
        self.file.seek(0, os.SEEK_END)
        if not self.file.tell():
            self.file.write(b"\0")
            self.file.flush()
        self.file.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close()
            self.file = None
            raise StartupError("Shellhound is already starting, updating, or running from "
                               "this folder. Stop it with Ctrl+C in its server window, "
                               "then start or update again.") from None
        return self

    def __exit__(self, *exc):
        if self.file is not None:
            if os.name == "nt":
                import msvcrt
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_UN)
            self.file.close()


def redact(text):
    # Package managers and Git can echo configured index/remote credentials.
    text = re.sub(r"(?i)(?:https?|ssh|git)://[^\s<>\"']+", "[configured URL]", text)
    text = re.sub(r"(?im)(authorization\s*[:=])[^\r\n]+", r"\1 [redacted]", text)
    return re.sub(r"(?i)((?:token|password|secret|authorization)\s*[:=]\s*)\S+",
                  r"\1[redacted]", text)


def stop_child(process, *, timeout=5):
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            os.killpg(process.pid, signal.SIGTERM)
        if timeout is None:
            # Server jobs must finish recording cancellation before an update
            # can acquire the checkout lock. Keep signals responsive on Windows.
            while process.poll() is None:
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    pass
        else:
            process.wait(timeout=timeout)
    except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt):
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()


def command(arguments, *, cwd, label, capture=True, env=None, timeout=300):
    options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {
        "start_new_session": True}
    try:
        process = subprocess.Popen(
            [str(arg) for arg in arguments], cwd=cwd, env=env,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.STDOUT if capture else None,
            text=True, encoding="utf-8", errors="replace", **options)
    except OSError:
        raise StartupError(f"Could not start {label}. Check that the required tool is installed "
                           "and this folder is writable, then start again.") from None
    started = time.monotonic()
    last_progress = started
    try:
        while True:
            try:
                # A finite wait also lets Windows dispatch SIGBREAK while a
                # supervised child is running. An infinite wait delays cleanup.
                output, _ = process.communicate(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                if not capture:
                    continue  # The server has no runtime deadline.
                if time.monotonic() - started >= timeout:
                    raise StartupError(f"{label} took too long. Check connectivity, proxy settings, "
                                       "and tool availability, then run the launcher again.") from None
                if time.monotonic() - last_progress >= 30:
                    announce(f"{label} is still running...")
                    last_progress = time.monotonic()
    except BaseException:
        stop_child(process, timeout=5 if capture else None)
        raise
    if process.returncode:
        detail = "\n" + "\n".join(redact(output or "").splitlines()[-12:]) if capture else ""
        raise StartupError(f"{label} failed. Correct the error and run the same launcher again."
                           f"{detail}")
    return output or ""


def check_port(host, port):
    sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
    try:
        if os.name != "nt":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
    except OSError:
        raise StartupError(f"Cannot use {host}:{port}. Stop the existing server or choose "
                           "another port with --port. No browser was opened.") from None
    finally:
        sock.close()


def digest_files(root, files, extra=None):
    digest = hashlib.sha256()
    for path in sorted(set(files)):
        if not path.resolve().is_relative_to(root.resolve()):
            raise StartupError("A build input points outside the interface folder. "
                               "Keep build inputs inside the checkout.")
        name = path.relative_to(root).as_posix().encode()
        content = path.read_bytes()
        digest.update(len(name).to_bytes(8, "big") + name)
        digest.update(len(content).to_bytes(8, "big") + content)
    digest.update(json.dumps(extra, sort_keys=True).encode())
    return digest.hexdigest()


def read_receipt(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def write_receipt(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def prepare_python(root):
    venv = managed_path(root, ".venv")
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not python.is_file():
        if venv.exists() and any(venv.iterdir()):
            raise StartupError("The existing .venv is incomplete. Move that environment aside "
                               "and start again to create a fresh one; keep your case folders.")
        announce("Creating the local Python environment (first setup).")
        command([sys.executable, "-m", "venv", venv], cwd=root, label="Python environment setup")
    info = json.loads(command([python, "-c", "import json,sys; print(json.dumps("
                              "{'version':list(sys.version_info[:3]),'prefix':sys.prefix,"
                              "'base':sys.base_prefix}))"], cwd=root, label="Python environment check"))
    if (tuple(info["version"]) < (3, 10) or Path(info["prefix"]).resolve() != venv.resolve()
            or info["prefix"] == info["base"]):
        raise StartupError("The .venv does not contain a compatible local Python environment. "
                           "Move it aside and start again with Python 3.10 or newer.")
    receipt_path = root / ".shellhound/python.json"
    key = digest_files(root, [root / "requirements.txt", root / "pyproject.toml"], info["version"])
    check = "import fastapi,uvicorn,maxminddb,yara,yaml; from server.app import create_app"
    healthy = False
    if read_receipt(receipt_path).get("inputs") == key:
        try:
            command([python, "-c", check], cwd=root, label="Python dependency check")
            command([python, "-m", "pip", "check"], cwd=root, label="Python dependency consistency check")
            healthy = True
        except StartupError:
            pass
    if not healthy:
        announce("Installing required Python packages into .venv (internet may be needed).")
        command([python, "-m", "pip", "install", "--disable-pip-version-check", "--no-input", "-r",
                 "requirements.txt"], cwd=root, label="Python package installation")
        command([python, "-c", check], cwd=root, label="Python dependency check")
        command([python, "-m", "pip", "check"], cwd=root, label="Python dependency consistency check")
        write_receipt(receipt_path, {"inputs": key})
    return python


def frontend_inputs(web):
    files = []
    for directory in (web / "src", web / "public", web / "tools"):
        if directory.exists():
            files.extend(path for path in directory.rglob("*") if path.is_file())
    files.extend(path for path in web.iterdir() if path.is_file() and (
        path.suffix in (".html", ".json", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts")
        or path.name.startswith(".env")))
    environment = {key: value for key, value in os.environ.items()
                   if key.startswith("VITE_") or key == "NODE_ENV"}
    return digest_files(web, files, {"format": 1, "environment": environment})


class _AssetReferences(HTMLParser):
    def __init__(self):
        super().__init__()
        self.assets = []

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key in ("src", "href") and value and value.startswith("/assets/"):
                self.assets.append(value[1:].split("?", 1)[0])


def build_inventory(directory):
    try:
        parser = _AssetReferences()
        parser.feed((directory / "index.html").read_text(encoding="utf-8"))
        if not parser.assets:
            return {}
        for asset in parser.assets:
            path = directory / asset
            if not path.resolve().is_relative_to(directory.resolve()) or not path.is_file():
                return {}
        files = {}
        for path in directory.rglob("*"):
            if path.is_file():
                if not path.resolve().is_relative_to(directory.resolve()):
                    return {}
                files[path.relative_to(directory).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        return files
    except (OSError, UnicodeError, ValueError):
        return {}


def node_tools(root):
    node = shutil.which("node")
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    if not node or not npm:
        raise StartupError("The updated interface needs Node.js and npm. Install Node.js "
                           "22.12 or newer (LTS recommended), reopen your terminal, and start again.")
    version = command([node, "--version"], cwd=root, label="Node.js version check").strip()
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", version)
    numbers = tuple(map(int, match.groups())) if match else (0, 0, 0)
    if not ((numbers[0] == 20 and numbers >= (20, 19, 0)) or numbers >= (22, 12, 0)):
        raise StartupError("This interface requires Node.js 20.19+ in the 20.x series, "
                           "or 22.12+. Install a supported Node.js LTS and start again.")
    # Invoke npm's JS directly; cmd.exe must not reparse checkout path characters.
    candidates = [Path(npm).resolve(), Path(npm).parent / "node_modules/npm/bin/npm-cli.js"]
    cli = next((path for path in candidates if path.is_file() and path.suffix == ".js"), None)
    if cli is None:
        raise StartupError("Could not locate npm's JavaScript entry point beside its launcher. "
                           "Install Node.js with npm included and start again.")
    return [node, str(cli)], version


def frontend_current(root):
    dist = managed_path(root, "web/dist")
    if not dist.exists():
        dist = managed_path(root, ".shellhound/frontend-previous")
    receipt = read_receipt(root / ".shellhound/frontend.json")
    inventory = build_inventory(dist)
    return bool(inventory and receipt.get("inputs") == frontend_inputs(root / "web")
                and receipt.get("outputs") == inventory)


def prepare_frontend(root):
    web = root / "web"
    dist = managed_path(root, "web/dist")
    stage = managed_path(root, ".shellhound/frontend-next")
    previous = managed_path(root, ".shellhound/frontend-previous")
    receipt_path = root / ".shellhound/frontend.json"
    if previous.exists() and not dist.exists():
        previous.replace(dist)  # Recover interruption between directory renames.
    inputs = frontend_inputs(web)
    receipt = read_receipt(receipt_path)
    inventory = build_inventory(dist)
    if inventory and receipt.get("inputs") == inputs and receipt.get("outputs") == inventory:
        return
    npm, node_version = node_tools(root)
    managed_path(root, "web/node_modules")
    npm_receipt = root / ".shellhound/npm.json"
    dependency_key = digest_files(web, [web / "package.json", web / "package-lock.json"],
                                 {"node": node_version, "platform": sys.platform})
    installed_lock = web / "node_modules/.package-lock.json"
    installed_hash = hashlib.sha256(installed_lock.read_bytes()).hexdigest() if installed_lock.is_file() else None
    old = read_receipt(npm_receipt)
    tools_present = all((web / path).is_file() for path in (
        "node_modules/typescript/bin/tsc", "node_modules/vite/bin/vite.js"))
    if not (tools_present and installed_hash and old.get("inputs") == dependency_key
            and old.get("installed") == installed_hash):
        announce("Installing required interface packages (internet may be needed).")
        command([*npm, "ci", "--include=dev", "--no-audit", "--no-fund"], cwd=web,
                label="Interface package installation")
        write_receipt(npm_receipt, {"inputs": dependency_key,
                                  "installed": hashlib.sha256(installed_lock.read_bytes()).hexdigest()})
    announce("Preparing the updated interface. The existing build stays intact until this succeeds.")
    if stage.exists():
        shutil.rmtree(stage)
    command([*npm, "run", "build", "--", "--outDir", stage, "--emptyOutDir"],
            cwd=web, label="Interface build")
    outputs = build_inventory(stage)
    if not outputs:
        raise StartupError("The interface build is incomplete. Start again to retry; "
                           "the previous build has been preserved.")
    if frontend_inputs(web) != inputs:
        raise StartupError("Interface sources changed while building. Finish the edit or pull, "
                           "then start again so both parts use the same version.")
    if previous.exists():
        shutil.rmtree(previous)
    if dist.exists():
        dist.replace(previous)
    try:
        stage.replace(dist)
    except OSError:
        if previous.exists() and not dist.exists():
            previous.replace(dist)
        raise StartupError("Could not replace the interface build. Close programs holding "
                           "its files open, then start again.") from None
    write_receipt(receipt_path, {"inputs": inputs, "outputs": outputs})
    if previous.exists():
        shutil.rmtree(previous)


def update_checkout(root):
    git = shutil.which("git")
    if not git:
        raise StartupError("Update needs Git. Install Git and reopen the terminal, or download "
                           "a fresh source copy and use Start.")
    def query(*args):
        environment = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "Never"}
        return command([git, *args], cwd=root, label="Git update", env=environment, timeout=120).strip()
    try:
        top = query("rev-parse", "--show-toplevel")
    except StartupError:
        raise StartupError("Git could not open this checkout. For a downloaded ZIP, download "
                           "a fresh copy to update. For a clone, check its ownership and Git access.") from None
    if Path(top).resolve() != root.resolve():
        raise StartupError("This folder is not the Git repository root. Download or clone "
                           "Shellhound into its own folder before using Update.")
    try:
        query("symbolic-ref", "--quiet", "--short", "HEAD")
    except StartupError:
        raise StartupError("This checkout is detached. Switch to a branch before updating.") from None
    if query("status", "--porcelain"):
        raise StartupError("This checkout has local changes. Commit or set them aside yourself "
                           "before updating. Shellhound has not changed them.")
    try:
        upstream = query("rev-parse", "--abbrev-ref", "@{upstream}")
    except StartupError:
        raise StartupError("This branch has no upstream. Set its Git tracking branch before "
                           "using Update, or use Start with the current local code.") from None
    announce(f"Updating from {redact(upstream)} (fast-forward only).")
    try:
        query("pull", "--ff-only")
    except StartupError as exc:
        raise StartupError("Update could not finish. Check network access and Git authentication; "
                           "if branches diverged, resolve that in Git. No reset or automatic "
                           f"conflict resolution was performed.\n{exc}") from None


def run_source(root, args, argv, *, lock_held=False):
    with (nullcontext() if lock_held else CheckoutLock(root)):
        check_port(args.host, args.port)
        if args.update:
            update_checkout(root)
            # Keep the lock here while freshly imported startup code performs
            # all preparation. No detached exec on Windows, and no lock gap.
            remaining = [arg for arg in argv if arg != "--update"]
            command([sys.executable, "-c", "from server.main import main; "
                     "raise SystemExit(main(_checkout_lock_held=True))", *remaining],
                    cwd=root, label="Updated Shellhound startup", capture=False)
            return 0
        announce("Checking local setup. Downloads happen only if required packages need preparation.")
        if not frontend_current(root):
            node_tools(root)  # Report missing build tools before downloading Python packages.
        python = prepare_python(root)
        prepare_frontend(root)
        git = shutil.which("git")
        if git:
            try:
                revision = command([git, "rev-parse", "--short", "HEAD"], cwd=root,
                                   label="Local revision check").strip()
                announce(f"Starting Shellhound ({revision}).")
            except StartupError:
                announce("Starting Shellhound.")
        command([python, "-m", "server.runtime", *argv], cwd=root,
                label="Shellhound server", capture=False)
        return 0
