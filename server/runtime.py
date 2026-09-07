"""Prepared server process, also used directly by an installed wheel."""
from __future__ import annotations

import socket
import sys
import threading
import webbrowser

from server.config import Config
from server.startup import StartupError, announce


def run(args):
    import uvicorn
    from server.app import create_app

    config = Config(workspace=args.workspace, host=args.host, port=args.port, token=args.token)
    sock = socket.socket(socket.AF_INET6 if ":" in config.host else socket.AF_INET, socket.SOCK_STREAM)
    try:
        if sys.platform == "win32":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((config.host, config.port))
    except OSError:
        sock.close()
        raise StartupError(f"Cannot use {config.host}:{config.port}. Stop the existing server "
                           "or choose another --port. No browser was opened.") from None
    done = threading.Event()
    host = f"[{config.host}]" if ":" in config.host else config.host
    url = f"http://{host}:{config.port}/"
    try:
        server = uvicorn.Server(uvicorn.Config(create_app(config), log_level="warning", access_log=False))

        def ready():
            while not done.wait(0.05):
                if server.started:
                    announce(f"Ready: {url}")
                    announce(f"Workspace: {config.workspace}")
                    announce("Keep this window open. Press Ctrl+C here to stop Shellhound.")
                    if not args.no_browser:
                        try:
                            if not webbrowser.open(url):
                                announce("No browser was opened automatically. Open the address above.")
                        except Exception:
                            announce("Could not open a browser. Open the address above.")
                    return

        watcher = threading.Thread(target=ready, daemon=True)
        watcher.start()
        try:
            server.run(sockets=[sock])
        finally:
            done.set()
            watcher.join(timeout=1)
        if not server.started:
            raise StartupError("The server did not become ready. Check the startup error and try again.")
        return 0
    finally:
        done.set()
        sock.close()


if __name__ == "__main__":
    from server.main import argument_parser
    try:
        sys.exit(run(argument_parser().parse_args()))
    except StartupError as exc:
        print(f"[!] {exc}", file=sys.stderr, flush=True)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
