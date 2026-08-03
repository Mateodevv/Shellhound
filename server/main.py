# server/main.py
"""Entry point: `python -m server.main` starts the panel and opens the browser.

    python -m server.main                        # default workspace, port 8710
    python -m server.main --workspace D:\\Cases  # explicit workspace
    python -m server.main --port 9000 --no-browser
"""
import argparse
import threading
import webbrowser

import uvicorn

from server.app import create_app
from server.config import DEFAULT_PORT, Config


def main():
    parser = argparse.ArgumentParser(
        description="SHELLHOUND — web-native DFIR workbench for webserver "
                    "compromises.")
    parser.add_argument("--workspace", help="folder holding the cases "
                        "(default: ~/ShellhoundCases or SHELLHOUND_WORKSPACE)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--token", help="fixed access token (default: random "
                        "per start; required for non-loopback binds)")
    parser.add_argument("--no-browser", action="store_true",
                        help="do not open the browser automatically")
    args = parser.parse_args()

    config = Config(workspace=args.workspace, host=args.host, port=args.port,
                    token=args.token)
    if not config.loopback and not args.token:
        parser.error("a non-loopback bind requires an explicit --token")

    app = create_app(config)
    url = f"http://{config.host}:{config.port}/"
    print(f"[*] SHELLHOUND panel: {url}")
    print(f"[*] Workspace: {config.workspace}")
    if not config.loopback:
        print(f"[!] Non-loopback bind — access requires ?token={config.token}")

    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    uvicorn.run(app, host=config.host, port=config.port, log_level="warning")


if __name__ == "__main__":
    main()
