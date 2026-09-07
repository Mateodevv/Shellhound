# server/main.py
"""Public entry point; help and source setup need only the standard library."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

from server.config import DEFAULT_PORT


def argument_parser():
    parser = argparse.ArgumentParser(allow_abbrev=False,
        description="SHELLHOUND — prepare the application and open the local workbench.")
    parser.add_argument("--workspace", help="case folder (default: ~/ShellhoundCases "
                        "or SHELLHOUND_WORKSPACE)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--token", help="fixed access token; required outside localhost")
    parser.add_argument("--no-browser", action="store_true",
                        help="start without opening the browser")
    parser.add_argument("--update", action="store_true",
                        help="pull this branch's upstream, then prepare and start (Git checkout only)")
    return parser


def main(argv=None, *, _checkout_lock_held=False):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argument_parser()
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.host not in ("127.0.0.1", "::1", "localhost") and not args.token:
        parser.error("a non-loopback bind requires an explicit --token")
    if sys.version_info < (3, 10):
        parser.error("Python 3.10 or newer is required. Install it and start again.")

    from server.startup import StartupError, termination_signals
    try:
        with termination_signals():
            return _start(args, argv, lock_held=_checkout_lock_held)
    except StartupError as exc:
        print(f"[!] {exc}", file=sys.stderr, flush=True)
        return 1
    except KeyboardInterrupt:
        print("\n[*] Shellhound stopped.", flush=True)
        return 130
    except OSError:
        print("[!] Shellhound could not access a required file or start a program. "
              "Check folder permissions and installed tools, then start again.",
              file=sys.stderr, flush=True)
        return 1


def _start(args, argv, *, lock_held=False):
    from server.startup import StartupError, is_source_checkout, run_source
    root = Path(__file__).resolve().parent.parent
    if is_source_checkout(root):
        # Resolve against the caller's directory before either process handoff.
        workspace = (args.workspace or os.environ.get("SHELLHOUND_WORKSPACE")
                     or Path.home() / "ShellhoundCases")
        args.workspace = str(Path(workspace).expanduser().resolve())
        argv = ["--workspace", args.workspace, "--host", args.host, "--port", str(args.port)]
        if args.token is not None:
            argv.append("--token=" + args.token)
        if args.no_browser:
            argv.append("--no-browser")
        if args.update:
            argv.append("--update")
        return run_source(root, args, argv, lock_held=lock_held)
    if args.update:
        raise StartupError("This is an installed package, not a Git checkout. "
                           "Install the newer wheel with this environment's pip.")
    from server.runtime import run
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
