"""Subprocess fixture for real server shutdown with pending analysis work."""
from pathlib import Path
import sys
import time

from server.jobs import manager
from server.main import argument_parser
from server.runtime import run
from server.workspace import create_case


def main():
    args = argument_parser().parse_args()
    root = Path(args.workspace)
    case = create_case(root, "shutdown case")

    def work(ctx):
        (root / "job-started").touch()
        ctx.cancel_event.wait(timeout=30)
        (root / "job-cancelling").touch()
        # Model an engine finishing a transaction after noticing cancellation.
        deadline = time.monotonic() + 30
        while not (root / "release-job").exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        (root / "job-cleaned-up").touch()
        return {}

    manager.submit(case, "test", work)
    try:
        return run(args)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
