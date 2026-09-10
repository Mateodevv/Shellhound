"""Preparation contracts: fresh code must never run with a stale interface."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.request

from server import startup
from server.main import main


class FrontendPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="shellhound startup ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.web = self.root / "web"
        (self.web / "src").mkdir(parents=True)
        (self.web / "public").mkdir()
        (self.root / ".shellhound").mkdir()
        for name in ("package.json", "package-lock.json", "tsconfig.json"):
            (self.web / name).write_text("{}", encoding="utf-8")
        (self.web / "src/App.tsx").write_text("old interface", encoding="utf-8")
        self.installs = self.builds = 0
        self.fail_install = self.fail_build = self.incomplete = False
        for replacement in (
                patch.object(startup, "node_tools", return_value=(["node", "npm.js"], "v22.12.0")),
                patch.object(startup, "command", side_effect=self.tool),
                patch.object(startup, "announce")):
            replacement.start()
            self.addCleanup(replacement.stop)

    def tool(self, arguments, **kwargs):
        if "ci" in arguments:
            self.installs += 1
            if self.fail_install:
                raise startup.StartupError("synthetic install failure")
            for name in (".package-lock.json", "typescript/bin/tsc", "vite/bin/vite.js"):
                path = self.web / "node_modules" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("installed", encoding="utf-8")
        elif "build" in arguments:
            self.builds += 1
            stage = Path(arguments[arguments.index("--outDir") + 1])
            (stage / "assets").mkdir(parents=True)
            (stage / "index.html").write_text('<script src="/assets/app.js"></script>', encoding="utf-8")
            if not self.incomplete:
                (stage / "assets/app.js").write_bytes((self.web / "src/App.tsx").read_bytes())
            if self.fail_build:
                raise startup.StartupError("synthetic build failure")
        else:
            self.fail(f"Unexpected package operation: {arguments}")
        return ""

    def prepare(self):
        startup.prepare_frontend(self.root)

    def test_first_build_then_offline_unchanged_start(self):
        self.prepare()
        with patch.object(startup, "node_tools", side_effect=AssertionError("offline start needs no Node")):
            self.prepare()
        self.assertEqual((1, 1), (self.installs, self.builds))

    def test_missing_build_tools_stop_before_python_package_downloads(self):
        from server.main import argument_parser
        with patch.object(startup, "check_port"), \
                patch.object(startup, "node_tools", side_effect=startup.StartupError("Install Node.js")), \
                patch.object(startup, "prepare_python", side_effect=AssertionError("unexpected install")):
            with self.assertRaisesRegex(startup.StartupError, "Install Node.js"):
                startup.run_source(self.root, argument_parser().parse_args([]), [])

    def test_changes_are_detected_by_content_even_with_unchanged_mtime(self):
        self.prepare()
        source = self.web / "src/App.tsx"
        original = source.stat()
        source.write_text("new interface", encoding="utf-8")
        os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
        self.prepare()
        self.assertEqual("new interface", (self.web / "dist/assets/app.js").read_text())
        self.assertEqual((1, 2), (self.installs, self.builds))

    def test_added_deleted_assets_config_and_local_build_settings(self):
        self.prepare()
        paths = [self.web / "public/new.txt", self.web / ".env.production.local",
                 self.web / "tsconfig.json", self.web / "src/extra.ts"]
        for path in paths:
            with self.subTest(path=path.name):
                previous = self.builds
                path.write_text("changed", encoding="utf-8")
                self.prepare()
                path.unlink()
                self.prepare()
                self.assertEqual(previous + 2, self.builds)
        with patch.dict(os.environ, {"VITE_LABEL": "different build"}):
            self.prepare()
        self.assertEqual(10, self.builds)
        self.assertNotIn("different build", (self.root / ".shellhound/frontend.json").read_text())

    def test_dependency_change_installs_again(self):
        self.prepare()
        (self.web / "package-lock.json").write_text('{"changed":true}')
        self.prepare()
        self.assertEqual((2, 2), (self.installs, self.builds))

    def test_missing_or_corrupted_output_is_repaired(self):
        self.prepare()
        (self.web / "dist/assets/app.js").unlink()
        self.prepare()
        (self.web / "dist/assets/app.js").write_text("broken")
        self.prepare()
        self.assertEqual(3, self.builds)

    def test_legacy_build_is_rebuilt_once(self):
        dist = self.web / "dist"
        dist.mkdir()
        (dist / "index.html").write_text("previous installation")
        self.prepare()
        self.prepare()
        self.assertEqual(1, self.builds)

    def test_failed_build_keeps_previous_output_and_can_retry(self):
        self.prepare()
        (self.web / "src/App.tsx").write_text("updated")
        old_receipt = (self.root / ".shellhound/frontend.json").read_bytes()
        self.fail_build = True
        with self.assertRaises(startup.StartupError):
            self.prepare()
        self.assertEqual("old interface", (self.web / "dist/assets/app.js").read_text())
        self.assertEqual(old_receipt, (self.root / ".shellhound/frontend.json").read_bytes())
        self.fail_build = False
        self.prepare()
        self.assertEqual("updated", (self.web / "dist/assets/app.js").read_text())

    def test_incomplete_build_and_install_failure_never_record_success(self):
        self.fail_install = True
        with self.assertRaises(startup.StartupError):
            self.prepare()
        self.assertFalse((self.root / ".shellhound/npm.json").exists())
        self.fail_install = False
        self.incomplete = True
        with self.assertRaisesRegex(startup.StartupError, "incomplete"):
            self.prepare()
        self.assertFalse((self.root / ".shellhound/frontend.json").exists())
        self.incomplete = False
        self.prepare()
        self.assertTrue((self.web / "dist/assets/app.js").is_file())

    def test_interrupted_directory_swap_is_recovered(self):
        self.prepare()
        (self.web / "dist").replace(self.root / ".shellhound/frontend-previous")
        self.prepare()
        self.assertEqual(1, self.builds)
        self.assertTrue((self.web / "dist/assets/app.js").is_file())


class StartupBoundaryTests(unittest.TestCase):
    def test_relative_workspace_is_resolved_before_handoff(self):
        for argv, environment, expected in (
                (["--workspace", "relative cases"], {}, "relative cases"),
                ([], {"SHELLHOUND_WORKSPACE": "environment cases"}, "environment cases")):
            with self.subTest(expected=expected), patch.dict(os.environ, environment), \
                    patch.object(startup, "is_source_checkout", return_value=True), \
                    patch.object(startup, "run_source", return_value=0) as source:
                self.assertEqual(0, main(argv))
                forwarded = source.call_args.args[2]
                self.assertEqual(str((Path.cwd() / expected).resolve()),
                                 forwarded[forwarded.index("--workspace") + 1])

    def test_help_does_not_import_application_or_prepare_anything(self):
        result = subprocess.run([sys.executable, "-S", "-m", "server.main", "--help"],
                                capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("--update", result.stdout)

    def test_imports_have_no_setup_side_effects(self):
        with patch.object(startup, "command", side_effect=AssertionError("unexpected setup")):
            import importlib
            import server.main
            importlib.reload(server.main)

    def test_wheel_start_does_not_prepare_checkout(self):
        with patch.object(startup, "is_source_checkout", return_value=False), \
                patch.object(startup, "run_source", side_effect=AssertionError("source setup")), \
                patch("server.runtime.run", return_value=0) as run:
            self.assertEqual(0, main(["--no-browser", "--port", "9123", "--workspace", "my cases"]))
            self.assertEqual("my cases", run.call_args.args[0].workspace)
            self.assertTrue(run.call_args.args[0].no_browser)

    def test_checkout_lock_blocks_another_process_and_releases(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            script = ("from pathlib import Path; from server.startup import CheckoutLock; "
                      f"lock=CheckoutLock(Path({folder!r})); lock.__enter__(); lock.__exit__()")
            with startup.CheckoutLock(root):
                result = subprocess.run([sys.executable, "-c", script], capture_output=True)
                self.assertNotEqual(0, result.returncode)
                self.assertIn(b"already", result.stderr)
            result = subprocess.run([sys.executable, "-c", script], capture_output=True)
            self.assertEqual(0, result.returncode, result.stderr)

    def test_occupied_port_does_not_open_browser_or_touch_workspace(self):
        with socket.socket() as sock, tempfile.TemporaryDirectory() as folder:
            sock.bind(("127.0.0.1", 0))
            sock.listen()
            workspace = Path(folder) / "not created"
            with patch("server.runtime.webbrowser.open", side_effect=AssertionError("browser opened")), \
                    patch.object(startup, "is_source_checkout", return_value=False), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(1, main(["--port", str(sock.getsockname()[1]),
                                          "--workspace", str(workspace)]))
            self.assertFalse(workspace.exists())

    def test_missing_and_unsupported_node_report_recovery(self):
        with patch.object(startup.shutil, "which", return_value=None):
            with self.assertRaisesRegex(startup.StartupError, "Install Node.js"):
                startup.node_tools(Path.cwd())
        with patch.object(startup.shutil, "which", return_value="node"), \
                patch.object(startup, "command", return_value="v20.18.0"):
            with self.assertRaisesRegex(startup.StartupError, "20.19"):
                startup.node_tools(Path.cwd())

    def test_credentials_are_redacted_from_tool_errors(self):
        raw = ("https://person:secret@example.invalid/path?token=private password=hidden\n"
               "Authorization: Bearer confidential")
        safe = startup.redact(raw)
        for secret in ("person", "secret", "private", "hidden", "confidential"):
            self.assertNotIn(secret, safe)

    def test_cancellation_waits_for_child_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / "child-ready"
            child = (f"from pathlib import Path; import time; Path({str(marker)!r}).write_text('ready'); "
                     "time.sleep(15)")
            script = ("import sys; from pathlib import Path; "
                      "from server.startup import command,termination_signals\n"
                      "with termination_signals():\n"
                      f" command([sys.executable,'-c',{child!r}],cwd=Path.cwd(),"
                      "label='synthetic child',capture=False)\n")
            options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {
                "start_new_session": True}
            process = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, **options)
            try:
                deadline = time.monotonic() + 5
                while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(marker.exists(), "synthetic child did not start")
                stopping = time.monotonic()
                startup.stop_child(process)
                # A surviving child retains the output pipe and prevents EOF.
                process.communicate(timeout=3)
                self.assertLess(time.monotonic() - stopping, 8,
                                "cancellation waited for the child to finish naturally")
            finally:
                startup.stop_child(process)
                process.communicate(timeout=20)

    def test_browser_opens_only_when_real_http_server_is_ready(self):
        import uvicorn
        from server import runtime
        from server.main import argument_parser
        original_server = uvicorn.Server
        holder = []
        browser_result = []
        errors = []
        opened = threading.Event()
        def make_server(config):
            server = original_server(config)
            holder.append(server)
            return server
        def browser(url):
            try:
                with urllib.request.urlopen(url, timeout=3) as response:
                    browser_result.append((response.status, response.headers.get("Cache-Control")))
            except Exception as exc:
                errors.append(exc)
            finally:
                opened.set()
            return True
        with tempfile.TemporaryDirectory() as folder, socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
            reservation.close()
            args = argument_parser().parse_args(["--port", str(port), "--workspace", folder])
            def serve():
                try:
                    runtime.run(args)
                except Exception as exc:
                    errors.append(exc)
                    opened.set()
            with patch.object(uvicorn, "Server", side_effect=make_server), \
                    patch.object(runtime.webbrowser, "open", side_effect=browser):
                thread = threading.Thread(target=serve)
                thread.start()
                try:
                    self.assertTrue(opened.wait(10), "browser callback was never reached")
                    self.assertEqual([], errors)
                    self.assertEqual([(200, "no-store")], browser_result)
                finally:
                    for server in holder:
                        server.should_exit = True
                    thread.join(timeout=10)
                self.assertFalse(thread.is_alive())

    def test_managed_shutdown_drains_jobs_before_unlock_and_restart(self):
        from server import db
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            args = ["--workspace", str(root), "--port", str(port), "--no-browser"]
            child = [sys.executable, "-m", "tests.startup_job_fixture", *args]
            # Make delayed signal dispatch deterministic. Python 3.10 on
            # Windows could turn the old supervisor's expired timed wait into
            # an effectively unbounded wait before forwarding cancellation.
            delayed_break = (
                " original_break = signal.getsignal(signal.SIGBREAK)\n"
                " def delayed_break(signum, frame):\n"
                "  time.sleep(0.025)\n"
                "  original_break(signum, frame)\n"
                " signal.signal(signal.SIGBREAK, delayed_break)\n"
            ) if os.name == "nt" else ""
            script = ("import signal, time; from pathlib import Path; from server.startup import "
                      "CheckoutLock,command,termination_signals\n"
                      f"with CheckoutLock(Path({folder!r})), termination_signals():\n"
                      + delayed_break +
                      f" command({child!r},cwd=Path.cwd(),label='server',capture=False)\n")
            options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {
                "start_new_session": True}
            with (root / "server.log").open("w") as output:
                process = subprocess.Popen([sys.executable, "-c", script], stdout=output,
                                           stderr=subprocess.STDOUT, **options)
                try:
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        try:
                            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1):
                                break
                        except OSError:
                            self.assertIsNone(process.poll(), (root / "server.log").read_text())
                            time.sleep(0.05)
                    else:
                        self.fail("server did not become ready")
                    self.assertTrue((root / "job-started").exists())
                    if os.name == "nt":
                        process.send_signal(signal.CTRL_BREAK_EVENT)
                    else:
                        os.killpg(process.pid, signal.SIGTERM)
                    deadline = time.monotonic() + 10
                    while not (root / "job-cancelling").exists() and time.monotonic() < deadline:
                        self.assertIsNone(process.poll(), "launcher exited without draining jobs")
                        time.sleep(0.05)
                    self.assertTrue((root / "job-cancelling").exists(),
                                    (root / "server.log").read_text(errors="replace"))
                    # The old supervisor killed the worker after five seconds.
                    with self.assertRaises(subprocess.TimeoutExpired):
                        process.wait(timeout=5.5)
                    with self.assertRaisesRegex(startup.StartupError, "already"):
                        with startup.CheckoutLock(root):
                            pass
                    (root / "release-job").touch()
                    process.wait(timeout=10)
                    self.assertTrue((root / "job-cleaned-up").exists())
                    with startup.CheckoutLock(root):
                        pass
                    conn = db.connect(root / "shutdown-case")
                    try:
                        job = db.one(conn, "SELECT state, finished FROM jobs")
                        self.assertEqual("cancelled", job["state"])
                        self.assertTrue(job["finished"])
                    finally:
                        conn.close()
                finally:
                    (root / "release-job").touch()
                    startup.stop_child(process, timeout=10)

            # A new runtime must expose terminal state, with no orphaned job
            # keeping the analysis controls disabled after a restart.
            with (root / "restart.log").open("w") as output:
                process = subprocess.Popen([sys.executable, "-m", "server.runtime", *args,
                                            "--token", "shutdown-test"], stdout=output,
                                           stderr=subprocess.STDOUT, **options)
                try:
                    request = urllib.request.Request(
                        f"http://127.0.0.1:{port}/api/cases/shutdown-case/jobs",
                        headers={"X-Token": "shutdown-test"})
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        try:
                            with urllib.request.urlopen(request, timeout=1) as response:
                                jobs = json.load(response)
                            break
                        except OSError:
                            self.assertIsNone(process.poll(), (root / "restart.log").read_text())
                            time.sleep(0.05)
                    else:
                        self.fail("restart did not become ready")
                    self.assertEqual(["cancelled"], [job["state"] for job in jobs])
                finally:
                    startup.stop_child(process)


class PythonPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / ".shellhound").mkdir()
        self.venv = self.root / ".venv"
        executable = self.venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        executable.parent.mkdir(parents=True)
        executable.touch()
        (self.root / "requirements.txt").write_text("fastapi>=0.115")
        (self.root / "pyproject.toml").write_text("[project]")
        self.installs = 0
        self.healthy = False
        self.fail = False

    def tool(self, args, **kwargs):
        if "json.dumps" in str(args[-1]):
            return json.dumps({"version": [3, 13, 0], "prefix": str(self.venv), "base": "/base"})
        if "install" in args:
            self.installs += 1
            if self.fail:
                raise startup.StartupError("synthetic package failure")
            self.healthy = True
        elif not self.healthy:
            raise startup.StartupError("missing dependency")
        return ""

    def test_python_dependencies_reused_changed_and_missing(self):
        with patch.object(startup, "command", side_effect=self.tool):
            startup.prepare_python(self.root)
            startup.prepare_python(self.root)
            self.assertEqual(1, self.installs)
            (self.root / "requirements.txt").write_text("fastapi>=0.116")
            startup.prepare_python(self.root)
            self.assertEqual(2, self.installs)
            self.healthy = False
            startup.prepare_python(self.root)
            self.assertEqual(3, self.installs)

    def test_failed_python_install_can_retry_without_success_receipt(self):
        with patch.object(startup, "command", side_effect=self.tool):
            self.fail = True
            with self.assertRaises(startup.StartupError):
                startup.prepare_python(self.root)
            self.assertFalse((self.root / ".shellhound/python.json").exists())
            self.fail = False
            startup.prepare_python(self.root)
            self.assertTrue((self.root / ".shellhound/python.json").is_file())


@unittest.skipUnless(shutil.which("git"), "Git is needed for local update fixtures")
class GitUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="shellhound git ")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.origin = self.base / "origin"
        self.origin.mkdir()
        self.git(self.origin, "init", "-b", "main")
        (self.origin / "version.txt").write_text("one")
        self.git(self.origin, "add", "version.txt")
        self.git(self.origin, "commit", "-m", "initial fixture")
        self.clone = self.base / "checkout"
        self.git(self.base, "clone", str(self.origin), str(self.clone))

    def git(self, cwd, *args):
        result = subprocess.run(["git", "-c", "user.name=Startup Test", "-c",
                                 "user.email=startup@example.invalid", "-c", "commit.gpgsign=false",
                                 *args], cwd=cwd, capture_output=True, text=True)
        if result.returncode:
            self.fail(result.stderr)
        return result.stdout.strip()

    def publish(self):
        (self.origin / "version.txt").write_text("two")
        self.git(self.origin, "commit", "-am", "updated fixture")

    def test_fast_forward_updates_current_tracking_branch(self):
        self.publish()
        startup.update_checkout(self.clone)
        self.assertEqual("two", (self.clone / "version.txt").read_text())
        self.assertEqual("main", self.git(self.clone, "branch", "--show-current"))

    def test_local_changes_are_preserved(self):
        self.publish()
        (self.clone / "version.txt").write_text("my edit")
        with self.assertRaisesRegex(startup.StartupError, "local changes"):
            startup.update_checkout(self.clone)
        self.assertEqual("my edit", (self.clone / "version.txt").read_text())

    def test_divergence_never_resets_or_merges(self):
        self.publish()
        (self.clone / "local.txt").write_text("local")
        self.git(self.clone, "add", "local.txt")
        self.git(self.clone, "commit", "-m", "local fixture")
        before = self.git(self.clone, "rev-parse", "HEAD")
        with self.assertRaisesRegex(startup.StartupError, "diverged"):
            startup.update_checkout(self.clone)
        self.assertEqual(before, self.git(self.clone, "rev-parse", "HEAD"))
        self.assertEqual("one", (self.clone / "version.txt").read_text())

    def test_detached_and_missing_upstream_are_actionable(self):
        self.git(self.clone, "branch", "--unset-upstream")
        with self.assertRaisesRegex(startup.StartupError, "no upstream"):
            startup.update_checkout(self.clone)
        self.git(self.clone, "checkout", "--detach")
        with self.assertRaisesRegex(startup.StartupError, "detached"):
            startup.update_checkout(self.clone)

    def test_failed_remote_access_keeps_checkout(self):
        self.git(self.clone, "remote", "set-url", "origin", str(self.base / "missing"))
        before = self.git(self.clone, "rev-parse", "HEAD")
        with self.assertRaisesRegex(startup.StartupError, "network access"):
            startup.update_checkout(self.clone)
        self.assertEqual(before, self.git(self.clone, "rev-parse", "HEAD"))

    def test_update_runs_fresh_coordinator_and_keeps_lock_until_runtime_exits(self):
        source = Path(__file__).resolve().parents[1]
        (self.origin / "server").mkdir()
        for name in ("__init__.py", "config.py", "main.py", "startup.py"):
            shutil.copy2(source / "server" / name, self.origin / "server" / name)
        (self.origin / "web").mkdir()
        (self.origin / "web/package.json").write_text("{}")
        (self.origin / "requirements.txt").write_text("")
        (self.origin / ".gitignore").write_text(".shellhound/\n__pycache__/\n")
        startup_file = self.origin / "server/startup.py"
        original = startup_file.read_text(encoding="utf-8")
        startup_file.write_text(original + '\ndef prepare_python(root):\n'
                               '    raise StartupError("old coordinator was reused")\n', encoding="utf-8")
        (self.origin / "server/runtime.py").write_text(
            'import json,time\nfrom pathlib import Path\n'
            'from server.main import argument_parser\n'
            'args=argument_parser().parse_args()\n'
            'Path(".shellhound/runtime.json").write_text(json.dumps(vars(args)))\n'
            'time.sleep(1.5)\n', encoding="utf-8")
        self.git(self.origin, "add", ".")
        self.git(self.origin, "commit", "-m", "initial startup fixture")
        self.git(self.clone, "pull", "--ff-only")
        startup_file.write_text(original + '\ndef prepare_python(root):\n'
                               '    return Path(sys.executable)\n'
                               '\ndef node_tools(root):\n'
                               '    return (["synthetic-node"], "v22.12.0")\n'
                               '\ndef prepare_frontend(root):\n'
                               '    (root / ".shellhound/fresh.txt").write_text("fresh")\n', encoding="utf-8")
        self.git(self.origin, "commit", "-am", "new coordinator fixture")
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {
            "start_new_session": True}
        args = [sys.executable, "-m", "server.main", "--no-browser", "--port", str(port)]
        process = subprocess.Popen([*args, "--update", "--workspace", "relative cases"],
                                   cwd=self.clone, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options)
        try:
            runtime = self.clone / ".shellhound/runtime.json"
            deadline = time.monotonic() + 10
            while not runtime.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(runtime.exists(), "updated runtime did not start")
            self.assertIsNone(process.poll(), "launcher detached before runtime exited")
            duplicate = subprocess.run(args, cwd=self.clone, capture_output=True, text=True, timeout=5)
            self.assertNotEqual(0, duplicate.returncode)
            self.assertIn("already", duplicate.stderr)
            out, err = process.communicate(timeout=10)
            self.assertEqual(0, process.returncode, (out + err).decode(errors="replace"))
            self.assertEqual(str((self.clone / "relative cases").resolve()),
                             json.loads(runtime.read_text())["workspace"])
            self.assertTrue((self.clone / ".shellhound/fresh.txt").exists())
        finally:
            startup.stop_child(process)
            process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
