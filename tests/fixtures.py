# tests/fixtures.py
"""Minimal evidence, built in a temporary directory.

Deliberately NOT a demo case: these fixtures exist to make the engines
produce output that can be asserted on, and nothing more. Every file here
is the smallest thing that trips exactly one rule, so a failing test names
the broken rule instead of pointing at a large blob.

Everything is invented. Addresses come from the documentation ranges
reserved by RFC 5737, domains end in .test (RFC 6761), and the "webshells"
are the shortest text files the rules react to -- probes in the spirit of
an EICAR file, not working tools.

A note learned the hard way on Windows: a virus scanner will silently
refuse to let anything READ a file containing certain PHP patterns, and
the failure surfaces as OSError(22) rather than as a scanner message. The
payloads below stay clear of those patterns on purpose, and
`assert_readable` checks the assumption instead of trusting it.
"""
import os
import shutil
import tempfile
from datetime import date, timedelta
from pathlib import Path

# --- one file per rule ------------------------------------------------------
# Key = the substring of the rule name the file is expected to trigger.

WEBSHELL_FILES = {
    # Unguarded PHP in a writable upload directory, and it can run commands.
    "wp-content/uploads/2026/01/kb-media.php":
        "<?php\n@system($_GET['cmd']);\n",
    # A harmless extension in front of the real one.
    "wp-content/uploads/2026/01/logo.jpg.php":
        "<?php\necho 1;\n",
    # PHP inside something that claims to be an image.
    "wp-content/uploads/2026/01/banner.png":
        "\x89PNG\r\n\x1a\n<?php echo 2; ?>\n",
    # Nested decode chain.
    "wp-content/uploads/2026/01/pack.php":
        "<?php\n$x = gzinflate(base64_decode($p));\n",
    # A file that writes request input to disk.
    "wp-content/uploads/2026/01/drop.php":
        "<?php\nfile_put_contents($_POST['n'], $_POST['d']);\n",
    # A genuine CMS file: has the guard, sits where it belongs. Must NOT be
    # flagged -- this is the false-positive guard of the whole suite.
    "wp-includes/functions.php":
        "<?php\nif (!defined('ABSPATH')) { exit; }\nfunction wp_x() { return 1; }\n",
}

HTACCESS = "AddType application/x-httpd-php .jpg\n"

WP_VERSION = "<?php\n$wp_version = '6.4.2';\n"

# A dump with the two things the SQL engine must find: an injected value and
# an account inventory. Column order matches a real wp_users export, because
# the engine reads positionally.
SQL_DUMP = """-- MySQL dump 10.13  Distrib 8.0.36
-- Host: localhost    Database: shop_prod
-- Server version 8.0.36

CREATE TABLE `wp_users` (
  `ID` bigint NOT NULL,
  `user_login` varchar(60) NOT NULL,
  `user_pass` varchar(255) NOT NULL,
  `user_nicename` varchar(50) NOT NULL,
  `user_email` varchar(100) NOT NULL,
  `user_url` varchar(100) NOT NULL,
  `user_registered` datetime NOT NULL,
  `user_activation_key` varchar(255) NOT NULL,
  `user_status` int NOT NULL,
  `display_name` varchar(250) NOT NULL
);
INSERT INTO `wp_users` VALUES
(1,'s.keller','$P$Bxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.','s-keller','keller@example.test','','2019-03-04 09:12:00','',0,'S. Keller'),
(2,'support-tmp','5f4dcc3b5aa765d61d8327deb882cf99','support-tmp','support-tmp@example.test','','2026-01-08 03:17:00','',0,'Support');

CREATE TABLE `wp_usermeta` (
  `umeta_id` bigint NOT NULL,
  `user_id` bigint NOT NULL,
  `meta_key` varchar(255) NOT NULL,
  `meta_value` longtext
);
INSERT INTO `wp_usermeta` VALUES
(1,1,'wp_capabilities','a:1:{s:13:"administrator";b:1;}'),
(2,2,'wp_capabilities','a:1:{s:13:"administrator";b:1;}');

CREATE TABLE `wp_posts` (
  `ID` bigint NOT NULL,
  `post_content` longtext,
  `post_title` text
);
INSERT INTO `wp_posts` VALUES
(1,'<p>Normaler Text</p>','Startseite'),
(2,'<iframe src="//zaehler.example.test/t.js" width="0" height="0"></iframe>','Kontakt');
"""

ATTACKER = "203.0.113.42"
BRUTE = "198.51.100.77"
SCANNER = "198.51.100.9"
VISITOR = "192.0.2.10"


def _log_line(ip, when, method, uri, status, agent="Mozilla/5.0"):
    stamp = when.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return (f'{ip} - - [{stamp}] "{method} {uri} HTTP/1.1" {status} 512 '
            f'"-" "{agent}"\n')


def _access_log():
    """A log that carries every alert the tests assert on -- and enough
    ordinary traffic that the actor list is not just attackers."""
    start = date(2026, 1, 5)
    out = []
    for day in range(4):
        d = start + timedelta(days=day)
        for hour in (8, 12, 17):
            when = _dt(d, hour, 0)
            out.append(_log_line(VISITOR, when, "GET", "/", 200))
            out.append(_log_line(VISITOR, when, "GET", "/shop/", 200))
    # Scanner announces itself: INFO, never an alert about this system.
    for i in range(4):
        out.append(_log_line(SCANNER, _dt(start, 3, i), "GET",
                             f"/wp-admin/x{i}.php", 404, agent="Nikto/2.5.0"))
    # Brute force: many login POSTs, then a redirect -- the pattern of a
    # login that worked.
    for i in range(40):
        out.append(_log_line(BRUTE, _dt(start + timedelta(days=1), 2, i),
                             "POST", "/wp-login.php", 200))
    out.append(_log_line(BRUTE, _dt(start + timedelta(days=1), 3, 0),
                         "POST", "/wp-login.php", 302))
    # The shell is fetched successfully -- the strongest log trace there is.
    for i in range(6):
        out.append(_log_line(ATTACKER, _dt(start + timedelta(days=2), 9, i),
                             "GET", "/wp-content/uploads/2026/01/kb-media.php",
                             200))
    # SQL injection answered with 200.
    out.append(_log_line(
        ATTACKER, _dt(start + timedelta(days=2), 10, 0), "GET",
        "/shop/index.php?id=1'+UNION+SELECT+1,2,3--", 200))
    # Path traversal answered with 200.
    out.append(_log_line(
        ATTACKER, _dt(start + timedelta(days=2), 10, 5), "GET",
        "/index.php?f=../../../../etc/passwd", 200))
    return "".join(out)


def _dt(d, hour, minute):
    from datetime import datetime
    return datetime(d.year, d.month, d.day, hour, min(minute, 59))


def assert_readable(path):
    """Prove the file can be read back.

    On Windows a virus scanner may block reading a file it dislikes, and it
    does so as OSError(22) -- a test that skipped this would fail later with
    a confusing "engine found nothing"."""
    try:
        with open(path, "rb") as fh:
            fh.read(64)
    except OSError as e:
        raise AssertionError(
            f"fixture not readable: {path} ({e}). On Windows this is usually "
            f"the virus scanner -- exclude the temp directory.") from e


class Evidence:
    """A temporary case directory with webroot, logs and a dump."""

    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="shellhound-test-"))
        self.case_dir = self.root / "case"
        self.case_dir.mkdir()
        self.webroot = self.root / "webroot"
        self.logs = self.root / "logs"
        self.dump = self.root / "dump.sql"

    def build(self):
        for rel, body in WEBSHELL_FILES.items():
            path = self.webroot / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
            assert_readable(path)
        (self.webroot / "wp-content/uploads/2026/01/.htaccess").write_text(
            HTACCESS, encoding="utf-8")
        wp_inc = self.webroot / "wp-includes"
        wp_inc.mkdir(parents=True, exist_ok=True)
        (wp_inc / "version.php").write_text(WP_VERSION, encoding="utf-8")

        self.logs.mkdir()
        log = self.logs / "access.log"
        log.write_text(_access_log(), encoding="utf-8")
        assert_readable(log)

        self.dump.write_text(SQL_DUMP, encoding="utf-8")
        assert_readable(self.dump)
        return self

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def __enter__(self):
        return self.build()

    def __exit__(self, *exc):
        self.cleanup()
        return False


def register(conn, evidence):
    """Register the fixture paths the way the API would."""
    from server import db
    for kind, path in (("webroot", evidence.webroot),
                       ("access_logs", evidence.logs),
                       ("sql_dump", evidence.dump)):
        conn.execute(
            "INSERT OR IGNORE INTO evidence (kind, path, added) VALUES (?,?,?)",
            (kind, str(path), db.now()))
    conn.commit()


__all__ = ["Evidence", "register", "assert_readable", "ATTACKER", "BRUTE",
           "SCANNER", "VISITOR", "os"]
