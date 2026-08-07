# tests/fixtures_hostile.py
"""Evidence shaped like the cases that actually break things.

WHY THIS EXISTS. `fixtures.Evidence` builds one clean case: one log file, one
dump, one webroot, lower-case paths throughout, every line well formed -- and
a single time zone, `+0000`. A suite of three hundred tests ran on it and let
fifty-five bugs through, and roughly half of them were invisible on that shape
rather than untested:

  * At offset ZERO, applying an offset twice is the same as applying it once.
    Five separate time-zone bugs could not be seen.
  * With ONE log file, two sources cannot collide on a basename.
  * With ONE dump, SQLite hands the re-inserted row the same id, so a delete
    that uses the wrong id happens to hit the right rows.
  * Under TWO HUNDRED clients, a cap at two hundred does not cut anything.
  * With lower-case paths, a lower-casing bug produces the same string.

So this module is not "more fixtures". It is the same evidence along the AXES
where the code has a choice to make, because every one of those choices was
made wrong at least once.

USE IT LIKE THIS -- the point is to run the SAME assertions over several
shapes, not to write new assertions per shape:

    for shape in hostile_shapes():
        with self.subTest(shape=shape.name):
            case = shape.build().case_dir
            ...

Nothing here is a payload. The "shells" are the shortest text that trips one
rule, in the spirit of an EICAR file, and every address comes from the ranges
RFC 5737 reserves for documentation.
"""
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.fixtures import assert_readable

# --- addresses, kept apart from the clean fixture's ------------------------
ATTACKER = "203.0.113.42"
VISITOR = "192.0.2.10"
CUSTOMER = "192.0.2.77"
EDITOR = "192.0.2.88"
IPV6 = "2001:db8::dead:beef"

BASE = datetime(2026, 1, 5, 5, 0, 0, tzinfo=timezone.utc)

# A file that trips exactly one content rule, and its harmless twin.
SHELL = "<?php\n@system($_GET['cmd']);\n"
INNOCENT = "<?php\nif (!defined('ABSPATH')) { exit; }\nfunction wp_x() { return 1; }\n"

# PHP hidden in an image, SHOUTING -- the tag is case-insensitive in PHP and
# the check was not.
PNG_WITH_PHP = b"\x89PNG\r\n\x1a\n<?PHP echo 2; ?>\n"

# A dump whose DATA contains DDL, an escaped backslash and a prefix
# placeholder: three separate parser traps in one ordinary-looking export.
TRAP_DUMP = """-- MySQL dump 10.13  Distrib 8.0.36
-- Host: localhost    Database: shop_prod
--

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
(2,'support-tmp','5f4dcc3b5aa765d61d8327deb882cf99','support-tmp','support-tmp@example.test','','2026-01-06 12:00:00','',0,'Support');

CREATE TABLE `wp_usermeta` (
  `umeta_id` bigint NOT NULL,
  `user_id` bigint NOT NULL,
  `meta_key` varchar(255) NOT NULL,
  `meta_value` longtext
);
INSERT INTO `wp_usermeta` VALUES
(1,1,'wp_capabilities','a:1:{s:13:"administrator";b:1;}'),
(2,2,'wp_capabilities','a:1:{s:13:"administrator";b:1;}');

CREATE TABLE `wp_options` (
  `option_id` bigint NOT NULL,
  `option_name` varchar(191) NOT NULL,
  `option_value` longtext
);
INSERT INTO `wp_options` VALUES
(1,'schema_backup','CREATE TABLE `x` (`c` int)'),
(2,'upload_path','C:\\\\newsite\\\\uploads'),
(3,'doc_note','in templates the table is called #__content'),
(4,'plain','nothing special');

CREATE TABLE `wp_posts` (
  `ID` bigint NOT NULL,
  `post_content` longtext,
  `post_title` text
);
INSERT INTO `wp_posts` VALUES
(1,'<p>Ordinary text</p>','Home'),
(2,'<iframe src="//zaehler.example.test/t.js" width="0" height="0"></iframe>','Contact');
"""

# The .htaccess every shared host ships. It must NOT be a finding.
CPANEL_HTACCESS = ("<IfModule mime_module>\n"
                   "  AddHandler application/x-httpd-ea-php81 .php .php8 .phtml\n"
                   "</IfModule>\n")

# This one must.
EVIL_HTACCESS = "AddType application/x-httpd-php .jpg\n"


def line(ip, when, uri, status=200, offset="+0000", method="GET",
         agent="Mozilla/5.0"):
    """One access-log line. `when` is UTC; `offset` is what the SERVER wrote,
    so the stamp is shifted into that offset the way a real log is."""
    sign = 1 if offset[0] == "+" else -1
    shift = sign * (int(offset[1:3]) * 3600 + int(offset[3:5]) * 60)
    local = when + timedelta(seconds=shift)
    stamp = local.strftime("%d/%b/%Y:%H:%M:%S ") + offset
    return (f'{ip} - - [{stamp}] "{method} {uri} HTTP/1.1" {status} 512 '
            f'"-" "{agent}"\n')


class Shape:
    """One case shape, named. `name` is what a subTest reports, so it has to
    say what is different about it rather than being shape_3."""

    def __init__(self, name, why, **options):
        self.name = name
        self.why = why
        self.options = options

    def build(self):
        return HostileEvidence(**self.options).build()

    def __repr__(self):
        return f"<Shape {self.name}>"


class HostileEvidence:
    """A case directory with evidence built along the chosen axes.

    Every option defaults to the AWKWARD value, because the clean shape is
    already covered by `fixtures.Evidence` and running both through the same
    assertions is the entire point.
    """

    def __init__(self, offset="+0200", second_offset=None,
                 duplicate_log_name=False, two_dumps=False,
                 mixed_case=False, upload_parent=False,
                 undated_line=True, ipv6=True, truncated_head=False,
                 many_clients=0, root_level_file=True):
        self.offset = offset
        self.second_offset = second_offset
        self.duplicate_log_name = duplicate_log_name
        self.two_dumps = two_dumps
        self.mixed_case = mixed_case
        self.upload_parent = upload_parent
        self.undated_line = undated_line
        self.ipv6 = ipv6
        self.truncated_head = truncated_head
        self.many_clients = many_clients
        self.root_level_file = root_level_file

        parent = "uploads" if upload_parent else "cases"
        self.root = Path(tempfile.mkdtemp(prefix="shellhound-hostile-")) / parent
        self.root.mkdir(parents=True)
        self.case_dir = self.root / "case"
        self.case_dir.mkdir()
        self.webroot = self.root / ("WebRoot" if mixed_case else "webroot")
        self.logs = self.root / "logs"
        self.logs2 = self.root / "logs-vhost-b"
        self.dump = self.root / "dump.sql"
        self.dump2 = self.root / "second-host.sql"

    # --- the site ---------------------------------------------------------

    @property
    def shell_rel(self):
        """The confirmed shell, webroot-relative and in its real spelling."""
        return ("wp-content/Uploads/2026/01/KB-Media.php" if self.mixed_case
                else "wp-content/uploads/2026/01/kb-media.php")

    def _write_site(self):
        for rel, body in (
            (self.shell_rel, SHELL),
            ("wp-includes/functions.php", INNOCENT),
            # Not in an upload directory and perfectly ordinary: it is the
            # control for the location rules, which once read the analyst's
            # own folder names instead of the site's.
            ("lib/helper.php", SHELL),
        ):
            path = self.webroot / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
            assert_readable(path)
        if self.root_level_file:
            # Two files with the SAME NAME at different depths. Attributing a
            # request to the wrong one is invisible until they both exist.
            for rel in ("index.php", "shop/index.php", "wp-admin/index.php"):
                path = self.webroot / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(INNOCENT, encoding="utf-8")
        img = self.webroot / self.shell_rel.rsplit("/", 1)[0] / "banner.png"
        img.write_bytes(PNG_WITH_PHP)
        (self.webroot / self.shell_rel.rsplit("/", 1)[0] / ".htaccess").write_text(
            EVIL_HTACCESS, encoding="utf-8")
        (self.webroot / ".htaccess").write_text(CPANEL_HTACCESS, encoding="utf-8")

    # --- the logs ---------------------------------------------------------

    def _primary_log(self):
        rows = []
        if self.truncated_head:
            # Rotation cuts on line boundaries; a head that starts mid-record
            # means the beginning was removed.
            rows.append('5 "-" "curl"\n')
        for day in range(3):
            for hour in (8, 12, 17):
                when = BASE + timedelta(days=day, hours=hour - 5)
                rows.append(line(VISITOR, when, "/", offset=self.offset))
                rows.append(line(CUSTOMER, when, "/shop/index.php",
                                 offset=self.offset))
                rows.append(line(EDITOR, when, "/wp-admin/index.php",
                                 offset=self.offset))
        # The one client that really touched the root index.php.
        rows.append(line(ATTACKER, BASE + timedelta(hours=4), "/index.php",
                         offset=self.offset))
        # A failed probe an hour BEFORE the first success: the sentence about
        # it is where an offset applied twice becomes visible.
        rows.append(line(ATTACKER, BASE + timedelta(days=1, hours=3),
                         "/" + self.shell_rel, 404, offset=self.offset))
        for i in range(6):
            rows.append(line(ATTACKER, BASE + timedelta(days=1, hours=4,
                                                        minutes=i),
                             "/" + self.shell_rel, 200, offset=self.offset))
        if self.ipv6:
            rows.append(line(IPV6, BASE + timedelta(days=1, hours=5),
                             "/index.php", offset=self.offset))
        if self.undated_line:
            # Well formed in every other respect: it has a client, a method
            # and a target, and only its month is nonsense.
            rows.append('203.0.113.9 - - [06/Xxx/2026:08:00:00 %s] '
                        '"GET /%s HTTP/1.1" 200 5 "-" "curl"\n'
                        % (self.offset, self.shell_rel))
        if self.second_offset:
            # One server across a daylight-saving change writes both. Every
            # European log does this twice a year.
            rows.append(line(VISITOR, BASE + timedelta(days=200), "/",
                             offset=self.second_offset))
        for i in range(self.many_clients):
            rows.append(line(f"198.51.{i // 254}.{i % 254 + 1}",
                             BASE + timedelta(days=2, seconds=i),
                             "/index.php?option=com_jce&task=profiles.import",
                             offset=self.offset))
        return "".join(rows)

    def _write_logs(self):
        self.logs.mkdir()
        (self.logs / "access.log").write_text(self._primary_log(),
                                              encoding="utf-8")
        assert_readable(self.logs / "access.log")
        # An Apache error log the engine skips on purpose. It stays on disk,
        # so the freshness fingerprint has to account for it.
        (self.logs / "error.log").write_text(
            "[Mon Jan 06 08:00:00.000000 2026] [php:error] [pid 1] "
            "PHP Fatal error:  x in /var/www/a.php on line 3\n" * 40,
            encoding="utf-8")
        if self.duplicate_log_name:
            # A SECOND vhost, and its log has the same name. Two files, one
            # basename -- which is what made the coverage check accuse an
            # honest file of forged timestamps.
            self.logs2.mkdir()
            (self.logs2 / "access.log").write_text("".join(
                line(VISITOR, BASE + timedelta(days=40, hours=h),
                     "/other/", offset=self.offset) for h in range(60)),
                encoding="utf-8")

    # --- the database -----------------------------------------------------

    def _write_dumps(self):
        self.dump.write_text(TRAP_DUMP, encoding="utf-8")
        assert_readable(self.dump)
        if self.two_dumps:
            # A second host, compromised the same way. Two facts, not one.
            self.dump2.write_text(TRAP_DUMP, encoding="utf-8")

    # --- assembly ---------------------------------------------------------

    def build(self):
        self._write_site()
        self._write_logs()
        self._write_dumps()
        return self

    @property
    def log_targets(self):
        return ([str(self.logs), str(self.logs2)] if self.duplicate_log_name
                else [str(self.logs)])

    @property
    def dump_targets(self):
        return ([str(self.dump), str(self.dump2)] if self.two_dumps
                else [str(self.dump)])

    def register(self, conn):
        """Register the paths the way the API would."""
        from server import db
        for kind, path in (("webroot", self.webroot),
                           ("access_logs", self.logs),
                           ("sql_dump", self.dump)):
            conn.execute("INSERT OR IGNORE INTO evidence (kind, path, added) "
                         "VALUES (?,?,?)", (kind, str(path), db.now()))
        if self.duplicate_log_name:
            conn.execute("INSERT OR IGNORE INTO evidence (kind, path, added) "
                         "VALUES (?,?,?)",
                         ("access_logs", str(self.logs2), db.now()))
        if self.two_dumps:
            conn.execute("INSERT OR IGNORE INTO evidence (kind, path, added) "
                         "VALUES (?,?,?)",
                         ("sql_dump", str(self.dump2), db.now()))
        conn.commit()

    def analyse(self, confirm=True):
        """Run the engines the way a real case does, and optionally decide
        everything -- most statements about a case only exist once something
        is confirmed."""
        from server import db
        from server.engines import logindex, sqldump, webshell
        conn = db.connect(self.case_dir)
        self.register(conn)
        conn.close()
        webshell.scan(self.case_dir, [str(self.webroot)])
        logindex.build(self.case_dir, self.log_targets)
        for path in self.dump_targets:
            sqldump.scan(self.case_dir, [path])
        if confirm:
            conn = db.connect(self.case_dir)
            conn.execute("UPDATE findings SET triage = 'confirmed'")
            conn.commit()
            conn.close()
        return self

    def cleanup(self):
        shutil.rmtree(self.root.parent, ignore_errors=True)

    def __enter__(self):
        return self.build()

    def __exit__(self, *exc):
        self.cleanup()
        return False


def hostile_shapes():
    """The axes, one shape each, so a failure names what was different.

    Deliberately NOT the cartesian product: sixty combinations that each take
    a second to build is a suite nobody runs. Each shape turns ONE dial away
    from the clean case, plus one that turns them all at once for the
    interactions.
    """
    return [
        Shape("utc", "the clean shape, as a control", offset="+0000"),
        Shape("plus-two", "an offset applied twice is only visible above zero",
              offset="+0200"),
        Shape("mixed-offsets", "one server across a daylight-saving change",
              offset="+0100", second_offset="+0200"),
        Shape("negative-offset", "signs are a place to get an operator wrong",
              offset="-0500"),
        Shape("half-hour-offset", "India is +05:30 and exists",
              offset="+0530"),
        Shape("two-logs-same-name", "two vhosts each keeping an access.log",
              duplicate_log_name=True),
        Shape("two-dumps", "SQLite stops reusing the rowid at two rows",
              two_dumps=True),
        Shape("mixed-case-paths", "a URL is not the file system",
              mixed_case=True),
        Shape("evidence-under-uploads",
              "the analyst's own folder names must decide nothing",
              upload_parent=True),
        Shape("truncated-head", "a log whose beginning was cut off",
              truncated_head=True),
        Shape("many-clients", "a cap at 200 cuts nothing below 200",
              many_clients=250),
        Shape("everything", "the interactions, not the axes",
              offset="+0200", second_offset="+0100",
              duplicate_log_name=True, two_dumps=True, mixed_case=True,
              upload_parent=True, truncated_head=True, many_clients=250),
    ]


__all__ = ["HostileEvidence", "Shape", "hostile_shapes", "line",
           "ATTACKER", "VISITOR", "CUSTOMER", "EDITOR", "IPV6",
           "TRAP_DUMP", "CPANEL_HTACCESS", "EVIL_HTACCESS", "BASE"]
