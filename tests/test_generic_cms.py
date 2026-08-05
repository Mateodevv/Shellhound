# tests/test_generic_cms.py
"""Finding the accounts when the CMS is not one of the two we parse.

WordPress and Joomla are read by column POSITION -- their schemas are fixed.
Everything else is read by column NAME, which is the only signal left when
the schema is unknown. The tests that matter here are the restraints: an
orders table must not become an account list, and a column that is not a date
must not be shown as one.
"""
import tempfile
import unittest
from pathlib import Path

from server import db
from server.engines import sqldump

DRUPAL = """-- MySQL dump 10.13
-- Server version: 8.0.35
-- Database: site

CREATE TABLE `users_field_data` (
  `uid` int, `name` varchar(60), `mail` varchar(254), `pass` varchar(255),
  `created` int, `access` int, `status` tinyint
);
INSERT INTO `users_field_data` VALUES
 (1,'admin','admin@example.test','$2y$10$aaaaaaaaaaaaaaaaaaaaaa','2026-01-02 10:00:00','2026-06-01 08:00:00',1),
 (7,'backdoor','x@evil.test','5f4dcc3b5aa765d61d8327deb882cf99','2026-06-05 23:41:00',0,1),
 (9,'locked','g@example.test','$2y$10$zzzzzzzzzzzzzzzzzzzzzz','2026-02-02 10:00:00','',0);

CREATE TABLE `node_field_data` (`nid` int, `title` varchar(255));
INSERT INTO `node_field_data` VALUES (1,'Hello');

CREATE TABLE `watchdog` (`wid` int, `message` text);
INSERT INTO `watchdog` VALUES (1,'log');

CREATE TABLE `orders` (
  `id` int, `name` varchar(60), `email` varchar(120), `total` decimal
);
INSERT INTO `orders` VALUES (1,'Meier','meier@example.test',42.00);
"""

TYPO3 = """-- MySQL dump 10.13
-- Database: t3

CREATE TABLE `be_users` (
  `uid` int, `username` varchar(50), `email` varchar(255),
  `password` varchar(100), `crdate` int, `disable` tinyint
);
INSERT INTO `be_users` VALUES
 (1,'_cli_','cli@example.test','$argon2i$x','2026-01-01 00:00:00',0);

CREATE TABLE `sys_log` (`uid` int, `details` text);
INSERT INTO `sys_log` VALUES (1,'x');
CREATE TABLE `tt_content` (`uid` int, `header` varchar(255));
INSERT INTO `tt_content` VALUES (1,'x');
"""


class GenericExtractionTests(unittest.TestCase):

    def _scan(self, sql):
        case = Path(tempfile.mkdtemp(prefix="shellhound-gen-"))
        folder = Path(tempfile.mkdtemp(prefix="shellhound-gendump-"))
        db.connect(case).close()
        (folder / "dump.sql").write_text(sql, encoding="utf-8")
        sqldump.scan(case, [str(folder)])
        conn = db.connect(case)
        try:
            return (db.rows(conn, "SELECT * FROM db_accounts ORDER BY user_id"),
                    db.rows(conn, "SELECT * FROM db_dumps"))
        finally:
            conn.close()

    def test_drupal_is_named(self):
        _, dumps = self._scan(DRUPAL)
        self.assertEqual("Drupal", dumps[0]["cms"])

    def test_typo3_is_named(self):
        _, dumps = self._scan(TYPO3)
        self.assertEqual("TYPO3", dumps[0]["cms"])

    def test_the_accounts_are_found_by_column_name(self):
        accounts, _ = self._scan(DRUPAL)
        logins = {a["login"] for a in accounts}
        self.assertEqual({"admin", "backdoor", "locked"}, logins)

    def test_an_orders_table_is_not_an_account_list(self):
        """A name and an e-mail are not enough -- half the tables in a shop
        database have those, and filling the account list with customers
        would bury the one planted administrator."""
        accounts, _ = self._scan(DRUPAL)
        self.assertNotIn("orders", {a["tbl"] for a in accounts})

    def test_a_weak_hash_is_still_recognised(self):
        accounts, _ = self._scan(DRUPAL)
        by_login = {a["login"]: a for a in accounts}
        self.assertIn("weak", by_login["backdoor"]["hash_type"])
        self.assertEqual("bcrypt", by_login["admin"]["hash_type"])

    def test_an_active_column_is_read_as_the_opposite_of_blocked(self):
        """`status`/`active` mean the reverse of `blocked`. Reading them the
        same way would report every live account as locked."""
        accounts, _ = self._scan(DRUPAL)
        by_login = {a["login"]: a for a in accounts}
        self.assertEqual(0, by_login["admin"]["blocked"])
        self.assertEqual(1, by_login["locked"]["blocked"])

    def test_a_disable_column_is_read_as_blocked(self):
        accounts, _ = self._scan(TYPO3)
        self.assertEqual(0, accounts[0]["blocked"])

    def test_a_value_that_is_not_a_date_is_not_shown_as_one(self):
        """Drupal's `access` is a date; a column of that name elsewhere could
        be a flag. The VALUE decides -- an account list that presents `0` as
        a login date is worse than one with the column empty."""
        accounts, _ = self._scan(DRUPAL)
        by_login = {a["login"]: a for a in accounts}
        self.assertEqual("2026-06-01 08:00:00", by_login["admin"]["last_login"])
        self.assertEqual("", by_login["backdoor"]["last_login"])

    def test_wordpress_still_goes_through_the_positional_reader(self):
        """The generic path must not take over from the two schemas that are
        actually known."""
        from tests.fixtures import Evidence, register
        ev = Evidence().build()
        try:
            conn = db.connect(ev.case_dir)
            register(conn, ev)
            conn.close()
            sqldump.scan(ev.case_dir, [str(ev.dump)])
            conn = db.connect(ev.case_dir)
            try:
                accounts = db.rows(conn, "SELECT * FROM db_accounts")
            finally:
                conn.close()
            self.assertTrue(accounts, "the known-schema reader found nothing")
            self.assertTrue(any(a["cms"] == "WordPress" for a in accounts))
        finally:
            ev.cleanup()


class TableDetectionTests(unittest.TestCase):

    def test_columns_decide_when_the_name_does_not(self):
        self.assertTrue(sqldump._looks_like_user_table(
            ["id", "username", "email", "password"]))
        self.assertTrue(sqldump._looks_like_user_table(
            ["uid", "user_login", "user_email", "user_pass"]))

    def test_all_three_kinds_are_required(self):
        self.assertFalse(sqldump._looks_like_user_table(
            ["id", "name", "email", "total"]), "an orders table matched")
        self.assertFalse(sqldump._looks_like_user_table(
            ["id", "password", "created"]), "no identity, no account table")
        self.assertFalse(sqldump._looks_like_user_table([]))

    def test_a_known_name_wins_without_the_columns(self):
        self.assertTrue(sqldump._is_user_table("wp_users", []))
        self.assertTrue(sqldump._is_user_table("t3_be_users", []))
        self.assertFalse(sqldump._is_user_table("wp_posts", []))


if __name__ == "__main__":
    unittest.main()
