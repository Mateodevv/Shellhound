"""Database account facts retain their source and never become observation times."""
import tempfile
import unittest
from pathlib import Path

from server import db, ioc_model


class AccountAttributesTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.case = Path(temporary.name)
        self.conn = db.connect(self.case)
        self.addCleanup(self.conn.close)

    def account(self, dump=1, registered="2024-01-02 03:04:05"):
        return {"dump_id": dump, "tbl": "cms_users", "cms": "joomla", "login": "analyst-test",
                "user_id": "4", "registered": registered, "admin": 1}

    def test_registration_is_a_source_fact_and_survives_database_reindexing(self):
        identifier = db.add_ioc(self.conn, "analyst-test", "user")
        first = self.account()
        ioc_model.record_account(self.conn, identifier, first)
        ioc_model.record_account(self.conn, identifier, {**first, "id": 999})
        row = ioc_model.detail(self.conn, identifier)["object"]
        self.assertEqual(1, len(row["account_sources"]))
        self.assertEqual(first["registered"], row["account_sources"][0]["registered"])
        self.assertIsNone(row["first_seen"])
        self.assertIsNone(row["last_seen"])
        ioc_model.record_account(self.conn, identifier, self.account(dump=2, registered="2025-09-03"))
        dates = {entry["registered"] for entry in ioc_model.detail(self.conn, identifier)["object"]["account_sources"]}
        self.assertEqual({"2024-01-02 03:04:05", "2025-09-03"}, dates)

    def test_missing_registration_remains_explicit_and_deletion_cannot_leak_attributes(self):
        identifier = db.add_ioc(self.conn, "analyst-test", "user")
        ioc_model.record_account(self.conn, identifier, self.account(registered=""))
        row = ioc_model.detail(self.conn, identifier)["object"]
        self.assertEqual("", row["account_sources"][0]["registered"])
        self.conn.execute("DELETE FROM iocs WHERE id=?", (identifier,))
        replacement = db.add_ioc(self.conn, "different-user", "user")
        self.assertEqual([], ioc_model.detail(self.conn, replacement)["object"]["account_sources"])

    def test_migration_backfills_only_uniquely_identifiable_legacy_sources(self):
        account = self.account()
        identifier = db.add_ioc(self.conn, account["login"], "user", origin=ioc_model.account_origin(account))
        ambiguous = db.add_ioc(self.conn, "shared-admin", "user", origin=ioc_model.account_origin(account))
        for login, dump in [(account["login"], 1), ("shared-admin", 1), ("shared-admin", 2)]:
            self.conn.execute("INSERT INTO db_accounts(dump_id,cms,tbl,user_id,login,registered,admin) VALUES(?,?,?,?,?,?,?)",
                              (dump, account["cms"], account["tbl"], "4", login, account["registered"], 1))
        self.conn.execute("ALTER TABLE iocs DROP COLUMN account_sources")
        self.conn.execute("UPDATE meta SET value='16' WHERE key='schema_version'")
        self.conn.commit()
        migrated = db.connect(self.case)
        try:
            self.assertEqual(account["registered"], ioc_model.detail(migrated, identifier)["object"]["account_sources"][0]["registered"])
            self.assertEqual([], ioc_model.detail(migrated, ambiguous)["object"]["account_sources"])
            self.assertEqual(identifier, db.one(migrated, "SELECT id FROM iocs WHERE value=?", (account["login"],))["id"])
        finally:
            migrated.close()
        reopened = db.connect(self.case)
        try:
            self.assertEqual(0, reopened.total_changes)
        finally:
            reopened.close()
