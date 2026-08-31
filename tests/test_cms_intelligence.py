import json
import tempfile
import unittest
from pathlib import Path

from server import cmsintelligence, db, workspace
from server.app import create_app
from server.config import Config
from server.engines import cmsinventory, sqldump


def php(value):
    """Tiny fixture encoder; production only contains the bounded decoder."""
    if value is None:
        return "N;"
    if isinstance(value, bool):
        return f"b:{int(value)};"
    if isinstance(value, int):
        return f"i:{value};"
    if isinstance(value, str):
        return f's:{len(value.encode("utf-8"))}:"{value}";'
    if isinstance(value, list):
        pairs = "".join(php(index) + php(item)
                        for index, item in enumerate(value))
        return f"a:{len(value)}:{{{pairs}}}"
    if isinstance(value, dict):
        pairs = "".join(php(key) + php(item) for key, item in value.items())
        return f"a:{len(value)}:{{{pairs}}}"
    raise TypeError(type(value))


class CmsIntelligenceTests(unittest.TestCase):
    def test_wordpress_inventory_includes_always_loaded_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mu = root / "wp-content" / "mu-plugins"
            mu.mkdir(parents=True)
            (mu / "guard.php").write_text(
                "<?php\n/* Plugin Name: Guard\nVersion: 1.2 */\n", encoding="utf-8")
            (root / "wp-content" / "object-cache.php").write_text(
                "<?php\n", encoding="utf-8")

            items = list(cmsinventory.inventory_wordpress(root))
            by_type = {item[0]: item for item in items}
            self.assertEqual("Guard", by_type["Must-use plugin"][1])
            self.assertEqual("object-cache.php", by_type["Drop-in"][1])

    def test_wordpress_extensions_access_cron_and_content(self):
        collector = cmsintelligence.Collector()
        collector.collect("wp_options",
                          ["option_id", "option_name", "option_value", "autoload"], [
            [1, "active_plugins", php([
                "wordfence/wordfence.php", "unknown-loader/loader.php"]), "yes"],
            [2, "template", "twentytwentyfive", "yes"],
            [3, "users_can_register", "1", "yes"],
            [4, "default_role", "administrator", "yes"],
            [5, "cron", php({1780000000: {
                "remote_loader": {"hash": {
                    "schedule": "hourly", "interval": 3600,
                    "args": ["https://control.example/run"],
                }}
            }}), "yes"],
        ])
        collector.collect("wp_usermeta",
                          ["umeta_id", "user_id", "meta_key", "meta_value"], [
            [1, 7, "wp_capabilities", php({"administrator": True})],
            [2, 7, "session_tokens", php({"verifier-is-not-retained": {
                "expiration": 1780003600, "login": 1779990000,
                "ip": "203.0.113.10", "ua": "Synthetic Browser",
            }})],
            [3, 7, "_application_passwords", php([{
                "uuid": "not-needed", "name": "Automation",
                "password": "hash-is-not-retained", "created": 1779900000,
                "last_used": 1779991000, "last_ip": "198.51.100.9",
            }])],
        ])
        collector.collect("wp_posts", [
            "ID", "post_author", "post_date", "post_date_gmt", "post_content",
            "post_title", "post_excerpt", "post_status", "post_name",
            "post_modified", "post_modified_gmt", "post_type",
        ], [[9, 7, "2026-05-01 10:00:00", "2026-05-01 10:00:00",
             '<script src="https://inject.example/p.js"></script>', "Invoice", "",
             "inherit", "invoice", "2026-05-02 10:00:00",
             "2026-05-02 10:00:00", "attachment"]])
        collector.collect("wp_postmeta",
                          ["meta_id", "post_id", "meta_key", "meta_value"],
                          [[1, 9, "_wp_attached_file", "2026/05/invoice.php"]])

        result = collector.finish(["WordPress"])
        self.assertEqual(3, len(result["extensions"]))
        self.assertEqual(
            {"application_password", "capabilities", "session"},
            {item["kind"] for item in result["access"]})
        self.assertEqual("control.example", result["persistence"][0]["domains"][0])
        self.assertEqual("2026/05/invoice.php", result["content"][0]["path"])
        self.assertIn("executable_attachment", result["content"][0]["signals"])
        self.assertIn("<script", result["content"][0]["content"])
        self.assertFalse(result["content"][0]["content_truncated"])
        serialized = json.dumps(result)
        self.assertNotIn("verifier-is-not-retained", serialized)
        self.assertNotIn("hash-is-not-retained", serialized)

    def test_joomla_extensions_groups_sessions_tasks_and_content(self):
        collector = cmsintelligence.Collector()
        collector.collect("jos_extensions", [
            "extension_id", "name", "type", "element", "folder", "client_id",
            "enabled", "protected", "manifest_cache",
        ], [[41, "System - Synthetic", "plugin", "synthetic", "system", 0, 1, 0,
             json.dumps({"version": "4.2.0"})]])
        collector.collect("jos_usergroups", ["id", "parent_id", "title"],
                          [[8, 1, "Super Users"]])
        collector.collect("jos_user_usergroup_map", ["user_id", "group_id"],
                          [[12, 8]])
        collector.collect("jos_session",
                          ["session_id", "client_id", "guest", "time", "data",
                           "userid", "username"],
                          [["secret-session-id", 1, 0, 1779990000,
                            "private session body", 12, "synthetic-admin"]])
        collector.collect("jos_scheduler_tasks", [
            "id", "type", "title", "state", "cron_rules", "params",
            "last_execution", "next_execution", "priority",
        ], [[3, "plg_task_request", "Remote request", 1,
             json.dumps({"exp": "*/5 * * * *"}),
             json.dumps({"url": "https://tasks.example/collect", "token": "secret"}),
             "2026-05-02 09:00:00", "2026-05-02 09:05:00", 1]])
        collector.collect("jos_content", [
            "id", "title", "introtext", "fulltext", "state", "created",
            "created_by", "modified",
        ], [[5, "Welcome", '<iframe src="https://inject.example/x"></iframe>',
             "", 1, "2026-05-01 08:00:00", 12, "2026-05-02 08:00:00"]])

        result = collector.finish(["Joomla"])
        self.assertEqual("4.2.0", result["extensions"][0]["version"])
        self.assertEqual({"group", "session"},
                         {item["kind"] for item in result["access"]})
        self.assertEqual("*/5 * * * *", result["persistence"][0]["schedule"])
        self.assertEqual(["tasks.example"], result["persistence"][0]["domains"])
        self.assertIn("iframe", result["content"][0]["signals"])
        self.assertIn("<iframe", result["content"][0]["content"])
        serialized = json.dumps(result)
        self.assertNotIn("secret-session-id", serialized)
        self.assertNotIn("private session body", serialized)
        self.assertNotIn('"token": "secret"', serialized)

    def test_content_body_is_bounded_and_marked(self):
        collector = cmsintelligence.Collector()
        body = "x" * (cmsintelligence._CONTENT_BODY_LIMIT + 100)
        collector.collect("wp_posts", ["ID", "post_content", "post_title"],
                          [[1, body, "Large post"]])
        item = collector.finish(["WordPress"])["content"][0]
        self.assertEqual(cmsintelligence._CONTENT_BODY_LIMIT, len(item["content"]))
        self.assertTrue(item["content_truncated"])

    def test_scanner_persists_a_bounded_snapshot_on_the_dump(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "case"
            case_dir.mkdir()
            dump = Path(tmp) / "wordpress.sql"
            active = php(["safe-plugin/plugin.php"])
            dump.write_text(
                "-- Database: synthetic\n"
                "CREATE TABLE `wp_options` (`option_id` bigint, `option_name` varchar(191), "
                "`option_value` longtext, `autoload` varchar(20));\n"
                f"INSERT INTO `wp_options` VALUES (1,'active_plugins','{active}','yes');\n"
                "CREATE TABLE `wp_usermeta` (`umeta_id` bigint, `user_id` bigint, "
                "`meta_key` varchar(255), `meta_value` longtext);\n",
                encoding="utf-8")

            stats = sqldump.scan(case_dir, [str(dump)])
            self.assertEqual(1, stats["dumps"])
            conn = db.connect(case_dir)
            try:
                row = db.one(conn, "SELECT cms, intelligence FROM db_dumps")
                snapshot = json.loads(row["intelligence"])
            finally:
                conn.close()
            self.assertIn("WordPress", row["cms"])
            self.assertEqual("safe-plugin", snapshot["extensions"][0]["name"])

    def test_source_rows_continue_across_insert_statements(self):
        collector = cmsintelligence.Collector()
        columns = ["option_id", "option_name", "option_value", "autoload"]
        collector.collect("wp_options", columns,
                          [[1, "siteurl", "https://one.example", "yes"]])
        collector.collect("wp_options", columns,
                          [[2, "home", "https://two.example", "yes"]], row_offset=1)
        rows = collector.finish(["WordPress"])["configuration"]
        self.assertEqual([1, 2], [row["source_row"] for row in rows])

    def test_database_api_correlates_wordpress_and_joomla_with_file_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case_dir = workspace.create_case(root, "CMS correlation")
            wp_dump = root / "wordpress.sql"
            wp_dump.write_text(
                "CREATE TABLE `wp_options` (`option_id` bigint, `option_name` varchar(191), "
                "`option_value` longtext, `autoload` varchar(20));\n"
                f"INSERT INTO `wp_options` VALUES (1,'active_plugins','{php(['missing/missing.php'])}','yes');\n"
                "CREATE TABLE `wp_users` (`ID` bigint, `user_login` varchar(60), "
                "`user_pass` varchar(255), `user_nicename` varchar(50), `user_email` varchar(100), "
                "`user_url` varchar(100), `user_registered` datetime, `user_activation_key` varchar(255), "
                "`user_status` int, `display_name` varchar(250));\n"
                "INSERT INTO `wp_users` VALUES (7,'recent-admin','$P$Bsynthetic','recent-admin',"
                "'recent@example.test','','2026-08-27 12:00:00','',0,'Recent Admin');\n"
                "CREATE TABLE `wp_usermeta` (`umeta_id` bigint, `user_id` bigint, "
                "`meta_key` varchar(255), `meta_value` longtext);\n"
                f"INSERT INTO `wp_usermeta` VALUES (1,7,'wp_capabilities','{php({'administrator': True})}'),"
                f"(2,7,'session_tokens','{php({'verifier': {'expiration': 1780003600}})}'),"
                f"(3,7,'_application_passwords','{php([{'name': 'Automation', 'created': 1779900000}])}');\n",
                encoding="utf-8")
            joomla_dump = root / "joomla.sql"
            joomla_dump.write_text(
                "CREATE TABLE `jos_extensions` (`extension_id` int, `name` varchar(100), "
                "`type` varchar(20), `element` varchar(100), `folder` varchar(100), "
                "`client_id` int, `enabled` int, `protected` int, `manifest_cache` text);\n"
                "INSERT INTO `jos_extensions` VALUES "
                "(8,'System - Example','plugin','example','system',0,1,0,'{\"version\":\"2.0\"}');\n"
                "CREATE TABLE `jos_usergroups` (`id` int, `parent_id` int, `title` varchar(100));\n"
                "INSERT INTO `jos_usergroups` VALUES (8,1,'Super Users');\n",
                encoding="utf-8")
            sqldump.scan(case_dir, [str(wp_dump), str(joomla_dump)])

            conn = db.connect(case_dir)
            try:
                wp_id = conn.execute(
                    "INSERT INTO cms_installs (root,cms,version,version_source) "
                    "VALUES (?,?,?,?)", (str(root / "web-wp"), "WordPress", "6.9", "")).lastrowid
                jo_id = conn.execute(
                    "INSERT INTO cms_installs (root,cms,version,version_source) "
                    "VALUES (?,?,?,?)", (str(root / "web-joomla"), "Joomla", "5.4", "")).lastrowid
                conn.execute(
                    "INSERT INTO cms_items (install_id,type,name,slug,version,path,version_source) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (jo_id, "Plugin (system)", "System - Example", "example", "2.0",
                     str(root / "web-joomla" / "plugins" / "system" / "example"), ""))
                conn.execute(
                    "INSERT INTO cms_items (install_id,type,name,slug,version,path,version_source) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (wp_id, "Must-use plugin", "Forensic Loader", "forensic-loader", "1.0",
                     str(root / "web-wp" / "wp-content" / "mu-plugins" / "forensic-loader.php"), ""))
                conn.commit()
            finally:
                conn.close()

            app = create_app(Config(workspace=root, token="test"))
            route = next(route.endpoint for route in app.routes
                         if getattr(route, "path", "") == "/api/cases/{slug}/database"
                         and "GET" in (getattr(route, "methods", set()) or set()))
            data = route(case_dir.name, "en")
            intel = data["intelligence"]

            missing = next(row for row in intel["extensions"]
                           if row.get("name") == "missing")
            self.assertEqual("missing", missing["filesystem"]["status"])
            self.assertIn("active_missing_files", missing["signals"])
            joomla = next(row for row in intel["extensions"]
                          if row.get("cms") == "Joomla" and not row.get("filesystem_only"))
            self.assertEqual("present", joomla["filesystem"]["status"])
            mu_plugin = next(row for row in intel["extensions"]
                             if row.get("type") == "Must-use plugin")
            self.assertTrue(mu_plugin["enabled"])
            self.assertGreaterEqual(intel["summary"]["needs_review"], 1)
            access_reviews = [row for row in intel["review_queue"]
                              if row["category"] == "access"]
            self.assertEqual(2, len(access_reviews),
                             "one account plus one independently revocable app password")


if __name__ == "__main__":
    unittest.main()
