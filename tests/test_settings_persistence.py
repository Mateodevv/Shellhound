"""Settings changes must preserve credentials and the last readable file."""
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from server import ruleswitch, settings
from server.engines import yarascan


class SettingsPersistenceTests(unittest.TestCase):
    def setUp(self):
        base = Path(__file__).resolve().parents[1] / "workspace" / "defender-safe-temp"
        base.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.temp.cleanup)
        self.ws = Path(self.temp.name)
        self.target = settings.path(self.ws)
        self.data = {
            "keys": {"virustotal": "sentinel-provider-one", "abuseipdb": "sentinel-provider-two",
                     "future_provider": {"credential": "sentinel-future"}},
            "opencti": {"url": "https://cti.example", "token": "sentinel-integration",
                        "ingester_id": "dba5717c-b7d1-474f-8aad-bf9c2d61312c",
                        "future_field": {"value": "preserve"}, "external_file_uploads": True},
            "future_setting": {"value": [1, 2]},
        }

    def writers(self):
        return {
            "ack": lambda: settings.set_ack(self.ws, True),
            "detection": lambda: settings.set_indirect_php(self.ws, True),
            "yara": lambda: settings.set_yara_disabled(self.ws, ["sentinel.yar"]),
            "provider": lambda: settings.set_key(self.ws, "virustotal", "replacement-sentinel"),
            "integration": lambda: settings.set_opencti(self.ws, {"sample_uploads": True}),
            "rule": lambda: ruleswitch.set_enabled(self.ws, "sentinel-rule", False),
        }

    def seed(self, data=None):
        self.target.write_text(json.dumps(self.data if data is None else data), encoding="utf-8")
        return self.target.read_bytes()

    def assert_no_temporary_files(self):
        self.assertEqual([], list(self.ws.glob("settings.json.*.tmp")))

    def test_every_writer_preserves_file_after_transient_read_error(self):
        actual_read = Path.read_text
        for name, writer in self.writers().items():
            with self.subTest(writer=name):
                original = self.seed()
                failed = False

                def read_once(target, *args, **kwargs):
                    nonlocal failed
                    if target == self.target and not failed:
                        failed = True
                        raise PermissionError("synthetic credential-free read failure")
                    return actual_read(target, *args, **kwargs)

                with patch.object(Path, "read_text", read_once):
                    with self.assertRaises(settings.SettingsError):
                        writer()
                self.assertTrue(failed)
                self.assertEqual(original, self.target.read_bytes())
                self.assert_no_temporary_files()

    def test_every_writer_rejects_corruption_and_malformed_credentials(self):
        invalid = [b"{broken", b"[]", b"null", b'{"keys":null}', b'{"keys":[]}',
                   b'{"keys":{"virustotal":123}}', b'{"keys":{"abuseipdb":false}}',
                   b'{"opencti":null}', b'{"opencti":[]}', b'{"opencti":{"token":123}}',
                   b'{"opencti":{"url":false}}', b'{"opencti":{"ingester_id":[]}}',
                   b"\xff"]
        for name, writer in self.writers().items():
            for index, original in enumerate(invalid):
                with self.subTest(writer=name, invalid=index):
                    self.target.write_bytes(original)
                    with self.assertRaises(settings.SettingsError):
                        writer()
                    self.assertEqual(original, self.target.read_bytes())
                    self.assert_no_temporary_files()

    def test_every_writer_preserves_other_credentials_and_unknown_fields(self):
        for name, writer in self.writers().items():
            with self.subTest(writer=name):
                self.seed()
                writer()
                saved = json.loads(self.target.read_text(encoding="utf-8"))
                self.assertEqual(self.data["future_setting"], saved["future_setting"])
                self.assertEqual(self.data["keys"]["future_provider"], saved["keys"]["future_provider"])
                self.assertEqual(self.data["opencti"]["future_field"], saved["opencti"]["future_field"])
                self.assertEqual("sentinel-provider-two", saved["keys"]["abuseipdb"])
                self.assertEqual("replacement-sentinel" if name == "provider" else "sentinel-provider-one",
                                 saved["keys"]["virustotal"])
                self.assertEqual("sentinel-integration", saved["opencti"]["token"])
                self.assertFalse(saved["opencti"]["external_file_uploads"])
                self.assert_no_temporary_files()

    def test_every_writer_can_create_missing_settings(self):
        for name, writer in self.writers().items():
            with self.subTest(writer=name):
                self.target.unlink(missing_ok=True)
                writer()
                self.assertIsInstance(json.loads(self.target.read_text(encoding="utf-8")), dict)

    def test_failed_replace_preserves_file_and_retry_succeeds(self):
        original = self.seed()
        with patch.object(Path, "replace", side_effect=PermissionError("synthetic replace failure")):
            with self.assertRaises(settings.SettingsError) as caught:
                settings.set_ack(self.ws, True)
        self.assertNotIn(str(self.ws), str(caught.exception))
        self.assertNotIn("synthetic", str(caught.exception))
        self.assertEqual(original, self.target.read_bytes())
        self.assert_no_temporary_files()
        settings.set_ack(self.ws, True)
        self.assertTrue(settings.load(self.ws)["enrichment_ack"])
        self.assertEqual(self.data["keys"]["virustotal"], settings.load(self.ws)["keys"]["virustotal"])

    def test_failed_flush_preserves_file_and_removes_temporary_file(self):
        original = self.seed()
        with patch.object(settings.os, "fsync", side_effect=OSError("synthetic flush failure")):
            with self.assertRaises(settings.SettingsError):
                settings.set_ack(self.ws, True)
        self.assertEqual(original, self.target.read_bytes())
        self.assert_no_temporary_files()

    def test_temporary_file_is_private_before_replace(self):
        self.seed()
        actual_replace = Path.replace
        observed = []

        def replace_private(source, target):
            observed.append(source)
            self.assertTrue(source.name.startswith("settings.json."))
            if os.name != "nt":
                self.assertEqual(stat.S_IRUSR | stat.S_IWUSR, stat.S_IMODE(source.stat().st_mode))
            return actual_replace(source, target)

        with patch.object(Path, "replace", replace_private):
            settings.set_ack(self.ws, True)
        self.assertEqual(1, len(observed))
        self.assert_no_temporary_files()

    def test_explicit_removal_only_clears_the_selected_provider(self):
        self.seed()
        settings.set_key(self.ws, "virustotal", "")
        saved = settings.load(self.ws)
        self.assertEqual("", saved["keys"]["virustotal"])
        self.assertEqual("sentinel-provider-two", saved["keys"]["abuseipdb"])
        self.assertEqual("sentinel-integration", saved["opencti"]["token"])

    def test_restart_retains_credentials_and_public_responses_are_masked(self):
        self.seed()
        settings.set_ack(self.ws, True)
        code = """import json, sys
from server import settings
workspace = sys.argv[1]
assert settings.load(workspace)['keys']['virustotal'] == 'sentinel-provider-one'
assert settings.opencti_config(workspace)['token'] == 'sentinel-integration'
public = settings.public(workspace)
assert public['services']['virustotal']['configured']
assert public['opencti']['configured']
assert 'sentinel-provider-one' not in json.dumps(public)
assert 'sentinel-integration' not in json.dumps(public)
"""
        subprocess.run([sys.executable, "-c", code, str(self.ws)],
                       cwd=Path(__file__).resolve().parents[1], check=True, capture_output=True)

    def test_read_only_load_remains_fail_closed(self):
        self.target.write_text("{broken", encoding="utf-8")
        loaded = settings.load(self.ws)
        self.assertFalse(any(loaded["keys"].values()))
        self.assertFalse(loaded["opencti"]["token"])

    def seed_yara_rule(self):
        rule = Path(yarascan.rules_dir(self.ws)) / "sentinel.yar"
        rule.parent.mkdir(parents=True, exist_ok=True)
        rule.write_text("rule Sentinel { condition: false }\n", encoding="utf-8")
        return rule

    def test_yara_mutations_stop_on_first_read_failure_without_removing_file(self):
        actual_read = Path.read_text
        for delete in (False, True):
            with self.subTest(delete=delete):
                rule = self.seed_yara_rule()
                data = {**self.data, "yara_disabled": ["other.yar", "sentinel.yar"]}
                original = self.seed(data)
                failed = False

                def read_once(target, *args, **kwargs):
                    nonlocal failed
                    if target == self.target and not failed:
                        failed = True
                        raise PermissionError("synthetic first-read failure")
                    return actual_read(target, *args, **kwargs)

                with patch.object(Path, "read_text", read_once):
                    with self.assertRaises(settings.SettingsError):
                        if delete:
                            yarascan.delete_rule(self.ws, "sentinel.yar")
                        else:
                            yarascan.set_rule_enabled(self.ws, "sentinel.yar", False)
                self.assertTrue(failed)
                self.assertTrue(rule.is_file())
                self.assertEqual(original, self.target.read_bytes())

    def test_yara_delete_preserves_rule_when_settings_are_corrupt(self):
        rule = self.seed_yara_rule()
        original = b"{broken"
        self.target.write_bytes(original)
        with self.assertRaises(settings.SettingsError):
            yarascan.delete_rule(self.ws, "sentinel.yar")
        self.assertTrue(rule.is_file())
        self.assertEqual(original, self.target.read_bytes())

    def test_yara_mutations_preserve_credentials_and_other_off_switches(self):
        for action in ("enable", "disable", "delete"):
            with self.subTest(action=action):
                rule = self.seed_yara_rule()
                off = ["other.yar"] if action == "disable" else ["other.yar", "sentinel.yar"]
                self.seed({**self.data, "yara_disabled": off, "rules_disabled": ["other-rule"]})
                if action == "delete":
                    yarascan.delete_rule(self.ws, "sentinel.yar")
                else:
                    yarascan.set_rule_enabled(self.ws, "sentinel.yar", action == "enable")
                saved = settings.load(self.ws, for_write=True)
                expected = ["other.yar", "sentinel.yar"] if action == "disable" else ["other.yar"]
                self.assertEqual(expected, saved["yara_disabled"])
                self.assertEqual(["other-rule"], saved["rules_disabled"])
                self.assertEqual(self.data["keys"], saved["keys"])
                self.assertEqual("sentinel-integration", saved["opencti"]["token"])
                self.assertEqual(self.data["future_setting"], saved["future_setting"])
                self.assertEqual(action != "delete", rule.is_file())


if __name__ == "__main__":
    unittest.main()
