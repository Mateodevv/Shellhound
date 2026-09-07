"""English catalogue coverage and compatibility with old language preferences."""
import re
import unittest
from pathlib import Path

from server import i18n

SRC = Path(__file__).resolve().parent.parent / "web" / "src"
WEB = SRC / "i18n"
KEY_RE = re.compile(r"^\s*'([^']+)':", re.M)
# Only the literal form. `tr(`job.${kind}`)` and friends are computed at
# runtime and cannot be checked from here -- see the note on the test below.
USE_RE = re.compile(r"\btr\(\s*'([^']+)'")


def _catalogue(name):
    return set(KEY_RE.findall((WEB / name).read_text(encoding="utf-8")))


def _used():
    """Every key the interface asks for by name, and where it asks."""
    out = {}
    for path in sorted(SRC.rglob("*.ts")) + sorted(SRC.rglob("*.tsx")):
        for key in USE_RE.findall(path.read_text(encoding="utf-8")):
            out.setdefault(key, set()).add(path.name)
    return out


class ServerCatalogueTests(unittest.TestCase):

    def test_every_key_has_english_copy(self):
        self.assertGreater(len(i18n.CATALOGUE), 50)
        for key, value in i18n.CATALOGUE.items():
            self.assertIsInstance(value, str, key)
            self.assertTrue(value.strip(), key)

    def test_old_language_preferences_always_resolve_to_english(self):
        for preference in ("en", "de", "DE-AT", "de-DE", "fr", "", None):
            with self.subTest(preference=preference):
                self.assertEqual("en", i18n.lang_of(preference))
                for key in i18n.CATALOGUE:
                    self.assertEqual(i18n.t("en", key), i18n.t(preference, key))

    def test_placeholders_and_unknown_keys(self):
        self.assertEqual("First successful request for file.txt",
                         i18n.t("de", "chain.file.firstOk", name="file.txt"))
        self.assertEqual("no.such.key", i18n.t("en", "no.such.key"))

    def test_country_names_ignore_legacy_language_preferences(self):
        from unittest.mock import Mock, patch
        from server import geoip
        reader = Mock()
        reader.get.return_value = {"country": {
            "iso_code": "DE", "names": {"en": "Germany", "de": "Deutschland"}}}
        with patch.object(geoip, "_get_reader", return_value=reader), \
                patch.dict(geoip._cache, clear=True):
            result = geoip.lookup("unused", "8.8.8.8", "de")
            self.assertEqual("Germany", result["name"])
            self.assertEqual("de", result["iso"])
            self.assertEqual(result, geoip.lookup("unused", "8.8.8.8", "en"))



class WebCatalogueTests(unittest.TestCase):

    def setUp(self):
        if not (WEB / "en.ts").is_file():
            self.skipTest("frontend sources not present")
        self.en = _catalogue("en.ts")


    def test_catalogue_is_not_empty(self):
        # An empty parser result must not make coverage checks pass.
        self.assertGreater(len(self.en), 300)

    def test_every_key_the_interface_asks_for_exists(self):
        """The failure this catches is silent in the browser and loud in a
        screenshot: `tr()` falls back to echoing the key, so a missing entry
        renders the literal `findings.search` where a placeholder belongs.
        Nothing throws, nothing logs, and it survives until somebody looks.

        Only literal `tr('...')` calls are checked. A key built from a
        variable is invisible here, which is the reason the job list keeps an
        explicit list of kinds instead of interpolating whatever arrives."""
        used = _used()
        self.assertGreater(len(used), 400, "the scan found almost nothing")
        missing = {k: sorted(v) for k, v in used.items() if k not in self.en}
        self.assertEqual({}, missing, "keys used but never defined")

    # There is deliberately no test for the other direction. Most of the
    # catalogue is reached through computed keys -- `category.${id}.what`,
    # `sev.${n}`, lookup tables of key names -- so a literal scan calls some
    # 300 live entries dead. An allowlist that large would be wrong within a
    # week and would teach nothing.


if __name__ == "__main__":
    unittest.main()
