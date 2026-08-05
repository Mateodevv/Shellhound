# tests/test_i18n.py
"""The catalogues on both sides of the codebase.

The frontend catalogue is TypeScript and the server catalogue is Python, but
they fail the same way: a key that exists in one language and not the other
shows up as a raw dotted key in the interface, and nobody notices until a
German user opens the view. These tests catch that at commit time instead.

The English catalogue is the source of truth. German may not have keys of
its own -- one that English does not know is either a typo or a leftover.
"""
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

    def test_every_key_has_every_language(self):
        for key, entry in i18n.CATALOGUE.items():
            for lang in i18n.LANGUAGES:
                self.assertIn(lang, entry, f"{key} is missing {lang}")
                self.assertTrue(entry[lang].strip(), f"{key}/{lang} is empty")

    def test_placeholders_match_across_languages(self):
        """A placeholder that only one language knows silently drops a value."""
        holes = re.compile(r"\{(\w+)\}")
        for key, entry in i18n.CATALOGUE.items():
            names = {lang: set(holes.findall(text))
                     for lang, text in entry.items()}
            first = names[i18n.DEFAULT]
            for lang, found in names.items():
                self.assertEqual(first, found,
                                 f"{key}: {lang} has {found}, "
                                 f"{i18n.DEFAULT} has {first}")

    def test_unknown_key_returns_itself(self):
        # Conspicuous in the interface beats silently empty.
        self.assertEqual(i18n.t("en", "no.such.key"), "no.such.key")

    def test_lang_of_normalises(self):
        self.assertEqual(i18n.lang_of("de"), "de")
        self.assertEqual(i18n.lang_of("DE-AT"), "de")
        self.assertEqual(i18n.lang_of(""), i18n.DEFAULT)
        self.assertEqual(i18n.lang_of(None), i18n.DEFAULT)
        self.assertEqual(i18n.lang_of("fr"), i18n.DEFAULT)

    def test_german_falls_back_to_english_not_to_the_key(self):
        i18n.CATALOGUE["test.only.english"] = {"en": "only English"}
        try:
            self.assertEqual(i18n.t("de", "test.only.english"), "only English")
        finally:
            del i18n.CATALOGUE["test.only.english"]


class WebCatalogueTests(unittest.TestCase):

    def setUp(self):
        if not (WEB / "en.ts").is_file():
            self.skipTest("frontend sources not present")
        self.en = _catalogue("en.ts")
        self.de = _catalogue("de.ts")

    def test_catalogues_cover_the_same_keys(self):
        self.assertEqual(set(), self.en - self.de,
                         "keys missing from the German catalogue")
        self.assertEqual(set(), self.de - self.en,
                         "keys in German that English does not know")

    def test_catalogue_is_not_empty(self):
        # Guards against a parsing change quietly turning both sides into
        # empty sets, which would make the comparison above pass on nothing.
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
