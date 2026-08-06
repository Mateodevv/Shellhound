# tests/test_yara.py
"""The analyst's own rules.

Two things matter here and neither is "does YARA work" -- that is YARA's job.
What this file guards is the behaviour AROUND it: that a broken rule file
costs one rule and not the run, and that the two silences which look alike
stay distinguishable. "No YARA findings" must never be ambiguous between
"the rules found nothing" and "there were no rules".
"""
import tempfile
import unittest
from pathlib import Path

from server import db
from server.engines import yarascan

GOOD_RULES = """
rule Eval_On_Post : webshell
{
    meta:
        severity = "high"
    strings:
        $a = "eval($_POST" ascii
    condition:
        $a
}

rule Plain_Marker
{
    strings:
        $m = "SHELLHOUND-TEST-MARKER" ascii
    condition:
        $m
}

rule Quiet_Note
{
    meta:
        severity = "info"
    strings:
        $n = "just-a-note-marker" ascii
    condition:
        $n
}
"""

BROKEN_RULES = "rule Nope { condition: this is not yara }"


@unittest.skipIf(yarascan.yara is None, "yara-python not installed")
class YaraScanTests(unittest.TestCase):

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="shellhound-yws-"))
        self.case = Path(tempfile.mkdtemp(prefix="shellhound-ycase-"))
        self.root = Path(tempfile.mkdtemp(prefix="shellhound-yroot-"))
        db.connect(self.case).close()
        (self.ws / "yara").mkdir()
        (self.ws / "yara" / "rules.yar").write_text(GOOD_RULES, encoding="utf-8")
        (self.root / "shell.php").write_text('<?php eval($_POST["x"]);',
                                             encoding="utf-8")
        (self.root / "note.txt").write_text("SHELLHOUND-TEST-MARKER",
                                            encoding="utf-8")
        (self.root / "clean.php").write_text('<?php echo "hi";', encoding="utf-8")

    def _findings(self):
        conn = db.connect(self.case)
        try:
            return db.rows(conn, "SELECT * FROM findings WHERE source = 'yara'")
        finally:
            conn.close()

    def _skipped(self):
        conn = db.connect(self.case)
        try:
            return db.rows(conn, "SELECT * FROM skipped WHERE source = 'yara'")
        finally:
            conn.close()

    def test_a_rule_fires_on_the_file_it_describes(self):
        yarascan.scan(self.case, [str(self.root)], workspace=self.ws)
        hits = {Path(f["artifact"]).name: f for f in self._findings()}
        self.assertIn("shell.php", hits)
        self.assertIn("note.txt", hits)
        self.assertNotIn("clean.php", hits, "a clean file was flagged")

    def test_findings_land_on_the_file_artifact(self):
        """Same artifact kind as the shipped scan, so triage, propagation and
        IOC collection carry on unchanged instead of opening a second list."""
        yarascan.scan(self.case, [str(self.root)], workspace=self.ws)
        for f in self._findings():
            self.assertEqual("file", f["artifact_kind"])
            self.assertTrue(f["rule"].startswith("YARA: "))

    def test_severity_comes_from_the_rule_metadata(self):
        yarascan.scan(self.case, [str(self.root)], workspace=self.ws)
        by_rule = {f["rule"]: f["severity"] for f in self._findings()}
        self.assertEqual(db.SEV_HIGH, by_rule["YARA: Eval_On_Post"])

    def test_a_rule_without_metadata_is_medium_not_high(self):
        """A match is somebody's rule matching -- until a human looks, that
        is MEDIUM. Defaulting to HIGH would let a stranger's rule set the
        colour of the work list."""
        yarascan.scan(self.case, [str(self.root)], workspace=self.ws)
        by_rule = {f["rule"]: f["severity"] for f in self._findings()}
        self.assertEqual(db.SEV_MEDIUM, by_rule["YARA: Plain_Marker"])

    def test_the_evidence_names_what_matched_not_the_bytes(self):
        """A rule can match on a credential, and the evidence line travels
        into the case archive."""
        yarascan.scan(self.case, [str(self.root)], workspace=self.ws)
        hit = next(f for f in self._findings()
                   if f["rule"] == "YARA: Eval_On_Post")
        self.assertIn("Eval_On_Post", hit["evidence"])
        self.assertIn("$a", hit["evidence"])
        self.assertNotIn("eval($_POST", hit["evidence"],
                         "the matched bytes leaked into the evidence")

    # --- a broken rule file -------------------------------------------------

    def test_a_broken_rule_file_does_not_cost_the_run(self):
        (self.ws / "yara" / "broken.yar").write_text(BROKEN_RULES,
                                                     encoding="utf-8")
        stats = yarascan.scan(self.case, [str(self.root)], workspace=self.ws)
        self.assertEqual(1, stats["broken_rules"])
        self.assertGreater(stats["findings"], 0,
                           "the good rules stopped running")

    def test_a_broken_rule_file_is_reported_by_name(self):
        """An unchecked thing is reported, not passed over in silence --
        the same rule as everywhere else in this toolkit."""
        (self.ws / "yara" / "broken.yar").write_text(BROKEN_RULES,
                                                     encoding="utf-8")
        yarascan.scan(self.case, [str(self.root)], workspace=self.ws)
        skipped = self._skipped()
        self.assertTrue(any(s["path"] == "broken.yar" for s in skipped))
        self.assertTrue(any("did not compile" in s["reason"] for s in skipped))

    def test_an_oversized_file_is_reported_not_ignored(self):
        big = self.root / "big.bin"
        big.write_bytes(b"\x00" * (yarascan.MAX_SCAN_BYTES + 10))
        yarascan.scan(self.case, [str(self.root)], workspace=self.ws)
        self.assertTrue(any(Path(s["path"]).name == "big.bin"
                            for s in self._skipped()))

    # --- the two silences ---------------------------------------------------

    def test_status_distinguishes_no_rules_from_no_yara(self):
        empty = Path(tempfile.mkdtemp(prefix="shellhound-yempty-"))
        self.assertEqual("norules", yarascan.status(empty)["reason"])
        self.assertEqual("", yarascan.status(self.ws)["reason"])

    def test_status_counts_the_rules_and_names_the_broken_file(self):
        (self.ws / "yara" / "broken.yar").write_text(BROKEN_RULES,
                                                     encoding="utf-8")
        st = yarascan.status(self.ws)
        self.assertTrue(st["available"])
        self.assertEqual(3, st["rules"])
        self.assertEqual(["broken.yar"], [b["file"] for b in st["broken"]])

    def test_rules_belong_to_the_workspace(self):
        """Like the pattern library: a rule set grows across cases, while a
        case only records what it found."""
        self.assertEqual(str(self.ws / "yara"), yarascan.rules_dir(self.ws))


class YaraIsRequiredTests(unittest.TestCase):
    """It used to be optional, and the engine used to be a no-op without it.

    That stopped being tenable when the web shell content rules became YARA
    rules: a missing package would mean thirteen detections quietly not
    running, and a scanner that silently finds less is worse than one that
    refuses to start. These tests hold the new promise instead of the old
    one -- that the package is there, and that the rules it needs shipped
    with it."""

    def test_the_package_is_importable(self):
        import yara
        self.assertTrue(hasattr(yara, "compile"))

    def test_it_is_declared_as_a_hard_dependency(self):
        """Not in an extra. An install that omits it is an install that
        detects less without saying so."""
        root = Path(__file__).resolve().parent.parent
        requirements = (root / "requirements.txt").read_text(encoding="utf-8")
        pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("yara-python", requirements)
        deps = pyproject.split("[project.urls]")[0]
        self.assertIn("yara-python", deps)

    def test_the_bundled_rules_ship_with_the_package(self):
        root = Path(__file__).resolve().parent.parent
        pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("rules_bundled/*.yar", pyproject)
        self.assertTrue(list((root / "server" / "rules_bundled").glob("*.yar")))

    def test_status_never_reports_a_missing_package(self):
        st = yarascan.status(Path(tempfile.mkdtemp(prefix="shellhound-yreq-")))
        self.assertTrue(st["available"])
        self.assertNotEqual("package", st["reason"])


if __name__ == "__main__":
    unittest.main()
