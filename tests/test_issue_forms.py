# tests/test_issue_forms.py
"""The GitHub issue forms.

A malformed form does not raise anything anywhere -- GitHub simply stops
offering it in the issue chooser, and nobody notices until the first person
who wanted to file that kind of report files nothing instead. These checks
cover the mistakes that fail exactly that quietly: `validations` on a block
type that has none, a markdown block carrying an id, a dropdown option that
YAML read as a number.

PyYAML is not a dependency of the tool. Where it is missing the module skips
rather than fails -- the forms are repository metadata, and a contributor
without it should still get a green suite.
"""
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:                                   # pragma: no cover
    yaml = None

FORMS = Path(__file__).resolve().parent.parent / ".github" / "ISSUE_TEMPLATE"

# https://docs.github.com/issues/tracking-your-work-with-issues/using-templates
TOP_LEVEL = {"name", "description", "title", "labels", "assignees", "body",
             "projects", "type"}
BLOCK_TYPES = {"markdown", "input", "textarea", "dropdown", "checkboxes"}
# Only these carry a `validations` key at block level.
VALIDATABLE = {"input", "textarea", "dropdown"}


def _forms():
    return sorted(p for p in FORMS.glob("*.yml") if p.name != "config.yml")


@unittest.skipIf(yaml is None, "PyYAML not installed")
class IssueFormTests(unittest.TestCase):

    def setUp(self):
        self.forms = {p.name: yaml.safe_load(p.read_text(encoding="utf-8"))
                      for p in _forms()}
        self.assertTrue(self.forms, "no issue forms found")

    def test_every_form_parses_and_has_the_required_keys(self):
        for name, doc in self.forms.items():
            self.assertIsInstance(doc, dict, name)
            for key in ("name", "description", "body"):
                self.assertIn(key, doc, f"{name} has no {key}")
            self.assertTrue(doc["body"], f"{name} has an empty body")

    def test_no_unknown_top_level_key(self):
        """An unknown key is not ignored -- it invalidates the file."""
        for name, doc in self.forms.items():
            self.assertEqual(set(), set(doc) - TOP_LEVEL, name)

    def test_every_block_has_a_known_type(self):
        for name, doc in self.forms.items():
            for i, block in enumerate(doc["body"]):
                self.assertIn(block.get("type"), BLOCK_TYPES,
                              f"{name} block {i}")

    def test_only_input_textarea_and_dropdown_are_validated(self):
        """`validations` on a markdown or checkboxes block breaks the form.
        A required checkbox is expressed on the OPTION, not on the block."""
        for name, doc in self.forms.items():
            for i, block in enumerate(doc["body"]):
                if block["type"] not in VALIDATABLE:
                    self.assertNotIn("validations", block,
                                     f"{name} block {i} ({block['type']})")

    def test_markdown_blocks_carry_nothing_but_a_value(self):
        for name, doc in self.forms.items():
            for i, block in enumerate(doc["body"]):
                if block["type"] != "markdown":
                    continue
                self.assertNotIn("id", block, f"{name} block {i}")
                self.assertEqual({"value"}, set(block.get("attributes", {})),
                                 f"{name} block {i}")

    def test_every_other_block_has_an_id_and_a_label(self):
        for name, doc in self.forms.items():
            for i, block in enumerate(doc["body"]):
                if block["type"] == "markdown":
                    continue
                self.assertTrue(block.get("id"), f"{name} block {i} has no id")
                self.assertTrue(block.get("attributes", {}).get("label"),
                                f"{name} block {i} has no label")

    def test_ids_are_unique_within_a_form(self):
        for name, doc in self.forms.items():
            ids = [b["id"] for b in doc["body"] if "id" in b]
            self.assertEqual(len(ids), len(set(ids)), name)

    def test_dropdown_options_are_strings(self):
        """The one that bites: unquoted `3.10` is the float 3.1, and the
        option silently reads as "3.1" in the chooser."""
        for name, doc in self.forms.items():
            for block in doc["body"]:
                if block["type"] != "dropdown":
                    continue
                for option in block["attributes"]["options"]:
                    self.assertIsInstance(option, str,
                                          f"{name}/{block['id']}: {option!r}")

    def test_checkbox_options_have_labels(self):
        for name, doc in self.forms.items():
            for block in doc["body"]:
                if block["type"] != "checkboxes":
                    continue
                for option in block["attributes"]["options"]:
                    self.assertTrue(option.get("label"),
                                    f"{name}/{block['id']}")

    def test_every_form_requires_the_evidence_acknowledgement(self):
        """The whole point of the set. This is forensics software: the
        natural way to report a bug is to paste the log line, the path or the
        hash that broke it, and every one of those is somebody's incident.
        A form that lets a reporter past without confirming otherwise is the
        one that will carry a real case into a public issue."""
        for name, doc in self.forms.items():
            required = [option
                        for block in doc["body"]
                        if block["type"] == "checkboxes"
                        for option in block["attributes"]["options"]
                        if option.get("required")]
            self.assertTrue(required, f"{name} has no required acknowledgement")


@unittest.skipIf(yaml is None, "PyYAML not installed")
class ChooserConfigTests(unittest.TestCase):

    def setUp(self):
        path = FORMS / "config.yml"
        self.assertTrue(path.is_file(), "config.yml is missing")
        self.doc = yaml.safe_load(path.read_text(encoding="utf-8"))

    def test_blank_issues_are_off(self):
        """Every form requires the acknowledgement above; a blank issue is
        the route around all of them."""
        self.assertFalse(self.doc.get("blank_issues_enabled", True))

    def test_contact_links_are_complete(self):
        for link in self.doc.get("contact_links", []):
            for key in ("name", "url", "about"):
                self.assertTrue(link.get(key), f"{link} has no {key}")

    def test_security_reporting_is_routed_away_from_public_issues(self):
        urls = " ".join(l["url"] for l in self.doc.get("contact_links", []))
        self.assertIn("SECURITY.md", urls)


if __name__ == "__main__":
    unittest.main()
