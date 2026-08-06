# tests/test_brand.py
"""The mark exists twice, and has to stay the same thing twice.

`web/public/favicon.svg` must be a standalone file the browser can fetch
before any script runs; `web/src/components/Mark.tsx` is what the interface
draws. Neither can be generated from the other at build time without adding
a build step for three shapes. So they are duplicated on purpose -- and this
is the check that stops them drifting into two different logos, which is a
thing nobody notices until a screenshot is taken.

Only the GEOMETRY and the COLOURS are compared. Markup differs legitimately:
SVG attributes are hyphenated and JSX ones are camelCase, and the component
can drop the tile.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAVICON = ROOT / "web" / "public" / "favicon.svg"
COMPONENT = ROOT / "web" / "src" / "components" / "Mark.tsx"

# The three things that make the mark what it is.
PATH_D = "M5 24H16V10h11"
ACCENT = "#3987e5"
SEVERITY = "#d03b3b"
TILE = "#0b0e14"


class MarkTests(unittest.TestCase):

    def setUp(self):
        for path in (FAVICON, COMPONENT):
            if not path.is_file():
                self.skipTest(f"{path.name} not present")
        self.favicon = FAVICON.read_text(encoding="utf-8")
        self.component = COMPONENT.read_text(encoding="utf-8")

    def test_both_draw_the_same_path(self):
        for name, text in (("favicon", self.favicon),
                           ("component", self.component)):
            self.assertIn(PATH_D, text, f"{name} draws a different step")

    def test_both_use_the_same_colours(self):
        """Blue is what was measured, red is the one thing concluded. A mark
        that drifts to one colour has lost the argument it was drawn for."""
        for name, text in (("favicon", self.favicon),
                           ("component", self.component)):
            self.assertIn(ACCENT, text, f"{name} lost the accent")
            self.assertIn(SEVERITY, text, f"{name} lost the severity node")
            self.assertIn(TILE, text, f"{name} lost the tile colour")

    def test_the_node_sits_on_the_knee_in_both(self):
        """The red point marks the moment of the step. Anywhere else it is
        decoration."""
        for name, text in (("favicon", self.favicon),
                           ("component", self.component)):
            self.assertRegex(text, r'cx=[">{ ]*"?16"?', name)
            self.assertRegex(text, r'cy=[">{ ]*"?10"?', name)

    def test_the_stroke_weight_matches(self):
        """It is chosen for 16px: 4 on a 32 grid survives as two device
        pixels. A thinner one disappears in the tab strip."""
        self.assertIn('stroke-width="4"', self.favicon)
        self.assertIn('strokeWidth="4"', self.component)

    def test_the_favicon_is_valid_xml(self):
        """`--` inside a comment is illegal in XML, and the file then renders
        nowhere at all -- which is invisible in the source."""
        import xml.etree.ElementTree as ET
        ET.fromstring(self.favicon)

    def test_the_favicon_carries_no_external_reference(self):
        body = re.sub(r"<!--.*?-->", "", self.favicon, flags=re.S)
        for forbidden in ("href", "<script", "<image", "url(", "@import"):
            self.assertNotIn(forbidden, body)

    def test_the_favicon_stays_small(self):
        # It is fetched on every page load, before anything else runs.
        self.assertLess(len(self.favicon.encode("utf-8")), 3072)


class BannerTests(unittest.TestCase):
    """The README banner. GitHub renders it as an image without the author's
    fonts, so a `<text>` element would come out in whatever the renderer
    happens to have."""

    def setUp(self):
        self.path = ROOT / "assets" / "brand" / "banner.svg"
        if not self.path.is_file():
            self.skipTest("banner not present")
        self.text = self.path.read_text(encoding="utf-8")
        self.body = re.sub(r"<!--.*?-->", "", self.text, flags=re.S)

    def test_it_is_valid_xml(self):
        import xml.etree.ElementTree as ET
        ET.fromstring(self.text)

    def test_the_wordmark_is_drawn_and_not_typed(self):
        for forbidden in ("<text", "<tspan", "font-family", "font-size"):
            self.assertNotIn(forbidden, self.body)

    def test_it_is_self_contained(self):
        for forbidden in ("href", "<script", "<image", "url(", "@import"):
            self.assertNotIn(forbidden, self.body)

    def test_it_carries_its_own_background(self):
        """GitHub shows a README on a white or a dark page from the same
        file. A banner without its own field only works on one of them."""
        self.assertIn("#0b0e14", self.body)

    def test_it_uses_the_same_mark(self):
        self.assertIn(PATH_D, self.body)


if __name__ == "__main__":
    unittest.main()
