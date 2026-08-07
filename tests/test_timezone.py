# tests/test_timezone.py
"""How a measured instant is rendered, and what is never invented.

The stored facts do not change here: an epoch in UTC plus the offset that
stood in the log line. Everything tested below is presentation -- and
presentation is where timestamps go wrong in a way nobody notices, because a
wrong hour still looks exactly like a right one.

The two failures guarded against:

  * SHIFTING TWICE. The chronology hands out times already shifted by the
    log's offset. A renderer that shifts again moves every timestamp in the
    prose by an hour or two, and it reads perfectly.
  * INVENTING A ZONE NAME. A log line carries `+0200`, which is CEST and
    equally EET and SAST. A name printed next to a timestamp would be a
    guess wearing the clothes of a measurement.
"""
import unittest
from pathlib import Path

from server.chain import iso, local, offset_label


class OffsetLabelTests(unittest.TestCase):

    def test_zero_is_utc(self):
        """The one offset whose name is not a guess."""
        self.assertEqual("UTC", offset_label(0))

    def test_a_positive_offset(self):
        self.assertEqual("UTC+02:00", offset_label(7200))

    def test_a_negative_offset(self):
        self.assertEqual("UTC-05:00", offset_label(-18000))

    def test_a_half_hour_offset(self):
        """India is +05:30 and exists."""
        self.assertEqual("UTC+05:30", offset_label(19800))

    def test_no_zone_name_is_ever_produced(self):
        """+0200 is CEST, EET and SAST. Printing one of them would be a
        guess dressed as a measurement."""
        for tz in (0, 3600, 7200, -18000, 19800, 46800):
            label = offset_label(tz)
            self.assertTrue(label.startswith("UTC"), label)
            for name in ("CEST", "CET", "EST", "PST", "IST", "SAST"):
                self.assertNotIn(name, label)


class RenderTests(unittest.TestCase):
    """`iso` is handed a value ALREADY IN THE MODE'S FRAME and only formats
    and labels it.

    It used to subtract the offset again in `utc` mode, on the assumption
    that every value reaching it was local. That assumption was false:
    `log_at` adds the offset in `log` mode and adds NOTHING in `utc` mode, so
    a UTC value had the offset taken off a second time. The sentence then
    disagreed by two hours with the event it was attached to -- and both read
    perfectly.

    Shifting now happens in exactly one place, `log_at`. These tests state
    that boundary from both sides."""

    EPOCH = 1780000000          # 2026-05-28 20:26:40 UTC
    TZ = 7200                   # the log said +0200

    def test_log_mode_renders_what_it_was_given(self):
        self.assertEqual("2026-05-28 22:26:40 UTC+02:00",
                         iso(local(self.EPOCH, self.TZ), self.TZ, "log"))

    def test_utc_mode_renders_what_it_was_given_too(self):
        """A UTC value stays a UTC value. Subtracting the offset here was the
        bug: `log_at` already decided not to add it."""
        self.assertEqual("2026-05-28 20:26:40 UTC",
                         iso(self.EPOCH, self.TZ, "utc"))

    def test_the_offset_is_applied_exactly_once(self):
        """The property behind both tests above: whatever the mode, the
        rendered clock reading equals the value handed in."""
        for mode, value in (("log", local(self.EPOCH, self.TZ)),
                            ("utc", self.EPOCH)):
            rendered = iso(value, self.TZ, mode)
            self.assertEqual(value, _seconds(rendered[:19]),
                             f"{mode} mode shifted the value it was given")

    def test_the_two_modes_describe_the_same_instant(self):
        as_log = iso(local(self.EPOCH, self.TZ), self.TZ, "log")
        as_utc = iso(self.EPOCH, self.TZ, "utc")
        self.assertNotEqual(as_log[:19], as_utc[:19])
        # 22:26 +02:00 and 20:26 UTC are the same moment.
        self.assertEqual(2 * 3600,
                         _seconds(as_log[:19]) - _seconds(as_utc[:19]))

    def test_a_zone_is_always_stated(self):
        """A bare timestamp in a report is not a time, it is a time and a
        question."""
        for mode in ("log", "utc"):
            for tz in (0, 7200, -18000):
                rendered = iso(local(self.EPOCH, tz), tz, mode)
                self.assertIn("UTC", rendered, f"{mode}/{tz}: {rendered}")

    def test_nothing_renders_as_a_dash(self):
        self.assertEqual("—", iso(None, 7200))
        self.assertEqual("—", iso(0, 7200))


class ChainZoneTests(unittest.TestCase):
    """What the chronology CALLS the zone its events are in.

    This is where it went wrong once already: the label was read from a key
    the overview never returned, so it said "UTC" for every case while the
    events were shifted by their own offsets. Silent, and wrong by whatever
    the offset was.

    And the harder half: there is often no single offset. One Austrian
    server crossing a daylight-saving change writes +0100 and +0200 in the
    same case. Naming one of them would be wrong by an hour for the rest, so
    none is named and the mixture is stated instead."""

    def _case(self, *lines):
        import tempfile
        from server import db
        from server.engines import logindex
        case = Path(tempfile.mkdtemp(prefix="shellhound-tzchain-"))
        db.connect(case).close()
        logs = Path(tempfile.mkdtemp(prefix="shellhound-tzlog-"))
        (logs / "a.log").write_text("".join(lines), encoding="utf-8")
        logindex.build(case, [str(logs)])
        return case

    @staticmethod
    def _line(when, offset, path="/a"):
        return (f'203.0.113.7 - - [{when} {offset}] "GET {path} HTTP/1.1" '
                f'200 5 "-" "x"\n')

    def test_one_offset_is_named(self):
        from server.chain import case_chain
        case = self._case(self._line("10/Jun/2026:22:58:11", "+0200"))
        chain = case_chain(case, "en", "log")
        self.assertEqual("UTC+02:00", chain["zone"])
        self.assertFalse(chain["tz_mixed"])

    def test_a_log_already_in_utc_says_utc(self):
        from server.chain import case_chain
        case = self._case(self._line("10/Jun/2026:22:58:11", "+0000"))
        self.assertEqual("UTC", case_chain(case, "en", "log")["zone"])

    def test_a_negative_offset_is_named(self):
        from server.chain import case_chain
        case = self._case(self._line("10/Jun/2026:22:58:11", "-0500"))
        self.assertEqual("UTC-05:00", case_chain(case, "en", "log")["zone"])

    def test_two_offsets_name_none_and_say_so(self):
        """The daylight-saving case, which is not exotic: every European
        server produces it twice a year."""
        from server.chain import case_chain
        case = self._case(self._line("10/Jun/2026:22:58:11", "+0200"),
                          self._line("10/Jan/2026:22:58:11", "+0100", "/b"))
        chain = case_chain(case, "en", "log")
        self.assertTrue(chain["tz_mixed"])
        self.assertEqual("", chain["zone"])
        self.assertEqual(["UTC+01:00", "UTC+02:00"], chain["tz_offsets"])

    def test_utc_mode_is_never_mixed(self):
        """That is what it is for: one comparable timeline whatever the
        sources did."""
        from server.chain import case_chain
        case = self._case(self._line("10/Jun/2026:22:58:11", "+0200"),
                          self._line("10/Jan/2026:22:58:11", "+0100", "/b"))
        chain = case_chain(case, "en", "utc")
        self.assertFalse(chain["tz_mixed"])
        self.assertEqual("UTC", chain["zone"])

    def test_the_index_reports_the_offsets_it_saw(self):
        from server.engines import logindex
        case = self._case(self._line("10/Jun/2026:22:58:11", "+0200"),
                          self._line("10/Jan/2026:22:58:11", "+0100", "/b"))
        self.assertEqual([3600, 7200],
                         logindex.overview(case)["tz_offsets"])


def _seconds(stamp):
    from datetime import datetime, timezone
    return int(datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S")
               .replace(tzinfo=timezone.utc).timestamp())


if __name__ == "__main__":
    unittest.main()
