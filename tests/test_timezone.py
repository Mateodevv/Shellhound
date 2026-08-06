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
    """`iso` is handed an ALREADY LOCAL value -- see the module docstring."""

    EPOCH = 1780000000          # 2026-05-28 20:26:40 UTC
    TZ = 7200                   # the log said +0200

    def test_log_mode_renders_what_it_was_given(self):
        already_local = local(self.EPOCH, self.TZ)
        self.assertEqual("2026-05-28 22:26:40 UTC+02:00",
                         iso(already_local, self.TZ, "log"))

    def test_utc_mode_takes_the_offset_back_off(self):
        """The value arrives shifted. UTC mode must UNDO that, not add to
        it -- adding twice is a two-hour error that reads perfectly."""
        already_local = local(self.EPOCH, self.TZ)
        self.assertEqual("2026-05-28 20:26:40 UTC",
                         iso(already_local, self.TZ, "utc"))

    def test_the_two_modes_describe_the_same_instant(self):
        already_local = local(self.EPOCH, self.TZ)
        as_log = iso(already_local, self.TZ, "log")
        as_utc = iso(already_local, self.TZ, "utc")
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


def _seconds(stamp):
    from datetime import datetime, timezone
    return int(datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S")
               .replace(tzinfo=timezone.utc).timestamp())


if __name__ == "__main__":
    unittest.main()
