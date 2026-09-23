"""Named source clocks resolve historical offsets without reinterpreting filesystem epochs."""
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from server import log_evidence, log_parsers, source_time
from server.chain import filesystem_times


class SourceTimeTests(unittest.TestCase):
    def test_named_zone_observes_summer_and_winter_offsets(self):
        for day, utc in (('2026-01-10T12:00:00', '2026-01-10T11:00:00+00:00'),
                         ('2026-07-10T12:00:00', '2026-07-10T10:00:00+00:00')):
            self.assertEqual(source_time.example(day, 'Europe/Berlin')['utc'], utc)
        self.assertIn('Europe/Berlin', source_time.catalogue()['zones'])

    def test_recorded_offset_wins_and_ambiguous_times_remain_unknown(self):
        self.assertEqual(log_parsers.timestamp('2026-07-10T12:00:00+03:00', 'Europe/Berlin'),
                         int(datetime(2026, 7, 10, 9, tzinfo=timezone.utc).timestamp()))
        for zone in ('auto', 'unknown', ''):
            self.assertIsNone(log_parsers.timestamp('2026-07-10T12:00:00', zone))
        for raw in ('2026-10-25T02:30:00', '2026-03-29T02:30:00'):
            self.assertIsNone(log_parsers.timestamp(raw, 'Europe/Berlin'))

    def test_log_preview_matches_parser_and_file_epochs_are_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'error.log'
            path.write_text('2026/07/10 12:00:00 [error] 123#123: Ordinary diagnostic\n', encoding='utf-8')
            before = filesystem_times(path)
            preview = log_evidence.preview(str(path), 'Europe/Berlin')
            self.assertEqual(preview['sources'][0]['time_examples'][0]['utc'], '2026-07-10T10:00:00+00:00')
            self.assertEqual(before, filesystem_times(path))


if __name__ == '__main__':
    unittest.main()
