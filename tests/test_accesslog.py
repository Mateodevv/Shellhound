"""Access-log formats whose field boundaries have caused silent data loss."""
import tempfile
import unittest
from pathlib import Path

from server.engines import accesslog, logindex


VHOST_COMBINED = (
    'www.sample-sample.de 209.38.250.42 - - '
    '[01/Jan/2026:00:31:20 +0100] "POST / HTTP/1.1" 200 19 '
    '"-" "Go-http-client/1.1" /index.html'
)

VHOST_TRAVERSAL = (
    'www.sample-sample.de 23.225.177.250 - - '
    '[01/Jan/2026:02:02:02 +0100] '
    '"POST /cgi-bin/%%32%65%%32%65/bin/sh HTTP/1.1" 400 226 '
    '"-" "libredtail-http" /cgi-bin/%2e%2e/bin/sh'
)


class VhostAccessLogTests(unittest.TestCase):

    def test_vhost_prefix_keeps_the_client_as_the_ip(self):
        parsed = accesslog.parse_line(VHOST_COMBINED)
        self.assertIsNotNone(parsed)
        self.assertEqual("209.38.250.42", parsed["ip"])
        self.assertEqual("POST", parsed["method"])
        self.assertEqual("/", parsed["uri"])
        self.assertEqual("Go-http-client/1.1", parsed["user_agent"])

    def test_vhost_prefix_is_supported_by_common_format_too(self):
        parsed = accesslog.parse_line(
            'www.sample-sample.de 209.38.244.170 - - '
            '[01/Jan/2026:00:31:20 +0100] "GET / HTTP/1.0" 400 362'
        )
        self.assertIsNotNone(parsed)
        self.assertEqual("209.38.244.170", parsed["ip"])
        self.assertEqual("/", parsed["uri"])

    def test_vhost_lines_are_indexed_instead_of_counted_as_unparsed(self):
        with tempfile.TemporaryDirectory(prefix="shellhound-vhost-case-") as case:
            with tempfile.TemporaryDirectory(prefix="shellhound-vhost-logs-") as logs:
                Path(logs, "access.log").write_text(
                    VHOST_COMBINED + "\n" + VHOST_TRAVERSAL + "\n",
                    encoding="utf-8",
                )
                stats = logindex.build(Path(case), [logs])

        self.assertEqual(2, stats["lines"])
        self.assertEqual(0, stats["unparsed"])
        self.assertEqual(2, stats["clients"])

    def test_standard_combined_format_still_keeps_its_first_field(self):
        parsed = accesslog.parse_line(
            '203.0.113.7 - - [01/Jan/2026:00:31:20 +0100] '
            '"GET / HTTP/1.1" 200 19 "-" "curl"'
        )
        self.assertIsNotNone(parsed)
        self.assertEqual("203.0.113.7", parsed["ip"])


if __name__ == "__main__":
    unittest.main()
