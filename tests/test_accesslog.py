"""Access-log formats whose field boundaries have caused silent data loss."""
import tempfile
import unittest
from pathlib import Path

from server import coverage
from server.engines import accesslog, detect, logindex


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

IIS_FIELDS = (
    "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port "
    "cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus "
    "sc-win32-status time-taken"
)

IIS_REQUEST = (
    "2026-02-10 00:05:10 192.168.0.204 GET "
    "/wp-content/plugins/hellopress/wp_filemanager.php token=a%2Bb 443 - "
    "51.120.74.232 Mozilla/5.0+(Windows+NT+10.0) "
    "https://example.test/start+page 301 0 0 1306"
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


class IisW3CAccessLogTests(unittest.TestCase):

    def test_fields_header_gives_columns_their_forensic_meaning(self):
        parser = accesslog.AccessLogParser()
        self.assertIsNone(parser.parse(IIS_FIELDS))

        parsed = parser.parse(IIS_REQUEST)

        self.assertIsNotNone(parsed)
        self.assertEqual("51.120.74.232", parsed["ip"])
        self.assertEqual("2026-02-10 00:05:10", parsed["time"])
        self.assertEqual("GET", parsed["method"])
        self.assertEqual(
            "/wp-content/plugins/hellopress/wp_filemanager.php?token=a%2Bb",
            parsed["uri"],
        )
        self.assertEqual("301", parsed["status"])
        self.assertEqual("-", parsed["size"])
        self.assertEqual("Mozilla/5.0 (Windows NT 10.0)",
                         parsed["user_agent"])
        self.assertEqual("https://example.test/start page", parsed["referrer"])

    def test_reordered_fields_and_optional_response_size_are_supported(self):
        parser = accesslog.AccessLogParser()
        parser.parse(
            "#Fields: sc-status c-ip cs-uri-stem date sc-bytes cs-method time"
        )

        parsed = parser.parse(
            "200 203.0.113.8 /health 2026-02-10 42 HEAD 13:14:15"
        )

        self.assertEqual("203.0.113.8", parsed["ip"])
        self.assertEqual("42", parsed["size"])
        self.assertEqual("HEAD", parsed["method"])

    def test_repeated_fields_directive_changes_the_active_schema(self):
        parser = accesslog.AccessLogParser()
        parser.parse("#Fields: date time c-ip cs-method cs-uri-stem sc-status")
        self.assertIsNotNone(
            parser.parse("2026-02-10 00:00:01 203.0.113.1 GET /first 200")
        )
        parser.parse("#Fields: c-ip date time cs-uri-stem sc-status cs-method")
        parsed = parser.parse(
            "203.0.113.2 2026-02-10 00:00:02 /second 404 POST"
        )
        self.assertEqual("203.0.113.2", parsed["ip"])
        self.assertEqual("POST", parsed["method"])

    def test_malformed_w3c_row_is_rejected_instead_of_shifted(self):
        parser = accesslog.AccessLogParser()
        parser.parse(IIS_FIELDS)
        self.assertIsNone(parser.parse(IIS_REQUEST.rsplit(" ", 1)[0]))

    def test_w3c_timestamp_is_utc(self):
        self.assertEqual((1770681910.0, 0),
                         accesslog.fast_epoch("2026-02-10 00:05:10"))

    def test_w3c_metadata_is_not_counted_as_unparsed(self):
        with tempfile.TemporaryDirectory(prefix="shellhound-iis-case-") as case:
            with tempfile.TemporaryDirectory(prefix="shellhound-iis-logs-") as logs:
                Path(logs, "u_ex.log").write_text(
                    "#Software: Microsoft Internet Information Services 10.0\n"
                    "#Version: 1.0\n"
                    "#Date: 2026-02-10 00:05:10\n"
                    f"{IIS_FIELDS}\n{IIS_REQUEST}\n",
                    encoding="utf-8",
                )
                stats = logindex.build(Path(case), [logs])

        self.assertEqual(1, stats["lines"])
        self.assertEqual(0, stats["unparsed"])
        self.assertEqual(0, stats["undated"])
        self.assertEqual(1, stats["clients"])

    def test_guided_evidence_detection_recognises_w3c_logs(self):
        with tempfile.TemporaryDirectory(prefix="shellhound-iis-detect-") as root:
            logs = Path(root, "logs")
            logs.mkdir()
            Path(logs, "u_ex.log").write_text(
                f"#Software: Microsoft Internet Information Services 10.0\n"
                f"{IIS_FIELDS}\n{IIS_REQUEST}\n",
                encoding="utf-8",
            )

            proposals = detect.scan(root)["candidates"]["access_logs"]

        self.assertEqual(1, len(proposals))
        self.assertEqual(str(Path(root)), proposals[0]["path"])
        self.assertIn("u_ex.log", proposals[0]["why"])

    def test_w3c_header_is_not_mistaken_for_a_truncated_log_head(self):
        with tempfile.TemporaryDirectory(prefix="shellhound-iis-head-") as root:
            path = Path(root, "u_ex.log")
            path.write_text(
                f"#Software: Microsoft Internet Information Services 10.0\n"
                f"{IIS_FIELDS}\n{IIS_REQUEST}\n",
                encoding="utf-8",
            )

            first, parses = coverage._first_record_line(path)

        self.assertEqual(IIS_REQUEST, first.rstrip("\r\n"))
        self.assertTrue(parses)


if __name__ == "__main__":
    unittest.main()
