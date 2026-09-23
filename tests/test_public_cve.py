import json
import unittest
from unittest.mock import MagicMock, patch
from server.integrations.cve import fetch_record

class PublicCveTests(unittest.TestCase):
    def test_invalid_id_never_contacts_provider(self):
        with patch("urllib.request.build_opener") as opener:
            with self.assertRaises(ValueError):
                fetch_record("https://example.org")
            opener.assert_not_called()

    def test_record_preserves_version_exceptions(self):
        record = {"cveMetadata": {"cveId": "CVE-2025-12345"}, "containers": {"cna": {"affected": [{"versions": [{"version": "1", "lessThan": "3", "status": "affected", "changes": [{"at": "2", "status": "unaffected"}]}]}]}}}
        with patch("urllib.request.build_opener") as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = json.dumps(record).encode()
            result = fetch_record("cve-2025-12345")
            self.assertEqual(result["record"], record)
            self.assertIn("fetched_at", result)

    def test_mismatched_record_is_rejected(self):
        with patch("urllib.request.build_opener") as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = b'{"cveMetadata":{"cveId":"CVE-2025-99999"}}'
            with self.assertRaises(ValueError):
                fetch_record("CVE-2025-12345")

    def test_oversized_response_is_rejected(self):
        with patch("urllib.request.build_opener") as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = b' ' * (2*1024*1024+1)
            with self.assertRaises(ValueError):
                fetch_record("CVE-2025-12345")
