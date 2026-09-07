import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import opencti_smoke


class OpenCTISmokeTests(unittest.TestCase):
    def test_offline_fixture_covers_graph_without_network_or_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(opencti_smoke, "OpenCTIClient") as client, patch.object(opencti_smoke.service, "connection_test") as connection:
                proof = opencti_smoke.run(root, offline=True, output_root=root / "smoke", emit=lambda _value: None)
            self.assertEqual("offline-preview", proof["state"])
            self.assertEqual(8, proof["preview"]["iocs"])
            self.assertEqual(4, proof["preview"]["relationships"])
            client.assert_not_called()
            connection.assert_not_called()
            case = Path(proof["fixture_dir"])
            preview = json.loads((case / "opencti-preview.json").read_text(encoding="utf-8"))
            self.assertFalse(any(s["selected"] for s in preview["samples"]))
            self.assertNotIn(str(root).replace("\\", "\\\\"), json.dumps(preview))
            self.assertTrue(any(o["type"] == "malware" for o in preview["objects"]))
            self.assertTrue((case / "opencti-proof.json").is_file())

    def test_invalid_mutation_flag_combinations_fail_before_network(self):
        with patch.object(opencti_smoke.service, "connection_test") as connection:
            with self.assertRaises(ValueError):
                opencti_smoke.run(Path("unused"), sample=True)
            with self.assertRaises(ValueError):
                opencti_smoke.run(Path("unused"), offline=True, transfer=True)
            connection.assert_not_called()


if __name__ == "__main__":
    unittest.main()
