import tempfile
import unittest
from pathlib import Path

from tools import mutation_summary


class MutationSummaryTests(unittest.TestCase):
    def test_reports_are_prioritized_and_partial_runs_are_explicit(self):
        with tempfile.TemporaryDirectory(prefix="shellhound-mut-summary-") as root:
            folder = Path(root)
            (folder / "survivors-app.txt").write_text(
                "[job-id] 1\nserver/app.py core/ReplaceBinaryOperator 2\n"
                "worker outcome: normal, test outcome: survived\n"
                "total jobs: 10\ncomplete: 8 (80.00%)\n"
                "surviving mutants: 1 (12.50%)\n", encoding="utf-8")
            (folder / "survivors-small.txt").write_text(
                "[job-id] 2\nserver/i18n.py core/ReplaceComparisonOperator 1\n"
                "worker outcome: normal, test outcome: survived\n"
                "total jobs: 4\ncomplete: 4 (100.00%)\n"
                "surviving mutants: 1 (25.00%)\n", encoding="utf-8")
            out = mutation_summary.summarize(folder)
        self.assertLess(out.index("| P0 | app"), out.index("| P2 | small"))
        self.assertIn("8/10", out)
        self.assertIn("PARTIAL", out)
        self.assertIn("lower bounds", out)

    def test_empty_artifact_folder_is_an_error(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(FileNotFoundError):
                mutation_summary.summarize(Path(root))


if __name__ == "__main__":
    unittest.main()
