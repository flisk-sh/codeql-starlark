import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "starlark_analyze.py"


class ScanRootTests(unittest.TestCase):
    def run_cli(self, root, output):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(root), "--output", str(output)],
            capture_output=True,
            text=True,
        )

    def test_invalid_roots_exit_with_a_path_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            regular_file = base / "regular-file"
            regular_file.touch()
            output = base / "report.sarif"
            for root in (base / "missing", regular_file):
                with self.subTest(root=root):
                    result = self.run_cli(root, output)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(str(root), result.stderr)
                    self.assertFalse(output.exists())

    def test_empty_scan_warns_and_writes_sarif(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "report.sarif"
            result = self.run_cli(root, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Warning: no files matched", result.stderr)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["runs"][0]["results"], [])
