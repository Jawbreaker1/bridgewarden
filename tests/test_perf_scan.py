import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PERF_SCRIPT = REPO_ROOT / "scripts" / "perf_scan.py"


class PerfScanScriptTests(unittest.TestCase):
    def test_documented_entrypoint_runs_from_repository_root(self) -> None:
        completed = subprocess.run(
            [str(PERF_SCRIPT), "--sizes", "100", "--runs", "1"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("BridgeWarden perf baseline", completed.stdout)

    def test_output_option_writes_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "perf.json"
            completed = subprocess.run(
                [
                    str(PERF_SCRIPT),
                    "--sizes",
                    "100",
                    "--runs",
                    "1",
                    "--output",
                    str(output_path),
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(result["sizes"], [100])
            self.assertEqual(result["runs"], 1)
            self.assertEqual(
                set(result["results"]["100"]),
                {"permissive", "balanced", "strict"},
            )


if __name__ == "__main__":
    unittest.main()
