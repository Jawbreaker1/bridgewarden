import json
import tempfile
from pathlib import Path
import unittest

from bridgewarden.audit import AuditLogger
from bridgewarden.pipeline import guard_text
from bridgewarden.tools import bw_fetch_repo, bw_read_file


class AuditLogWriterTests(unittest.TestCase):
    def test_audit_log_appends_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path)
            result = guard_text("hello", source={"kind": "fixture"})
            logger.log(result, timestamp="2024-01-01T00:00:00+00:00")

            lines = log_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            data = json.loads(lines[0])
            self.assertEqual(data["timestamp"], "2024-01-01T00:00:00+00:00")
            self.assertNotIn("sanitized_text", data)
            self.assertNotIn("original_text", data)

    def test_tool_level_blocks_are_audited(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path)
            result = bw_read_file(
                "../secrets.txt",
                base_dir=Path(tmpdir),
                audit_logger=logger,
            )

            self.assertEqual(result.decision, "BLOCK")
            lines = log_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            data = json.loads(lines[0])
            self.assertEqual(data["decision"], "BLOCK")
            self.assertEqual(data["reasons"], ["PATH_TRAVERSAL"])

    def test_repo_preflight_blocks_are_audited(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(log_path)
            result = bw_fetch_repo(
                "https://github.com/org/repo",
                audit_logger=logger,
            )

            self.assertEqual(result["summary"]["blocked"], 1)
            lines = log_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            data = json.loads(lines[0])
            self.assertEqual(data["decision"], "BLOCK")
            self.assertEqual(data["reasons"], ["NETWORK_DISABLED"])
