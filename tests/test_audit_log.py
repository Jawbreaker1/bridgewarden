import json
import tempfile
from pathlib import Path
import unittest

from bridgewarden.audit import AuditLogger
from bridgewarden.pipeline import guard_text


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
